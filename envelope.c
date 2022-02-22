/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <utime.h>

#ifdef HAVE_LIBOPENDKIM
#include <opendkim/dkim.h>
#endif /* HAVE_LIBOPENDKIM */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "envelope.h"
#include "header.h"
#include "queue.h"
#include "simta_malloc.h"

simta_result env_read_old(const char *, ucl_object_t *, SNET *);

int
env_is_old(struct envelope *env, int dfile_fd) {
    struct timeval tv_now;
    struct stat    sb;
    int            bounce_seconds;

    if (env->e_age == ENV_AGE_UNKNOWN) {
        if (fstat(dfile_fd, &sb) != 0) {
            syslog(LOG_ERR, "Syserror: env_is_old fstat %s/D%s: %m", env->e_dir,
                    env->e_id);
            return (0);
        }

        if (simta_gettimeofday(&tv_now) != 0) {
            return (0);
        }

        bounce_seconds = simta_config_int("deliver.queue.bounce");
        if (bounce_seconds > 0) {
            if ((tv_now.tv_sec - sb.st_mtime) >= bounce_seconds) {
                env->e_age = ENV_AGE_OLD;
            } else {
                env->e_age = ENV_AGE_NOT_OLD;
            }
        }
    }

    if (env->e_age == ENV_AGE_OLD) {
        return (1);
    }

    return (0);
}


struct envelope *
env_create(const char *dir, const char *id, const char *e_mail,
        const struct envelope *parent) {
    struct envelope *env;
    struct timespec  ts_now;
    int              pid;
    /* way bigger than we should ever need */
    char buf[ 1024 ];

    env = simta_calloc(1, sizeof(struct envelope));

    if ((id == NULL) || (*id == '\0')) {
        if (clock_gettime(CLOCK_REALTIME, &ts_now) != 0) {
            env_free(env);
            return (NULL);
        }

        if ((pid = getpid()) < 0) {
            syslog(LOG_ERR, "Syserror: env_set_id getpid: %m");
            env_free(env);
            return (NULL);
        }

        snprintf(buf, 1023, "%lX.%lX.%lX.%d", (unsigned long)ts_now.tv_sec,
                (unsigned long)ts_now.tv_nsec, (unsigned long)random(), pid);

        id = buf;
    }

    env->e_id = simta_strdup(id);
    env->e_bounceable = true;
    env->e_puntable = true;

    if (e_mail != NULL) {
        env_sender(env, e_mail);
    }

    if (parent) {
        env->e_dinode = parent->e_dinode;
        env->e_n_exp_level = parent->e_n_exp_level + 1;
        env->e_8bitmime = parent->e_8bitmime;
        env->e_archive_only = parent->e_archive_only;
        env->e_bounceable = parent->e_bounceable;
        env->e_jailed = parent->e_jailed;
        env->e_puntable = parent->e_puntable;
    } else if (strcasecmp(simta_config_str("receive.queue.strategy"), "jail") ==
               0) {
        env->e_jailed = true;
    }

    env->e_dir = dir;

    return (env);
}


void
rcpt_free(struct recipient *r) {
    if (r != NULL) {
        if (r->r_rcpt != NULL) {
            free(r->r_rcpt);
            r->r_rcpt = NULL;
        }

        if (r->r_err_text != NULL) {
            line_file_free(r->r_err_text);
            r->r_err_text = NULL;
        }

        memset(r, 0, sizeof(struct recipient));
        free(r);
    }
}


void
env_rcpt_free(struct envelope *env) {
    struct recipient *r;
    struct recipient *r_next;


    for (r = env->e_rcpt; r != NULL; r = r_next) {
        r_next = r->r_next;
        rcpt_free(r);
    }

    env->e_rcpt = NULL;
    env->e_n_rcpt = 0;
}


void
env_clear_errors(struct envelope *env) {
    struct recipient *r;

    env->e_error = 0;

    if (env->e_err_text != NULL) {
        line_file_free(env->e_err_text);
        env->e_err_text = NULL;
    }

    env->e_flags = (env->e_flags & (~ENV_FLAG_BOUNCE));
    env->e_flags = (env->e_flags & (~ENV_FLAG_TEMPFAIL));

    for (r = env->e_rcpt; r != NULL; r = r->r_next) {
        if (r->r_err_text != NULL) {
            line_file_free(r->r_err_text);
            r->r_err_text = NULL;
        }
        r->r_status = 0;
    }

    return;
}


void
env_hostname(struct envelope *env, const char *hostname) {
    if (env->e_hostname && (strcasecmp(env->e_hostname, hostname) == 0)) {
        return;
    }


    if ((hostname == NULL) || (*hostname == '\0')) {
        yaslfree(env->e_hostname);
        env->e_hostname = NULL;
        return;
    }

    if (env->e_hostname) {
        yaslclear(env->e_hostname);
    } else {
        env->e_hostname = yaslempty();
    }
    env->e_hostname = yaslcat(env->e_hostname, hostname);
}


int
env_sender(struct envelope *env, const char *e_mail) {
    if (env->e_mail != NULL) {
        syslog(LOG_ERR, "Envelope env <%s>: env already has a sender",
                env->e_id);
        return (1);
    }

    env->e_mail = simta_strdup(e_mail);

    return (0);
}


void
env_free(struct envelope *env) {
    if (env == NULL) {
        return;
    }

    if (env->e_mid != NULL) {
        free(env->e_mid);
    }

    if (env->e_subject != NULL) {
        free(env->e_subject);
    }

    if (env->e_header_from != NULL) {
        free(env->e_header_from);
    }

    if (env->e_env_list_entry != NULL) {
        dll_remove_entry(&simta_env_list, env->e_env_list_entry);
    }

    if (env->e_mail != NULL) {
        free(env->e_mail);
    }

    if (env->e_mail_orig != NULL) {
        free(env->e_mail_orig);
    }

    if (env->e_sender_entry != NULL) {
        dll_remove_entry(&(env->e_sender_entry->se_list->sl_entries),
                env->e_sender_entry->se_dll);
        env->e_sender_entry->se_list->sl_n_entries--;
        if (env->e_sender_entry->se_list->sl_entries == NULL) {
            dll_remove_entry(
                    &simta_sender_list, env->e_sender_entry->se_list->sl_dll);
            free(env->e_sender_entry->se_list);
        }
        free(env->e_sender_entry);
    }

    if (env->e_hostname != NULL) {
        yaslfree(env->e_hostname);
    }

    if (env->e_id != NULL) {
        free(env->e_id);
    }

    env_rcpt_free(env);
    env_clear_errors(env);
    memset(env, 0, sizeof(struct envelope));
    free(env);

    return;
}


ucl_object_t *
env_repr(struct envelope *e) {
    struct recipient *r;
    ucl_object_t *    repr;
    ucl_object_t *    rcpts;

    /* Build the output object */
    repr = ucl_object_new();
    ucl_object_insert_key(
            repr, ucl_object_fromstring(e->e_id), "envelope_id", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_fromint(e->e_dinode), "body_inode", 0, false);
    ucl_object_insert_key(repr, ucl_object_fromint(e->e_n_exp_level),
            "expansion_level", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_fromstring(e->e_hostname), "hostname", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_fromstring(e->e_mail), "sender", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_frombool(e->e_8bitmime), "8bitmime", 0, false);
    ucl_object_insert_key(repr, ucl_object_frombool(e->e_archive_only),
            "archive_only", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_frombool(e->e_jailed), "jailed", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_frombool(e->e_bounceable), "bounceable", 0, false);
    ucl_object_insert_key(
            repr, ucl_object_frombool(e->e_puntable), "puntable", 0, false);

    rcpts = ucl_object_typed_new(UCL_ARRAY);
    ucl_object_insert_key(repr, rcpts, "recipients", 0, false);
    for (r = e->e_rcpt; r != NULL; r = r->r_next) {
        ucl_array_append(rcpts, ucl_object_fromstring(r->r_rcpt));
    }

    return repr;
}


void
env_stdout(struct envelope *e) {
    printf("%s\n", ucl_object_emit(env_repr(e), UCL_EMIT_JSON));
}


int
env_recipient(struct envelope *e, const char *addr) {
    struct recipient *r;

    r = simta_calloc(1, sizeof(struct recipient));

    if ((addr == NULL) || (*addr == '\0')) {
        r->r_rcpt = simta_strdup("");
    } else {
        r->r_rcpt = simta_strdup(addr);
    }

    r->r_next = e->e_rcpt;
    e->e_rcpt = r;
    e->e_n_rcpt++;

    return (0);
}


simta_result
env_outfile(struct envelope *env) {
    yastr headers;
#ifdef HAVE_LIBOPENDKIM
    yastr tmp;
#endif /* HAVE_LIBOPENDKIM */

    headers = env->e_extra_headers;
    env->e_extra_headers = NULL;

#ifdef HAVE_LIBOPENDKIM
    if (env->e_flags & ENV_FLAG_DKIMSIGN) {
        tmp = env_dkim_sign(env);
        if (headers != NULL) {
            tmp = yaslcatyasl(yaslcat(tmp, "\n"), headers);
            yaslfree(headers);
        }
        headers = tmp;
        env->e_flags ^= ENV_FLAG_DKIMSIGN;
    }
#endif /* HAVE_LIBOPENDKIM */

    if (headers) {
        env_dfile_copy(env, NULL, headers);
        yaslfree(headers);
    }

    if ((env->e_flags & ENV_FLAG_TFILE) == 0) {
        if (env_tfile(env) != SIMTA_OK) {
            return SIMTA_ERR;
        }
    }

    if (env_efile(env) != 0) {
        return SIMTA_ERR;
    }

    return SIMTA_OK;
}


int
env_dfile_open(struct envelope *env) {
    char        dfile_fname[ MAXPATHLEN + 1 ];
    int         fd;
    struct stat sbuf;

    sprintf(dfile_fname, "%s/D%s", env->e_dir, env->e_id);

    if ((fd = open(dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0664)) < 0) {
        syslog(LOG_ERR, "Syserror: env_dfile_open open %s: %m", dfile_fname);
        return (-1);
    }

    env->e_flags |= ENV_FLAG_DFILE;

    if (fstat(fd, &sbuf) != 0) {
        syslog(LOG_ERR, "Syserror: env_dfile_open fstat %s: %m", dfile_fname);
        if (close(fd) != 0) {
            syslog(LOG_ERR, "Syserror: env_dfile_open close %s: %m",
                    dfile_fname);
        }
        return (-1);
    }

    env->e_dinode = sbuf.st_ino;

    return (fd);
}


int
env_tfile_unlink(struct envelope *e) {
    char tf[ MAXPATHLEN + 1 ];

    simta_debuglog(3, "env_tfile_unlink %s", e->e_id);

    sprintf(tf, "%s/t%s", e->e_dir, e->e_id);

    if (unlink(tf) != 0) {
        syslog(LOG_ERR, "Syserror: env_tfile_unlink unlink %s: %m", tf);
        return (-1);
    }

    e->e_flags = (e->e_flags & (~ENV_FLAG_TFILE));

    return (0);
}


simta_result
env_tfile(struct envelope *e) {
    int            fd;
    FILE *         tff = NULL;
    char           tf[ MAXPATHLEN + 1 ];
    ucl_object_t * repr = NULL;
    unsigned char *buf = NULL;
    simta_result   ret = SIMTA_ERR;

    assert(e->e_dir != NULL);
    assert(e->e_id != NULL);

    if (e->e_rcpt == NULL) {
        syslog(LOG_ERR, "Envelope env <%s>: no recipients while writing tfile",
                e->e_id);
        return SIMTA_ERR;
    }

    sprintf(tf, "%s/t%s", e->e_dir, e->e_id);

    /* make tfile */
    if ((fd = open(tf, O_WRONLY | O_CREAT | O_EXCL, 0664)) < 0) {
        syslog(LOG_ERR, "Syserror: env_tfile open %s: %m", tf);
        return SIMTA_ERR;
    }

    if ((tff = fdopen(fd, "w")) == NULL) {
        close(fd);
        syslog(LOG_ERR, "Syserror: env_tfile fdopen: %m");
        goto cleanup;
    }

    /* FIXME: should there be more error checking for libucl? */
    repr = env_repr(e);
    buf = ucl_object_emit(repr, UCL_EMIT_JSON);
    if (fprintf(tff, "%s\n", buf) < 0) {
        syslog(LOG_ERR, "Syserror: env_tfile fprintf: %m");
        goto cleanup;
    }

    e->e_flags |= ENV_FLAG_TFILE;
    ret = SIMTA_OK;

cleanup:
    if (repr) {
        ucl_object_unref(repr);
    }

    if (buf) {
        free(buf);
    }

    if (tff) {
        if (fclose(tff) != 0) {
            syslog(LOG_ERR, "Syserror: env_tfile fclose: %m");
            ret = SIMTA_ERR;
        }
    }

    if (ret != SIMTA_OK) {
        unlink(tf);
    }

    return ret;
}


int
sender_list_add(struct envelope *e) {
    struct dll_entry *   sl_dll;
    struct dll_entry *   se_dll;
    struct sender_list * list;
    struct sender_entry *entry;

    if ((sl_dll = dll_lookup_or_create(&simta_sender_list, e->e_mail)) ==
            NULL) {
        return (1);
    }

    if ((list = (struct sender_list *)sl_dll->dll_data) == NULL) {
        list = simta_calloc(1, sizeof(struct sender_list));
        list->sl_dll = sl_dll;
        sl_dll->dll_data = list;
    }

    if ((se_dll = dll_lookup_or_create(&(list->sl_entries), e->e_id)) == NULL) {
        return (1);
    }

    if (se_dll->dll_data != NULL) {
        return (0);
    }

    entry = simta_calloc(1, sizeof(struct sender_entry));
    se_dll->dll_data = entry;
    e->e_sender_entry = entry;
    entry->se_env = e;
    entry->se_list = list;
    entry->se_dll = se_dll;
    list->sl_n_entries++;

    return (0);
}

#ifdef HAVE_LIBOPENDKIM
yastr
env_dkim_sign(struct envelope *env) {
    char           df[ MAXPATHLEN + 1 ];
    DKIM_LIB *     libhandle;
    unsigned int   flags;
    DKIM *         dkim = NULL;
    DKIM_STAT      result;
    yastr          signature = NULL;
    yastr          key = NULL;
    char           buf[ 16384 ];
    unsigned char *dkim_header;
    SNET *         snet;
    ssize_t        chunk;

    sprintf(df, "%s/D%s", env->e_dir, env->e_id);

    if ((key = simta_slurp(simta_config_str("deliver.dkim.key"))) == NULL) {
        return (NULL);
    }

    if ((libhandle = dkim_init(NULL, NULL)) == NULL) {
        syslog(LOG_ERR, "Liberror: env_dkim_sign dkim_init");
        yaslfree(key);
        return (NULL);
    }

    /* Data is stored in UNIX format, so tell libopendkim to fix
     * CRLF issues.
     */
    flags = DKIM_LIBFLAGS_FIXCRLF;
    if (dkim_options(libhandle, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &flags,
                sizeof(flags)) != DKIM_STAT_OK) {
        syslog(LOG_ERR, "Liberror: env_dkim_sign dkim_options flags");
        goto error;
    }

    /* Only sign the headers recommended by RFC 6376 */
    if (dkim_options(libhandle, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
                dkim_should_signhdrs,
                sizeof(unsigned char **)) != DKIM_STAT_OK) {
        syslog(LOG_ERR, "Liberror: env_dkim_sign dkim_options signhdrs");
        goto error;
    }

    if ((dkim = dkim_sign(libhandle, (unsigned char *)(env->e_id), NULL,
                 (unsigned char *)key,
                 (unsigned char *)simta_config_str("deliver.dkim.selector"),
                 (unsigned char *)simta_config_str("deliver.dkim.domain"),
                 DKIM_CANON_RELAXED, DKIM_CANON_RELAXED, DKIM_SIGN_RSASHA256,
                 -1, &result)) == NULL) {
        syslog(LOG_NOTICE, "Liberror: env_dkim_sign dkim_sign: %s",
                dkim_getresultstr(result));
        goto error;
    }

    if ((snet = snet_open(df, O_RDONLY, 0, 1024 * 1024)) == NULL) {
        syslog(LOG_ERR, "Liberror: env_dkim_sign snet_open %s: %m", buf);
        goto error;
    }

    while ((chunk = snet_read(snet, buf, 16384, NULL)) > 0) {
        if ((result = dkim_chunk(dkim, (unsigned char *)buf, chunk)) != 0) {
            syslog(LOG_NOTICE, "Liberror: env_dkim_sign dkim_chunk: %s: %s",
                    dkim_getresultstr(result), dkim_geterror(dkim));
            snet_close(snet);
            goto error;
        }
    }

    snet_close(snet);

    if ((result = dkim_chunk(dkim, NULL, 0)) != 0) {
        syslog(LOG_NOTICE, "Liberror: env_dkim_sign dkim_chunk: %s: %s",
                dkim_getresultstr(result), dkim_geterror(dkim));
        goto error;
    }
    if ((result = dkim_eom(dkim, NULL)) != 0) {
        syslog(LOG_NOTICE, "Liberror: env_dkim_sign dkim_eom: %s: %s",
                dkim_getresultstr(result), dkim_geterror(dkim));
        goto error;
    }
    if ((result = dkim_getsighdr_d(dkim, 16, &dkim_header, (size_t *)&chunk)) !=
            0) {
        syslog(LOG_NOTICE, "Liberror: env_dkim_sign dkim_getsighdr_d: %s: %s",
                dkim_getresultstr(result), dkim_geterror(dkim));
        goto error;
    }

    /* Get rid of carriage returns in libopendkim output */
    signature =
            yaslcat(yaslauto("DKIM-Signature: "), (const char *)dkim_header);
    yaslstrip(signature, "\r");

error:
    yaslfree(key);
    dkim_free(dkim);
    dkim_close(libhandle);

    return (signature);
}
#endif /* HAVE_LIBOPENDKIM */

int
env_efile(struct envelope *e) {
    char              tf[ MAXPATHLEN + 1 ];
    char              ef[ MAXPATHLEN + 1 ];
    char              df[ MAXPATHLEN + 1 ];
    struct timeval    tv_now;
    struct dll_entry *e_dll;

    sprintf(tf, "%s/t%s", e->e_dir, e->e_id);
    sprintf(ef, "%s/E%s", e->e_dir, e->e_id);
    sprintf(df, "%s/D%s", e->e_dir, e->e_id);

    if (rename(tf, ef) < 0) {
        syslog(LOG_ERR, "Syserror: env_efile rename %s %s: %m", tf, ef);
        unlink(tf);
        return (-1);
    }

    if (e->e_dir == simta_dir_fast) {
        simta_fast_files++;
        simta_debuglog(2, "Envelope env <%s> fast_files increment %d", e->e_id,
                simta_fast_files);
    }

    simta_debuglog(3, "env_efile %s %s %s", e->e_dir, e->e_id,
            e->e_hostname ? e->e_hostname : "");

    e->e_flags = (e->e_flags & (~ENV_FLAG_TFILE));
    e->e_flags |= ENV_FLAG_EFILE;

    if (simta_gettimeofday(&tv_now) != 0) {
        return (-1);
    }

    e->e_etime.tv_sec = tv_now.tv_sec;

    env_fsync(ef);
    env_fsync(df);
    /* fsync() does not ensure that the directory entries for the files
     * have been synced, so we must explicitly sync the directory.
     */
    env_fsync(e->e_dir);

    if ((e_dll = dll_lookup_or_create(&simta_env_list, e->e_id)) == NULL) {
        return (1);
    }

    if (e_dll->dll_data == NULL) {
        e_dll->dll_data = e;
        e->e_env_list_entry = e_dll;
    }

    if (sender_list_add(e) != 0) {
        return (1);
    }

    return (0);
}

int
env_fsync(const char *path) {
    int fd;
    int ret = 0;

    if ((fd = open(path, O_RDONLY)) < 0) {
        syslog(LOG_ERR, "Syserror: env_fsync open %s: %m", path);
        return (1);
    }

    /* fdatasync() "does not flush modified metadata unless that metadata is
     * needed in order to allow a subsequent data retrieval to be correctly
     * handled." We don't require that all metadata be synced to disk, so if
     * fdatasync() is available it's preferred.
     */
#if defined(_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
    if (fdatasync(fd) < 0) {
#else
    if (fsync(fd) < 0) {
#endif
        syslog(LOG_ERR, "Syserror: env_fsync fsync %s: %m", path);
        ret = 1;
    }
    close(fd);

    return (ret);
}

/* calling this function updates the attempt time */

int
env_touch(struct envelope *env) {
    char           fname[ MAXPATHLEN ];
    struct timeval tv_now;

    sprintf(fname, "%s/E%s", env->e_dir, env->e_id);

    if (utime(fname, NULL) != 0) {
        syslog(LOG_ERR, "Syserror: env_touch utime %s: %m", fname);
        return (-1);
    }

    if (simta_gettimeofday(&tv_now) != 0) {
        return (-1);
    }

    env->e_etime.tv_sec = tv_now.tv_sec;

    return (0);
}


simta_result
env_read(bool initial, struct envelope *env, SNET **s_lock) {
    simta_result        ret = SIMTA_ERR;
    yastr               filename = NULL;
    yastr               unparsed = NULL;
    SNET *              snet = NULL;
    const char *        data;
    struct ucl_parser * parser = NULL;
    ucl_object_t *      env_data = NULL;
    ucl_object_iter_t   iter = NULL;
    const ucl_object_t *rcpt = NULL;
    struct dll_entry *  e_dll;

    if (initial && (s_lock != NULL)) {
        syslog(LOG_ERR, "Envelope.read no lock allowed during initial read");
        return SIMTA_ERR;
    }

    filename = yaslcatprintf(yaslauto(env->e_dir), "/E%s", env->e_id);

    if ((snet = snet_open(filename, O_RDWR, 0, 1024 * 1024)) == NULL) {
        if (errno != ENOENT) {
            syslog(LOG_ERR, "Syserror: env_read snet_open %s: %m", filename);
        }
        return SIMTA_ERR;
    }

    if (initial) {
        /* test to see if env is locked by a q_runner */
        if (lockf(snet_fd(snet), F_TEST, 0) != 0) {
            syslog(LOG_ERR, "Syserror: env_read lockf %s: %m", filename);
            goto cleanup;
        }
    } else if (s_lock != NULL) {
        *s_lock = snet;

        /* lock envelope fd */
        if (lockf(snet_fd(snet), F_TLOCK, 0) != 0) {
            if (errno != EAGAIN) {
                /* file not locked by a diferent process */
                syslog(LOG_ERR, "Syserror: env_read lockf %s: %m", filename);
            }
            goto cleanup;
        }
    }

    /* Check if this is an old-style file */
    data = snet_getline(snet, NULL);
    if (data == NULL) {
        syslog(LOG_ERR, "Envelope.read %s: expected non-empty file", filename);
        goto cleanup;
    } else if (*data == 'V') {
        if (strtol(data + 1, NULL, 10) != 5) {
            syslog(LOG_ERR, "Envelope.read %s: unsupported old file version %s",
                    filename, data + 1);
            goto cleanup;
        }
        env_data = ucl_object_new();
        ret = env_read_old(filename, env_data, snet);
    } else {
        unparsed = yaslauto(data);
        while ((data = snet_getline(snet, NULL)) != NULL) {
            unparsed = yaslcat(unparsed, "\n");
            unparsed = yaslcat(unparsed, data);
        }
        parser = ucl_parser_new(UCL_PARSER_DEFAULT);
        if (!ucl_parser_add_string(parser, unparsed, yasllen(unparsed))) {
            syslog(LOG_ERR, "Envelope.read %s: parsing failed: %s", filename,
                    ucl_parser_get_error(parser));
            goto cleanup;
        }
        env_data = ucl_parser_get_object(parser);
    }

    data = ucl_object_tostring(ucl_object_lookup(env_data, "envelope_id"));
    if (strcmp(env->e_id, data) != 0) {
        syslog(LOG_WARNING, "Envelope.read %s: envelope id mismatch: %s",
                filename, data);
        goto cleanup;
    }

    if (initial) {
        env->e_dinode =
                ucl_object_toint(ucl_object_lookup(env_data, "body_inode"));
        if (env->e_dinode == 0) {
            syslog(LOG_WARNING, "Envelope.read %s: body_inode is 0", filename);
        }

        env->e_n_exp_level = ucl_object_toint(
                ucl_object_lookup(env_data, "expansion_level"));
        env->e_jailed =
                ucl_object_toboolean(ucl_object_lookup(env_data, "jailed"));
        env->e_bounceable =
                ucl_object_toboolean(ucl_object_lookup(env_data, "bounceable"));
        env->e_puntable =
                ucl_object_toboolean(ucl_object_lookup(env_data, "puntable"));
        env_hostname(env,
                ucl_object_tostring(ucl_object_lookup(env_data, "hostname")));
        env->e_8bitmime =
                ucl_object_toboolean(ucl_object_lookup(env_data, "8bitmime"));
        env->e_archive_only = ucl_object_toboolean(
                ucl_object_lookup(env_data, "archive_only"));
        env_sender(env,
                ucl_object_tostring(ucl_object_lookup(env_data, "sender")));
    } else {
        if (env->e_dinode != ucl_object_toint(ucl_object_lookup(
                                     env_data, "body_inode")) ||
                env->e_n_exp_level != ucl_object_toint(ucl_object_lookup(
                                              env_data, "expansion_level")) ||
                env->e_jailed != ucl_object_toboolean(ucl_object_lookup(
                                         env_data, "jailed")) ||
                env->e_bounceable != ucl_object_toboolean(ucl_object_lookup(
                                             env_data, "bounceable")) ||
                env->e_puntable != ucl_object_toboolean(ucl_object_lookup(
                                           env_data, "puntable")) ||
                (strcasecmp(env->e_hostname,
                         ucl_object_tostring(ucl_object_lookup(
                                 env_data, "hostname"))) != 0) ||
                env->e_8bitmime != ucl_object_toboolean(ucl_object_lookup(
                                           env_data, "8bitmime")) ||
                env->e_archive_only != ucl_object_toboolean(ucl_object_lookup(
                                               env_data, "archive_only")) ||
                (strcasecmp(env->e_mail, ucl_object_tostring(ucl_object_lookup(
                                                 env_data, "sender"))) != 0)) {
            syslog(LOG_ERR,
                    "Envelope.read %s: inconsistent metadata: %s does not "
                    "match in-memory %s",
                    filename, ucl_object_emit(env_data, UCL_EMIT_JSON_COMPACT),
                    ucl_object_emit(env_repr(env), UCL_EMIT_JSON_COMPACT));
            goto cleanup;
        }

        iter = ucl_object_iterate_new(
                ucl_object_lookup(env_data, "recipients"));
        while ((rcpt = ucl_object_iterate_safe(iter, false)) != NULL) {
            if (env_recipient(env, ucl_object_tostring(rcpt)) != 0) {
                goto cleanup;
            }
        }

        if (env->e_rcpt == NULL) {
            syslog(LOG_ERR, "Envelope.read %s: no recipients", filename);
            goto cleanup;
        }
    }

    ret = SIMTA_OK;

cleanup:
    yaslfree(unparsed);
    if (parser != NULL) {
        ucl_parser_free(parser);
    }
    if (iter != NULL) {
        ucl_object_iterate_free(iter);
    }

    /* close snet if no need to maintain lock */
    if ((snet != NULL) && (s_lock == NULL || ret != SIMTA_OK)) {
        if (snet_close(snet) < 0) {
            syslog(LOG_ERR, "Liberror: env_read snet_close %s: %m", filename);
            ret = 1;
        }
    }

    yaslfree(filename);
    filename = NULL;

    if (ret == SIMTA_OK) {
        if ((e_dll = dll_lookup_or_create(&simta_env_list, env->e_id)) ==
                NULL) {
            return SIMTA_ERR;
        }

        if (e_dll->dll_data == NULL) {
            e_dll->dll_data = env;
            env->e_env_list_entry = e_dll;
        }

        if (sender_list_add(env) != 0) {
            return SIMTA_ERR;
        }
    }

    return ret;
}


simta_result
env_read_old(const char *filename, ucl_object_t *env_data, SNET *snet) {
    ucl_object_t *rcpts;
    char *        line;
    int           attrs;
    int           line_no = 2;

    rcpts = ucl_object_typed_new(UCL_ARRAY);
    ucl_object_insert_key(env_data, rcpts, "recipients", 0, false);
    ucl_object_insert_key(
            env_data, ucl_object_frombool(true), "puntable", 0, false);
    ucl_object_insert_key(
            env_data, ucl_object_frombool(true), "bounceable", 0, false);

    /* Emessage-id */
    while ((line = snet_getline(snet, NULL)) != NULL) {
        line_no++;
        switch (*line) {
        case 'M':
            /* never implemented */
            break;
        case 'E':
            ucl_object_insert_key(env_data, ucl_object_fromstring(line + 1),
                    "envelope_id", 0, false);
            break;
        case 'I':
            ucl_object_insert_key(env_data,
                    ucl_object_fromstring_common(
                            line + 1, 0, UCL_STRING_PARSE_INT),
                    "body_inode", 0, false);
            break;

        case 'X':
            ucl_object_insert_key(env_data,
                    ucl_object_fromstring_common(
                            line + 1, 0, UCL_STRING_PARSE_INT),
                    "expansion_level", 0, false);
            break;

        case 'J':
            ucl_object_insert_key(env_data,
                    ucl_object_frombool(*(line + 1) == '2'), "jailed", 0,
                    false);
            break;

        case 'H':
            ucl_object_insert_key(env_data, ucl_object_fromstring(line + 1),
                    "hostname", 0, false);
            break;

        case 'D':
            attrs = strtol(line + 1, NULL, 10);
            ucl_object_insert_key(env_data, ucl_object_frombool(attrs & 0x01),
                    "archive_only", 0, false);
            ucl_object_insert_key(env_data, ucl_object_frombool(attrs & 0x02),
                    "8bitmime", 0, false);
            break;

        case 'F':
            ucl_object_insert_key(env_data, ucl_object_fromstring(line + 1),
                    "sender", 0, false);
            break;

        case 'R':
            ucl_array_append(rcpts, ucl_object_fromstring(line + 1));
            break;

        default:
            syslog(LOG_WARNING, "Envelope read %s %d: unparsable line %s",
                    filename, line_no, line);
            return SIMTA_ERR;
        }
    }

    return SIMTA_OK;
}

ino_t
env_dfile_copy(struct envelope *env, char *source, char *header) {
    int         dfile_fd = -1;
    ino_t       retval = 0;
    FILE *      dfile = NULL;
    struct stat sbuf;
    SNET *      snet = NULL;
    char *      line;
    char        df[ MAXPATHLEN + 1 ];

    /* If the tfile has already been written it has incorrect Dinode
     * information.
     */
    if (env->e_flags & ENV_FLAG_TFILE) {
        env_tfile_unlink(env);
    }

    if (source == NULL) {
        if (!(env->e_flags & ENV_FLAG_DFILE)) {
            syslog(LOG_ERR, "env_dfile_copy: no source");
            return (0);
        }

        sprintf(df, "%s/D%s", env->e_dir, env->e_id);
        if ((snet = snet_open(df, O_RDONLY, 0, 1024 * 1024)) != NULL) {
            if (unlink(df)) {
                syslog(LOG_ERR, "Syserror: env_dfile_copy unlink %s: %m", df);
                goto error;
            }
        }
    } else {
        snet = snet_open(source, O_RDONLY, 0, 1024 * 1024);
    }

    if (snet == NULL) {
        syslog(LOG_ERR, "Liberror: env_dfile_copy snet_open: %m");
        return (0);
    }

    if ((dfile_fd = env_dfile_open(env)) < 0) {
        goto error;
    }

    if ((dfile = fdopen(dfile_fd, "w")) == NULL) {
        syslog(LOG_ERR, "Syserror: env_dfile_copy fdopen: %m");
        if (close(dfile_fd) != 0) {
            syslog(LOG_ERR, "Syserror: env_dfile_copy close: %m");
        }
        goto error;
    }

    if (header) {
        if (fprintf(dfile, "%s\n", header) < 0) {
            syslog(LOG_ERR, "Syserror: env_dfile_copy fprintf: %m");
            goto error;
        }
    }

    while ((line = snet_getline(snet, NULL)) != NULL) {
        if (fprintf(dfile, "%s\n", line) < 0) {
            syslog(LOG_ERR, "Syserror: env_dfile_copy fprintf: %m");
            goto error;
        }
    }

    if (fstat(dfile_fd, &sbuf) == 0) {
        retval = sbuf.st_ino;
    } else {
        syslog(LOG_ERR, "Syserror: env_dfile_copy fstat: %m");
    }

error:
    if (dfile != NULL && (fclose(dfile) != 0)) {
        syslog(LOG_ERR, "Syserror: env_dfile_copy fclose: %m");
    }

    if (snet != NULL && (snet_close(snet) != 0)) {
        syslog(LOG_ERR, "Liberror: env_dfile_copy snet_close: %m");
    }

    if (retval == 0) {
        env_dfile_unlink(env);
    }

    return (retval);
}

int
env_truncate_and_unlink(struct envelope *env, SNET *snet_lock) {
    char efile_fname[ MAXPATHLEN + 1 ];

    if (snet_lock != NULL) {
        if (ftruncate(snet_fd(snet_lock), (off_t)0) == 0) {
            env_unlink(env);
            return (0);
        }

        sprintf(efile_fname, "%s/E%s", env->e_dir, env->e_id);
        syslog(LOG_ERR, "Syserror: env_truncate_and_unlink ftruncate %s: %m",
                efile_fname);
    }

    return (env_unlink(env));
}


int
env_dfile_unlink(struct envelope *e) {
    char df[ MAXPATHLEN + 1 ];

    simta_debuglog(3, "env_dfile_unlink env <%s>", e->e_id);

    sprintf(df, "%s/D%s", e->e_dir, e->e_id);

    if (unlink(df) != 0) {
        syslog(LOG_ERR, "Syserror: env_dfile_unlink unlink %s: %m", df);
        return (-1);
    }

    e->e_flags = (e->e_flags & (~ENV_FLAG_DFILE));

    return (0);
}


/* truncate the efile before calling this function */

int
env_unlink(struct envelope *env) {
    char efile_fname[ MAXPATHLEN + 1 ];

    sprintf(efile_fname, "%s/E%s", env->e_dir, env->e_id);

    if (unlink(efile_fname) != 0) {
        syslog(LOG_ERR, "Syserror: env_unlink unlink %s: %m", efile_fname);
        return (-1);
    }

    env->e_flags = (env->e_flags & (~ENV_FLAG_EFILE));

    if (env->e_dir == simta_dir_fast) {
        simta_fast_files--;
        simta_debuglog(3, "env_unlink env <%s> fast_files decrement %d",
                env->e_id, simta_fast_files);
    }

    env_dfile_unlink(env);

    simta_debuglog(
            2, "env_unlink env <%s> %s: unlinked", env->e_id, env->e_dir);

    return (0);
}


int
env_move(struct envelope *env, char *target_dir) {
    char dfile_new[ MAXPATHLEN ];
    char efile_new[ MAXPATHLEN ];
    char dfile_old[ MAXPATHLEN ];
    char efile_old[ MAXPATHLEN ];

    /* only move messages to slow or fast */
    assert((target_dir == simta_dir_slow) || (target_dir == simta_dir_fast));

    /* move message to target_dir if it isn't there already */
    if (env->e_dir != target_dir) {
        sprintf(efile_old, "%s/E%s", env->e_dir, env->e_id);
        sprintf(dfile_old, "%s/D%s", env->e_dir, env->e_id);
        sprintf(dfile_new, "%s/D%s", target_dir, env->e_id);
        sprintf(efile_new, "%s/E%s", target_dir, env->e_id);

        if (link(dfile_old, dfile_new) != 0) {
            syslog(LOG_ERR, "Syserror: env_move link %s %s: %m", dfile_old,
                    dfile_new);
            return (-1);
        }

        if (link(efile_old, efile_new) != 0) {
            syslog(LOG_ERR, "Syserror: env_move link %s %s: %m", efile_old,
                    efile_new);
            if (unlink(dfile_new) != 0) {
                syslog(LOG_ERR, "Syserror: env_move unlink %s: %m", dfile_new);
            }
            return (-1);
        }

        if (target_dir == simta_dir_fast) {
            simta_fast_files++;
            simta_debuglog(3, "env_move env <%s> fast_files increment %d",
                    env->e_id, simta_fast_files);
        }

        if (env_unlink(env) != 0) {
            if (unlink(efile_new) != 0) {
                syslog(LOG_ERR, "env_move unlink %s: %m", efile_new);
            } else {
                if (target_dir == simta_dir_fast) {
                    simta_fast_files--;
                    simta_debuglog(3, "env_move %s fast_files decrement %d",
                            env->e_id, simta_fast_files);
                }

                if (unlink(dfile_new) != 0) {
                    syslog(LOG_ERR, "env_move unlink %s: %m", dfile_new);
                }
            }
            return (-1);
        }

        env->e_dir = target_dir;
        env->e_flags |= ENV_FLAG_EFILE;

        simta_debuglog(
                1, "Envelope env <%s>: moved to %s", env->e_id, env->e_dir);
    }

    return (0);
}


int
env_string_recipients(struct envelope *env, char *line) {
    struct string_address *sa;
    char *                 addr;

    sa = string_address_init(line);

    while ((addr = string_address_parse(sa)) != NULL) {
        if (env_recipient(env, addr) != 0) {
            string_address_free(sa);
            return (1);
        }
    }

    string_address_free(sa);

    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
