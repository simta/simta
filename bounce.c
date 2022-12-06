/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "envelope.h"
#include "header.h"
#include "queue.h"
#include "simta_statsd.h"


int
bounce_yastr(struct envelope *bounce_env, int mode, const yastr text) {
    int ret = 0;

    if (mode != 0) {
        bounce_env->e_error = mode;
    }

    if (bounce_env->e_err_text == NULL) {
        bounce_env->e_err_text = line_file_create();
    }

    if (mode != 0) {
        if (line_append(bounce_env->e_err_text, text, COPY) == NULL) {
            ret = -1;
        }
    } else {
        if (line_prepend(bounce_env->e_err_text, text, COPY) == NULL) {
            ret = -1;
        }
    }

    return (ret);
}

int
bounce_text(struct envelope *bounce_env, int mode, const char *t1,
        const char *t2, const char *t3) {
    int   ret;
    yastr buf;

    buf = yaslauto(t1);
    if (t2) {
        buf = yaslcat(buf, t2);
    }
    if (t3) {
        buf = yaslcat(buf, t3);
    }

    ret = bounce_yastr(bounce_env, mode, buf);
    yaslfree(buf);
    return (ret);
}


void
bounce_stdout(struct envelope *bounce_env) {
    struct line  *l;
    yastr         buf = NULL;
    ucl_object_t *repr;
    ucl_object_t *b_obj;

    if ((bounce_env->e_err_text == NULL) ||
            ((l = bounce_env->e_err_text->l_first) == NULL) ||
            (bounce_env->e_error == 0)) {
        return;
    }

    repr = env_repr(bounce_env);

    buf = yaslauto("mailer-daemon@");
    buf = yaslcatyasl(buf, simta_hostname);
    ucl_object_replace_key(
            repr, simta_ucl_object_fromyastr(buf), "header_from", 0, false);
    yaslfree(buf);
    buf = NULL;

    b_obj = ucl_object_typed_new(UCL_ARRAY);
    ucl_object_insert_key(repr, b_obj, "bounce_lines", 0, false);
    while (l != NULL) {
        ucl_array_append(b_obj, simta_ucl_object_fromstring(l->line_data));
        l = l->line_next;
    }

    printf("%s\n", ucl_object_emit(repr, UCL_EMIT_JSON));
}


ino_t
bounce_dfile_out(struct envelope *bounce_env, SNET *message) {
    int               ret = 0;
    char              dfile_fname[ MAXPATHLEN ];
    int               dfile_fd;
    int               write_body = 0;
    FILE             *dfile;
    struct line      *l;
    char             *line;
    yastr             daytime = NULL;
    struct stat       sbuf;
    struct recipient *r;

    sprintf(dfile_fname, "%s/D%s", bounce_env->e_dir, bounce_env->e_id);

#ifdef HAVE_LIBOPENDKIM
    if (simta_config_bool("deliver.dkim.enabled")) {
        bounce_env->e_flags |= ENV_FLAG_DKIMSIGN;
    }
#endif /* HAVE_LIBOPENDKIM */

    if ((dfile_fd = env_dfile_open(bounce_env)) < 0) {
        goto error;
    }

    if ((dfile = fdopen(dfile_fd, "w")) == NULL) {
        syslog(LOG_ERR, "Syserror: bounce_dfile_out fdopen %s: %m",
                dfile_fname);
        if (close(dfile_fd) != 0) {
            syslog(LOG_ERR, "Syserror: bounce_dfile_out fclose %s: %m",
                    dfile_fname);
        }
        return (0);
    }

    if (message != NULL) {
        if (fstat(snet_fd(message), &sbuf) != 0) {
            syslog(LOG_ERR, "Syserror: bounce_dfile_out fstat: %m");
            goto cleanup;
        }

        if (sbuf.st_size < simta_config_int("deliver.queue.bounce_size")) {
            write_body = 1;
        }
    }

    if ((daytime = rfc5322_timestamp()) == NULL) {
        goto cleanup;
    }

    /* dfile message headers */
    fprintf(dfile, "From: <mailer-daemon@%s>\n", simta_hostname);
    for (r = bounce_env->e_rcpt; r != NULL; r = r->r_next) {
        if (r->r_rcpt == NULL || *r->r_rcpt == '\0') {
            fprintf(dfile, "To: <%s>\n", simta_postmaster);
        } else {
            fprintf(dfile, "To: <%s>\n", r->r_rcpt);
        }
    }
    fprintf(dfile, "Date: %s\n", daytime);
    fprintf(dfile, "Message-ID: <%s@%s>\n", bounce_env->e_id, simta_hostname);
    fprintf(dfile, "Subject: undeliverable mail\n");
    fprintf(dfile, "\n");

    for (l = bounce_env->e_err_text->l_first; l != NULL; l = l->line_next) {
        fprintf(dfile, "%s\n", l->line_data);
    }
    fprintf(dfile, "\n");

    if (message != NULL) {
        if (write_body == 1) {
            fprintf(dfile, "Bounced message:\n");
        } else {
            fprintf(dfile, "Bounced message headers:\n");
        }
        fprintf(dfile, "\n");

        while ((line = snet_getline(message, NULL)) != NULL) {
            if ((*line == '\0') && (write_body == 0)) {
                /* End of headers, stop writing */
                break;
            } else {
                fprintf(dfile, "%s\n", line);
            }
        }
    }

    ret = 1;

cleanup:
    if (fclose(dfile) != 0) {
        syslog(LOG_ERR, "Syserror: bounce_dfile_out fclose %s: %m",
                dfile_fname);
        ret = 0;
    }

error:
    yaslfree(daytime);

    if (ret != 0) {
        return (bounce_env->e_dinode);
    }

    env_dfile_unlink(bounce_env);

    return (0);
}


struct envelope *
bounce(struct envelope *env, int body, const char *err) {
    struct envelope *env_bounce;
    char             dfile_fname[ MAXPATHLEN ];
    int              dfile_fd;
    SNET            *sn = NULL;

    if (body == 1) {
        sprintf(dfile_fname, "%s/D%s", env->e_dir, env->e_id);
        if ((dfile_fd = open(dfile_fname, O_RDONLY, 0)) < 0) {
            syslog(LOG_ERR, "Syserror: bounce open %s: %m", dfile_fname);
            return (NULL);
        }

        if ((sn = snet_attach(dfile_fd, 1024 * 1024)) == NULL) {
            close(dfile_fd);
            return (NULL);
        }
    }

    env->e_flags |= ENV_FLAG_BOUNCE;

    if ((env_bounce = bounce_snet(env, sn, NULL, err)) == NULL) {
        return (NULL);
    }

    if (sn != NULL) {
        snet_close(sn);
    }

    return (env_bounce);
}

static char *
old_or_jailed(struct envelope *env) {
    if (env->e_jailed) {
        return ("quarantined");
    }
    return ("undeliverable");
}


struct envelope *
bounce_snet(
        struct envelope *env, SNET *sn, struct host_q *hq, const char *err) {
    struct envelope  *bounce_env;
    int               n_bounces = 0;
    struct recipient *r;
    struct line      *l;
    char              buf[ 1024 ];
    const char       *return_address = NULL;

    if ((bounce_env = env_create(simta_dir_fast, NULL, "", env)) == NULL) {
        return (NULL);
    }

    /* bounces must be able to get out of jail */
    bounce_env->e_jailed = false;

    /* if the postmaster is a failed recipient,
     * we need to put the bounce in the dead queue.
     */
    for (r = env->e_rcpt; r != NULL; r = r->r_next) {
        if (((env->e_flags & ENV_FLAG_BOUNCE) || (r->r_status == R_FAILED))) {
            if (*(r->r_rcpt) == '\0') {
                bounce_env->e_dir = simta_dir_dead;
                break;
            }
        }
    }

    if (env->e_jailed) {
        return_address = simta_config_str("deliver.jail.parole_officer");
    }

    if (return_address == NULL) {
        return_address = env->e_mail;
    }

    if (env_recipient(bounce_env, return_address) != 0) {
        goto cleanup1;
    }

    if (bounce_env->e_err_text == NULL) {
        bounce_env->e_err_text = line_file_create();
    }

    line_append(bounce_env->e_err_text,
            "Message delivery failed for "
            "one or more recipients, check specific errors below\n",
            COPY);

    if (env->e_age == ENV_AGE_OLD) {
        sprintf(buf, "This message is old and %s.\n", old_or_jailed(env));
        line_append(bounce_env->e_err_text, buf, COPY);
    }

    if (env->e_jailed) {
        /* Nothing */
    } else if (hq == NULL) {
        if (err == NULL) {
            line_append(bounce_env->e_err_text,
                    "An error occurred during the expansion of "
                    "the message recipients.\n",
                    COPY);
        } else {
            sprintf(buf, "%s\n", err);
            line_append(bounce_env->e_err_text, buf, COPY);
        }

    } else if (hq->hq_err_text != NULL) {
        sprintf(buf,
                "The following error occurred during delivery to "
                "host %s:\n",
                hq->hq_hostname);
        line_append(bounce_env->e_err_text, buf, COPY);
        for (l = hq->hq_err_text->l_first; l != NULL; l = l->line_next) {
            line_append(bounce_env->e_err_text, l->line_data, COPY);
        }
        line_append(bounce_env->e_err_text, "", COPY);

    } else {
        sprintf(buf, "An error occurred during delivery to host %s.\n",
                hq->hq_hostname);
        line_append(bounce_env->e_err_text, buf, COPY);
    }

    if (env->e_err_text != NULL) {
        sprintf(buf,
                "The following error occurred during delivery of "
                "message %s:\n",
                env->e_id);
        line_append(bounce_env->e_err_text, buf, COPY);

        if (err != NULL) {
            sprintf(buf, "%s\n", err);
            line_append(bounce_env->e_err_text, buf, COPY);
        }

        for (l = env->e_err_text->l_first; l != NULL; l = l->line_next) {
            line_append(bounce_env->e_err_text, l->line_data, COPY);
        }

        line_append(bounce_env->e_err_text, "", COPY);
    }

    syslog(LOG_INFO, "Bounce env <%s>: %s: To <%s> From <>", env->e_id,
            bounce_env->e_id, bounce_env->e_rcpt->r_rcpt);

    for (r = env->e_rcpt; r != NULL; r = r->r_next) {
        if ((env->e_flags & ENV_FLAG_BOUNCE) || (r->r_status == R_FAILED)) {
            n_bounces++;
            syslog(LOG_INFO, "Bounce env <%s>: %s: Bouncing <%s> From <%s>",
                    env->e_id, bounce_env->e_id, r->r_rcpt, env->e_mail);
            sprintf(buf, "address %s\n", r->r_rcpt);
            line_append(bounce_env->e_err_text, buf, COPY);
            if (r->r_err_text != NULL) {
                for (l = r->r_err_text->l_first; l != NULL; l = l->line_next) {
                    line_append(bounce_env->e_err_text, l->line_data, COPY);
                }
            }
        }
    }

    if (bounce_dfile_out(bounce_env, sn) == 0) {
        syslog(LOG_ERR, "Bounce env <%s>: %s: bounce_dfile_out failed",
                env->e_id, bounce_env->e_id);
        goto cleanup2;
    }

    if (env_outfile(bounce_env) != SIMTA_OK) {
        goto cleanup2;
    }

    statsd_counter("bounce", "messages", 1);
    statsd_counter("bounce", "addresses", n_bounces);

    syslog(LOG_INFO, "Bounce env <%s>: %s: Bounced %d addresses", env->e_id,
            bounce_env->e_id, n_bounces);

    return (bounce_env);

cleanup2:
    syslog(LOG_ERR, "Bounce env <%s>: Message Deleted: System Error",
            bounce_env->e_id);

cleanup1:
    env_free(bounce_env);
    return (NULL);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
