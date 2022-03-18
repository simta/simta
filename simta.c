/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LDAP
#include <ldap.h>
#endif /* HAVE_LDAP */

#ifdef HAVE_LIBIDN2
#include <idn2.h>
#endif /* HAVE_LIBIDN2 */

#include "argcargv.h"
#include "dns.h"
#include "ml.h"
#include "red.h"
#include "simta_ldap.h"

#include "embedded_config.h"
#include "embedded_schema.h"

static simta_result       simta_read_publicsuffix(const char *);
static struct ucl_parser *simta_ucl_parser(void);


/* global variables */
struct dll_entry *   simta_sender_list = NULL;
struct dll_entry *   simta_env_list = NULL;
struct timeval       simta_tv_now = {0, 0};
struct timespec      simta_log_ts;
struct envelope *    simta_env_queue = NULL;
ucl_object_t *       simta_host_q = NULL;
struct host_q *      simta_deliver_q = NULL;
struct host_q *      simta_unexpanded_q = NULL;
struct proc_type *   simta_proc_stab = NULL;
ucl_object_t *       simta_config = NULL;
int                  simta_disk_cycle = 0;
int                  simta_global_connections = 0;
int                  simta_global_throttle_connections = 0;
int                  simta_q_runner_local = 0;
int                  simta_q_runner_slow = 0;
int                  simta_exp_level_max = 5;
enum simta_proc_type simta_process_type = PROCESS_DEFAULT;
int                  simta_filesystem_cleanup = 0;
int                  simta_message_count = 0;
int                  simta_smtp_outbound_attempts = 0;
int                  simta_smtp_outbound_delivered = 0;
int                  simta_fast_files = 0;
int                  simta_debug = 1;
int                  simta_child_signal = 0;
yastr                simta_postmaster = NULL;
yastr                simta_dir_dead = NULL;
yastr                simta_dir_local = NULL;
yastr                simta_dir_slow = NULL;
yastr                simta_dir_fast = NULL;
yastr                simta_dir_command = NULL;
yastr                simta_hostname;
DNSR *               simta_dnsr = NULL;
ucl_object_t *       simta_publicsuffix_list = NULL;


void
panic(const char *message) {
    syslog(LOG_CRIT, "%s", message);
    abort();
}


simta_result
simta_gettimeofday(struct timeval *tv) {
    struct timespec ts_now;
#ifdef CLOCK_MONOTONIC_COARSE
    clockid_t clock = CLOCK_MONOTONIC_COARSE;
#elif defined(CLOCK_MONOTONIC_FAST)
    clockid_t clock = CLOCK_MONOTONIC_FAST;
#else
    clockid_t clock = CLOCK_MONOTONIC;
#endif /* CLOCK_MONOTONIC_COARSE */
    if (clock_gettime(clock, &ts_now) != 0) {
        syslog(LOG_ERR, "Syserror: simta_gettimeofday clock_gettime: %s",
                strerror(errno));
        return (SIMTA_ERR);
    }

    simta_tv_now.tv_sec = ts_now.tv_sec;
    simta_tv_now.tv_usec = (ts_now.tv_nsec + 500) / 1000;

    if (tv) {
        memcpy(tv, &simta_tv_now, sizeof(struct timeval));
    }

    return SIMTA_OK;
}

void
simta_openlog(bool cl, int options) {
    static yastr ident = NULL;

    if (cl) {
        closelog();
    }

    if (ident) {
        yaslfree(ident);
    }

    clock_gettime(CLOCK_REALTIME, &simta_log_ts);

    ident = yaslcatprintf(yaslauto(simta_progname), "[%d.%ld]", getpid(),
            simta_log_ts.tv_sec);
    openlog(ident, LOG_NOWAIT | options, LOG_SIMTA);

    return;
}


void
simta_debuglog(int level, const char *format, ...) {
    va_list vl;

    va_start(vl, format);
    if (simta_debug >= level) {
        vsyslog(LOG_DEBUG, format, vl);
    }
    va_end(vl);
}

static struct ucl_parser *
simta_ucl_parser(void) {
    struct ucl_parser *parser;

    parser = ucl_parser_new(
            UCL_PARSER_KEY_LOWERCASE | UCL_PARSER_NO_IMPLICIT_ARRAYS);

    ucl_parser_register_variable(parser, "HOSTNAME", simta_hostname);

    return parser;
}


simta_result
simta_read_config(const char *fname, const char *extra) {
    char                    hostname[ DNSR_MAX_HOSTNAME + 1 ];
    struct ucl_parser *     parser;
    ucl_object_t *          container;
    ucl_object_t *          obj;
    const ucl_object_t *    i_obj;
    const ucl_object_t *    j_obj;
    ucl_object_iter_t       i, j;
    struct ucl_schema_error schema_err;
    const char *            err;
    const char *            buf;
    yastr                   path;
    struct timeval          tv_now;

    if (gethostname(hostname, DNSR_MAX_HOSTNAME) != 0) {
        perror("gethostname");
        return SIMTA_ERR;
    }

    simta_hostname = yaslauto(hostname);
    yasltolower(simta_hostname);
    yasltrim(simta_hostname, ".");

    /* Parse the hard-coded defaults */
    simta_debuglog(2, "simta_read_config: reading embedded base config");

    parser = simta_ucl_parser();

    if (!ucl_parser_add_string(parser, SIMTA_CONFIG_BASE, 0)) {
        syslog(LOG_ERR, "simta_read_config: base UCL parsing failed");
        if ((err = ucl_parser_get_error(parser)) != NULL) {
            syslog(LOG_ERR, "simta_read_config: libucl error: %s", err);
        }
        return SIMTA_ERR;
    }

    simta_config = ucl_parser_get_object(parser);

    ucl_parser_free(parser);

    if (fname == NULL) {
        fname = "/etc/simta.conf";
        if (access(fname, F_OK) != 0) {
            syslog(LOG_INFO,
                    "Config: skipping file parsing: default config %s doesn't "
                    "exist",
                    fname);
            fname = NULL;
        }
    }

    /* Parse the config file */
    if (fname) {
        parser = simta_ucl_parser();
        if (!ucl_parser_add_file(parser, fname)) {
            syslog(LOG_ERR, "simta_read_config: UCL parsing failed");
            if ((err = ucl_parser_get_error(parser)) != NULL) {
                syslog(LOG_ERR, "simta_read_config: libucl error: %s", err);
            }
            return SIMTA_ERR;
        }

        ucl_object_merge(simta_config, ucl_parser_get_object(parser), false);
        ucl_parser_free(parser);
    }

    /* Add extra config */
    if (extra) {
        simta_debuglog(1, "Parsing extra config from string: %s", extra);
        parser = simta_ucl_parser();
        if (!ucl_parser_add_string(parser, extra, 0)) {
            syslog(LOG_ERR, "simta_read_config: extra UCL parsing failed: %s",
                    ucl_parser_get_error(parser));
            return SIMTA_ERR;
        }
        ucl_object_merge(simta_config, ucl_parser_get_object(parser), false);
        ucl_parser_free(parser);
    }

    /* Preprocess some things that should be lists */
    simta_ucl_ensure_array(simta_config_obj("receive.connection"), "dns_list");
    simta_ucl_ensure_array(simta_config_obj("receive.auth.authz"), "dns_list");
    simta_ucl_ensure_array(simta_config_obj("receive.mail_from"), "dns_list");
    simta_ucl_ensure_array(simta_config_obj("receive.rcpt_to"), "dns_list");

    /* Set up localhost */
    if (red_host_lookup(simta_hostname, false) == NULL) {
        /* No explicit config, check the placeholder */
        container = ucl_object_ref(simta_config_obj("domain"));
        obj = ucl_object_pop_key(container, "localhost");
        if (obj == NULL) {
            /* No explicit config placeholder, fall back to the default */
            obj = ucl_object_pop_key(container, "localhost.DEFAULT");
        } else {
            ucl_object_delete_key(container, "localhost.DEFAULT");
        }
        ucl_object_unref(container);
        red_host_insert(simta_hostname, obj);
    }

    /* Populate rule defaults. There's probably a more UCL-y way to do this,
     * but I don't really want to get into macros.
     */
    i = ucl_object_iterate_new(simta_config_obj("domain"));
    while ((i_obj = ucl_object_iterate_safe(i, false)) != NULL) {
        simta_ucl_merge_defaults(i_obj, "defaults.red", "receive");
        simta_ucl_merge_defaults(i_obj, "defaults.red", "deliver");

        simta_ucl_ensure_array(i_obj, "rule");
        j = ucl_object_iterate_new(ucl_object_lookup(i_obj, "rule"));
        while ((j_obj = ucl_object_iterate_safe(j, false)) != NULL) {
            if ((buf = ucl_object_tostring(ucl_object_lookup(j_obj, "type"))) !=
                    NULL) {
                simta_ucl_merge_defaults(j_obj, "defaults.red_rule", "receive");
                simta_ucl_merge_defaults(j_obj, "defaults.red_rule", "expand");
                simta_ucl_merge_defaults(j_obj, "defaults.red_rule", buf);
                if (ucl_object_lookup(j_obj, "associated_domain") == NULL) {
                    obj = ucl_object_ref(j_obj);
                    ucl_object_insert_key(obj,
                            simta_ucl_object_fromstring(ucl_object_key(i_obj)),
                            "associated_domain", 0, false);
                    ucl_object_unref(obj);
                }
                if (strcmp(buf, "ldap") == 0) {
                    simta_ucl_ensure_array(
                            ucl_object_lookup(j_obj, "ldap"), "search");
                }
            }
        }
        ucl_object_iterate_free(j);
    }
    ucl_object_iterate_free(i);

    /* Validate the config */
    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (!ucl_parser_add_string(parser, SIMTA_CONFIG_SCHEMA, 0)) {
        syslog(LOG_ERR, "simta_read_config: schema UCL parsing failed");
        return SIMTA_ERR;
    }
    if ((err = ucl_parser_get_error(parser)) != NULL) {
        syslog(LOG_ERR, "simta_read_config: libucl error: %s", err);
        return SIMTA_ERR;
    }

    if (!ucl_object_validate(
                ucl_parser_get_object(parser), simta_config, &schema_err)) {
        syslog(LOG_ERR, "Config: schema validation failed on %s",
                ucl_object_emit(schema_err.obj, UCL_EMIT_JSON_COMPACT));
        syslog(LOG_ERR, "Config: validation failure: %s", schema_err.msg);
        return SIMTA_ERR;
    }

    syslog(LOG_INFO, "Config: successfully validated config");

    ucl_parser_free(parser);

#ifdef HAVE_LDAP
    /* Generate and check LDAP configs */
    i = ucl_object_iterate_new(simta_config_obj("domain"));
    while ((i_obj = ucl_object_iterate_safe(i, false)) != NULL) {
        j = ucl_object_iterate_new(ucl_object_lookup(i_obj, "rule"));
        while ((j_obj = ucl_object_iterate_safe(j, false)) != NULL) {
            if ((buf = ucl_object_tostring(ucl_object_lookup(j_obj, "type"))) !=
                    NULL) {
                if (strcmp(buf, "ldap") == 0) {
                    if (simta_ldap_config(j_obj) == NULL) {
                        syslog(LOG_ERR,
                                "Config: LDAP config validation failed on %s",
                                ucl_object_emit(i_obj, UCL_EMIT_JSON_COMPACT));
                        return SIMTA_ERR;
                    }
                }
            }
        }
        ucl_object_iterate_free(j);
    }
    ucl_object_iterate_free(i);
#endif /* HAVE_LDAP */

    if (simta_gettimeofday(&tv_now) != 0) {
        return SIMTA_ERR;
    }

    srandom(tv_now.tv_usec * tv_now.tv_sec * getpid());

    simta_debug = simta_config_int("core.debug_level");

    simta_postmaster = yaslcatyasl(yaslauto("postmaster@"), simta_hostname);

    buf = simta_config_str("core.base_dir");

    /* set up data dir pathnames */
    path = yaslcatlen(yaslauto(buf), "/", 1);

    simta_dir_fast = yaslcat(yasldup(path), "fast");
    simta_dir_slow = yaslcat(yasldup(path), "slow");
    simta_dir_dead = yaslcat(yasldup(path), "dead");
    simta_dir_local = yaslcat(yasldup(path), "local");
    simta_dir_command = yaslcat(yasldup(path), "command");

    yaslfree(path);

    /* Parse PSL */
    if (simta_config_bool("receive.dmarc.enabled") &&
            ((buf = simta_config_str("receive.dmarc.public_suffix_file")) !=
                    NULL)) {
        if (simta_read_publicsuffix(buf) != SIMTA_OK) {
            return SIMTA_ERR;
        }
    }

    return SIMTA_OK;
}

void
simta_dump_config(void) {
    printf("%s\n", ucl_object_emit(simta_config, UCL_EMIT_CONFIG));
}

const ucl_object_t *
simta_config_obj(const char *key) {
    const ucl_object_t *val;

    if ((val = ucl_object_lookup_path(simta_config, key)) == NULL) {
        simta_debuglog(2, "Config: request for nonexistent key %s", key);
    }

    return val;
}

/* FIXME: these should probably use safe conversions */
bool
simta_config_bool(const char *key) {
    return ucl_object_toboolean(simta_config_obj(key));
}

int64_t
simta_config_int(const char *key) {
    return ucl_object_toint(simta_config_obj(key));
}

const char *
simta_config_str(const char *key) {
    const ucl_object_t *val;
    if ((val = simta_config_obj(key)) == NULL) {
        return NULL;
    }
    return ucl_object_tostring_forced(val);
}

yastr
simta_config_yastr(const char *key) {
    const ucl_object_t *val;
    if ((val = simta_config_obj(key)) == NULL) {
        return NULL;
    }
    return yaslauto(ucl_object_tostring_forced(val));
}

enum simta_charset
simta_check_charset(const char *str) {
    const unsigned char *c;
    size_t               charlen;
    int                  i;
    uint32_t             u;
    uint8_t              mask;
    enum simta_charset   ret = SIMTA_CHARSET_ASCII;

    for (c = (unsigned char *)str; *c != '\0'; c++) {
        if (*c < 0x80) {
            continue;
        }
        ret = SIMTA_CHARSET_UTF8;
        if ((*c & 0xe0) == 0xc0) {
            charlen = 2;
            mask = 0x1f;
        } else if ((*c & 0xf0) == 0xe0) {
            charlen = 3;
            mask = 0x0f;
        } else if ((*c & 0xf8) == 0xf0) {
            charlen = 4;
            mask = 0x07;
        } else {
            /* RFC 3629 limits UTF-8 to 21 bits (4 bytes), so
             * anything else that has the high bit set is either an
             * out-of-order continuation octet or completely invalid.
             */
            return (SIMTA_CHARSET_INVALID);
        }

        u = *c & mask;
        for (i = 1; i < charlen; i++) {
            c++;
            if ((*c & 0xc0) != 0x80) {
                return (SIMTA_CHARSET_INVALID);
            }
            u <<= 6;
            u |= (*c & 0x3f);
        }

        /* Check that the codepoint used the shortest representation */
        if ((u < 0x80) || ((u < 0x800) && (charlen > 2)) ||
                ((u < 0x10000) && (charlen > 3))) {
            return (SIMTA_CHARSET_INVALID);
        }

        /* Check for invalid codepoints */
    }

    return (ret);
}

static simta_result
simta_read_publicsuffix(const char *fname) {
    SNET *              snet = NULL;
    char *              line, *p;
    const ucl_object_t *parent = NULL;
    const ucl_object_t *obj = NULL;
    ucl_object_t *      ref;
    ucl_object_t *      newobj;
#ifdef HAVE_LIBIDN2
    char *idna = NULL;
#endif /* HAVE_LIBIDN2 */

    /* Set up public suffix list */
    if ((snet = snet_open(fname, O_RDONLY, 0, 1024 * 1024)) == NULL) {
        fprintf(stderr, "simta_read_publicsuffix: open %s: %s", fname,
                strerror(errno));
        return SIMTA_ERR;
    }

    simta_publicsuffix_list = ucl_object_new();
    /* Formal algorithm from https://publicsuffix.org/list/
     * If no rules match, the prevailing rule is "*".
     */
    ucl_object_insert_key(
            simta_publicsuffix_list, ucl_object_new(), "*", 1, true);

    while ((line = snet_getline(snet, NULL)) != NULL) {
        /* Each line is only read up to the first whitespace; entire
         * lines can also be commented using //.
         */
        if ((*line == '\0') || isspace(*line) ||
                (strncmp(line, "//", 2) == 0)) {
            continue;
        }
        for (p = line; ((*p != '\0') && (!isspace(*p))); p++)
            ;
        *p = '\0';
        parent = simta_publicsuffix_list;


#ifdef HAVE_LIBIDN2
        if (simta_check_charset(line) == SIMTA_CHARSET_UTF8) {
            if (idn2_to_ascii_8z(line, &idna,
                        IDN2_NONTRANSITIONAL | IDN2_NFC_INPUT) == IDN2_OK) {
                line = idna;
            }
        }
#endif /* HAVE_LIBIDN2 */

        while (*line != '\0') {
            if ((p = strrchr(line, '.')) == NULL) {
                p = line;
            } else {
                *p = '\0';
                p++;
            }

            obj = ucl_object_lookup(parent, p);
            if (obj == NULL) {
                newobj = ucl_object_new();
                ref = ucl_object_ref(parent);
                ucl_object_insert_key(ref, newobj, p, 0, true);
                ucl_object_unref(ref);
                parent = newobj;
            } else {
                parent = obj;
            }

            *p = '\0';
        }

#ifdef HAVE_LIBIDN2
        if (idna) {
            free(idna);
            idna = NULL;
        }
#endif /* HAVE_LIBIDN2 */
    }
    if (snet_close(snet) != 0) {
        perror("snet_close");
        return SIMTA_ERR;
    }

    return SIMTA_OK;
}

pid_t
simta_waitpid(pid_t child, int *childstatus, int options) {
    pid_t              retval = 0;
    int                ll;
    pid_t              pid;
    int                status;
    int                exitstatus;
    long               milliseconds;
    struct proc_type **p_search;
    struct proc_type * p_remove;
    struct timeval     tv_now;
    struct host_q *    hq;

    if (simta_gettimeofday(&tv_now) != 0) {
        return (-1);
    }

    for (;;) {
        simta_child_signal = 0;

        if ((pid = waitpid(0, &status, options)) <= 0) {
            break;
        }

        for (p_search = &simta_proc_stab; *p_search != NULL;
                p_search = &((*p_search)->p_next)) {
            if ((*p_search)->p_id == pid) {
                break;
            }
        }

        if (*p_search == NULL) {
            if (pid == child) {
                if (childstatus) {
                    *childstatus = status;
                }
                return (pid);
            }
            syslog(LOG_ERR, "Child: %d: unknown child process", pid);
            retval--;
            continue;
        }

        p_remove = *p_search;
        *p_search = p_remove->p_next;

        assert(p_remove->p_limit != NULL);
        (*p_remove->p_limit)--;

        milliseconds = SIMTA_ELAPSED_MSEC(p_remove->p_tv, tv_now);
        ll = LOG_INFO;

        if (WIFEXITED(status)) {
            if ((exitstatus = WEXITSTATUS(status)) != EXIT_OK) {
                if ((p_remove->p_type == PROCESS_Q_SLOW) &&
                        (exitstatus == SIMTA_EXIT_OK_LEAKY)) {

                    /* remote host activity, requeue to encourage it */
                    if ((hq = host_q_lookup(p_remove->p_host)) != NULL) {
                        hq->hq_leaky = true;
                        hq_deliver_pop(hq);

                        if (hq_deliver_push(hq, &tv_now, NULL) != 0) {
                            retval--;
                        }

                    } else {
                        simta_debuglog(
                                1, "Queue %s: Not Found", p_remove->p_host);
                    }

                } else {
                    retval--;
                    ll = LOG_ERR;
                }
            }

            switch (p_remove->p_type) {
            case PROCESS_Q_LOCAL:
                syslog(ll,
                        "Child: local runner %d exited %d "
                        "(%ld milliseconds, %d siblings remaining)",
                        pid, exitstatus, milliseconds, *p_remove->p_limit);
                break;

            case PROCESS_Q_SLOW:
                syslog(ll,
                        "Child: queue runner %d for %s exited %d "
                        "(%ld milliseconds, %d siblings remaining)",
                        pid,
                        *(p_remove->p_host) ? p_remove->p_host : S_UNEXPANDED,
                        exitstatus, milliseconds, *p_remove->p_limit);
                break;

            case PROCESS_RECEIVE:
                p_remove->p_ss->ss_count--;
                p_remove->p_cinfo->c_proc_total--;

                syslog(ll,
                        "Child: %s receive process %d for %s exited %d "
                        "(%ld milliseconds, %d siblings remaining, %d %s)",
                        p_remove->p_ss->ss_service, pid, p_remove->p_host,
                        exitstatus, milliseconds, *p_remove->p_limit,
                        p_remove->p_ss->ss_count, p_remove->p_ss->ss_service);
                break;

            default:
                retval--;
                syslog(LOG_ERR,
                        "Child: unknown process %d exited %d "
                        "(%ld milliseconds)",
                        pid, exitstatus, milliseconds);
                break;
            }

        } else if (WIFSIGNALED(status)) {
            syslog(LOG_ERR,
                    "Child: %d died with signal %d "
                    "(%ld milliseconds)",
                    pid, WTERMSIG(status), milliseconds);
            retval--;

        } else {
            syslog(LOG_ERR, "Child: %d died (%ld milliseconds)", pid,
                    milliseconds);
            retval--;
        }

        if (p_remove->p_host) {
            free(p_remove->p_host);
        }
        free(p_remove);

        if (options == 0) {
            /* We rely on the caller to loop as needed, since they might want
             * to do work before waiting again.
             */
            break;
        }
    }

    return (retval);
}

simta_result
simta_signal_server(int signal) {
    const char *pid_file;
    yastr       pid_string;
    int         pid;

    pid_file = ucl_object_tostring(simta_config_obj("core.pid_file"));
    if ((pid_string = simta_slurp(pid_file)) == NULL) {
        syslog(LOG_NOTICE, "simta_signal_server: failed to read pid file %s",
                pid_file);
        return SIMTA_ERR;
    }
    sscanf(pid_string, "%d\n", &pid);

    if (pid <= 0) {
        syslog(LOG_NOTICE, "simta_signal_server: illegal pid %d in %s", pid,
                pid_file);
        return SIMTA_ERR;
    }

    if (kill(pid, signal) < 0) {
        syslog(LOG_NOTICE, "Syserror: simta_signal_server %d %d: %m", signal,
                pid);
        return SIMTA_ERR;
    }

    return SIMTA_OK;
}

yastr
simta_slurp(const char *path) {
    SNET *  snet;
    yastr   contents;
    ssize_t chunk;
    char    buf[ 16384 ];

    if ((snet = snet_open(path, O_RDONLY, 0, 1024 * 1024)) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_slurp snet_open %s: %m", path);
        return (NULL);
    }

    contents = yaslempty();
    while ((chunk = snet_read(snet, buf, 16384, NULL)) > 0) {
        contents = yaslcatlen(contents, buf, chunk);
    }

    snet_close(snet);
    return (contents);
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
