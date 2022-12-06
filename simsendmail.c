/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

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
#include "simta.h"
#include "simta_malloc.h"

void catch_sigint(int) __attribute__((noreturn));

const char *simta_progname = "simsendmail";

/* dfile vars are global to unlink dfile if SIGINT */
static int              dfile_fd = -1;
static struct envelope *env;

/* catch SIGINT */

void
catch_sigint(int sigint __attribute__((unused))) {
    if (dfile_fd) {
        env_dfile_unlink(env);
    }

    exit(EX_TEMPFAIL);
}


int
main(int argc, char *argv[]) {
    SNET                  *snet_stdin;
    char                  *sender = NULL;
    char                  *addr;
    yastr                  daytime = NULL;
    char                  *line = NULL;
    yastr                  buf;
    struct receive_headers rh;
    int                    usage = 0;
    int                    line_no = 0;
    size_t                 line_len;
    int                    c;
    int                    ignore_dot = 0;
    int                    x;
    int                    header;
    int                    rc;
    int                    ret = EX_TEMPFAIL;
    int                    message_size = 0;
    FILE                  *dfile = NULL;
    bool                   read_headers = false;
    uid_t                  uid;
    struct recipient      *r;
    struct passwd         *passwd;
    const char            *pw_name;

    /* ignore a good many options */
    opterr = 0;

    while ((c = getopt(argc, argv, "b:f:io:r:st")) != -1) {
        switch (c) {
        case 'b':
            if (strlen(optarg) == 1) {
                switch (*optarg) {
                case 'a':
                    /* -ba ARPANET mode */
                case 'd':
                    /* -bd Daemon mode, background */
                case 's':
                    /* 501 Permission denied */
                    printf("501 Mode not supported\n");
                    exit(EX_USAGE);

                case 'D':
                    /* -bD Daemon mode, foreground */
                case 'i':
                    /* -bi init the alias db */
                case 'p':
                    /* -bp surmise the mail queue*/
                case 't':
                    /* -bt address test mode */
                case 'v':
                    /* -bv verify names only */
                    printf("Mode not supported\n");
                    exit(EX_USAGE);

                case 'm':
                    /* -bm deliver mail the usual way */
                default:
                    /* ignore all other flags */
                    break;
                }
            }
            break;

        case 'f':
        case 'r':
            /* Specify a different from address, for testing purposes */
            sender = optarg;
            if (!is_emailaddr(sender)) {
                usage = 1;
            }
            break;

        case 'i':
            /* Ignore a single dot on a line as an end of message marker */
            ignore_dot = 1;
            break;

        case 'o':
            if (strcmp(optarg, "i") == 0) {
                /* -oi ignore dots */
                ignore_dot = 1;
            }
            break;

        case 's':
            /* signal server */
            goto signal_server;

        case 't':
            /* Read message headers for recipients */
            read_headers = true;
            break;

        default:
            break;
        }
    }

    if (usage != 0) {
        fprintf(stderr,
                "Usage: %s "
                "[ -b option ] "
                "[ -f address ] "
                "[ -i ] "
                "[ -o option ] "
                "[ -s ] "
                "[ -t ] "
                "[[ -- ] to-address ...]\n",
                argv[ 0 ]);
        exit(EX_USAGE);
    }

    if (read_headers && (optind == argc)) {
        fprintf(stderr, "%s: no recipients\n", argv[ 0 ]);
        exit(EX_USAGE);
    }

    if (simta_read_config(NULL, NULL) != SIMTA_OK) {
        exit(EX_TEMPFAIL);
    }

    simta_openlog(false, 0);

    uid = getuid();
    if ((passwd = getpwuid(uid)) == NULL) {
        pw_name = "No password entry";
    } else if (passwd->pw_name == NULL) {
        pw_name = "No user name in password entry";
    } else {
        pw_name = passwd->pw_name;
    }

    if (passwd && sender == NULL) {
        sender = yaslcatprintf(yaslempty(), "%s@%s", passwd->pw_name,
                simta_config_str("core.masquerade"));
    }

    /* create envelope */
    if ((env = env_create(simta_dir_local, NULL, sender, NULL)) == NULL) {
        perror("env_create");
        exit(EX_TEMPFAIL);
    }

#ifdef HAVE_LIBOPENDKIM
    if (simta_config_bool("deliver.dkim.enabled")) {
        env->e_flags |= ENV_FLAG_DKIMSIGN;
    }
#endif /* HAVE_LIBOPENDKIM */

    /* Local messages should never be jailed. */
    env->e_jailed = false;

    memset(&rh, 0, sizeof(struct receive_headers));
    rh.r_env = env;

    /* optind = first to-address */
    for (x = optind; x < argc; x++) {
        addr = simta_strdup(argv[ x ]);

        if (correct_emailaddr(&addr) == 0) {
            fprintf(stderr, "Invalid email address: %s\n", addr);
            exit(EX_DATAERR);
        }

        env_recipient(env, addr);

        free(addr);
    }

    /* need to read stdin in a line-oriented fashon */
    if ((snet_stdin = snet_attach(0, 1024 * 1024)) == NULL) {
        perror("snet_attach");
        exit(EX_TEMPFAIL);
    }

    /* start in header mode */
    header = 1;

    /* RFC 5322 2.1.1. Line Length Limits:
     * There are two limits that this standard places on the number of
     * characters in a line. Each line of characters MUST be no more than
     * 998 characters, and SHOULD be no more than 78 characters, excluding
     * the CRLF.
     */

    /* catch SIGINT and cleanup */
    if (signal(SIGINT, catch_sigint) == SIG_ERR) {
        perror("signal");
        exit(EX_TEMPFAIL);
    }

    /* open Dfile */
    if ((dfile_fd = env_dfile_open(env)) < 0) {
        perror("open");
        exit(EX_TEMPFAIL);
    }

    if ((dfile = fdopen(dfile_fd, "w")) == NULL) {
        perror("fdopen");
        goto error;
    }

    daytime = rfc5322_timestamp();
    buf = yaslempty();
    buf = yaslcatprintf(buf,
            "Received: from %s (UID %d)\n\tby %s (simsendmail) id %s;\n\t%s",
            (passwd ? passwd->pw_name : "unknown"), uid, simta_hostname,
            env->e_id, daytime);
    header_text(line_no, buf, &rh, NULL);

    while ((header == 1) && ((line = snet_getline(snet_stdin, NULL)) != NULL)) {
        line_no++;

        line_len = strlen(line);
        message_size += line_len;

        if (line_len > 998) {
            fprintf(stderr, "%s: line %d too long\n", argv[ 0 ], line_no);

            ret = EX_DATAERR;
            goto error;
        }

        if (header_text(line_no, line, &rh, NULL) != 0) {
            header = 0;
        }
    }

    if ((rc = header_check(&rh, read_headers, true, true)) != 0) {
        if (rc > 0) {
            ret = EX_DATAERR;
        } else {
            ret = EX_TEMPFAIL;
        }
        goto error;
    }

    /* make sure we have a recipient */
    if (env->e_rcpt == NULL) {
        fprintf(stderr, "%s: no recipients\n", argv[ 0 ]);
        ret = EX_DATAERR;
        goto error;
    }

    /* print headers to Dfile */
    if (rh.r_headers != NULL) {
        if (header_file_out(rh.r_headers, dfile) < 0) {
            perror("header_file_out");
            ret = EX_DATAERR;
            goto error;
        }
    }

    if (line != NULL) {
        /* insert a blank line if need be */
        if (*line != '\0') {
            fprintf(dfile, "\n");
        }

        if ((ignore_dot == 0) && ((line[ 0 ] == '.') && (line[ 1 ] == '\0'))) {
            goto done;
        }

        fprintf(dfile, "%s\n", line);
    }

    while ((line = snet_getline(snet_stdin, NULL)) != NULL) {
        line_no++;

        if ((ignore_dot == 0) && ((line[ 0 ] == '.') && (line[ 1 ] == '\0'))) {
            goto done;
        }

        line_len = strlen(line);
        message_size += line_len;

        if (line_len > 998) {
            fprintf(stderr, "%s: line %d too long\n", argv[ 0 ], line_no);

            ret = EX_DATAERR;
            goto error;
        }

        fprintf(dfile, "%s\n", line);
    }

done:
    if (snet_close(snet_stdin) != 0) {
        perror("snet_close");

        ret = EX_TEMPFAIL;
        goto error;
    }

    simta_debuglog(2, "%s env %s dinode %d", argv[ 0 ], env->e_id,
            (int)(env->e_dinode));

    /* close Dfile */
    if (fclose(dfile) != 0) {
        perror("fclose");
        goto error;
    }

    syslog(LOG_INFO, "Local %s: From <%s>: UID %d: %s", env->e_id, env->e_mail,
            uid, pw_name);
    for (r = env->e_rcpt; r != NULL; r = r->r_next) {
        syslog(LOG_INFO, "Local %s: To <%s>", env->e_id, r->r_rcpt);
    }

    /* store Efile */
    if (env_outfile(env) != SIMTA_OK) {
        syslog(LOG_INFO, "Local %s: Message Aborted", env->e_id);
        perror("env_outfile");
        goto error;
    }

    syslog(LOG_INFO, "Local %s: Message Accepted: lines %d size %d", env->e_id,
            line_no, message_size);

signal_server:
    /* if possible, signal server */
    simta_signal_server(SIGUSR1);

    return (EX_OK);

error:
    if (env->e_flags & ENV_FLAG_DFILE) {
        env_dfile_unlink(env);
    }

    return (ret);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
