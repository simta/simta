/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/wait.h>

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

#include "argcargv.h"
#include "envelope.h"
#include "line_file.h"
#include "ml.h"
#include "simta_malloc.h"


/* return 0 on success
     * return <0 on syscall failure
     * return >0 return code from binary program
     *
     * syslog errors before returning
     */

int
deliver_binary(struct deliver *d) {
    int    x;
    int    fd[ 2 ];
    pid_t  pid;
    int    status;
    pid_t  rc;
    SNET  *snet;
    char  *slash;
    char  *line;
    char  *recipient;
    char  *at;
    char  *binary;
    char  *domain = "NULL";
    ACAV  *acav;
    char  *agent;
    char **deliver_argv;
    int    deliver_argc;

    if (pipe(fd) < 0) {
        syslog(LOG_ERR, "Syserror: deliver_binary pipe: %m");
        return (EX_TEMPFAIL);
    }

    simta_gettimeofday(NULL);

    switch (pid = fork()) {
    case -1:
        syslog(LOG_ERR, "Syserror: deliver_binary fork: %m");
        return (EX_TEMPFAIL);

    case 0:
        simta_openlog(true, 0);
        /* use fd[ 0 ] to communicate with parent, parent uses fd[ 1 ] */
        if (close(fd[ 1 ]) < 0) {
            syslog(LOG_ERR, "Syserror: deliver_binary close: %m");
            exit(EX_TEMPFAIL);
        }

        /* stdout -> fd[ 0 ] */
        if (dup2(fd[ 0 ], 1) < 0) {
            syslog(LOG_ERR, "Syserror: deliver_binary dup2: %m");
            exit(EX_TEMPFAIL);
        }

        /* stderr -> fd[ 0 ] */
        if (dup2(fd[ 0 ], 2) < 0) {
            syslog(LOG_ERR, "Syserror: deliver_binary dup2: %m");
            exit(EX_TEMPFAIL);
        }

        if (close(fd[ 0 ]) < 0) {
            syslog(LOG_ERR, "Syserror: deliver_binary close: %m");
            exit(EX_TEMPFAIL);
        }

        /* f -> stdin */
        if (dup2(d->d_dfile_fd, 0) < 0) {
            syslog(LOG_ERR, "Syserror: deliver_binary dup2: %m");
            exit(EX_TEMPFAIL);
        }

        acav = acav_alloc();
        /* FIXME: if we use something other than acav_parse() we might could
         * do less copying.
         */
        agent = simta_strdup(d->d_deliver_agent);
        deliver_argc = acav_parse(acav, agent, &deliver_argv);

        recipient = d->d_rcpt->r_rcpt;

        at = strchr(recipient, '@');
        *at = '\0';
        domain = at + 1;

        binary = deliver_argv[ 0 ];
        if ((slash = strrchr(binary, '/')) != NULL) {
            deliver_argv[ 0 ] = slash;
        }

        /* variable replacement on the args */
        for (x = 1; x < deliver_argc; x++) {
            if (*(deliver_argv[ x ]) == '$') {
                switch (*(deliver_argv[ x ] + 1)) {
                /* $S Sender */
                case 'S':
                    if (*(deliver_argv[ x ] + 2) == '\0') {
                        deliver_argv[ x ] = d->d_env->e_mail;
                    }
                    break;

                /* $R Recipient */
                case 'R':
                    if (*(deliver_argv[ x ] + 2) == '\0') {
                        deliver_argv[ x ] = recipient;
                    }
                    break;

                /* $D Domain */
                case 'D':
                    if (*(deliver_argv[ x ] + 2) == '\0') {
                        deliver_argv[ x ] = domain;
                    }
                    break;

                default:
                    /* unsupported option? */
                    break;
                }
            }
        }

        execv(binary, deliver_argv);
        /* if we are here, there is an error */
        syslog(LOG_ERR, "Syserror: deliver_binary execv: %m");
        exit(EX_TEMPFAIL);

    default:
        /* use fd[ 1 ] to communicate with child, child uses fd[ 0 ] */
        if (close(fd[ 0 ]) < 0) {
            syslog(LOG_ERR, "Syserror: deliver_binary close: %m");
            return (EX_TEMPFAIL);
        }

        if ((snet = snet_attach(fd[ 1 ], 1024 * 1024)) == NULL) {
            syslog(LOG_ERR, "Liberror: deliver_binary snet_attach: %m");
            return (EX_TEMPFAIL);
        }

        while ((line = snet_getline(snet, NULL)) != NULL) {
            syslog(LOG_INFO, "Deliver.binary env <%s>: %d: %s", d->d_env->e_id,
                    pid, line);

            if (d->d_rcpt->r_err_text == NULL) {
                if ((d->d_rcpt->r_err_text = line_file_create()) == NULL) {
                    syslog(LOG_ERR,
                            "Syserror: deliver_binary line_file_create: %m");
                    snet_close(snet);
                    return (EX_TEMPFAIL);
                }
            }

            if (line_append(d->d_rcpt->r_err_text, line, COPY) == NULL) {
                syslog(LOG_ERR, "Syserror: deliver_binary line_append: %m");
                snet_close(snet);
                return (EX_TEMPFAIL);
            }
        }

        if (snet_close(snet) < 0) {
            syslog(LOG_ERR, "Liberror: deliver_binary snet_close: %m");
            return (EX_TEMPFAIL);
        }

        while ((rc = simta_waitpid(pid, &status, 0)) != pid) {
            if (rc < 0) {
                syslog(LOG_ERR, "Syserror: deliver_binary simta_waitpid: %m");
                return (EX_TEMPFAIL);
            }
        }

        if (WIFEXITED(status)) {
            syslog(LOG_WARNING, "Deliver.binary env <%s>: %d exited %d",
                    d->d_env->e_id, pid, WEXITSTATUS(status));

            return (WEXITSTATUS(status));

        } else if (WIFSIGNALED(status)) {
            syslog(LOG_ERR, "Deliver.binary env <%s>: %d died with signal %d",
                    d->d_env->e_id, pid, WTERMSIG(status));
            return (EX_TEMPFAIL);

        } else {
            syslog(LOG_ERR, "Deliver.binary env <%s>: %d died", d->d_env->e_id,
                    pid);
            return (EX_TEMPFAIL);
        }
    }
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
