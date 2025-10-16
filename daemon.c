/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif /* __linux__ */

#ifdef HAVE_LIBSSL
#include "tls.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "argcargv.h"
#include "envelope.h"
#include "ll.h"
#include "q_cleanup.h"
#include "queue.h"
#include "simta.h"
#include "simta_malloc.h"

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#endif /* HAVE_LDAP */

#ifdef HAVE_LIBSASL
#include "simta_sasl.h"
#endif /* HAVE_LIBSASL */

const char *simta_progname = "simta";

struct connection_info *cinfo_stab = NULL;
int                     simta_pidfd;
int                     simsendmail_signal = 0;
int                     command_signal = 0;
struct sigaction        sa;
struct sigaction        osahup;
struct sigaction        osachld;
struct sigaction        osausr1;
struct sigaction        osausr2;
const char             *version = PACKAGE_VERSION;
struct simta_socket    *simta_listen_sockets = NULL;


int          daemon_local(void);
int          hq_launch(void);
simta_result sender_promote(char *);
simta_result mid_promote(char *);

void                 env_log_metrics(struct dll_entry *);
void                 sender_log_metrics(struct dll_entry *);
int                  daemon_commands(struct simta_dirp *);
void                 usr1(int);
void                 usr2(int);
void                 hup(int);
void                 chld(int);
int                  main(int, char *av[]);
int                  simta_wait_for_child(int);
int                  simta_sigaction_reset(bool);
int                  simta_server(bool);
int                  simta_daemonize_server(void);
int                  simta_child_receive(struct simta_socket *);
struct simta_socket *simta_listen_port(const char *);
int                  simta_listen(void);
struct proc_type    *simta_proc_add(int, int);
int                  simta_proc_q_runner(int, struct host_q *);
int                  simta_read_command(struct simta_dirp *);
int                  set_sleep_time(int *, int);

void
usr1(int sig) {
    simsendmail_signal = 1;
    return;
}


void
usr2(int sig) {
    command_signal = 1;
    return;
}


void
hup(int sig) {
    /* hup does nothing at the moment */
    return;
}


void
chld(int sig) {
    simta_child_signal = 1;
    return;
}


int
simta_listen(void) {
    int                 retval = 1;
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;
#ifdef HAVE_LIBSSL
    struct simta_socket *ss;
#endif /* HAVE_LIBSSL */

    iter = ucl_object_iterate_new(simta_config_obj("receive.ports"));

    while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
        if (simta_listen_port(ucl_object_tostring_forced(obj)) == NULL) {
            goto error;
        }
    }

#ifdef HAVE_LIBSSL
    if (simta_config_bool("receive.tls.enabled")) {
        ucl_object_iterate_reset(iter, simta_config_obj("receive.tls.ports"));

        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            if ((ss = simta_listen_port(ucl_object_tostring_forced(obj))) ==
                    NULL) {
                goto error;
            }
            ss->ss_flags |= SIMTA_SOCKET_TLS;
        }
    }
#endif /* HAVE_LIBSSL */

    retval = 0;

error:
    ucl_object_iterate_free(iter);
    return (retval);
}

struct simta_socket *
simta_listen_port(const char *port) {
    int                  sockopt;
    int                  rc;
    char                 host[ NI_MAXHOST ];
    char                 service[ NI_MAXSERV ];
    struct addrinfo      hints;
    struct addrinfo     *ai, *air;
    struct simta_socket *ss = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE | AI_NUMERICSERV;

    if ((rc = getaddrinfo(NULL, port, &hints, &air)) != 0) {
        syslog(LOG_ERR, "Syserror: simta_listen getaddrinfo: %s",
                gai_strerror(rc));
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return (NULL);
    }

    for (ai = air; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET6) {
            if (!simta_config_bool("receive.ipv6")) {
                continue;
            }
        } else {
            if (!simta_config_bool("receive.ipv4")) {
                continue;
            }
        }

        ss = simta_calloc(1, sizeof(struct simta_socket));

        if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, host, sizeof(host),
                     service, sizeof(service), NI_NUMERICHOST)) != 0) {
            syslog(LOG_ERR, "Syserror: simta_listen getnameinfo: %s",
                    gai_strerror(rc));
            fprintf(stderr, "getnameinfo: %s\n", gai_strerror(rc));
            return (NULL);
        }
        ss->ss_service = simta_strdup(service);
        ss->ss_next = simta_listen_sockets;
        simta_listen_sockets = ss;

        if ((ss->ss_socket = socket(
                     ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            syslog(LOG_ERR, "Syserror: simta_listen socket %s:%s: %m", host,
                    service);
            perror("socket");
            return (NULL);
        }

        if (ai->ai_family == AF_INET6) {
            sockopt = 1;
            if (setsockopt(ss->ss_socket, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt,
                        sizeof(int)) < 0) {
                syslog(LOG_ERR, "Syserror: simta_listen setsockopt %s:%s: %m",
                        host, service);
                perror("setsockopt");
                return (NULL);
            }
        }

        sockopt = 1;
        if (setsockopt(ss->ss_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt,
                    sizeof(int)) < 0) {
            syslog(LOG_ERR, "Syserror: simta_listen setsockopt %s:%s: %m", host,
                    service);
            perror("setsockopt");
            return (NULL);
        }

        if (bind(ss->ss_socket, ai->ai_addr, ai->ai_addrlen) < 0) {
            syslog(LOG_ERR, "Syserror: simta_listen bind %s:%s: %m", host,
                    service);
            perror("bind");
            return (NULL);
        }

        if (listen(ss->ss_socket, 4096) < 0) {
            syslog(LOG_ERR, "Syserror: simta_listen listen %s:%s: %m", host,
                    service);
            perror("listen");
            return (NULL);
        }
    }

    freeaddrinfo(air);
    return (ss);
}


int
main(int ac, char **av) {
    int                  c, err = 0;
    bool                 dontrun = false;
    bool                 daemonize = true;
    char                *prog;
    struct simta_socket *ss;
    const char          *simta_uname = NULL;
    struct passwd       *simta_pw;
    const char          *config_fname = NULL;
    const char          *config_extra = NULL;
    const char          *simta_pwd;
    const char          *simta_file_pid;
#ifdef HAVE_LIBSSL
    SSL_CTX *ssl_ctx = NULL;
#endif /* HAVE_LIBSSL */

    if ((prog = strrchr(av[ 0 ], '/')) == NULL) {
        prog = av[ 0 ];
    } else {
        prog++;
    }

    while ((c = getopt(ac, av, "cCDf:h:u:U:V")) != -1) {
        switch (c) {
        case 'c': /* check config files */
            dontrun = true;
            break;

        case 'C': /* clean up directories */
            simta_filesystem_cleanup++;
            break;

        case 'D':
            daemonize = false;
            break;

        case 'f':
            config_fname = optarg;
            break;

        case 'h':
            simta_hostname = yaslauto(optarg);
            break;

        case 'u':
            simta_uname = optarg;
            break;

        case 'U':
            config_extra = optarg;
            break;

        case 'V':
            printf("%s\n", version);
            exit(SIMTA_EXIT_OK);

        default:
            err++;
        }
    }

    if (err || optind != ac) {
        fprintf(stderr, "Usage:\t%s", prog);
        fprintf(stderr, " [ -cCdV ]");
        fprintf(stderr, " [ -f config-file ]");
        fprintf(stderr, " [ -u user ]");
        fprintf(stderr, " [ -U ucl-config-string ]");
        fprintf(stderr, "\n");
        exit(SIMTA_EXIT_ERROR);
    }

    if (simta_gettimeofday(NULL) == SIMTA_ERR) {
        exit(SIMTA_EXIT_ERROR);
    }

    simta_openlog(false, LOG_PERROR);

    if (simta_read_config(config_fname, config_extra) != SIMTA_OK) {
        exit(SIMTA_EXIT_ERROR);
    }

#ifdef HAVE_LIBSSL
    if (simta_config_bool("receive.tls.enabled")) {
        /* Test whether our SSL config is usable */
        if ((ssl_ctx = tls_server_setup()) == NULL) {
            syslog(LOG_ERR, "Liberror: tls_server_setup: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            exit(SIMTA_EXIT_ERROR);
        }
        SSL_CTX_free(ssl_ctx);
    }
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    if (simta_config_bool("receive.auth.authn.enabled") &&
            !simta_config_bool("receive.auth.authn.honeypot")) {
        if (simta_sasl_init() != SIMTA_OK) {
            exit(SIMTA_EXIT_ERROR);
        }
    }
#endif /* HAVE_LIBSASL */

    /* ignore SIGPIPE */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Syserror: sigaction: %m");
        exit(SIMTA_EXIT_ERROR);
    }

    simta_pwd = simta_config_str("core.base_dir");
    if (chdir(simta_pwd) < 0) {
        perror(simta_pwd);
        exit(SIMTA_EXIT_ERROR);
    }

    if (dontrun) {
        simta_dump_config();
        exit(SIMTA_EXIT_OK);
    }

    /* if we're not a filesystem cleaner, open smtp service */
    if (simta_filesystem_cleanup == 0) {
        if (simta_listen() != 0) {
            exit(SIMTA_EXIT_ERROR);
        }
    }

    if (daemonize) {
        simta_file_pid = simta_config_str("core.pid_file");
        /* open and truncate the pid file */
        if ((simta_pidfd = open(simta_file_pid, O_CREAT | O_WRONLY, 0644)) <
                0) {
            fprintf(stderr, "open %s: ", simta_file_pid);
            perror(NULL);
            exit(SIMTA_EXIT_ERROR);
        }

        /* lock simta pid fd */
        if (flock(simta_pidfd, LOCK_EX | LOCK_NB) != 0) {
            if (errno == EAGAIN) {
                /* file locked by a diferent process */
                fprintf(stderr, "flock %s: daemon already running\n",
                        simta_file_pid);
                exit(SIMTA_EXIT_ERROR);

            } else {
                fprintf(stderr, "flock %s:", simta_file_pid);
                perror(NULL);
                exit(SIMTA_EXIT_ERROR);
            }
        }

        if (ftruncate(simta_pidfd, (off_t)0) < 0) {
            perror("ftruncate");
            exit(SIMTA_EXIT_ERROR);
        }
    }

    if (simta_uname == NULL) {
        simta_uname = simta_config_str("core.user");
    }

    if (simta_uname && (strlen(simta_uname) > 0)) {
        /* get our user info from /etc/passwd */
        if ((simta_pw = getpwnam(simta_uname)) == NULL) {
            fprintf(stderr, "getpwnam %s: user not found\n", simta_uname);
            exit(SIMTA_EXIT_ERROR);
        }


        /* set our initgroups */
        if (initgroups(simta_pw->pw_name, 0) != 0) {
            perror("setuid");
            exit(SIMTA_EXIT_ERROR);
        }

        /* set our gid */
        if (setgid(simta_pw->pw_gid) != 0) {
            perror("setgid");
            exit(SIMTA_EXIT_ERROR);
        }

        /* set our uid */
        if (setuid(simta_pw->pw_uid) != 0) {
            perror("setuid");
            exit(SIMTA_EXIT_ERROR);
        }

#ifdef __linux__
        /* we're debugging under linux */
        if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
            perror("prctl");
            exit(SIMTA_EXIT_ERROR);
        }
#endif /* __linux__ */
    }

    if (simta_filesystem_cleanup) {
        exit(simta_wait_for_child(PROCESS_CLEANUP));
    } else if (simta_wait_for_child(PROCESS_CLEANUP) != 0) {
        fprintf(stderr, "simta cleanup error, please check the log\n");
        exit(SIMTA_EXIT_ERROR);
    }

    /*
     * Disassociate from controlling tty.
     */
    if (daemonize) {
        closelog();

        switch (fork()) {
        case 0:
            if (setsid() < 0) {
                perror("setsid");
                exit(SIMTA_EXIT_ERROR);
            }
            int i, dt = getdtablesize();
            for (i = 0; i < dt; i++) {
                /* keep sockets & simta_pidfd open */
                for (ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next) {
                    if (i == ss->ss_socket) {
                        break;
                    }
                }
                if (ss != NULL) {
                    continue;
                }
                if (i == simta_pidfd) {
                    continue;
                }
                close(i);
            }
            if ((i = open("/", O_RDONLY, 0)) == 0) {
                dup2(i, 1);
                dup2(i, 2);
            }
            break;
        case -1:
            perror("fork");
            exit(SIMTA_EXIT_ERROR);
        default:
            exit(SIMTA_EXIT_OK);
        }
    }

    /* Start logging in daemon mode */
    if (simta_gettimeofday(NULL) == SIMTA_ERR) {
        exit(SIMTA_EXIT_ERROR);
    }

    if (daemonize) {
        simta_openlog(false, 0);
    }

    /* catch SIGHUP */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = hup;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, &osahup) < 0) {
        syslog(LOG_ERR, "Syserror: sigaction: %m");
        exit(SIMTA_EXIT_ERROR);
    }

    /* catch SIGCHLD */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = chld;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, &osachld) < 0) {
        syslog(LOG_ERR, "Syserror: sigaction: %m");
        exit(SIMTA_EXIT_ERROR);
    }

    /* catch SIGUSR1 */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = usr1;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, &osausr1) < 0) {
        syslog(LOG_ERR, "Syserror: sigaction: %m");
        exit(SIMTA_EXIT_ERROR);
    }

    /* catch SIGUSR2 */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = usr2;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR2, &sa, &osausr2) < 0) {
        syslog(LOG_ERR, "Syserror: sigaction: %m");
        exit(SIMTA_EXIT_ERROR);
    }

    if (daemonize) {
        syslog(LOG_NOTICE, "Restart: %s", version);
        exit(simta_daemonize_server());
    } else {
        exit(simta_server(false));
    }
}


int
simta_daemonize_server(void) {
    int pid;

    if (simta_gettimeofday(NULL) == SIMTA_ERR) {
        return (1);
    }

    switch (pid = fork()) {
    case 0:
        /* Fall through */
        simta_openlog(true, 0);
        return (simta_server(true));

    case -1:
        syslog(LOG_ERR, "Syserror: simta_child_queue_scheduler fork: %m");
        return (-1);

    default:
        if (simta_proc_add(PROCESS_SERVER, pid) == NULL) {
            return (1);
        }
        syslog(LOG_NOTICE, "Child: launched daemon %d.%ld", pid,
                simta_log_ts.tv_sec);
        return (0);
    }
}


int
set_sleep_time(int *sleep, int val) {
    if (val < 0) {
        val = 0;
    }

    if ((*sleep < 0) || (*sleep > val)) {
        *sleep = val;
        return (0);
    }

    return (1);
}


int
hq_launch(void) {
    struct host_q *hq;
    struct timeval tv_now;
    int            lag;
    time_t         waited;

    if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
        return (1);
    }

    hq = simta_deliver_q;
    hq_deliver_pop(hq);
    hq->hq_launches++;
    lag = tv_now.tv_sec - hq->hq_next_launch.tv_sec;

    if (hq->hq_last_launch.tv_sec != 0) {
        waited = tv_now.tv_sec - hq->hq_last_launch.tv_sec;
    } else {
        waited = 0;
    }

    if ((hq->hq_wait_longest.tv_sec == 0) ||
            (hq->hq_wait_longest.tv_sec < waited)) {
        hq->hq_wait_longest.tv_sec = waited;
    }

    if ((hq->hq_wait_shortest.tv_sec == 0) ||
            (hq->hq_wait_shortest.tv_sec > waited)) {
        hq->hq_wait_shortest.tv_sec = waited;
    }

    syslog(LOG_INFO,
            "Queue %s: launch %d: "
            "wait %lu lag %d last %lu shortest %lu longest %lu "
            "total messages %d",
            hq->hq_hostname, hq->hq_launches, waited, lag,
            hq->hq_wait_last.tv_sec, hq->hq_wait_shortest.tv_sec,
            hq->hq_wait_longest.tv_sec, hq->hq_entries);

    hq->hq_last_launch.tv_sec = tv_now.tv_sec;

    if (hq_deliver_push(hq, &tv_now, NULL) != 0) {
        return (1);
    }

    if (simta_child_q_runner(hq) != 0) {
        return (1);
    }

    return (0);
}


int
simta_server(bool daemon) {
    struct timeval           tv_launch_limiter = {0, 0};
    struct timeval           tv_disk = {0, 0};
    struct timeval           tv_unexpanded = {0, 0};
    struct timeval           tv_sleep = {0, 0};
    struct timeval           tv_now;
    const char              *sleep_reason;
    char                    *error_msg = NULL;
    int                      entries;
    int                      ready;
    int                      sleep_time;
    int                      launched;
    FILE                    *pf;
    struct simta_dirp        command_dirp;
    struct simta_dirp        slow_dirp;
    int                      fd_max;
    fd_set                   fdset;
    struct simta_socket     *ss;
    struct connection_info **c;
    struct connection_info  *remove;

    memset(&command_dirp, 0, sizeof(struct simta_dirp));
    command_dirp.sd_dir = simta_dir_command;

    memset(&slow_dirp, 0, sizeof(struct simta_dirp));
    slow_dirp.sd_dir = simta_dir_slow;

    if (daemon) {
        if ((pf = fdopen(simta_pidfd, "w")) == NULL) {
            syslog(LOG_ERR, "Syserror: simta_server fdopen: %m");
            exit(SIMTA_EXIT_ERROR);
        }
        fprintf(pf, "%d\n", (int)getpid());
        if (fflush(pf) != 0) {
            syslog(LOG_ERR, "Syserror: simta_server fflush: %m");
            exit(SIMTA_EXIT_ERROR);
        }
    }

    simta_process_type = PROCESS_SERVER;

    if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
        exit(SIMTA_EXIT_ERROR);
    }

    /* main daemon loop */
    simta_debuglog(1, "Daemon: start");
    for (;;) {
        /* LOCAL RUNNER */
        /* CLEAN CHILD PROCESSES */
        /* COMMAND DISK */
        /* SLOW DISK */
        /* QUEUE RUNS */
        /* LISTEN */
        /* GETTIMEOFDAY */
        /* CLEAN THROTTLE TABLE */
        /* RECEIVE CHILDREN */

        sleep_time = -1;
        sleep_reason = "Unset";

        if (simsendmail_signal != 0) {
            if (simta_q_runner_local <
                    simta_config_int("deliver.limits.local_runners")) {
                simta_debuglog(2, "Daemon: launching local queue runner");
                simsendmail_signal = 0;

                if (simta_child_q_runner(NULL) != 0) {
                    goto error;
                }
            } else {
                syslog(LOG_WARNING,
                        "Daemon: Received signal from simsendmail "
                        "with no room for more runners, deferring launch");
            }
        }

        if (simta_child_signal != 0) {
            if (simta_waitpid(0, NULL, WNOHANG) != 0) {
                goto error;
            }
        }

        if ((command_dirp.sd_dirp != NULL) || (command_signal != 0)) {
            for (entries = 1;; entries++) {
                if (command_dirp.sd_dirp == NULL) {
                    simta_debuglog(2, "Daemon.command: starting read");
                    command_signal = 0;
                } else {
                    simta_debuglog(3, "Daemon.command: entry read");
                }
                daemon_commands(&command_dirp);
                if (command_dirp.sd_dirp == NULL) {
                    simta_debuglog(2, "Daemon.command: finished read");
                    break;
                }
                if (entries > 10) {
                    break;
                }
            }
        }

        if (tv_now.tv_sec >= tv_disk.tv_sec) {
            for (entries = 1;; entries++) {
                if (slow_dirp.sd_dirp == NULL) {
                    simta_debuglog(2, "Daemon: starting slow queue read");
                    simta_disk_cycle++;
                } else {
                    simta_debuglog(3, "Daemon: slow queue entry read");
                }
                if (q_read_dir(&slow_dirp) != 0) {
                    goto error;
                }
                if (slow_dirp.sd_dirp == NULL) {
                    tv_disk.tv_sec = tv_now.tv_sec + 60;
                    simta_debuglog(2, "Daemon: finished slow queue read");
                    break;
                }
                if (entries > 10) {
                    break;
                }
            }
        }
        if (set_sleep_time(&sleep_time, tv_disk.tv_sec - tv_now.tv_sec) == 0) {
            sleep_reason = S_DISK;
            simta_debuglog(3, "Daemon: set_sleep_time %s: %d", sleep_reason,
                    sleep_time);
        }

        /* run unexpanded queue if we have entries, and it is time */
        if ((simta_unexpanded_q != NULL) &&
                (simta_unexpanded_q->hq_env_head != NULL)) {
            if (tv_now.tv_sec >= tv_unexpanded.tv_sec) {
                tv_unexpanded.tv_sec = tv_now.tv_sec + 60;
                simta_debuglog(2, "Daemon: launching unexpanded queue runner");
                if (simta_child_q_runner(simta_unexpanded_q) != 0) {
                    goto error;
                }
            }
            if (set_sleep_time(&sleep_time,
                        tv_unexpanded.tv_sec - tv_now.tv_sec) == 0) {
                sleep_reason = S_UNEXPANDED;
                simta_debuglog(3, "Daemon: set_sleep_time %s: %d", sleep_reason,
                        sleep_time);
            }
        }

        /* check to see if we need to launch queue runners */
        for (launched = 1; simta_deliver_q != NULL; launched++) {
            if (tv_launch_limiter.tv_sec > tv_now.tv_sec) {
                if (set_sleep_time(&sleep_time,
                            tv_launch_limiter.tv_sec - tv_now.tv_sec) == 0) {
                    sleep_reason = S_LIMITER;
                    simta_debuglog(3, "Daemon: set_sleep_time %s: %d",
                            sleep_reason, sleep_time);
                }
                break;
            }

            if (simta_deliver_q->hq_next_launch.tv_sec > tv_now.tv_sec) {
                if (set_sleep_time(&sleep_time,
                            simta_deliver_q->hq_next_launch.tv_sec -
                                    tv_now.tv_sec) == 0) {
                    sleep_reason = S_QUEUE;
                    simta_debuglog(3, "Daemon: set_sleep_time %s: %d",
                            sleep_reason, sleep_time);
                }
                simta_debuglog(1, "Daemon: next queue %s %d",
                        simta_deliver_q->hq_hostname,
                        (int)(simta_deliver_q->hq_next_launch.tv_sec -
                                tv_now.tv_sec));
                break;
            }

            if (simta_q_runner_slow >=
                    simta_config_int("deliver.limits.slow_runners")) {
                /* queues need to launch but process limit met */
                syslog(LOG_NOTICE,
                        "Daemon: Queue %s ready with no room for more runners, "
                        "deferring launch",
                        simta_deliver_q->hq_hostname);
                break;
            }

            simta_debuglog(2, "Daemon: launching queue runner %s",
                    simta_deliver_q->hq_hostname);
            if (hq_launch() != 0) {
                goto error;
            }

            if (launched % 10 == 0) {
                syslog(LOG_WARNING,
                        "Daemon: launched 10 queue runners, sleeping for 1 "
                        "second");
                tv_launch_limiter.tv_sec = tv_now.tv_sec + 1;
            }
        }

        if (command_dirp.sd_dirp != NULL) {
            simta_debuglog(2, "Daemon: reading commands");
            sleep_time = 0;
            sleep_reason = "reading commands";
        }

        if ((simsendmail_signal != 0) &&
                (simta_q_runner_local <
                        simta_config_int("deliver.limits.local_runners"))) {
            simta_debuglog(2, "Daemon: simsendmail signal");
            sleep_time = 0;
            sleep_reason = "simsendmail signal";
        }

        if (simta_child_signal != 0) {
            simta_debuglog(2, "Daemon: child signal");
            sleep_time = 0;
            sleep_reason = "child signal";
        }

        if (sleep_time < 0) {
            sleep_time = 0;
        }

        if (simta_listen_sockets == NULL) {
            if (sleep_time > 0) {
                simta_debuglog(
                        1, "Daemon: sleeping %d: %s", sleep_time, sleep_reason);
                sleep((unsigned int)sleep_time);
            }
            if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
                goto error;
            }
            continue;
        }

        if (sleep_time > 0) {
            tv_sleep.tv_sec = sleep_time;
        } else {
            tv_sleep.tv_sec = 0;
        }
        tv_sleep.tv_usec = 0;

        FD_ZERO(&fdset);
        fd_max = 0;

        for (ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next) {
            FD_SET(ss->ss_socket, &fdset);
            fd_max = MAX(fd_max, ss->ss_socket);
        }

        simta_debuglog(
                1, "Daemon: selecting %ld: %s", tv_sleep.tv_sec, sleep_reason);

        if ((ready = select(fd_max + 1, &fdset, NULL, NULL, &tv_sleep)) < 0) {
            if (errno != EINTR) {
                syslog(LOG_ERR, "Syserror: simta_child_smtp_daemon select: %m");
                goto error;
            }
        }

        simta_debuglog(2, "Daemon: select over");

        if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
            goto error;
        }

        for (c = &cinfo_stab; *c != NULL;) {
            if (((*c)->c_proc_total == 0) &&
                    timercmp(&((*c)->c_tv), &tv_now, <)) {
                remove = *c;
                *c = (*c)->c_next;
                simta_free(remove);

            } else {
                c = &((*c)->c_next);
            }
        }

        simta_debuglog(2, "Daemon: %d sockets ready", ready);
        if (ready <= 0) {
            continue;
        }

        for (ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next) {
            if (FD_ISSET(ss->ss_socket, &fdset)) {
                simta_debuglog(2, "Daemon: Connect received");
                if (simta_child_receive(ss) != 0) {
                    goto error;
                }
            }
        }
        simta_debuglog(2, "Daemon: done checking sockets");
    }

error:
    syslog(LOG_NOTICE, "Daemon: Shutdown %s", error_msg ? error_msg : "");

    return (1);
}


int
simta_wait_for_child(int child_type) {
    int         pid;
    int         status;
    const char *p_name;

    if (simta_gettimeofday(NULL) == SIMTA_ERR) {
        return (1);
    }

    switch (pid = fork()) {
    case -1:
        syslog(LOG_ERR, "Syserror: simta_wait_for_child fork: %m");
        return (1);

    case 0:
        simta_openlog(true, 0);
        switch (child_type) {
        case PROCESS_CLEANUP:
            exit(q_cleanup());

        case PROCESS_Q_SLOW:
            exit(q_runner_dir(simta_dir_slow));

        default:
            syslog(LOG_ERR,
                    "Syserror: wait_for_child: child_type out of range: %d",
                    child_type);
            return (1);
        }

    default:
        switch (child_type) {
        case PROCESS_CLEANUP:
            if (simta_filesystem_cleanup) {
                p_name = "filesystem cleaner";
            } else {
                p_name = "filesystem checker";
            }
            break;

        case PROCESS_Q_SLOW:
            p_name = "queue runner";
            break;

        default:
            syslog(LOG_ERR, "Child: %d: start type %d out of range", pid,
                    child_type);
            return (1);
        }

        syslog(LOG_NOTICE, "Child: launched %s %d", p_name, pid);

        if (simta_waitpid(pid, &status, 0) < 0) {
            syslog(LOG_ERR, "Syserror: wait_for_child simta_waitpid %d: %m",
                    pid);
            return (1);
        }

        if (WIFEXITED(status)) {
            syslog(LOG_NOTICE, "Child: %s %d exited %d", p_name, pid,
                    WEXITSTATUS(status));
            return (WEXITSTATUS(status));

        } else if (WIFSIGNALED(status)) {
            syslog(LOG_ERR, "Child: %s %d died with signal %d", p_name, pid,
                    WTERMSIG(status));
            return (1);

        } else {
            syslog(LOG_ERR, "Child: %s %d died", p_name, pid);
            return (1);
        }
    }
}


int
simta_sigaction_reset(bool retain_chld) {
    /* reset USR1, CHLD and HUP */
    if (!retain_chld) {
        if (sigaction(SIGCHLD, &osachld, 0) < 0) {
            syslog(LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m");
            return (1);
        }
    }
    if (sigaction(SIGHUP, &osahup, 0) < 0) {
        syslog(LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m");
        return (1);
    }
    if (sigaction(SIGUSR1, &osausr1, 0) < 0) {
        syslog(LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m");
        return (1);
    }
    if (sigaction(SIGUSR2, &osausr2, 0) < 0) {
        syslog(LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m");
        return (1);
    }

    return (0);
}


int
simta_child_receive(struct simta_socket *ss) {
    static struct timeval   tv_throttle = {0, 0};
    struct proc_type       *p;
    struct simta_socket    *s;
    struct connection_info *cinfo = NULL;
    struct sockaddr_storage sa;
    struct timeval          tv_add;
    int                     pid;
    int                     fd;
    int                     rc;
    socklen_t               salen;

    salen = sizeof(struct sockaddr_storage);
    if ((fd = accept(ss->ss_socket, (struct sockaddr *)&sa, &salen)) < 0) {
        syslog(LOG_ERR, "Syserror: simta_child_receive accept: %m");
        /* accept() errors aren't fatal */
        return (0);
    }

    /* Look up / Create IP related connection data entry */
    for (cinfo = cinfo_stab; cinfo != NULL; cinfo = cinfo->c_next) {
        if (sa.ss_family != cinfo->c_sa.ss_family) {
            continue;
        }
        if ((sa.ss_family == AF_INET6) &&
                (memcmp(&(((struct sockaddr_in6 *)&sa)->sin6_addr),
                         &(((struct sockaddr_in6 *)&(cinfo->c_sa))->sin6_addr),
                         sizeof(struct in6_addr)) == 0)) {
            break;
        } else if (memcmp(&(((struct sockaddr_in *)&sa)->sin_addr),
                           &(((struct sockaddr_in *)&(cinfo->c_sa))->sin_addr),
                           sizeof(struct in_addr)) == 0) {
            break;
        }
    }

    if (cinfo == NULL) {
        cinfo = simta_calloc(1, sizeof(struct connection_info));
        memcpy(&(cinfo->c_sa), &sa, sizeof(struct sockaddr_storage));

        if ((rc = getnameinfo((struct sockaddr *)&sa,
                     ((sa.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in)),
                     cinfo->c_ip, sizeof(cinfo->c_ip), NULL, 0,
                     NI_NUMERICHOST)) != 0) {
            syslog(LOG_ERR, "Syserror: simta_child_receive getnameinfo: %s",
                    gai_strerror(rc));
        }

        cinfo->c_next = cinfo_stab;
        cinfo_stab = cinfo;
    }

    cinfo->c_proc_total++;
    simta_global_connections++;

    if (simta_gettimeofday(NULL) == SIMTA_ERR) {
        return (1);
    }

    if (timercmp(&(cinfo->c_tv), &simta_tv_now, <)) {
        simta_ucl_object_totimeval(
                simta_config_obj("receive.connection.limits.throttle_interval"),
                &tv_add);
        timeradd(&simta_tv_now, &tv_add, &(cinfo->c_tv));
        cinfo->c_proc_throttle = 1;
    } else {
        cinfo->c_proc_throttle++;
    }

    if (timercmp(&tv_throttle, &simta_tv_now, <)) {
        simta_ucl_object_totimeval(
                simta_config_obj("receive.connection.limits.throttle_interval"),
                &tv_add);
        timeradd(&simta_tv_now, &tv_add, &tv_throttle);
        simta_global_throttle_connections = 1;
    } else {
        simta_global_throttle_connections++;
    }

    simta_debuglog(1,
            "Connect.stat %s: global_total %d "
            "global_throttle %d local_total %d local_throttle %d",
            cinfo->c_ip, simta_global_connections,
            simta_global_throttle_connections, cinfo->c_proc_total,
            cinfo->c_proc_throttle);

    switch (pid = fork()) {
    case 0:
        simta_openlog(true, 0);
        simta_process_type = PROCESS_RECEIVE;
        simta_host_q = NULL;
        if (simta_unexpanded_q != NULL) {
            simta_unexpanded_q->hq_env_head = NULL;
            simta_unexpanded_q->hq_entries = 0;
        }
        for (s = simta_listen_sockets; s != NULL; s = s->ss_next) {
            if (close(s->ss_socket) != 0) {
                syslog(LOG_ERR, "Syserror: simta_child_receive close: %m");
            }
        }
        /* smtp receive children may spawn children */
        simta_sigaction_reset(true);
        simta_proc_stab = NULL;
        simta_q_runner_slow = 0;
        exit(smtp_receive(fd, cinfo, ss));

    case -1:
        syslog(LOG_ERR, "Syserror: simta_child_receive fork: %m");
        return (1);

    default:
        /* Here we are the server */
        break;
    }

    if (close(fd) != 0) {
        syslog(LOG_ERR, "Syserror: simta_child_receive close: %m");
        return (1);
    }

    if ((p = simta_proc_add(PROCESS_RECEIVE, pid)) == NULL) {
        return (1);
    }

    p->p_limit = &simta_global_connections;
    p->p_ss = ss;
    p->p_ss->ss_count++;
    p->p_cinfo = cinfo;

    p->p_host = simta_strdup(cinfo->c_ip);

    syslog(LOG_NOTICE,
            "Child: launched %s receive process %d for %s "
            "(%d total, %d %s)",
            p->p_ss->ss_service, p->p_id, p->p_host, *p->p_limit,
            p->p_ss->ss_count, p->p_ss->ss_service);

    return (0);
}


int
simta_child_q_runner(struct host_q *hq) {
    int pid;

    if (simta_gettimeofday(NULL) == SIMTA_ERR) {
        return (1);
    }

    switch (pid = fork()) {
    case 0:
        simta_openlog(true, 0);
        simta_sigaction_reset(false);
        close(simta_pidfd);

        /* delivery children of receive processes should run all queues, so
         * we don't clear this for them.
         */
        if (simta_process_type != PROCESS_RECEIVE) {
            simta_host_q = NULL;
        }

        /* Stop using the parent's dnsr object, if it has one */
        if (simta_dnsr) {
            dnsr_free(simta_dnsr);
            simta_dnsr = NULL;
        }

#ifdef HAVE_LDAP
        /* Close open LDAP connections */
        simta_ldap_reset();
#endif /* HAVE_LDAP */

        if ((hq != NULL) && (hq == simta_unexpanded_q)) {
            simta_process_type = PROCESS_Q_SLOW;
            exit(q_runner());
        }

        if (simta_unexpanded_q != NULL) {
            simta_unexpanded_q->hq_env_head = NULL;
            simta_unexpanded_q->hq_entries = 0;
        }

        if (hq == NULL) {
            simta_process_type = PROCESS_Q_LOCAL;
            exit(q_runner_dir(simta_dir_local));

        } else {
            hq->hq_primary = 1;
            simta_process_type = PROCESS_Q_SLOW;
            simta_host_q = ucl_object_typed_new(UCL_OBJECT);
            ucl_object_insert_key(simta_host_q,
                    ucl_object_new_userdata(NULL, NULL, hq), hq->hq_hostname, 0,
                    true);
            exit(q_runner());
        }

        /* if you get here there is an error */
        panic("unreachable code");

    case -1:
        syslog(LOG_ERR, "Syserror: simta_child_q_runner fork: %m");
        return (1);

    default:
        /* here we are the server.  this is ok */
        break;
    }

    if (simta_proc_q_runner(pid, hq) != 0) {
        return (1);
    }

    return (0);
}


int
simta_proc_q_runner(int pid, struct host_q *hq) {
    struct proc_type *p;
    int               type;

    if (hq == NULL) {
        type = PROCESS_Q_LOCAL;
    } else {
        type = PROCESS_Q_SLOW;
    }

    if ((p = simta_proc_add(type, pid)) == NULL) {
        return (1);
    }

    if (hq == NULL) {
        p->p_limit = &simta_q_runner_local;
        (*p->p_limit)++;

        syslog(LOG_NOTICE, "Child: launched local runner %d (%d total)", pid,
                *p->p_limit);

    } else {
        p->p_limit = &simta_q_runner_slow;
        (*p->p_limit)++;

        if (hq->hq_hostname) {
            p->p_host = simta_strdup(hq->hq_hostname);
        }

        syslog(LOG_NOTICE, "Child: launched queue runner %d for %s (%d total)",
                pid, hq->hq_hostname ? hq->hq_hostname : S_UNEXPANDED,
                *p->p_limit);
    }

    return (0);
}


struct proc_type *
simta_proc_add(int process_type, int pid) {
    struct proc_type *p;

    p = simta_calloc(1, sizeof(struct proc_type));

    p->p_tv.tv_sec = simta_tv_now.tv_sec;
    p->p_id = pid;
    p->p_type = process_type;
    p->p_next = simta_proc_stab;
    simta_proc_stab = p;

    return (p);
}


simta_result
mid_promote(char *mid) {
    struct dll_entry *dll;
    struct envelope  *e;
    struct timeval    tv_nowait = {0, 0};

    if ((dll = dll_lookup(simta_env_list, mid)) != NULL) {
        e = (struct envelope *)dll->dll_data;

        if (env_parole(e) != SIMTA_OK) {
            return SIMTA_ERR;
        }

        if (e->e_hq != NULL) {
            hq_deliver_pop(e->e_hq);
            if (hq_deliver_push(e->e_hq, NULL, &tv_nowait) != 0) {
                return (1);
            }
            simta_debuglog(3, "Command: env <%s>: promoted queue %s", mid,
                    e->e_hq->hq_hostname);
        } else {
            simta_debuglog(2, "Command: env <%s>: not in a queue", mid);
        }
    } else {
        simta_debuglog(1, "Command: env <%s>: not found", mid);
    }

    return SIMTA_OK;
}


simta_result
sender_promote(char *sender) {
    struct dll_entry    *dll;
    struct sender_list  *sl;
    struct sender_entry *se;
    struct dll_entry    *dll_se;
    struct timeval       tv_nowait = {0, 0};

    if ((dll = dll_lookup(simta_sender_list, sender)) != NULL) {
        sl = (struct sender_list *)dll->dll_data;
        simta_debuglog(1, "Command: Sender %s: found %d messages", sender,
                sl->sl_n_entries);
        for (dll_se = sl->sl_entries; dll_se != NULL;
                dll_se = dll_se->dll_next) {
            se = (struct sender_entry *)dll_se->dll_data;
            env_parole(se->se_env);
            /* re-queue queue */
            if (se->se_env->e_hq != NULL) {
                hq_deliver_pop(se->se_env->e_hq);
                if (hq_deliver_push(se->se_env->e_hq, NULL, &tv_nowait) != 0) {
                    syslog(LOG_NOTICE,
                            "Command: Sender %s: hq_deliver_push "
                            "failed for %s",
                            sender, se->se_env->e_hq->hq_hostname);
                    return SIMTA_ERR;
                } else {
                    simta_debuglog(3, "Command: Sender %s: promoted queue %s",
                            sender, se->se_env->e_hq->hq_hostname);
                }
            }
        }
    }

    return SIMTA_OK;
}


int
daemon_commands(struct simta_dirp *sd) {
    struct dirent   *entry;
    struct timeval   tv_stop;
    char            *line;
    SNET            *snet;
    char             fname[ MAXPATHLEN + 1 ];
    int              lineno = 1;
    int              ret = 0;
    int              ac;
    int              int_arg;
    char           **av;
    ACAV            *acav;
    struct host_q   *hq;
    struct timeval   tv_nowait = {0, 0};
    struct envelope *e;

    if (sd->sd_dirp == NULL) {
        if (simta_gettimeofday(&(sd->sd_tv_start)) == SIMTA_ERR) {
            return (1);
        }

        if ((sd->sd_dirp = opendir(sd->sd_dir)) == NULL) {
            syslog(LOG_ERR, "Syserror: simta_read_command opendir %s: %m",
                    sd->sd_dir);
            return (1);
        }

        sd->sd_entries = 0;
        sd->sd_cycle++;
        return (0);
    }

    errno = 0;

    if ((entry = readdir(sd->sd_dirp)) == NULL) {
        if (errno != 0) {
            syslog(LOG_ERR, "Syserror: simta_read_command readdir %s: %m",
                    sd->sd_dir);
            return (1);
        }

        if (closedir(sd->sd_dirp) != 0) {
            syslog(LOG_ERR, "Syserror: simta_read_command closedir %s: %m",
                    sd->sd_dir);
            sd->sd_dirp = NULL;
            return (1);
        }

        sd->sd_dirp = NULL;

        if (simta_gettimeofday(&tv_stop) == SIMTA_ERR) {
            return (1);
        }

        syslog(LOG_INFO,
                "Command Metric: cycle %d Commands %d milliseconds %ld",
                sd->sd_cycle, sd->sd_entries,
                SIMTA_ELAPSED_MSEC(sd->sd_tv_start, tv_stop));

        return (0);
    }

    switch (*entry->d_name) {
    /* "C*" */
    case 'C':
        sd->sd_entries++;
        /* Command file */
        break;

    /* "c*" */
    case 'c':
        /* command temp file */
        return (0);

    /* "." && ".." */
    case '.':
        if (*(entry->d_name + 1) == '\0') {
            /* "." */
            return (0);
        } else if ((*(entry->d_name + 1) == '.') &&
                   (*(entry->d_name + 2) == '\0')) {
            /* ".." */
            return (0);
        }
        /* fall through to default */

    /* "*" */
    default:
        syslog(LOG_WARNING, "Command: unknown file: %s/%s", sd->sd_dir,
                entry->d_name);
        return (0);
    }

    sprintf(fname, "%s/%s", sd->sd_dir, entry->d_name);

    if ((snet = snet_open(fname, O_RDWR, 0)) == NULL) {
        if (errno != ENOENT) {
            syslog(LOG_ERR, "Liberror: simta_read_command snet_open %s: %m",
                    fname);
            return (1);
        }
        return (0);
    }

    acav = acav_alloc();

    if ((line = snet_getline(snet, NULL)) == NULL) {
        simta_debuglog(1, "Command %s: unexpected EOF", entry->d_name);
        ret = 1;
        goto error;
    }

    if ((ac = acav_parse(acav, line, &av)) < 0) {
        syslog(LOG_ERR, "Syserror: simta_read_command acav_parse: %m");
        ret = 1;
        goto error;
    }

    if (av[ 0 ] == NULL) {
        simta_debuglog(2, "Command %s: line %d: NULL", entry->d_name, lineno);

    } else if (strcasecmp(av[ 0 ], S_MESSAGE) == 0) {
        if (ac == 1) {
            simta_debuglog(2, "Command %s: Message", entry->d_name);
            env_log_metrics(simta_env_list);

        } else if (ac == 2) {
            simta_debuglog(2, "Command %s: Message %s", entry->d_name, av[ 1 ]);
            if (mid_promote(av[ 1 ]) != SIMTA_OK) {
                ret = 1;
            }

        } else {
            simta_debuglog(1, "Command %s: line %d: too many arguments",
                    entry->d_name, lineno);
            ret = 1;
        }

    } else if (strcasecmp(av[ 0 ], S_SENDER) == 0) {
        if (ac == 1) {
            simta_debuglog(2, "Command %s: Sender", entry->d_name);
            sender_log_metrics(simta_sender_list);

        } else if (ac == 2) {
            simta_debuglog(2, "Command %s: Sender %s", entry->d_name, av[ 1 ]);
            /* JAIL-ADD promote sender's mail */
            if (sender_promote(av[ 1 ]) != SIMTA_OK) {
                ret++;
            }
        } else {
            simta_debuglog(1, "Command %s: line %d: too many arguments",
                    entry->d_name, lineno);
        }

    } else if (strcasecmp(av[ 0 ], S_QUEUE) == 0) {
        if (ac == 1) {
            simta_debuglog(2, "Command %s: Queue", entry->d_name);
            queue_log_metrics(simta_deliver_q);
        } else if (ac == 2) {
            simta_debuglog(2, "Command %s: Queue %s", entry->d_name, av[ 1 ]);
            if ((hq = host_q_lookup(av[ 1 ])) != NULL) {
                hq_deliver_pop(hq);
                /* promote all the envs in the queue */
                for (e = hq->hq_env_head; e != NULL; e = e->e_hq_next) {
                    env_parole(e);
                }

                if (hq_deliver_push(hq, NULL, &tv_nowait) != 0) {
                    syslog(LOG_NOTICE,
                            "Command %s: Queue %s: hq_deliver_push "
                            "failed",
                            entry->d_name, av[ 1 ]);
                    ret = 1;
                } else {
                    simta_debuglog(1, "Command %s: Queue %s: promoted",
                            entry->d_name, av[ 1 ]);
                }
            } else {
                simta_debuglog(1, "Command %s: Queue %s: not found",
                        entry->d_name, av[ 1 ]);
            }

        } else {
            simta_debuglog(1, "Command %s: line %d: too many arguments",
                    entry->d_name, lineno);
        }

    } else if (strcasecmp(av[ 0 ], S_DEBUG) == 0) {
        if (ac == 1) {
            simta_debuglog(
                    1, "Command %s: Debug: %d", entry->d_name, simta_debug);
        } else if (ac == 2) {
            int_arg = atoi(av[ 1 ]);
            if (int_arg >= 0) {
                simta_debug = int_arg;
                simta_debuglog(2, "Command %s: Debug set: %d", entry->d_name,
                        simta_debug);
            } else {
                ret = 1;
                simta_debuglog(1, "Command %s: Debug illegal arg: %d",
                        entry->d_name, simta_debug);
            }
        } else {
            ret = 1;
            simta_debuglog(1, "Command %s: line %d: too many arguments",
                    entry->d_name, lineno);
        }

    } else {
        ret = 1;
        simta_debuglog(1, "Command %s: line %d: Unknown command: \"%s\"",
                entry->d_name, lineno, av[ 0 ]);
    }

error:
    if (snet_close(snet) < 0) {
        syslog(LOG_ERR, "Syserror: simta_read_command snet_close %s: %m",
                entry->d_name);
    }

    if (unlink(fname) != 0) {
        syslog(LOG_ERR, "Syserror: simta_read_command unlink %s: %m", fname);
    }

    acav_free(acav);

    return (ret);
}


void
env_log_metrics(struct dll_entry *dll_head) {
    yastr             linkname = NULL;
    yastr             filename = NULL;
    int               fd;
    FILE             *f;
    struct dll_entry *dll;
    struct envelope  *env;
    struct timeval    tv_now;
    struct stat       st_file;

    if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
        return;
    }

    linkname = yaslcat(
            yaslauto(simta_config_str("core.base_dir")), "/etc/mid_list");
    filename = yaslcatprintf(
            yasldup(linkname), "%lX", (unsigned long)tv_now.tv_sec);

    if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664)) < 0) {
        syslog(LOG_WARNING, "Syserror: env_log_metrics open %s: %m", filename);
        goto error;
    }

    if ((f = fdopen(fd, "w")) == NULL) {
        syslog(LOG_WARNING, "Syserror: env_log_metrics fdopen %s: %m",
                filename);
        close(fd);
        goto error;
    }

    fprintf(f, "MID List:\n\n");

    for (dll = dll_head; dll != NULL; dll = dll->dll_next) {
        env = (struct envelope *)dll->dll_data;
        fprintf(f, "%s\t%s\t%s\n", env->e_id, env->e_hostname, env->e_mail);
    }

    fclose(f);

    if ((stat(linkname, &st_file) == 0) && (unlink(linkname) != 0)) {
        syslog(LOG_WARNING, "Syserror: env_log_metrics unlink %s: %m",
                linkname);
    } else if (link(filename, linkname) != 0) {
        syslog(LOG_WARNING, "Syserror: env_log_metrics link %s %s: %m",
                filename, linkname);
    }

error:
    yaslfree(linkname);
    yaslfree(filename);

    return;
}

void
sender_log_metrics(struct dll_entry *dll_head) {
    yastr               linkname = NULL;
    yastr               filename = NULL;
    int                 fd;
    FILE               *f;
    struct dll_entry   *dll;
    struct sender_list *sl;
    struct timeval      tv_now;
    struct stat         st_file;

    if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
        return;
    }

    linkname = yaslcat(
            yaslauto(simta_config_str("core.base_dir")), "/etc/sender_list");
    filename = yaslcatprintf(
            yasldup(linkname), "%lX", (unsigned long)tv_now.tv_sec);

    if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664)) < 0) {
        syslog(LOG_WARNING, "Syserror: sender_log_metrics open %s: %m",
                filename);
        goto error;
    }

    if ((f = fdopen(fd, "w")) == NULL) {
        syslog(LOG_WARNING, "Syserror: sender_log_metrics fdopen %s: %m",
                filename);
        close(fd);
        goto error;
    }

    fprintf(f, "Sender List:\n\n");

    for (dll = dll_head; dll != NULL; dll = dll->dll_next) {
        sl = (struct sender_list *)dll->dll_data;
        fprintf(f, "%s\t%d\n", dll->dll_key, sl->sl_n_entries);
    }

    fclose(f);

    if ((stat(linkname, &st_file) == 0) && (unlink(linkname) != 0)) {
        syslog(LOG_WARNING, "Syserror: sender_log_metrics unlink %s: %m",
                linkname);
    } else if (link(filename, linkname) != 0) {
        syslog(LOG_WARNING, "Syserror: sender_log_metrics link %s %s: %m",
                filename, linkname);
    }

error:
    yaslfree(linkname);
    yaslfree(filename);

    return;
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
