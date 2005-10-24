/*
 * Copyright (c) 1999 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "simta.h"
#include "tls.h"

/* XXX testing purposes only, make paths configureable */
#define _PATH_SPOOL	"/var/spool/simta"

struct proc_type {
    struct proc_type	*p_next;
    int			p_id;
    int			p_type;
};

struct proc_type	*proc_stab = NULL;

int		simta_socket_smtp = 0;
int		simta_socket_submission = 0;
int		simta_pidfd;

#ifdef HAVE_LIBSSL
int		simta_socket_smtps = 0;
#endif /* HAVE_LIBSSL */

int		simsendmail_signal = 0;
int		child_signal = 0;
int		backlog = 5;
struct sigaction	sa, osahup, osachld, osausr1;

char		*maildomain = NULL;
char		*version = VERSION;

void		usr1( int );
void		hup ( int );
void		chld( int );
int		main( int, char *av[] );
int		simta_wait_for_child( int );
int		simta_waitpid( void );
int		simta_sigaction_reset( void );
int		simta_q_scheduler( void );

int		simta_proc_add( int, int );
int		simta_child_q_runner( struct host_q * );
int		simta_child_receive( int, int );
int		simta_child_smtp_daemon( void );

SSL_CTX		*ctx = NULL;

    void
usr1( int sig )
{
#ifndef Q_SIMULATION
    simsendmail_signal = 1;
#endif /* Q_SIMULATION */

    return;
}


    void
hup( int sig )
{
    /* hup does nothing at the moment */

    return;
}


    void
chld( int sig )
{
#ifndef Q_SIMULATION
    child_signal = 1;
#endif /* Q_SIMULATION */

    return;
}

#ifdef HAVE_LIBSASL
static int
sasl_my_log(void *context __attribute__((unused)),
            int priority,
            const char *message)
{
    const char *label;

    if (! message)
        return SASL_BADPARAM;

    switch (priority) {
    case SASL_LOG_ERR:
        label = "Error";
        break;
    case SASL_LOG_NOTE:
        label = "Info";
        break;
    default:
        label = "Other";
        break;
  }

    syslog( LOG_ERR, "SASL %s: %s\n", label, message);

  return SASL_OK;     
}

static sasl_callback_t callbacks[] = {
  {
    SASL_CB_LOG, &sasl_my_log, NULL
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};
#endif /* HAVE_LIBSASL */


    int
main( int ac, char **av )
{
    struct sockaddr_in	sin;
    struct servent	*se;
    int			launch_seconds;
    int			c, err = 0;
    int			dontrun = 0;
    int			reuseaddr = 1;
    int			q_run = 0;
    char		*prog;
    char		*spooldir = _PATH_SPOOL;
    FILE		*pf;
    int			use_randfile = 0;
    unsigned short	port = 0;
    extern int		optind;
    extern char		*optarg;
    char		*simta_uname = "simta";
    struct passwd	*simta_pw;
    char		*config_fname = SIMTA_FILE_CONFIG;
    char		*config_base_dir = SIMTA_BASE_DIR;
    char                *ca = "cert/ca.pem";
    char                *cert = "cert/cert.pem";
    char                *privatekey = "cert/cert.pem";
#ifdef HAVE_LIBSASL
    int			rc;
#endif /* HAVE_LIBSASL */

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

    launch_seconds = 60 * 10;

    while (( c = getopt( ac, av, " ab:cCdD:f:i:Im:M:p:qQ:rRs:SVw:x:y:z:" ))
	    != -1 ) {
	switch ( c ) {
	case ' ' :		/* Disable strict SMTP syntax checking */
	    simta_strict_smtp_syntax = 0;
	    break;

	case 'a' :		/* Automatically config with DNS */
	    simta_dns_config = 0;
	    break;

	case 'b' :		/*X listen backlog */
	    backlog = atoi( optarg );
	    break;

	case 'c' :		/* check config files */
	    dontrun++;
	    break;

	case 'C' :		/* clean up directories */
	    if ( q_run != 0 ) {
                fprintf( stderr, "simta -q or -Q and -C illegal\n" );
		exit( 1 );
	    }
	    simta_filesystem_cleanup++;
	    break;

	case 'd':
	    simta_debug++;
	    break;

	case 'D' :
	    config_base_dir = optarg;
	    break;

	case 'f' :
	    config_fname = optarg;
	    break;

	case 'i':
	    simta_reverse_url = optarg;
	    break;

	case 'I' :
	    simta_ignore_reverse = 1;
	    break;

	case 'M' :
	    maildomain = optarg;
	    break;

	case 'm' :		/* Max connections */
	    if (( simta_receive_connections_max = atoi( optarg )) < 0 ) {
		err++;
		fprintf( stderr, "%d: invalid max receive connections\n",
			simta_receive_connections_max );
	    }
	    break;

	case 'p' :		/* TCP port */
	    port = htons( atoi( optarg ));
	    break;

	case 'q' :
	    if ( simta_filesystem_cleanup != 0 ) {
                fprintf( stderr, "simta -q and -C illegal\n" );
		exit( 1 );
	    }

	    if ( q_run != 0 ) {
                fprintf( stderr, "simta invoke -Q or -q only once\n" );
		exit( 1 );
	    }

	    /* q_runner option: just run slow queue */
	    q_run++;
	    break;

	case 'Q' :
	    /* q_runner option: just run specific slow queue */
	    if ( simta_filesystem_cleanup != 0 ) {
                fprintf( stderr, "simta -Q and -C illegal\n" );
		exit( 1 );
	    }

	    if ( simta_queue_filter != NULL ) {
                fprintf( stderr, "simta -Q can't be invoked twice\n" );
		exit( 1 );
	    }

	    if ( q_run != 0 ) {
                fprintf( stderr, "simta invoke -Q or -q only once\n" );
		exit( 1 );
	    }

	    q_run++;
	    simta_queue_filter = optarg;
	    break;

	case 'r' :
	    use_randfile = 1;
	    break;

	case 'R' :
	    simta_global_relay = 1;
	    break;

	case 's' :		/* spool dir */
	    spooldir = optarg;
	    break;

	case 'S' :
	    simta_service_submission = SERVICE_SUBMISSION_ON;
	    break;

	case 'V' :		/* virgin */
	    printf( "%s\n", version );
	    exit( 0 );

        case 'w' :              /* authlevel 0:none, 1:serv, 2:client & serv */
            simta_service_smtps = atoi( optarg );
            if (( simta_service_smtps < 0 ) || ( simta_service_smtps > 2 )) {
                fprintf( stderr, "%s: %s: invalid authorization level\n",
                        prog, optarg );
                exit( 1 );
            }
            break;

        case 'x' :              /* ca file */
            ca = optarg;
            break;

        case 'y' :              /* cert file */
            cert = optarg;
            break;

        case 'z' :              /* private key */
            privatekey = optarg;
            break;

	default:
	    err++;
	}
    }

    if ( err || optind != ac ) {
	fprintf( stderr, "Usage:\t%s", prog );
	fprintf( stderr, " [ -' 'aCcdIrVq ] [ -b backlog ]" );
	fprintf( stderr, " [ -D base-dir ]" );
	fprintf( stderr, " [ -f config-file ]" );
	fprintf( stderr, " [ -i reference-URL ]" );
	fprintf( stderr, " [ -M maildomain ]" );
	fprintf( stderr, " [ -m max-connections ] [ -p port ]" );
	fprintf( stderr, " [ -Q queue]" );
	fprintf( stderr, " [ -s spooldir ]" );
	fprintf( stderr, " [ -w authlevel ] [ -x ca-pem-file ]" );
        fprintf( stderr, " [ -y cert-pem-file] [ -z key-pem-file ]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    /* get our user info from /etc/passwd */
    if (( simta_pw = getpwnam( simta_uname )) == NULL ) {
	fprintf( stderr, "getpwnam %s: user not found\n", simta_uname );
	exit( 1 );
    }

    /* set our umask */
    umask( 022 );

    /* openlog now, as some support functions require it. */
#ifdef ultrix
    openlog( prog, LOG_NOWAIT|LOG_PID );
#else /* ultrix */
#ifndef Q_SIMULATION
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_SIMTA );
#else /* Q_SIMULATION */
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_USER );
#endif /* Q_SIMULATION */
#endif /*ultrix */

    if ( simta_read_config( config_fname ) < 0 ) {
        exit( 1 );
    }

    /* ignore SIGPIPE */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = SIG_IGN;
    if ( sigaction( SIGPIPE, &sa, NULL ) < 0 ) {
	syslog( LOG_ERR, "Syserror: sigaction: %m" );
	exit( 1 );
    }

    if ( chdir( spooldir ) < 0 ) {
	perror( spooldir );
	exit( 1 );
    }

    /* init simta config / defaults */
    if ( simta_config( config_base_dir ) != 0 ) {
	exit( 1 );
    }

#ifndef Q_SIMULATION
    if ( simta_service_smtps ) {
	if ( tls_server_setup( use_randfile, simta_service_smtps, ca, cert,
		privatekey ) != 0 ) {
	    exit( 1 );
	}
	simta_tls = 1;
	simta_smtp_extension++;
    }

#ifdef HAVE_LIBSASL
    if ( simta_sasl ) {
	if (( rc = sasl_server_init( callbacks, "simta" )) != SASL_OK ) {
	    fprintf( stderr, "sasl_server_init: %s\n",
		sasl_errstring( rc, NULL, NULL ));
	    exit( 1 );
	}
    }
#endif /* HAVE_LIBSASL */

    if ( dontrun ) {
	exit( 0 );
    }

    /* if we're not a q_runner or filesystem cleaner, open smtp service */
    if (( q_run == 0 ) && ( simta_filesystem_cleanup == 0 )) {
	if ( simta_service_smtp ) {
	    /*
	     * Set up SMTP listener.
	     */
	    if ( port == 0 ) {
		if (( se = getservbyname( "smtp", "tcp" )) == NULL ) {
		    fprintf( stderr, "%s: can't find smtp service: "
			    "defaulting to port 25\n", prog );
		    port = htons( 25 );
		} else {
		    port = se->s_port;
		}
	    }
	    if (( simta_socket_smtp = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
		perror( "socket" );
		exit( 1 );
	    }
	    if ( reuseaddr ) {
		if ( setsockopt( simta_socket_smtp, SOL_SOCKET, SO_REUSEADDR,
			(void*)&reuseaddr, sizeof( int )) < 0 ) {
		    perror("setsockopt");
		}
	    }
	    memset( &sin, 0, sizeof( struct sockaddr_in ));
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port = port;
	    if ( bind( simta_socket_smtp, (struct sockaddr *)&sin,
		    sizeof( struct sockaddr_in )) < 0 ) {
		perror( "bind" );
		exit( 1 );
	    }
	    if ( listen( simta_socket_smtp, backlog ) < 0 ) {
		perror( "listen" );
		exit( 1 );
	    }
	}

#ifdef HAVE_LIBSSL
	if ( simta_service_smtps ) {
	    /*
	     * Set up SMTPS listener.
	     */
	    if (( se = getservbyname( "smtps", "tcp" )) == NULL ) {
		fprintf( stderr, "%s: can't find smtps service: "
			"defaulting to port 465\n", prog );
		port = htons( 465 );
	    } else {
		port = se->s_port;
	    }
	    if (( simta_socket_smtps =
		    socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
		perror( "socket" );
		exit( 1 );
	    }
	    if ( reuseaddr ) {
		if ( setsockopt( simta_socket_smtps, SOL_SOCKET, SO_REUSEADDR,
			(void*)&reuseaddr, sizeof( int )) < 0 ) {
		    perror("setsockopt");
		}
	    }
	    memset( &sin, 0, sizeof( struct sockaddr_in ));
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port = port;
	    if ( bind( simta_socket_smtps, (struct sockaddr *)&sin,
		    sizeof( struct sockaddr_in )) < 0 ) {
		perror( "bind" );
		exit( 1 );
	    }
	    if ( listen( simta_socket_smtps, backlog ) < 0 ) {
		perror( "listen" );
		exit( 1 );
	    }
	}
#endif /* HAVE_LIBSSL */

	if ( simta_service_submission ) {
	    /*
	     * Set up mail submission listener.
	     */
	    if (( se = getservbyname( "submission", "tcp" )) == NULL ) {
		fprintf( stderr, "%s: can't find mail submission service: "
			"defaulting to port 587\n", prog );
		port = htons( 587 );
	    } else {
		port = se->s_port;
	    }
	    if (( simta_socket_submission =
		    socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
		perror( "socket" );
		exit( 1 );
	    }
	    if ( reuseaddr ) {
		if ( setsockopt( simta_socket_submission, SOL_SOCKET,
			SO_REUSEADDR, (void*)&reuseaddr, sizeof( int )) < 0 ) {
		    perror("setsockopt");
		}
	    }
	    memset( &sin, 0, sizeof( struct sockaddr_in ));
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port = port;
	    if ( bind( simta_socket_submission, (struct sockaddr *)&sin,
		    sizeof( struct sockaddr_in )) < 0 ) {
		perror( "sub bind" );
		exit( 1 );
	    }
	    if ( listen( simta_socket_submission, backlog ) < 0 ) {
		perror( "listen" );
		exit( 1 );
	    }
	}
    }

    if ( q_run == 0 ) {
	/* open and truncate the pid file */
	if (( simta_pidfd =
		open( SIMTA_FILE_PID, O_CREAT | O_WRONLY, 0644 )) < 0 ) {
	    fprintf( stderr, "open %s: ", SIMTA_FILE_PID );
	    perror( NULL );
	    exit( 1 );
	}

	/* lock simta pid fd */
	if ( lockf( simta_pidfd, F_TLOCK, 0 ) != 0 ) {
	    if ( errno == EAGAIN ) {
		/* file locked by a diferent process */
		fprintf( stderr, "lockf %s: daemon already running",
			SIMTA_FILE_PID );
		exit( 1 );

	    } else {
		fprintf( stderr, "lockf %s: %m", SIMTA_FILE_PID );
		exit( 1 );
	    }
	}

	if ( ftruncate( simta_pidfd, (off_t)0 ) < 0 ) {
	    perror( "ftruncate" );
	    exit( 1 );
	}
    }
#endif /* Q_SIMULATION */

    /* set our initgroups */
    if ( initgroups( simta_pw->pw_name, 0 ) != 0 ) {
	perror( "setuid" );
	exit( 1 );
    }

    /* set our gid */
    if ( setgid( simta_pw->pw_gid ) != 0 ) {
	perror( "setgid" );
	exit( 1 );
    }

    /* set our uid */
    if ( setuid( simta_pw->pw_uid ) != 0 ) {
	perror( "setuid" );
	exit( 1 );
    }

    /* we're debugging under linux */
    if ( prctl( PR_SET_DUMPABLE, 1, 0, 0, 0 ) != 0 ) {
	perror( "prctl" );
	exit( 1 );
    }

#ifndef Q_SIMULATION
    if ( q_run ) {
	exit( simta_wait_for_child( PROCESS_Q_SLOW ));
    } else if ( simta_filesystem_cleanup ) {
	exit( simta_wait_for_child( PROCESS_CLEANUP ));
    } else if ( simta_wait_for_child( PROCESS_CLEANUP ) != 0 ) {
	fprintf( stderr, "simta cleanup error, please check the log\n" );
	exit( 1 );
    }
#endif /* Q_SIMULATION */

    /* close the log fd gracefully before we daemonize */
    closelog();

    /*
     * Disassociate from controlling tty.
     */
    if ( !simta_debug ) {
	int		i, dt;
	switch ( fork()) {
	case 0 :
	    if ( setsid() < 0 ) {
		perror( "setsid" );
		exit( 1 );
	    }
#ifndef Q_SIMULATION
	    dt = getdtablesize();
	    for ( i = 0; i < dt; i++ ) {
		/* keep socket & simta_pidfd open */
		if (( i != simta_socket_smtp )
#ifdef HAVE_LIBSSL
			&& (( simta_service_smtps ) &&
				( i != simta_socket_smtps ))
#endif /* HAVE_LIBSSL */
			&& (( simta_service_submission ) &&
				( i != simta_socket_submission ))
			&& ( i != simta_pidfd )) {
		    (void)close( i );
		}
	    }
#endif /* Q_SIMULATION */
	    if (( i = open( "/", O_RDONLY, 0 )) == 0 ) {
		dup2( i, 1 );
		dup2( i, 2 );
	    }
	    break;
	case -1 :
	    perror( "fork" );
	    exit( 1 );
	default :
	    exit( 0 );
	}
    }

    /* Start logging in daemon mode */
#ifdef ultrix
    openlog( prog, LOG_NOWAIT|LOG_PID );
#else /* ultrix */
#ifndef Q_SIMULATION
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_SIMTA );
#else /* Q_SIMULATION */
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_USER );
#endif /* Q_SIMULATION */
#endif /*ultrix */


#ifndef Q_SIMULATION
    if (( pf = fdopen( simta_pidfd, "w" )) == NULL ) {
        syslog( LOG_ERR, "Syserror: can't fdopen simta_pidfd" );
        exit( 1 );
    }
    fprintf( pf, "%d\n", (int)getpid());
    if ( fflush( pf ) != 0 ) {
	syslog( LOG_ERR, "Syserror: fflush: %m" );
	exit( 1 );
    }
#endif /* Q_SIMULATION */

    /* catch SIGHUP */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = hup;
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGHUP, &sa, &osahup ) < 0 ) {
	syslog( LOG_ERR, "Syserror: sigaction: %m" );
	exit( 1 );
    }

    /* catch SIGCHLD */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = chld;
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGCHLD, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "Syserror: sigaction: %m" );
	exit( 1 );
    }

    /* catch SIGUSR1 */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = usr1;
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGUSR1, &sa, &osausr1 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: sigaction: %m" );
	exit( 1 );
    }

    syslog( LOG_NOTICE, "Restart: %s", version );

#ifndef Q_SIMULATION
    if (( simta_service_smtp )
#ifdef HAVE_LIBSSL
	    || ( simta_service_smtps )
#endif /* HAVE_LIBSSL */
	    || ( simta_service_submission )) {
	if ( simta_child_smtp_daemon() != 0 ) {
	    return( 1 );
	}
    }
#endif /* Q_SIMULATION */

    exit( simta_q_scheduler());
}


    int
simta_q_scheduler( void )
{
    struct proc_type		*p;
    struct timeval		tv_now;
    struct timeval		tv_disk;
    struct timeval		tv_sleep;
    struct host_q		*hq;
    int				launched;
    int				late;

    /* read the disk ASAP */
    if ( gettimeofday( &tv_disk, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: q_scheduler gettimeofday: %m" );
	return( 1 );
    }

    /* main daemon loop */
    for (;;) {
	if ( simsendmail_signal != 0 ) {
	    simsendmail_signal = 0;
	    if ( simta_q_runner_local < simta_q_runner_local_max ) {
		if ( simta_child_q_runner( NULL ) != 0 ) {
		    break;
		}
	    }
	}

	if ( child_signal != 0 ) {
	    if ( simta_waitpid()) {
		break;
	    }
	}

	if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_scheduler gettimeofday: %m" );
	    break;
	}

	/* check to see if we need to read the disk */
	if ( tv_now.tv_sec >= tv_disk.tv_sec ) {
	    /* read disk */
	    if ( q_read_dir( simta_dir_slow ) != 0 ) {
		break;
	    }

	    tv_disk.tv_sec += simta_disk_period;

	    if ( gettimeofday( &tv_now, NULL ) != 0 ) {
		syslog( LOG_ERR, "Syserror: q_scheduler gettimeofday: %m" );
		break;
	    }

	    if ( tv_disk.tv_sec < tv_now.tv_sec ) {
		/* waited too long */
		syslog( LOG_WARNING, "Queue Lag: disk read %d seconds",
			tv_now.tv_sec - tv_disk.tv_sec );
		tv_disk = tv_now;
	    }

	    /* run unexpanded queue if we have entries */
	    if (( simta_unexpanded_q != NULL ) &&
		    ( simta_unexpanded_q->hq_env_head != NULL )) {
		if ( simta_child_q_runner( simta_unexpanded_q ) != 0 ) {
		    return( 1 );
		}
	    }
	}

	/* check to see if we need to launch queue runners */
	for ( launched = 0; simta_deliver_q != NULL; launched++ ) {
	    if ( gettimeofday( &tv_now, NULL ) != 0 ) {
		syslog( LOG_ERR, "Syserror: q_scheduler gettimeofday: %m" );
		break;
	    }

	    /* don't launch queue runners if it's not the right time */
	    if ( tv_now.tv_sec < simta_deliver_q->hq_launch.tv_sec ) {
		break;
	    }

	    /* don't launch queue runners if the process limit has been met */
	    if (( simta_q_runner_slow_max > 0 ) &&
		    ( simta_q_runner_slow == simta_q_runner_slow_max )) {
		syslog( LOG_WARNING, "Queue Lag: Q runner process limit met" );
		break;
	    }

	    if (( late = tv_now.tv_sec - hq->hq_launch.tv_sec ) > 0 ) {
		syslog( LOG_WARNING, "Queue Lag: launching runner %d seconds "
			"late for queue %s", late, hq->hq_hostname );
	    }

	    hq = simta_deliver_q;
	    hq_deliver_pop( hq );
	    hq->hq_launch.tv_sec = tv_now.tv_sec;

	    if ( simta_child_q_runner( hq ) != 0 ) {
		return( 1 );
	    }

	    if (( simta_launch_limit > 0 ) &&
		    (( launched % simta_launch_limit ) == 0 )) {
		sleep( 1 );
		break;
	    }

	    /* re-queue  */
	    hq_deliver_push( hq );
	}

	/* compute sleep time */
	if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_scheduler gettimeofday: %m" );
	    break;
	}

	if (( simta_q_runner_slow_max > simta_q_runner_slow ) &&
		( simta_deliver_q != NULL ) &&
		( simta_deliver_q->hq_launch.tv_sec < tv_disk.tv_sec )) {
	    tv_sleep.tv_sec =
		    simta_deliver_q->hq_launch.tv_sec - tv_now.tv_sec;
	} else {
	    tv_sleep.tv_sec = tv_disk.tv_sec - tv_now.tv_sec;
	}

	if (( simsendmail_signal == 0 ) && ( child_signal == 0 ) &&
		( tv_sleep.tv_sec > 0 )) {
	    sleep( tv_sleep.tv_sec );
	}
    }

    /* Kill SMTP server */
    for ( p = proc_stab; p != NULL; p = p->p_next ) {
	if ( p->p_type == PROCESS_SMTP_SERVER ) {
	    if ( kill( p->p_id, SIGKILL ) != 0 ) {
		syslog( LOG_ERR, "Syserror: simta_q_scheduler kill %d: %m",
			p->p_id );
	    }
	    break;
	}
    }

    return( 1 );
}


    int
simta_waitpid( void )
{
    int			errors = 0;
    int			pid;
    char		*p_name;
    int			status;
    int			exitstatus;
    struct proc_type	**p_search;
    struct proc_type	*p_remove;

    child_signal = 0;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	p_search = &proc_stab;

	for ( p_search = &proc_stab; *p_search != NULL;
		p_search = &((*p_search)->p_next)) {
	    if ((*p_search)->p_id == pid ) {
		break;
	    }
	}

	if ( *p_search == NULL ) {
	    syslog( LOG_ERR, "Child %d: Syserror: unkown child process", pid );
	    return( 1 );
	}

	p_remove = *p_search;
	*p_search = p_remove->p_next;

	switch ( p_remove->p_type ) {
	case PROCESS_Q_LOCAL:
	    p_name = "q_runner local";
	    simta_q_runner_local--;
	    break;

	case PROCESS_Q_SLOW:
	    p_name = "q_runner slow";
	    simta_q_runner_slow--;
	    break;

	case PROCESS_RECEIVE_SMTP:
	    p_name = "receive smtp";
	    simta_receive_connections--;
	    break;

	case PROCESS_RECEIVE_SMTPS:
	    p_name = "receive smtps";
	    simta_receive_connections--;
	    break;

	case PROCESS_RECEIVE_SUBMISSION:
	    p_name = "receive submission";
	    simta_receive_connections--;
	    break;

	case PROCESS_SMTP_SERVER:
	    p_name = "smtp server";
	    errors++;
	    break;

	default:
	    p_name = "unknown process";
	    syslog( LOG_ERR, "Child %d: Syserror: unknown process: %d",
		    p_remove->p_id, p_remove->p_type );
	    errors++;
	    break;
	}

	free( p_remove );

	if ( WIFEXITED( status )) {
	    if (( exitstatus = WEXITSTATUS( status )) != EXIT_OK ) {
		syslog( LOG_ERR, "Child %d: exited %s: %d", pid, p_name,
			exitstatus );
		return( 1 );
	    }

	    syslog( LOG_NOTICE, "Child %d: exited %s: %d", pid,
		    p_name, exitstatus );

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child %d: died %s: %d", pid, p_name,
		    WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "Child %d: died %s", pid, p_name );
	    return( 1 );
	}
    }

    return( errors );
}


    int
simta_wait_for_child( int child_type )
{
    int				pid;
    int				status;
    char			*p_name;

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "Syserror: simta_wait_for_child fork: %m" );
	return( 1 );

    case 0 :
	switch ( child_type ) {
	case PROCESS_CLEANUP:
	    exit( q_cleanup());

	case PROCESS_Q_SLOW:
	    exit( q_runner_dir( simta_dir_slow ));

	default:
	    syslog( LOG_ERR,
		    "Syserror: wait_for_child: child_type out of range: %d",
		    child_type );
	    exit( 1 );
	}

    default :
	switch ( child_type ) {
	case PROCESS_CLEANUP:
	    if ( simta_filesystem_cleanup ) {
		p_name = "filesystem clean";
		syslog( LOG_NOTICE, "Child %d: start %s", pid, p_name );
	    } else {
		p_name = "filesystem check";
		syslog( LOG_NOTICE, "Child %d: start %s", pid, p_name );
	    }
	    break;

	case PROCESS_Q_SLOW:
	    p_name = "stand_alone q_runner";
	    if ( simta_queue_filter ) {
		syslog( LOG_NOTICE, "Child %d: start %s: %s", pid, p_name,
			simta_queue_filter );
	    } else {
		syslog( LOG_NOTICE, "Child %d: start %s", pid, p_name );
	    }
	    break;

	default:
	    syslog( LOG_ERR, "Child %d: Syserror start: type %d out of range",
		    pid, child_type );
	    return( 1 );
	}

	if ( waitpid( pid, &status, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Child %d: Syserror: q_cleanup waitpid: %m", pid );
	    return( 1  );
	}

	if ( WIFEXITED( status )) {
	    syslog( LOG_NOTICE, "Child %d: exited %s: %d", pid, p_name,
		    WEXITSTATUS( status ));
	    return( WEXITSTATUS( status ));

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child %d: died %s: signal %d", pid, p_name,
		    WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "Child %d: died %s", pid, p_name );
	    return( 1 );
	}
    }
}


    int
simta_sigaction_reset( void )
{
    /* reset USR1, CHLD and HUP */
    if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	return( 1 );
    }
    if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	return( 1 );
    }
    if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	return( 1 );
    }

    return( 0 );
}


    int
simta_child_smtp_daemon( void )
{
    fd_set			fdset;
    int				fd_max = 0;
    int				pid;

    switch ( pid = fork()) {
    case 0 :
	/* Fall through to smtp server loop below */
	break;

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_smtp_daemon fork: %m" );
	abort();

    default :
	syslog( LOG_NOTICE, "Child %d: start: smtp server", pid );
	close( simta_socket_smtp );
	if ( simta_service_submission ) {
	    close( simta_socket_submission );
	}
#ifdef HAVE_LIBSSL
	if ( simta_service_smtps ) {
	    close( simta_socket_smtps );
	}
#endif /* HAVE_LIBSSL */

	if ( simta_proc_add( PROCESS_SMTP_SERVER, pid ) != 0 ) {
	    return( 1 );
	}

	return( 0 );
    }

    simta_process_type = PROCESS_SMTP_SERVER;
    close( simta_pidfd );

    /* main smtp server loop */
    for (;;) {
	FD_ZERO( &fdset );

	FD_SET( simta_socket_smtp, &fdset );
	fd_max = simta_socket_smtp;

	if ( simta_service_submission ) {
	    FD_SET( simta_socket_submission, &fdset );
	    fd_max = MAX( fd_max, simta_socket_submission );
	}

#ifdef HAVE_LIBSSL
	if ( simta_service_smtps ) {
	    FD_SET( simta_socket_smtps, &fdset );
	    fd_max = MAX( fd_max, simta_socket_smtps );
	}
#endif /* HAVE_LIBSSL */

	/* check to see if any children need to be accounted for */
	if ( child_signal != 0 ) {
	    if ( simta_waitpid() != 0 ) {
		break;
	    }
	}

	if ( select( fd_max + 1, &fdset, NULL, NULL, NULL ) < 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR,
			"Syserror: simta_child_smtp_daemon select: %m" );
		break;
	    }
	}

	/* check to see if we have any incoming connections */
	if ( FD_ISSET( simta_socket_smtp, &fdset )) {
	    if ( simta_child_receive( PROCESS_RECEIVE_SMTP,
		    simta_socket_smtp ) != 0 ) {
		break;
	    }
	}

	if (( simta_service_submission ) &&
		( FD_ISSET( simta_socket_submission, &fdset ))) {
	    if ( simta_child_receive( PROCESS_RECEIVE_SUBMISSION,
		    simta_socket_submission ) != 0 ) {
		break;
	    }
	}

#ifdef HAVE_LIBSSL
	if (( simta_service_smtps ) &&
		( FD_ISSET( simta_socket_smtps, &fdset ))) {
	    if ( simta_child_receive( PROCESS_RECEIVE_SMTPS,
		    simta_socket_smtps ) != 0 ) {
		break;
	    }
	}
#endif /* HAVE_LIBSSL */
    }

    return( 1 );
}


    int
simta_child_receive( int process_type, int s )
{
    struct sockaddr_in	sin;
    int			pid;
    int			fd;
    int			sinlen;
    char		*type;

    sinlen = sizeof( struct sockaddr_in );

    if (( fd = accept( s,
	    (struct sockaddr*)&sin, &sinlen )) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_child_receive accept: %m" );
	/* accept() errors aren't fatal */
	return( 0 );
    }

    switch ( pid = fork()) {
    case 0 :
	simta_process_type = process_type;

	close( simta_socket_smtp );
	if ( simta_service_submission ) {
	    close( simta_socket_submission );
	}
#ifdef HAVE_LIBSSL
	if ( simta_service_smtps ) {
	    close( simta_socket_smtps );
	}
#endif /* HAVE_LIBSSL */
	simta_sigaction_reset();
	exit( smtp_receive( fd, &sin ));

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_receive fork: %m" );
	abort();

    default :
	/* here we are the server.  this is ok */
	close( fd );
	break;
    }

    /* Here we are the server */
    switch ( process_type ) {
    case PROCESS_RECEIVE_SMTP:
	type = "smtp";
	break;

    case PROCESS_RECEIVE_SMTPS:
	type = "smtps";
	break;

    case PROCESS_RECEIVE_SUBMISSION:
	type = "submission";
	break;

    default:
	syslog( LOG_ERR, "Syserror: simta_child_receive process_type "
		"out of range: %d", process_type );
	return( 1 );
    }

    simta_receive_connections++;
    syslog( LOG_NOTICE, "Child %d: start: receive %s: %s", pid, type,
	    inet_ntoa( sin.sin_addr ));

    if ( simta_proc_add( process_type, pid ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    int
simta_child_q_runner( struct host_q *hq )
{
    int			pid;

#ifdef Q_SIMULATION
    if (( hq->hq_hostname != NULL ) && ( *(hq->hq_hostname) != '\0' )) {
	syslog( LOG_NOTICE, "Simulation: q_runner slow %s", hq->hq_hostname );
    } else {
	syslog( LOG_NOTICE, "Simulation: q_runner slow NULL" );
    }
    return( 0 );
#endif /* Q_SIMULATION */

    switch ( pid = fork()) {
    case 0 :
	simta_sigaction_reset();
	close( simta_pidfd );

	if ( hq == NULL ) {
	    simta_process_type = PROCESS_Q_LOCAL;
	    exit( q_runner_dir( simta_dir_local ));

	} else if ( hq == simta_unexpanded_q ) {
	    simta_process_type = PROCESS_Q_SLOW;
	    simta_host_q = NULL;
	    exit( q_runner());

	} else {
	    simta_host_q = hq;
	    hq->hq_next = NULL;

	    if ( simta_unexpanded_q != NULL ) {
		simta_unexpanded_q->hq_env_head = NULL;
		simta_unexpanded_q->hq_next = NULL;
		simta_unexpanded_q->hq_entries = 0;
	    }

	    exit( q_runner());
	}

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_q_runner fork: %m" );
	abort();

    default :
	/* here we are the server.  this is ok */
	break;
    }

    if ( hq == NULL ) {
	simta_q_runner_local++;
	syslog( LOG_NOTICE, "Child %d: start: q_runner local", pid );

	if ( simta_proc_add( PROCESS_Q_LOCAL, pid ) != 0 ) {
	    return( 1 );
	}

    } else {
	if (( hq->hq_hostname != NULL ) && ( *(hq->hq_hostname) != '\0' )) {
	    simta_q_runner_slow++;
	    syslog( LOG_NOTICE, "Child %d: start: q_runner slow %s", pid,
		    hq->hq_hostname );
	} else {
	    simta_q_runner_slow++;
	    syslog( LOG_NOTICE, "Child %d: start: q_runner slow NULL", pid );
	}

	if ( simta_proc_add( PROCESS_Q_SLOW, pid ) != 0 ) {
	    return( 1 );
	}
    }

    return( 0 );
}


    int
simta_proc_add( int process_type, int pid )
{
    struct proc_type	*p;

    if (( p = (struct proc_type*)malloc(
	    sizeof( struct proc_type ))) == NULL ) {
	syslog( LOG_ERR, "Syserror: simta_proc_add malloc: %m" );
	return( 1 );
    }
    memset( p, 0, sizeof( struct proc_type ));

    p->p_id = pid;
    p->p_type = process_type;
    p->p_next = proc_stab;
    proc_stab = p;

    return( 0 );
}
