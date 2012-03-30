/*
 * Copyright (c) 1999 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
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


struct connection_info		*cinfo_stab = NULL;
struct proc_type		*proc_stab = NULL;
int				simta_pidfd;
int				simsendmail_signal = 0;
int				child_signal = 0;
struct sigaction		sa, osahup, osachld, osausr1;
char				*version = VERSION;
SSL_CTX				*ctx = NULL;
struct simta_socket		*simta_listen_sockets = NULL;


void		usr1( int );
void		hup ( int );
void		chld( int );
int		main( int, char *av[] );
int		simta_wait_for_child( int );
int		simta_waitpid( void );
int		simta_sigaction_reset( void );
int		simta_q_scheduler( void );
int		simta_child_q_runner( struct host_q* );
int		simta_child_receive( struct simta_socket* );
int		simta_child_queue_scheduler( void );
int		simta_smtp_server( void );
int		set_rcvbuf( int );
struct simta_socket	*simta_listen( char*, int, int );
struct proc_type	*simta_proc_add( int, int );
int		simta_proc_q_runner( int, struct host_q* );


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
set_rcvbuf( int s )
{
    socklen_t			len;

    if ( simta_smtp_rcvbuf_max == 0 ) {
	len = sizeof( simta_smtp_rcvbuf_max );
	if ( getsockopt( s, SOL_SOCKET, SO_RCVBUF, &simta_smtp_rcvbuf_max,
		&len ) < 0 ) {
	    syslog( LOG_ERR, "set_rcvbuf getsockopt: %m" );
	    return( 1 );
	}
    }

    if ( setsockopt( s, SOL_SOCKET, SO_RCVBUF,
	    (void*)&simta_smtp_rcvbuf_min, sizeof( int )) < 0 ) {
	syslog( LOG_ERR, "set_rcvbuf setsockopt: %m" );
	return( 1 );
    }

    return( 0 );
}


     struct simta_socket *
simta_listen( char *service, int port_default, int port_override )
{
    int				reuseaddr = 1;
    struct sockaddr_in		sin;
    struct servent		*se;
    struct simta_socket		*ss;

    if (( ss = (struct simta_socket*)malloc(
	    sizeof( struct simta_socket ))) == NULL ) {
	syslog( LOG_ERR, "Syserror: simta_listen malloc: %m" );
	return( NULL );
    }
    memset( ss, 0, sizeof( struct simta_socket ));

    ss->ss_service = service;
    ss->ss_next = simta_listen_sockets;
    simta_listen_sockets = ss;

    if (( se = getservbyname( ss->ss_service, "tcp" )) == NULL ) {
	ss->ss_port = htons( port_default );
	syslog( LOG_INFO, "simta_listen getservbyname can't find %s: "
		"defaulting to port %d", ss->ss_service, ntohs( ss->ss_port ));
	fprintf( stderr, "simta_listen getservbyname can't find %s: "
		"defaulting to port %d\n", ss->ss_service,
		ntohs( ss->ss_port ));
    } else {
	ss->ss_port = se->s_port;
	syslog( LOG_DEBUG, "simta_listen getservbyname: %s port %d",
		ss->ss_service, ntohs( ss->ss_port ));
    }

    if (( ss->ss_socket = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "simta_listen socket %s: %m", ss->ss_service );
	perror( "socket" );
	return( NULL );
    }

    if ( setsockopt( ss->ss_socket, SOL_SOCKET, SO_REUSEADDR,
	    (void*)&reuseaddr, sizeof( int )) < 0 ) {
	syslog( LOG_ERR, "simta_listen setsockopt %s: %m", ss->ss_service );
	perror( "setsockopt" );
	return( NULL );
    }

    if ( simta_smtp_rcvbuf_min != 0 ) {
	if ( set_rcvbuf( ss->ss_socket ) != 0 ) {
	    return( NULL );
	}
    }

    memset( &sin, 0, sizeof( struct sockaddr_in ));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = ss->ss_port;

    if ( bind( ss->ss_socket, (struct sockaddr *)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "simta_listen bind %s: %m", ss->ss_service );
	perror( "bind" );
	return( NULL );
    }

    if ( listen( ss->ss_socket, simta_listen_backlog ) < 0 ) {
	syslog( LOG_ERR, "simta_listen listen %s: %m", ss->ss_service );
	perror( "listen" );
	return( NULL );
    }

    return( ss );
}


    int
main( int ac, char **av )
{
    int			c, err = 0;
    int			dontrun = 0;
    int			q_run = 0;
    char		*prog;
    char		*spooldir = _PATH_SPOOL;
    extern int		optind;
    extern char		*optarg;
    struct simta_socket	*ss;
#ifdef Q_SIMULATION
    char		*simta_uname = "simta";
#else /* Q_SIMULATION */
    char		*simta_uname = "simta";
#endif /* Q_SIMULATION */
    struct passwd	*simta_pw;
    char		*config_fname = SIMTA_FILE_CONFIG;
    char		*config_base_dir = SIMTA_BASE_DIR;
#ifdef HAVE_LIBSASL
    int			rc;
#endif /* HAVE_LIBSASL */

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

    while (( c = getopt( ac, av, " ab:cCdD:f:i:Il:m:M:p:P:qQ:rRs:SVw:x:y:z:" ))
	    != -1 ) {
	switch ( c ) {
	case ' ' :		/* Disable strict SMTP syntax checking */
	    simta_strict_smtp_syntax = 0;
	    break;

	case 'a' :		/* Automatically config with DNS */
	    simta_dns_config = 0;
	    break;

	case 'b' :		/*X listen backlog */
	    simta_listen_backlog = atoi( optarg );
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

	case 'l' :
	    simta_launch_limit = atoi( optarg );
	    break;

	case 'm' :		/* Max connections */
	    if (( simta_global_connections_max = atoi( optarg )) < 0 ) {
		err++;
		fprintf( stderr, "%d: invalid max receive connections\n",
			simta_global_connections_max );
	    }
	    break;

	case 'p' :		/* TCP port */
	    simta_smtp_port_defined = 1;
	    if ( atoi( optarg ) < 0 ) {
                fprintf( stderr, "simta -p [ port ] must be 0 or greater\n" );
		exit( 1 );
	    }
	    simta_smtp_port = htons( atoi( optarg ));
	    break;

	case 'P' :		/* ca dir */
	    simta_dir_ca = optarg;
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
	    simta_use_randfile = 1;
	    break;

	case 'R' :
	    simta_smtp_default_mode = SMTP_MODE_GLOBAL_RELAY;
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
            simta_file_ca = optarg;
            break;

        case 'y' :              /* cert file */
            simta_file_cert = optarg;
            break;

        case 'z' :              /* private key */
            simta_file_private_key = optarg;
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
	fprintf( stderr, " [ -l process_launch_limit ]" );
	fprintf( stderr, " [ -m max-connections ] [ -p port ]" );
	fprintf( stderr, " [ -P ca-directory ] [ -Q queue]" );
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

    if ( simta_gettimeofday( NULL ) != 0 ) {
        exit( 1 );
    }

    simta_openlog( 0 );

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
	if ( tls_server_setup( simta_use_randfile, simta_service_smtps,
		simta_file_ca, simta_dir_ca, simta_file_cert,
		simta_file_private_key ) != 0 ) {
	    exit( 1 );
	}
	simta_tls = 1;
	simta_smtp_extension++;
    }

#ifdef HAVE_LIBSASL
    if ( simta_sasl ) {
	if (( rc = sasl_server_init( callbacks, "simta" )) != SASL_OK ) {
	    syslog( LOG_ERR, "sasl_server_init: %s",
		    sasl_errstring( rc, NULL, NULL ));
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
    if (( q_run == 0 ) && ( simta_filesystem_cleanup == 0 ) &&
	    ( simta_smtp_default_mode != SMTP_MODE_OFF )) {
	if (( simta_smtp_port_defined == 0 ) || ( simta_smtp_port != 0 )) {
	    if ( simta_listen( "smtp", 25, simta_smtp_port ) == NULL ) {
		exit( 1 );
	    }
	}

#ifdef HAVE_LIBSSL
	if ( simta_service_smtps ) {
	    if (( ss = simta_listen( "smtps", 465, 0 )) == NULL ) {
		exit( 1 );
	    }
	    ss->ss_flags |= SIMTA_SOCKET_TLS;
	}
#endif /* HAVE_LIBSSL */

	if ( simta_service_submission ) {
	    if ( simta_listen( "submission", 587, 0 ) == NULL ) {
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
	if ( flock( simta_pidfd, LOCK_EX | LOCK_NB ) != 0 ) {
	    if ( errno == EAGAIN ) {
		/* file locked by a diferent process */
		fprintf( stderr, "flock %s: daemon already running\n",
			SIMTA_FILE_PID );
		exit( 1 );

	    } else {
		fprintf( stderr, "flock %s:" , SIMTA_FILE_PID );
		perror( NULL );
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
		/* keep sockets & simta_pidfd open */
		for ( ss = simta_listen_sockets; ss != NULL;
			ss = ss->ss_next ) {
		    if ( i == ss->ss_socket ) {
			break;
		    }
		}
		if ( ss != NULL ) {
		    continue;
		}
		if ( i == simta_pidfd ) {
		    continue;
		}
		close( i );
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
    if ( simta_gettimeofday( NULL ) != 0 ) {
        exit( 1 );
    }

    simta_openlog( 0 );

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
    if ( simta_listen_sockets != NULL ) {
	if ( simta_child_queue_scheduler() != 0 ) {
	    return( 1 );
	}
	exit( simta_smtp_server());
    }
#endif /* Q_SIMULATION */

    exit( simta_q_scheduler());
}


    int
simta_child_queue_scheduler( void )
{
    int				pid;
    struct simta_socket		*ss;

    if ( simta_gettimeofday( NULL ) != 0 ) {
        return( 1 );
    }

    switch ( pid = fork()) {
    case 0 :
	/* Fall through */
	simta_openlog( 1 );
	break;

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_queue_scheduler fork: %m" );
	abort();

    default :
	if ( simta_proc_add( PROCESS_Q_SCHEDULER, pid ) == NULL ) {
	    return( 1 );
	}
	syslog( LOG_NOTICE, "Child Start %d.%ld: master queue server", pid,
		simta_tv_now.tv_sec );
	return( 0 );
    }

    for ( ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next ) {
	close( ss->ss_socket );
    }

    return( simta_q_scheduler());
}


    /* this is the main queue scheduling routine */

    int
simta_q_scheduler( void )
{
    struct timespec		req;
    struct timespec		rem;
    struct timeval		tv_now;
    struct timeval		tv_disk;
    struct timeval		tv_sleep;
    struct host_q		*hq;
    int				lag;
    u_long			disk_wait;
    u_long			q_wait;
    u_long			waited;
    int				launched;
    u_long			launch_this_cycle;
    FILE			*pf;

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

    simta_process_type = PROCESS_Q_SCHEDULER;

    /* read the disk ASAP */
    if ( simta_gettimeofday( &tv_disk ) != 0 ) {
        return( 1 );
    }

    srandom((unsigned int)tv_disk.tv_usec );

    /* main daemon loop */
    for (;;) {
	if ( simsendmail_signal != 0 ) {
	    if ( simta_q_runner_local < simta_q_runner_local_max ) {
		simsendmail_signal = 0;

		if ( simta_child_q_runner( NULL ) != 0 ) {
		    return( 1 );
		}
	    } else {
		syslog( LOG_WARNING, "Daemon Delay: MAX_Q_RUNNERS_LOCAL met: "
			"local queue runner launch delayed" );
	    }
	}

	if ( child_signal != 0 ) {
	    if ( simta_waitpid()) {
		return( 1 );
	    }
	}

	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    return( 1 );
	}

	/* attempt to read the disk if it is scheduled */
	if ( tv_now.tv_sec >= tv_disk.tv_sec ) {
	    if (( simta_deliver_q != NULL ) && ( tv_now.tv_sec >=
		    simta_deliver_q->hq_next_launch.tv_sec )) {
		/* don't read the disk untill the queue is caught up */
		syslog( LOG_DEBUG,
			"Daemon Delay: Disk read currently delayed %d",
			(int)(tv_now.tv_sec - tv_disk.tv_sec));

	    } else {
		syslog( LOG_DEBUG, "Daemon: disk read start" );
		/* read disk */
		q_read_dir( simta_dir_slow );

		queue_log_metrics( simta_deliver_q );

		if ( simta_gettimeofday( &tv_now ) != 0 ) {
		    return( 1 );
		}

		tv_disk.tv_sec = tv_now.tv_sec + simta_min_work_time;
		launch_this_cycle = 0;

		/* run unexpanded queue if we have entries */
		if (( simta_unexpanded_q != NULL ) &&
			( simta_unexpanded_q->hq_env_head != NULL )) {
		    if ( simta_child_q_runner( simta_unexpanded_q ) != 0 ) {
			return( 1 );
		    }
		}
	    }
	}

	/* check to see if we need to launch queue runners */
	for ( launched = 1; simta_deliver_q != NULL; launched++ ) {
	    if ( simta_gettimeofday( &tv_now ) != 0 ) {
		return( 1 );
	    }

	    /* don't launch queue runners if it's not the right time */
	    if ( tv_now.tv_sec < simta_deliver_q->hq_next_launch.tv_sec ) {
		break;
	    }

	    /* don't launch queue runners if the process limit has been met */
	    if (( simta_q_runner_slow_max > 0 ) &&
		    ( simta_q_runner_slow == simta_q_runner_slow_max )) {
		syslog( LOG_WARNING, "Daemon Delay: MAX_Q_RUNNERS_SLOW met: "
			"slow queue runner launch delayed" );
		break;
	    }

	    hq = simta_deliver_q;
	    hq_deliver_pop( hq );
	    hq->hq_launches++;
	    launch_this_cycle++;
	    lag = tv_now.tv_sec - hq->hq_next_launch.tv_sec;

	    if ( hq->hq_last_launch.tv_sec != 0 ) {
		waited = tv_now.tv_sec - hq->hq_last_launch.tv_sec;
	    } else {
		waited = 0;
	    }

	    if (( hq->hq_wait_longest.tv_sec == 0 ) ||
		    ( hq->hq_wait_longest.tv_sec < waited )) {
		hq->hq_wait_longest.tv_sec = waited;
	    }

	    if (( hq->hq_wait_shortest.tv_sec == 0 ) ||
		    ( hq->hq_wait_shortest.tv_sec > waited )) {
		hq->hq_wait_shortest.tv_sec = waited;
	    }

	    syslog( LOG_INFO, "Queue %s: launch %d: "
		    "wait %lu lag %d last %lu shortest %lu longest %lu "
		    "total messages %d",
		    hq->hq_hostname, hq->hq_launches, waited, lag,
		    hq->hq_wait_last.tv_sec, hq->hq_wait_shortest.tv_sec,
		    hq->hq_wait_longest.tv_sec, hq->hq_entries );

	    if ( simta_child_q_runner( hq ) != 0 ) {
		return( 1 );
	    }

	    hq->hq_wait_last.tv_sec = waited;
	    hq->hq_last_launch.tv_sec = tv_now.tv_sec;

	    /* zero out the next_launch (we just did it) and reschedule */
	    hq->hq_next_launch.tv_sec = 0;
	    hq_deliver_push( hq, &tv_now );

	    if (( simta_launch_limit > 0 ) &&
		    (( launched % simta_launch_limit ) == 0 )) {
		syslog( LOG_WARNING, "Daemon Delay: MAX_Q_RUNNERS_LAUNCH met: "
			"sleeping for 1 second" );
		req.tv_sec = 1;
		req.tv_nsec = 0;

		while ( nanosleep( &req, &rem ) != 0 ) {
		    if ( errno == EINTR ) {
			req.tv_sec = rem.tv_sec;
			req.tv_nsec = rem.tv_nsec;
		    } else {
			syslog( LOG_ERR,
				"Syserror: q_scheduler nanosleep: %m" );
			return( 1 );
		    }
		}

		break;
	    }
	}

	/* compute sleep time */
	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    return( 1 );
	}

	if ( simta_deliver_q != NULL ) {
	    q_wait = simta_deliver_q->hq_next_launch.tv_sec - tv_now.tv_sec;
	    if ( q_wait < 0 ) {
		q_wait = 0;
	    }

	    syslog( LOG_DEBUG, "Daemon: next queue %s %d",
		    simta_deliver_q->hq_hostname, (int)q_wait );
	} else {
	    syslog( LOG_DEBUG, "Daemon: no deliver queues" );
	}

	if ( tv_now.tv_sec < tv_disk.tv_sec ) {
	    /* disk read is in the future */
	    disk_wait = tv_disk.tv_sec - tv_now.tv_sec;
	} else {
	    disk_wait = 0;
	}
	syslog( LOG_DEBUG, "Daemon: next disk read %d", (int)disk_wait );

	if ( simta_deliver_q == NULL ) {
	    /* no queue to deliver, schedule the disk read */
	    tv_sleep.tv_sec = disk_wait;

	} else if ( q_wait > 0 ) {
	    /* next queue delivery is in the future */
	    /* schedule whatever is sooner, disk read or the queue launch */
	    if ( disk_wait < q_wait ) {
		tv_sleep.tv_sec = disk_wait;
	    } else {
		tv_sleep.tv_sec = q_wait;
	    }

	} else if (( simta_q_runner_slow_max == 0 ) ||
		( simta_q_runner_slow < simta_q_runner_slow_max )) {
	    /* queues are underwater and either there is no process limit,
	     * or it has not yet been met.
	     */
	    tv_sleep.tv_sec = 0;

	} else {
	    /* queues are underwater and the process limit has been met */
	    tv_sleep.tv_sec = tv_now.tv_sec + 60;
	    syslog( LOG_NOTICE, "Daemon Delay: Queues are not caught up and "
		    "MAX_Q_RUNNERS_SLOW has been met: Delaying 60 seconds" );
	}

	if (( simsendmail_signal == 0 ) && ( child_signal == 0 ) &&
		( tv_sleep.tv_sec > 0 )) {
	    syslog( LOG_DEBUG, "Daemon: sleeping for %d",
		    (int)tv_sleep.tv_sec );
	    sleep((unsigned int)tv_sleep.tv_sec );
	}
    }

    return( 1 );
}


    int
simta_waitpid( void )
{
    int			errors = 0;
    int			ll;
    int			pid;
    int			activity;
    int			status;
    int			exitstatus;
    int			seconds;
    struct proc_type	**p_search;
    struct proc_type	*p_remove;
    struct timeval	tv_now;
    struct host_q	*hq;

    child_signal = 0;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return( 1 );
    }

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	p_search = &proc_stab;

	for ( p_search = &proc_stab; *p_search != NULL;
		p_search = &((*p_search)->p_next)) {
	    if ((*p_search)->p_id == pid ) {
		break;
	    }
	}

	if ( *p_search == NULL ) {
	    syslog( LOG_ERR, "Child Error %d.%ld: unkown child process", pid,
		    simta_tv_now.tv_sec );
	    errors++;
	    continue;
	}

	p_remove = *p_search;
	*p_search = p_remove->p_next;

	if ( p_remove->p_limit != NULL ) {
	    (*p_remove->p_limit)--;
	}

	seconds = tv_now.tv_sec - p_remove->p_tv.tv_sec;
	activity = 0;
	ll = LOG_INFO;

	if ( WIFEXITED( status )) {
	    if (( exitstatus = WEXITSTATUS( status )) != EXIT_OK ) {
		if (( p_remove->p_type == PROCESS_Q_SLOW ) &&
			( exitstatus == SIMTA_EXIT_OK_LEAKY )) {
		    activity = 1;
		    /* remote host activity, requeue to encourage it */
		    if (( hq = host_q_lookup( p_remove->p_host )) != NULL ) {
			hq_deliver_pop( hq );
			hq->hq_last_leaky.tv_sec = tv_now.tv_sec;
			hq_deliver_push( hq, &tv_now );
		    }

		} else {
		    errors++;
		    ll = LOG_ERR;
		}
	    }

	    switch ( p_remove->p_type ) {
	    case PROCESS_Q_LOCAL:
		syslog( ll, "Child Exited %d.%ld: %d (%d Local %d)",
			pid, p_remove->p_tv.tv_sec, exitstatus, seconds,
			*p_remove->p_limit );
		break;

	    case PROCESS_Q_SLOW:
		syslog( ll, "Child Exited %d.%ld: %d (%d Slow %d %s %s)",
			pid, p_remove->p_tv.tv_sec, exitstatus, seconds,
			*p_remove->p_limit,
			p_remove->p_host ? p_remove->p_host : "Unexpanded",
			activity ? "Activity" : "Unresponsive" );
		break;

	    case PROCESS_RECEIVE:
		p_remove->p_ss->ss_count--;
		p_remove->p_cinfo->c_proc_total--;
		syslog( ll, "Child Exited %d.%ld: %d (%d Receive %d %s %d %s)",
			pid, p_remove->p_tv.tv_sec, exitstatus, seconds,
			*p_remove->p_limit, p_remove->p_ss->ss_service,
			p_remove->p_ss->ss_count, p_remove->p_host );
		break;

	    case PROCESS_Q_SCHEDULER:
		errors++;
		syslog( LOG_ERR, "Child Exited %d.%ld: %d (%d Scheduler)",
			pid, p_remove->p_tv.tv_sec, exitstatus, seconds );
		break;

	    default:
		errors++;
		syslog( LOG_ERR, "Child Exited %d.%ld: %d (%d Unknown)",
			pid, p_remove->p_tv.tv_sec, exitstatus, seconds );
		break;
	    }

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child Died %d.%ld: %d (%d seconds)", pid,
		    p_remove->p_tv.tv_sec, WTERMSIG( status ), seconds );
	    errors++;

	} else {
	    syslog( LOG_ERR, "Child Died %d.%ld: (%d seconds)", pid,
		    p_remove->p_tv.tv_sec, seconds );
	    errors++;
	}

	if ( p_remove->p_host ) {
	    free( p_remove->p_host );
	}
	free( p_remove );
    }

    return( errors );
}


    int
simta_wait_for_child( int child_type )
{
    int				pid;
    int				status;
    char			*p_name;

    if ( simta_gettimeofday( NULL ) != 0 ) {
	return( 1 );
    }

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "Syserror: simta_wait_for_child fork: %m" );
	return( 1 );

    case 0 :
	simta_openlog( 1 );
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
		syslog( LOG_NOTICE, "Child Start %d.%ld: %s", pid,
			simta_tv_now.tv_sec, p_name );
	    } else {
		p_name = "filesystem check";
		syslog( LOG_NOTICE, "Child Start %d.%ld: %s", pid,
			simta_tv_now.tv_sec, p_name );
	    }
	    break;

	case PROCESS_Q_SLOW:
	    p_name = "stand_alone q_runner";
	    if ( simta_queue_filter ) {
		syslog( LOG_NOTICE, "Child Start %d.%ld: %s: %s", pid,
			simta_tv_now.tv_sec, p_name, simta_queue_filter );
	    } else {
		syslog( LOG_NOTICE, "Child Start %d.%ld: %s", pid,
			simta_tv_now.tv_sec, p_name );
	    }
	    break;

	default:
	    syslog( LOG_ERR, "Child Error %d.%ld: start type %d out of range",
		    pid, simta_tv_now.tv_sec, child_type );
	    return( 1 );
	}

	if ( waitpid( pid, &status, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Child Error %d.%ld: wait_for_child waitpid: %m",
		    pid, simta_tv_now.tv_sec );
	    return( 1  );
	}

	if ( WIFEXITED( status )) {
	    syslog( LOG_NOTICE, "Child Exited %d.%ld: %s: %d", pid,
		    simta_tv_now.tv_sec, p_name, WEXITSTATUS( status ));
	    return( WEXITSTATUS( status ));

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child Died %d.%ld: %s: signal %d", pid,
		    simta_tv_now.tv_sec, p_name, WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "Child Died %d.%ld: %s", pid, simta_tv_now.tv_sec,
		    p_name );
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
simta_smtp_server( void )
{
    int				fd_max;
    fd_set			fdset;
    struct proc_type		*p;
    struct simta_socket		*ss;
    struct connection_info	**c;
    struct connection_info	*remove;
    struct timeval		tv_now;

    simta_process_type = PROCESS_SMTP_SERVER;
    close( simta_pidfd );

    /* main smtp server loop */
    for (;;) {
	FD_ZERO( &fdset );
	fd_max = 0;

	for ( ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next ) {
	    FD_SET( ss->ss_socket, &fdset );
	    fd_max = MAX( fd_max, ss->ss_socket );
	}

	if ( select( fd_max + 1, &fdset, NULL, NULL, NULL ) < 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR,
			"Syserror: simta_child_smtp_daemon select: %m" );
		goto error;
	    }
	}

	/* check to see if any children need to be accounted for */
	if ( child_signal != 0 ) {
	    if ( simta_waitpid() != 0 ) {
		goto error;
	    }
	    continue;
	}

	/* clean up the connection_info table */
	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    return( 1 );
	}

	for ( c = &cinfo_stab; *c != NULL; ) {
	    if (((*c)->c_proc_total == 0 ) && ((*c)->c_tv.tv_sec + 
		    simta_local_throttle_sec < tv_now.tv_sec )) {
		remove = *c;
		*c = (*c)->c_next;
		free( remove );

	    } else {
		c = &((*c)->c_next);
	    }
	}

	for ( ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next ) {
	    if ( FD_ISSET( ss->ss_socket, &fdset )) {
		if ( simta_child_receive( ss ) != 0 ) {
		    goto error;
		}
	    }
	}
    }

error:
    /* Kill queue scheduler */
    for ( p = proc_stab; p != NULL; p = p->p_next ) {
	if ( p->p_type == PROCESS_Q_SCHEDULER ) {
	    if ( kill( p->p_id, SIGKILL ) != 0 ) {
		syslog( LOG_ERR, "Syserror: simta_smtp_server kill %d.%ld: %m",
			p->p_id, p->p_tv.tv_sec );
	    }
	    break;
	}
    }

    return( 1 );
}


    int
simta_child_receive( struct simta_socket *ss )
{
    struct proc_type	*p;
    struct simta_socket		*s;
    struct connection_info	*cinfo = NULL;
    struct sockaddr_in		sin;
    int				pid;
    int				fd;
    socklen_t			sinlen;

    sinlen = sizeof( struct sockaddr_in );

    if (( fd = accept( ss->ss_socket, (struct sockaddr*)&sin, &sinlen )) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_child_receive accept: %m" );
	/* accept() errors aren't fatal */
	return( 0 );
    }

    /* Look up / Create IP related connection data entry */
    for ( cinfo = cinfo_stab; cinfo != NULL; cinfo = cinfo->c_next ) {
	if ( memcmp( &(cinfo->c_sin.sin_addr), &sin.sin_addr,
		sizeof( struct in_addr )) == 0 ) {
	    break;
	}
    }

    if ( cinfo == NULL ) {
	if (( cinfo = (struct connection_info*)malloc(
		sizeof( struct connection_info ))) == NULL ) {
	    syslog( LOG_ERR, "Syserror: simta_child_receive malloc: %m" );
	    return( 1 );
	}
	memset( cinfo, 0, sizeof( struct connection_info ));
	memcpy( &(cinfo->c_sin), &sin, sizeof( struct sockaddr ));

	cinfo->c_next = cinfo_stab;
	cinfo_stab = cinfo;
    }

    cinfo->c_proc_total++;
    simta_global_connections++;

    if ( simta_gettimeofday( NULL ) != 0 ) {
	return( 1 );
    }

    if ( simta_local_throttle_max > 0 ) {
	if (( cinfo->c_tv.tv_sec + simta_local_throttle_sec
		    < simta_tv_now.tv_sec ) ||
		(( cinfo->c_tv.tv_sec + simta_local_throttle_sec
		    == simta_tv_now.tv_sec ) &&
		( cinfo->c_tv.tv_usec <= simta_tv_now.tv_usec ))) {
	    cinfo->c_tv = simta_tv_now;
	    cinfo->c_proc_throttle = 1;
	} else {
	    cinfo->c_proc_throttle++;
	}
    }

    if ( simta_global_throttle_max > 0 ) {
	if (( simta_global_throttle_tv.tv_sec + simta_global_throttle_sec
		    < simta_tv_now.tv_sec ) ||
		(( simta_global_throttle_tv.tv_sec +
		    simta_global_throttle_sec == simta_tv_now.tv_sec ) &&
		( simta_global_throttle_tv.tv_usec <= simta_tv_now.tv_usec ))) {
	    simta_global_throttle_tv = simta_tv_now;
	    simta_global_throttle_connections = 1;
	} else {
	    simta_global_throttle_connections++;
	}
    }

    syslog( LOG_DEBUG, "Connect.stat %s: global_total %d "
	    "global_throttle %d local_total %d local_throttle %d",
	    inet_ntoa( cinfo->c_sin.sin_addr ), simta_global_connections,
	    simta_global_throttle_connections, cinfo->c_proc_total,
	    cinfo->c_proc_throttle );

    switch ( pid = fork()) {
    case 0:
	simta_openlog( 1 );
	simta_process_type = PROCESS_RECEIVE;
	for ( s = simta_listen_sockets; s != NULL; s = s->ss_next ) {
	    if ( close( s->ss_socket ) != 0 ) {
		syslog( LOG_ERR, "Syserror: simta_child_receive close: %m" );
	    }
	}
	simta_sigaction_reset();
	exit( smtp_receive( fd, cinfo, ss ));

    case -1:
	syslog( LOG_ERR, "Syserror: simta_child_receive fork: %m" );
	abort();

    default:
	/* Here we are the server */
	break;
    }

    if ( close( fd ) != 0 ) {
	syslog( LOG_ERR, "Syserror: simta_child_receive close: %m" );
	return( 1 );
    }

    if (( p = simta_proc_add( PROCESS_RECEIVE, pid )) == NULL ) {
	return( 1 );
    }

    p->p_limit = &simta_global_connections;
    p->p_ss = ss;
    p->p_ss->ss_count++;
    p->p_cinfo = cinfo;

    if (( p->p_host = strdup( inet_ntoa( cinfo->c_sin.sin_addr ))) == NULL ) {
	syslog( LOG_ERR, "Syserror: simta_child_receive strdup: %m" );
	free( p );
	return( 1 );
    }

    syslog( LOG_NOTICE, "Child Start %d.%ld: Receive %d %s %d: %s", p->p_id,
	    p->p_tv.tv_sec, *p->p_limit, p->p_ss->ss_service,
	    p->p_ss->ss_count, p->p_host );

    return( 0 );
}


    int
simta_child_q_runner( struct host_q *hq )
{
    int			pid;

#ifdef Q_SIMULATION
    assert( hq != NULL );
    return( 0 );
#endif /* Q_SIMULATION */

    if ( simta_gettimeofday( NULL ) != 0 ) {
	return( 1 );
    }

    switch ( pid = fork()) {
    case 0 :
	simta_openlog( 1 );
	simta_sigaction_reset();
	close( simta_pidfd );
	simta_host_q = NULL;

	if (( hq != NULL ) && ( hq == simta_unexpanded_q )) {
	    simta_process_type = PROCESS_Q_SLOW;
	    exit( q_runner());
	}

	if ( simta_unexpanded_q != NULL ) {
	    simta_unexpanded_q->hq_env_head = NULL;
	    simta_unexpanded_q->hq_next = NULL;
	    simta_unexpanded_q->hq_entries = 0;
	}

	if ( hq == NULL ) {
	    simta_process_type = PROCESS_Q_LOCAL;
	    exit( q_runner_dir( simta_dir_local ));

	} else {
	    simta_host_q = hq;
	    hq->hq_next = NULL;
	    hq->hq_primary = 1;
	    simta_process_type = PROCESS_Q_SLOW;
	    exit( q_runner());
	}

	/* if you get here there is an error */
	panic( "unreachable code" );

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_q_runner fork: %m" );
	abort();

    default :
	/* here we are the server.  this is ok */
	break;
    }

    if ( simta_proc_q_runner( pid, hq ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    int
simta_proc_q_runner( int pid, struct host_q *hq )
{
    struct proc_type	*p;
    int			type;

    if ( hq == NULL ) {
	type = PROCESS_Q_LOCAL;
    } else {
	type = PROCESS_Q_SLOW;
    }

    if (( p = simta_proc_add( type, pid )) == NULL ) {
	return( 1 );
    }

    if ( hq == NULL ) {
	p->p_limit = &simta_q_runner_local;
	(*p->p_limit)++;

	syslog( LOG_NOTICE, "Child Start %d.%ld: Local %d", pid, p->p_tv.tv_sec,
		*p->p_limit );

    } else {
	p->p_limit = &simta_q_runner_slow;
	(*p->p_limit)++;

	if ( hq->hq_hostname == NULL ) {
	    syslog( LOG_NOTICE, "Child Start %d.%ld: Unexpanded %d",
		    pid, p->p_tv.tv_sec, *p->p_limit );

	} else {
	    if (( p->p_host = strdup( hq->hq_hostname )) == NULL ) {
		syslog( LOG_ERR, "Syserror: simta_proc_add strdup: %m" );
		free( p );
		return( 1 );
	    }

	    syslog( LOG_NOTICE, "Child Start %d.%ld: Deliver %d %s", pid,
		    p->p_tv.tv_sec, *p->p_limit, p->p_host );
	}
    }

    return( 0 );
}


    struct proc_type *
simta_proc_add( int process_type, int pid )
{
    struct proc_type	*p;

    if (( p = (struct proc_type*)malloc(
	    sizeof( struct proc_type ))) == NULL ) {
	syslog( LOG_ERR, "Syserror: simta_proc_add malloc: %m" );
	return( NULL );
    }
    memset( p, 0, sizeof( struct proc_type ));

    p->p_tv.tv_sec = simta_tv_now.tv_sec;
    p->p_id = pid;
    p->p_type = process_type;
    p->p_next = proc_stab;
    proc_stab = p;

    return( p );
}
