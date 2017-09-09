/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif /* __linux__ */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <snet.h>

#include "argcargv.h"
#include "envelope.h"
#include "ll.h"
#include "queue.h"
#include "simta.h"

#ifdef HAVE_LIBSSL
#include "tls.h"
#endif /* HAVE_LIBSSL */

const char			*simta_progname = "simta";

struct connection_info		*cinfo_stab = NULL;
int				simta_pidfd;
int				simsendmail_signal = 0;
int				command_signal = 0;
struct sigaction		sa;
struct sigaction		osahup;
struct sigaction		osachld;
struct sigaction		osausr1;
struct sigaction		osausr2;
const char			*version = PACKAGE_VERSION;
struct simta_socket		*simta_listen_sockets = NULL;


int daemon_local( void );
int hq_launch( void );
int sender_promote( char * );
int mid_promote( char * );

void		env_log_metrics( struct dll_entry * );
void		sender_log_metrics( struct dll_entry * );
int		daemon_commands( struct simta_dirp * );
void		usr1( int );
void		usr2( int );
void		hup ( int );
void		chld( int );
int		main( int, char *av[] );
int		simta_wait_for_child( int );
int		simta_sigaction_reset( int );
int		simta_server( void );
int		simta_daemonize_server( void );
int		simta_child_receive( struct simta_socket* );
int		set_rcvbuf( int );
struct simta_socket	*simta_listen( const char * );
struct proc_type	*simta_proc_add( int, int );
int		simta_proc_q_runner( int, struct host_q* );
int		simta_read_command( struct simta_dirp * );
int		set_sleep_time( int *, int );

    void
usr1( int sig )
{
#ifndef Q_SIMULATION
    simsendmail_signal = 1;
#endif /* Q_SIMULATION */
    return;
}


    void
usr2( int sig )
{
#ifndef Q_SIMULATION
    command_signal = 1;
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
    simta_child_signal = 1;
#endif /* Q_SIMULATION */
    return;
}


#ifdef HAVE_LIBSASL
    static int
sasl_my_log( void *context __attribute__((unused)), int priority,
	const char *message)
{
    const char *label;

    if ( message == NULL ) {
	return SASL_BADPARAM;
    }

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

    syslog( LOG_ERR, "SASL %s: %s", label, message );

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
	    syslog( LOG_ERR, "Syserror: set_rcvbuf getsockopt: %m" );
	    return( 1 );
	}
    }

    if ( setsockopt( s, SOL_SOCKET, SO_RCVBUF,
	    (void*)&simta_smtp_rcvbuf_min, sizeof( int )) < 0 ) {
	syslog( LOG_ERR, "Syserror: set_rcvbuf setsockopt: %m" );
	return( 1 );
    }

    return( 0 );
}


     struct simta_socket *
simta_listen( const char *port )
{
    int				sockopt;
    int				rc;
    char			host[ NI_MAXHOST ];
    char			service[ NI_MAXSERV ];
    struct addrinfo		hints;
    struct addrinfo		*ai, *air;
    struct simta_socket		*ss = NULL;

    memset( &hints, 0, sizeof( struct addrinfo ));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE | AI_NUMERICSERV;

    if (( rc = getaddrinfo( NULL, port, &hints, &air )) != 0 ) {
	syslog( LOG_ERR, "Syserror: simta_listen getaddrinfo: %s",
		gai_strerror( rc ));
	fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( rc ));
	return( NULL );
    }

    for ( ai = air; ai != NULL ; ai = ai->ai_next ) {
	if ( ai->ai_family == AF_INET6 ) {
	    if ( simta_ipv6 == 0 ) {
		continue;
	    }
	    simta_ipv6 = 1;
	} else {
	    if ( simta_ipv4 == 0 ) {
		continue;
	    }
	    simta_ipv4 = 1;
	}

	ss = calloc( 1, sizeof( struct simta_socket ));

	if (( rc = getnameinfo( ai->ai_addr, ai->ai_addrlen, host,
		sizeof( host ), service, sizeof( service ),
		NI_NUMERICHOST )) != 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_listen getnameinfo: %s",
		    gai_strerror( rc ));
	    fprintf( stderr, "getnameinfo: %s\n", gai_strerror( rc ));
	    return( NULL );
	}
	ss->ss_service = strdup( service );
	ss->ss_next = simta_listen_sockets;
	simta_listen_sockets = ss;

	if (( ss->ss_socket = socket( ai->ai_family, ai->ai_socktype,
		ai->ai_protocol )) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_listen socket %s:%s: %m",
		    host, service );
	    perror( "socket" );
	    return( NULL );
	}

	if ( ai->ai_family == AF_INET6 ) {
	    sockopt = 1;
	    if ( setsockopt( ss->ss_socket, IPPROTO_IPV6, IPV6_V6ONLY,
		    &sockopt, sizeof( int )) < 0 ) {
		syslog( LOG_ERR, "Syserror: simta_listen setsockopt %s:%s: %m",
			host, service );
		perror( "setsockopt" );
		return( NULL );
	    }
	}

	sockopt = 1;
	if ( setsockopt( ss->ss_socket, SOL_SOCKET, SO_REUSEADDR,
		&sockopt, sizeof( int )) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_listen setsockopt %s:%s: %m",
		    host, service );
	    perror( "setsockopt" );
	    return( NULL );
	}

	if ( simta_smtp_rcvbuf_min != 0 ) {
	    if ( set_rcvbuf( ss->ss_socket ) != 0 ) {
		return( NULL );
	    }
	}

	if ( bind( ss->ss_socket, ai->ai_addr, ai->ai_addrlen ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_listen bind %s:%s: %m",
		    host, service );
	    perror( "bind" );
	    return( NULL );
	}

	if ( listen( ss->ss_socket, simta_listen_backlog ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_listen listen %s:%s: %m",
		    host, service );
	    perror( "listen" );
	    return( NULL );
	}
    }

    freeaddrinfo( air );
    return( ss );
}


    int
main( int ac, char **av )
{
    int			c, err = 0;
    int			dontrun = 0;
    int			q_run = 0;
    char		*prog;
    extern int		optind;
    extern char		*optarg;
    struct simta_socket	*ss;
    const char          *simta_uname = "simta";
    struct passwd	*simta_pw;
    const char		*config_fname = SIMTA_FILE_CONFIG;
#ifdef HAVE_LIBSASL
    int			rc;
#endif /* HAVE_LIBSASL */
#ifdef HAVE_LIBSSL
    SSL_CTX		*ssl_ctx = NULL;
#endif /* HAVE_LIBSSL */

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

    while (( c = getopt( ac, av, "cCdD:f:p:qQ:u:V")) != -1 ) {
	switch ( c ) {
	case 'c' :		/* check config files */
	    dontrun++;
	    break;

	case 'C' :		/* clean up directories */
	    simta_filesystem_cleanup++;
	    break;

	case 'd':
	    simta_debug++;
	    break;

	case 'D' :
	    simta_base_dir = strdup( optarg );
	    break;

	case 'f' :
	    config_fname = optarg;
	    break;

	case 'p' :		/* TCP port */
	    simta_port_smtp = optarg;

	case 'q' :
	    /* q_runner option: run slow queue */
	    q_run++;
	    break;

	case 'Q' :
	    /* q_runner option: run specific slow queue */
	    q_run++;
	    simta_queue_filter = optarg;
	    break;

        case 'u' :
            simta_uname = optarg;
            break;

	case 'V' :
	    printf( "%s\n", version );
	    exit( 0 );

	default:
	    err++;
	}
    }

    if ( q_run > 1 ) {
	fprintf( stderr, "simta: only one -q or -Q option can be specified\n" );
	exit( 1 );
    }

    if ( q_run && simta_filesystem_cleanup ) {
	fprintf( stderr, "simta: -C and %s are mutually exclusive\n",
	    simta_queue_filter ? "-Q" : "-q" );
	exit( 1 );
    }

    if ( err || optind != ac ) {
	fprintf( stderr, "Usage:\t%s", prog );
	fprintf( stderr, " [ -cCdV ]" );
	fprintf( stderr, " [ -D base-dir ]" );
	fprintf( stderr, " [ -f config-file ]" );
	fprintf( stderr, " [ -p port ]" );
        fprintf( stderr, " [ -u user ]" );
	fprintf( stderr, " [ -q | -Q filter ]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    /* get our user info from /etc/passwd */
    if (( simta_pw = getpwnam( simta_uname )) == NULL ) {
	fprintf( stderr, "getpwnam %s: user not found\n", simta_uname );
	exit( 1 );
    }

    if ( simta_gettimeofday( NULL ) != 0 ) {
	exit( 1 );
    }

    simta_openlog( 0, LOG_PERROR );

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

    if ( chdir( simta_base_dir ) < 0 ) {
	perror( simta_base_dir );
	exit( 1 );
    }

    /* init simta config / defaults */
    if ( simta_config( ) != 0 ) {
	exit( 1 );
    }

#ifndef Q_SIMULATION
#ifdef HAVE_LIBSSL
    if ( simta_service_smtps ) {
	/* Test whether our SSL config is usable */
	if (( ssl_ctx = tls_server_setup( simta_service_smtps, simta_file_ca,
		simta_dir_ca, simta_file_cert, simta_file_private_key,
		simta_tls_ciphers )) == NULL ) {
	    syslog( LOG_ERR, "Liberror: tls_server_setup: %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	SSL_CTX_free( ssl_ctx );
	simta_tls = 1;
    }

    if ( simta_tls ) {
	simta_smtp_extension++;
    }
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    if ( simta_sasl == SIMTA_SASL_ON ) {
	if (( rc = sasl_server_init( callbacks, "simta" )) != SASL_OK ) {
	    syslog( LOG_ERR, "Liberror: sasl_server_init: %s",
		    sasl_errstring( rc, NULL, NULL ));
	    exit( 1 );
	}
    }
#endif /* HAVE_LIBSASL */
    if ( simta_sasl != SIMTA_SASL_OFF ) {
	simta_smtp_extension++;
    }

    if ( simta_max_message_size >= 0 ) {
	simta_smtp_extension++;
    }

    if ( dontrun ) {
	exit( 0 );
    }

    /* if we're not a q_runner or filesystem cleaner, open smtp service */
    if (( q_run == 0 ) && ( simta_filesystem_cleanup == 0 ) &&
	    ( simta_smtp_default_mode != SMTP_MODE_OFF )) {
	if ( simta_service_smtp ) {
	    if ( simta_listen( simta_port_smtp ) == NULL ) {
		exit( 1 );
	    }
	}

#ifdef HAVE_LIBSSL
	if ( simta_service_smtps ) {
	    if (( ss = simta_listen( simta_port_smtps )) == NULL ) {
		exit( 1 );
	    }
	    ss->ss_flags |= SIMTA_SOCKET_TLS;
	}
#endif /* HAVE_LIBSSL */

	if ( simta_service_submission ) {
	    if ( simta_listen( simta_port_submission ) == NULL ) {
		exit( 1 );
	    }
	}
    }

    if ( q_run == 0 ) {
	/* open and truncate the pid file */
	if (( simta_pidfd =
		open( simta_file_pid, O_CREAT | O_WRONLY, 0644 )) < 0 ) {
	    fprintf( stderr, "open %s: ", simta_file_pid );
	    perror( NULL );
	    exit( 1 );
	}

	/* lock simta pid fd */
	if ( flock( simta_pidfd, LOCK_EX | LOCK_NB ) != 0 ) {
	    if ( errno == EAGAIN ) {
		/* file locked by a diferent process */
		fprintf( stderr, "flock %s: daemon already running\n",
			simta_file_pid );
		exit( 1 );

	    } else {
		fprintf( stderr, "flock %s:" , simta_file_pid );
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

#ifdef __linux__
    /* we're debugging under linux */
    if ( prctl( PR_SET_DUMPABLE, 1, 0, 0, 0 ) != 0 ) {
	perror( "prctl" );
	exit( 1 );
    }
#endif /* __linux__ */

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
    if ( simta_debug < 8 ) {
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

    simta_openlog( 0, 0 );

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

    /* catch SIGUSR2 */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = usr2;
    sa.sa_flags = SA_RESTART;
    if ( sigaction( SIGUSR2, &sa, &osausr2 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: sigaction: %m" );
	exit( 1 );
    }

    syslog( LOG_NOTICE, "Restart: %s", version );

    exit( simta_daemonize_server());
}


    int
simta_daemonize_server( void )
{
    int				pid;

    if ( simta_gettimeofday( NULL ) != 0 ) {
	return( 1 );
    }

    switch ( pid = fork()) {
    case 0 :
	/* Fall through */
	simta_openlog( 1, 0 );
	return( simta_server());

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_queue_scheduler fork: %m" );
	return( -1 );

    default :
	if ( simta_proc_add( PROCESS_SERVER, pid ) == NULL ) {
	    return( 1 );
	}
	syslog( LOG_NOTICE, "Child: launched daemon %d.%ld", pid,
		simta_tv_now.tv_sec );
	return( 0 );
    }
}


    int
set_sleep_time( int *sleep, int val )
{
    if ( val < 0 ) {
	val = 0;
    }

    if (( *sleep < 0 ) || ( *sleep > val )) {
	*sleep = val;
	return( 0 );
    }

    return( 1 );
}


    int
hq_launch( void )
{
    struct host_q		*hq;
    struct timeval		tv_now;
    int				lag;
    time_t			waited;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return( 1 );
    }

    hq = simta_deliver_q;
    hq_deliver_pop( hq );
    hq->hq_launches++;
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

    hq->hq_last_launch.tv_sec = tv_now.tv_sec;

    if ( hq_deliver_push( hq, &tv_now, NULL ) != 0 ) {
	return( 1 );
    }

    if ( simta_child_q_runner( hq ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    int
simta_server( void )
{
    struct timeval		tv_launch_limiter = { 0, 0 };
    struct timeval		tv_disk = { 0, 0 };
    struct timeval		tv_unexpanded = { 0, 0 };
    struct timeval		tv_sleep = { 0, 0 };
    struct timeval		tv_now;
    const char			*sleep_reason;
    char			*error_msg = NULL;
    int				entries;
    int				ready;
    int				sleep_time;
    int				launched;
    FILE			*pf;
    struct simta_dirp		command_dirp;
    struct simta_dirp		slow_dirp;
    int				fd_max;
    fd_set			fdset;
    struct proc_type		*p;
    struct simta_socket		*ss;
    struct connection_info	**c;
    struct connection_info	*remove;

    memset( &command_dirp, 0, sizeof( struct simta_dirp ));
    command_dirp.sd_dir = simta_dir_command;

    memset( &slow_dirp, 0, sizeof( struct simta_dirp ));
    slow_dirp.sd_dir = simta_dir_slow;

#ifndef Q_SIMULATION
    if (( pf = fdopen( simta_pidfd, "w" )) == NULL ) {
	syslog( LOG_ERR, "Syserror: simta_server fdopen: %m" );
	exit( 1 );
    }
    fprintf( pf, "%d\n", (int)getpid());
    if ( fflush( pf ) != 0 ) {
	syslog( LOG_ERR, "Syserror: simta_server fflush: %m" );
	exit( 1 );
    }
#endif /* Q_SIMULATION */

    simta_process_type = PROCESS_SERVER;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	exit( 1 );
    }

    /* main daemon loop */
    simta_debuglog( 1, "Daemon: start" );
    for ( ; ; ) {
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

	if ( simsendmail_signal != 0 ) {
	    if ( simta_q_runner_local < simta_q_runner_local_max ) {
		simta_debuglog( 2, "Daemon: launching local queue runner" );
		simsendmail_signal = 0;

		if ( simta_child_q_runner( NULL ) != 0 ) {
		    goto error;
		}
	    } else {
		syslog( LOG_WARNING, "Daemon: Received signal from simsendmail "
			"but MAX_Q_RUNNERS_LOCAL met, deferring launch" );
	    }
	}

	if ( simta_child_signal != 0 ) {
	    if ( simta_waitpid( 0, NULL, WNOHANG ) != 0 ) {
		goto error;
	    }
	}

	if (( command_dirp.sd_dirp != NULL ) || ( command_signal != 0 )) {
	    for ( entries = 1; ; entries++ ) {
		if ( command_dirp.sd_dirp == NULL ) {
		    simta_debuglog( 2, "Daemon.command: starting read" );
		    command_signal = 0;
		} else {
		    simta_debuglog( 3, "Daemon.command: entry read" );
		}
		daemon_commands( &command_dirp );
		if ( command_dirp.sd_dirp == NULL ) {
		    simta_debuglog( 2, "Daemon.command: finished read" );
		    break;
		}
		if (( simta_command_read_entries > 0 ) &&
			( entries >= simta_command_read_entries )) {
		    break;
		}
	    }
	}

	if ( tv_now.tv_sec >= tv_disk.tv_sec ) {
	    for ( entries = 1; ; entries++ ) {
		if ( slow_dirp.sd_dirp == NULL ) {
		    simta_debuglog( 2, "Daemon: starting slow queue read" );
		    simta_disk_cycle++;
		} else {
		    simta_debuglog( 3, "Daemon: slow queue entry read" );
		}
		if ( q_read_dir( &slow_dirp ) != 0 ) {
		    goto error;
		}
		if ( slow_dirp.sd_dirp == NULL ) {
		    tv_disk.tv_sec = tv_now.tv_sec + simta_min_work_time;
		    simta_debuglog( 2, "Daemon: finished slow queue read" );
		    break;
		}
		if (( simta_disk_read_entries > 0 ) &&
			( entries >= simta_disk_read_entries )) {
		    break;
		}
	    }
	}
	if ( set_sleep_time( &sleep_time, tv_disk.tv_sec - tv_now.tv_sec )
		== 0 ) {
	    sleep_reason = S_DISK;
	    simta_debuglog( 3, "Daemon: set_sleep_time %s: %d", sleep_reason,
		    sleep_time );
	}

	/* run unexpanded queue if we have entries, and it is time */
	if (( simta_unexpanded_q != NULL ) &&
		( simta_unexpanded_q->hq_env_head != NULL )) {
	    if ( tv_now.tv_sec >= tv_unexpanded.tv_sec ) {
		tv_unexpanded.tv_sec = simta_unexpanded_time + tv_now.tv_sec;
		simta_debuglog( 2,
		    "Daemon: launching unexpanded queue runner" );
		if ( simta_child_q_runner( simta_unexpanded_q ) != 0 ) {
		    goto error;
		}
	    }
	    if ( set_sleep_time( &sleep_time,
		    tv_unexpanded.tv_sec - tv_now.tv_sec ) == 0 ) {
		sleep_reason = S_UNEXPANDED;
		simta_debuglog( 3, "Daemon: set_sleep_time %s: %d",
			sleep_reason, sleep_time );
	    }
	}

	/* check to see if we need to launch queue runners */
	for ( launched = 1; simta_deliver_q != NULL; launched++ ) {
	    if ( tv_launch_limiter.tv_sec > tv_now.tv_sec ) {
		if ( set_sleep_time( &sleep_time,
			tv_launch_limiter.tv_sec - tv_now.tv_sec ) == 0 ) {
		    sleep_reason = S_LIMITER;
		    simta_debuglog( 3, "Daemon: set_sleep_time %s: %d",
			    sleep_reason, sleep_time );
		}
		break;
	    }

	    if ( simta_deliver_q->hq_next_launch.tv_sec > tv_now.tv_sec ) {
		if ( set_sleep_time( &sleep_time,
			simta_deliver_q->hq_next_launch.tv_sec -
			tv_now.tv_sec ) == 0 ) {
		    sleep_reason = S_QUEUE;
		    simta_debuglog( 3, "Daemon: set_sleep_time %s: %d",
			    sleep_reason, sleep_time );
		}
		simta_debuglog( 1, "Daemon: next queue %s %d",
			simta_deliver_q->hq_hostname,
			(int)(simta_deliver_q->hq_next_launch.tv_sec -
			tv_now.tv_sec) );
		break;
	    }

	    if (( simta_q_runner_slow_max != 0 ) &&
		    ( simta_q_runner_slow >= simta_q_runner_slow_max )) {
		/* queues need to launch but process limit met */
		syslog( LOG_NOTICE, "Daemon: Queue %s is ready but "
			"MAX_Q_RUNNERS_SLOW met, deferring launch",
			simta_deliver_q->hq_hostname );
		break;
	    }

	    simta_debuglog( 2, "Daemon: launching queue runner %s",
		    simta_deliver_q->hq_hostname );
	    if ( hq_launch() != 0 ) {
		goto error;
	    }

	    if (( simta_launch_limit > 0 ) &&
		    (( launched % simta_launch_limit ) == 0 )) {
		syslog( LOG_WARNING, "Daemon: MAX_Q_RUNNERS_LAUNCH met: "
			"sleeping for 1 second" );
		tv_launch_limiter.tv_sec = tv_now.tv_sec + 1;
	    }
	}

	if ( command_dirp.sd_dirp != NULL ) {
	    simta_debuglog( 2, "Daemon: reading commands" );
	    sleep_time = 0;
	    sleep_reason = "reading commands";
	}

	if (( simsendmail_signal != 0 ) &&
		( simta_q_runner_local < simta_q_runner_local_max )) {
	    simta_debuglog( 2, "Daemon: simsendmail signal" );
	    sleep_time = 0;
	    sleep_reason = "simsendmail signal";
	}

	if ( simta_child_signal != 0 ) {
	    simta_debuglog( 2, "Daemon: child signal" );
	    sleep_time = 0;
	    sleep_reason = "child signal";
	}

	if ( sleep_time < 0 ) {
	    sleep_time = 0;
	}

	if ( simta_listen_sockets == NULL ) {
	    if ( sleep_time > 0 ) {
		simta_debuglog( 1, "Daemon: sleeping %d: %s", sleep_time,
			sleep_reason );
		sleep((unsigned int)sleep_time );
	    }
	    if ( simta_gettimeofday( &tv_now ) != 0 ) {
		goto error;
	    }
	    continue;
	}

	if ( sleep_time > 0 ) {
	    tv_sleep.tv_sec = sleep_time;
	} else {
	    tv_sleep.tv_sec = 0;
	}
	tv_sleep.tv_usec = 0;

	FD_ZERO( &fdset );
	fd_max = 0;

	for ( ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next ) {
	    FD_SET( ss->ss_socket, &fdset );
	    fd_max = MAX( fd_max, ss->ss_socket );
	}

	simta_debuglog( 1, "Daemon: selecting %ld: %s", tv_sleep.tv_sec,
		sleep_reason );

	if (( ready = select( fd_max + 1, &fdset, NULL, NULL, &tv_sleep ))
		< 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR,
			"Syserror: simta_child_smtp_daemon select: %m" );
		goto error;
	    }
	}

	simta_debuglog( 2, "Daemon: select over" );

	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    goto error;
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

	simta_debuglog( 2, "Daemon: %d sockets ready", ready );
	if ( ready <= 0 ) {
	    continue;
	}

	for ( ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next ) {
	    if ( FD_ISSET( ss->ss_socket, &fdset )) {
		simta_debuglog( 2, "Daemon: Connect received" );
		if ( simta_child_receive( ss ) != 0 ) {
		    goto error;
		}
	    }
	}
	simta_debuglog( 2, "Daemon: done checking sockets" );
    }

error:
    /* Kill queue scheduler */
    for ( p = simta_proc_stab; p != NULL; p = p->p_next ) {
	/*
	if ( p->p_type == PROCESS_Q_SCHEDULER ) {
	    if ( kill( p->p_id, SIGKILL ) != 0 ) {
		syslog( LOG_ERR, "Syserror: simta_smtp_server kill %d.%ld: %m",
			p->p_id, p->p_tv.tv_sec );
	    }
	    break;
	}
	*/
    }

    syslog( LOG_NOTICE, "Daemon: Shutdown %s", error_msg ? error_msg : "" );

    return( 1 );
}


    int
simta_wait_for_child( int child_type )
{
    int				pid;
    int				status;
    const char			*p_name;

    if ( simta_gettimeofday( NULL ) != 0 ) {
	return( 1 );
    }

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "Syserror: simta_wait_for_child fork: %m" );
	return( 1 );

    case 0 :
	simta_openlog( 1, 0 );
	switch ( child_type ) {
	case PROCESS_CLEANUP:
	    exit( q_cleanup());

	case PROCESS_Q_SLOW:
	    exit( q_runner_dir( simta_dir_slow ));

	default:
	    syslog( LOG_ERR,
		    "Syserror: wait_for_child: child_type out of range: %d",
		    child_type );
	    return( 1 );
	}

    default :
	switch ( child_type ) {
	case PROCESS_CLEANUP:
	    if ( simta_filesystem_cleanup ) {
		p_name = "filesystem cleaner";
	    } else {
		p_name = "filesystem checker";
	    }
	    break;

	case PROCESS_Q_SLOW:
	    p_name = "queue runner";
	    break;

	default:
	    syslog( LOG_ERR, "Child: %d.%ld: start type %d out of range",
		    pid, simta_tv_now.tv_sec, child_type );
	    return( 1 );
	}

	syslog( LOG_NOTICE, "Child: launched %s %d.%ld",
		p_name, pid, simta_tv_now.tv_sec );

	if ( simta_waitpid( pid, &status, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: wait_for_child simta_waitpid %d: %m",
		    pid );
	    return( 1  );
	}

	if ( WIFEXITED( status )) {
	    syslog( LOG_NOTICE, "Child: %s %d.%ld exited %d",
		    p_name, pid, simta_tv_now.tv_sec, WEXITSTATUS( status ));
	    return( WEXITSTATUS( status ));

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child: %s %d.%ld: died with signal %d",
		    p_name, pid, simta_tv_now.tv_sec, WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "Child: %s %d.%ld died",
		    p_name, pid, simta_tv_now.tv_sec );
	    return( 1 );
	}
    }
}


    int
simta_sigaction_reset( int retain_chld )
{
    /* reset USR1, CHLD and HUP */
    if ( retain_chld == 0 ) {
	if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	    return( 1 );
	}
    }
    if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	return( 1 );
    }
    if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	return( 1 );
    }
    if ( sigaction( SIGUSR2, &osausr2, 0 ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_sigaction_reset sigaction: %m" );
	return( 1 );
    }

    return( 0 );
}


    int
simta_child_receive( struct simta_socket *ss )
{
    struct proc_type	*p;
    struct simta_socket		*s;
    struct connection_info	*cinfo = NULL;
    struct sockaddr_storage	sa;
    int				pid;
    int				fd;
    int				rc;
    socklen_t			salen;

    salen = sizeof( struct sockaddr_storage );
    if (( fd = accept( ss->ss_socket, (struct sockaddr *)&sa, &salen )) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_child_receive accept: %m" );
	/* accept() errors aren't fatal */
	return( 0 );
    }

    /* Look up / Create IP related connection data entry */
    for ( cinfo = cinfo_stab; cinfo != NULL; cinfo = cinfo->c_next ) {
	if ( sa.ss_family != cinfo->c_sa.ss_family ) {
	    continue;
	}
	if (( sa.ss_family == AF_INET6 ) && (
		memcmp( &(((struct sockaddr_in6 *)&sa)->sin6_addr),
		&(((struct sockaddr_in6 *)&(cinfo->c_sa))->sin6_addr),
		sizeof( struct sockaddr_in6 )) == 0 )) {
	    break;
	} else if ( memcmp( &(((struct sockaddr_in *)&sa)->sin_addr),
		&(((struct sockaddr_in *)&(cinfo->c_sa))->sin_addr),
		sizeof( struct sockaddr_in )) == 0 ) {
	    break;
	}
    }

    if ( cinfo == NULL ) {
	cinfo = calloc( 1, sizeof( struct connection_info ));
	memcpy( &(cinfo->c_sa), &sa, sizeof( struct sockaddr_storage ));

	if (( rc = getnameinfo( (struct sockaddr *)&sa,
		(( sa.ss_family == AF_INET6 )
		? sizeof( struct sockaddr_in6 ) : sizeof( struct sockaddr_in )),
		cinfo->c_ip, sizeof( cinfo->c_ip ),
		NULL, 0, NI_NUMERICHOST )) != 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_child_receive getnameinfo: %s",
		    gai_strerror( rc ));
	}

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

    simta_debuglog( 1, "Connect.stat %s: global_total %d "
	    "global_throttle %d local_total %d local_throttle %d",
	    cinfo->c_ip, simta_global_connections,
	    simta_global_throttle_connections, cinfo->c_proc_total,
	    cinfo->c_proc_throttle );

    switch ( pid = fork()) {
    case 0:
	simta_openlog( 1, 0 );
	simta_process_type = PROCESS_RECEIVE;
	simta_host_q = NULL;
	if ( simta_unexpanded_q != NULL ) {
	    simta_unexpanded_q->hq_env_head = NULL;
	    simta_unexpanded_q->hq_next = NULL;
	    simta_unexpanded_q->hq_entries = 0;
	}
	for ( s = simta_listen_sockets; s != NULL; s = s->ss_next ) {
	    if ( close( s->ss_socket ) != 0 ) {
		syslog( LOG_ERR, "Syserror: simta_child_receive close: %m" );
	    }
	}
	/* smtp receive children may spawn children */
	simta_sigaction_reset( simta_q_runner_receive_max );
	simta_proc_stab = NULL;
	simta_q_runner_slow = 0;
	exit( smtp_receive( fd, cinfo, ss ));

    case -1:
	syslog( LOG_ERR, "Syserror: simta_child_receive fork: %m" );
	return( 1 );

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

    p->p_host = strdup( cinfo->c_ip );

    syslog( LOG_NOTICE, "Child: launched %s receive process %d.%ld for %s "
	    "(%d total, %d %s)",
	    p->p_ss->ss_service, p->p_id, p->p_tv.tv_sec, p->p_host,
	    *p->p_limit, p->p_ss->ss_count, p->p_ss->ss_service );

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
	simta_openlog( 1, 0 );
	simta_sigaction_reset( 0 );
	close( simta_pidfd );
	simta_host_q = NULL;

	/* Stop using the parent's dnsr object, if it has one */
	if ( simta_dnsr ) {
	    dnsr_free( simta_dnsr );
	    simta_dnsr = NULL;
	}

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
	return( 1 );

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

	syslog( LOG_NOTICE, "Child: launched local runner %d.%ld (%d total)",
		pid, p->p_tv.tv_sec, *p->p_limit );

    } else {
	p->p_limit = &simta_q_runner_slow;
	(*p->p_limit)++;

	if ( hq->hq_hostname ) {
	    p->p_host = strdup( hq->hq_hostname );
	}

	syslog( LOG_NOTICE, "Child: launched queue runner %d.%ld for %s "
		"(%d total)", pid, p->p_tv.tv_sec,
		hq->hq_hostname ? hq->hq_hostname : S_UNEXPANDED,
		*p->p_limit );
    }

    return( 0 );
}


    struct proc_type *
simta_proc_add( int process_type, int pid )
{
    struct proc_type	*p;

    p = calloc( 1, sizeof( struct proc_type ));

    p->p_tv.tv_sec = simta_tv_now.tv_sec;
    p->p_id = pid;
    p->p_type = process_type;
    p->p_next = simta_proc_stab;
    simta_proc_stab = p;

    return( p );
}


    int
mid_promote( char *mid )
{
    struct dll_entry		*dll;
    struct envelope		*e;
    struct timeval		tv_nowait = { 0, 0 };

    if (( dll = dll_lookup( simta_env_list, mid )) != NULL ) {
	e = (struct envelope*)dll->dll_data;

	if ( simta_rqueue_policy == RQUEUE_POLICY_JAIL ) {
	    if ( env_jail_status( e, ENV_JAIL_PAROLEE ) != 0 ) {
		syslog( LOG_NOTICE,
			"Command: env <%s>: env_jail_status failed", mid );
		return( 1 );
	    }
	}

	if ( e->e_hq != NULL ) {
	    /* e->e_hq->hq_priority++; */
	    hq_deliver_pop( e->e_hq );
	    if ( hq_deliver_push( e->e_hq, NULL, &tv_nowait ) != 0 ) {
		return( 1 );
	    }
	    simta_debuglog( 3, "Command: env <%s>: promoted queue %s", mid,
		    e->e_hq->hq_hostname );
	} else {
	    simta_debuglog( 2, "Command: env <%s>: not in a queue", mid );
	}
    } else {
	simta_debuglog( 1, "Command: env <%s>: not found", mid );
    }

    return( 0 );
}


    int
sender_promote( char *sender )
{
    struct dll_entry		*dll;
    struct sender_list		*sl;
    struct sender_entry		*se;
    struct dll_entry		*dll_se;
    struct timeval		tv_nowait = { 0, 0 };

    if (( dll = dll_lookup( simta_sender_list, sender )) != NULL ) {
	sl = (struct sender_list*)dll->dll_data;
	simta_debuglog( 1, "Command: Sender %s: found %d messages",
		sender, sl->sl_n_entries );
	for ( dll_se = sl->sl_entries; dll_se != NULL;
		dll_se = dll_se->dll_next ) {
	    se = (struct sender_entry*)dll_se->dll_data;
	    if ( simta_rqueue_policy == RQUEUE_POLICY_JAIL ) {
		/* tag env */
		if ( env_jail_status( se->se_env, ENV_JAIL_PAROLEE ) != 0 ) {
		    syslog( LOG_NOTICE,
			    "Command: Sender %s: env_jail_status failed for %s",
			    sender, se->se_env->e_id );
		}
	    }

	    /* re-queue queue */
	    if ( se->se_env->e_hq != NULL ) {
		/* se->se_env->e_hq->hq_priority++; */
		hq_deliver_pop( se->se_env->e_hq );
		if ( hq_deliver_push( se->se_env->e_hq, NULL,
			&tv_nowait ) != 0 ) {
		    syslog( LOG_NOTICE,
			    "Command: Sender %s: hq_deliver_push failed for %s",
			    sender, se->se_env->e_hq->hq_hostname );
		} else {
		    simta_debuglog( 3, "Command: Sender %s: promoted queue %s",
			    sender, se->se_env->e_hq->hq_hostname );
		}
	    }
	}
    }

    return( 0 );
}


    int
daemon_commands( struct simta_dirp *sd )
{
    struct dirent		*entry;
    struct timeval		tv_stop;
    char			*line;
    SNET			*snet;
    char			fname[ MAXPATHLEN + 1 ];
    int				lineno = 1;
    int				ret = 0;
    int				ac;
    int				int_arg;
    char			**av;
    ACAV			*acav;
    struct host_q		*hq;
    struct timeval		tv_nowait = { 0, 0 };
    struct envelope		*e;

    if ( sd->sd_dirp == NULL ) {
	if ( simta_gettimeofday( &(sd->sd_tv_start)) != 0 ) {
	    return( 1 );
	}

	if (( sd->sd_dirp = opendir( sd->sd_dir )) == NULL ) {
	    syslog( LOG_ERR, "Syserror: simta_read_command opendir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	sd->sd_entries = 0;
	sd->sd_cycle++;
	return( 0 );
    }

    errno = 0;

    if (( entry = readdir( sd->sd_dirp )) == NULL ) {
	if ( errno != 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_read_command readdir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	if ( closedir( sd->sd_dirp ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_read_command closedir %s: %m",
		    sd->sd_dir );
	    sd->sd_dirp = NULL;
	    return( 1 );
	}

	sd->sd_dirp = NULL;

	if ( simta_gettimeofday( &tv_stop ) != 0 ) {
	    return( 1 );
	}

	syslog( LOG_INFO,
		"Command Metric: cycle %d Commands %d milliseconds %ld",
		sd->sd_cycle, sd->sd_entries,
		SIMTA_ELAPSED_MSEC( sd->sd_tv_start, tv_stop ));

	return( 0 );
    }

    switch ( *entry->d_name ) {
    /* "C*" */
    case 'C':
	sd->sd_entries++;
	/* Command file */
	break;

    /* "c*" */
    case 'c':
	/* command temp file */
	return( 0 );

    /* "." && ".." */
    case '.':
	if ( * ( entry->d_name + 1 ) == '\0' ) {
	    /* "." */
	    return( 0 );
	} else if (( * ( entry->d_name + 1 ) == '.' ) &&
		( * ( entry->d_name + 2 ) == '\0' )) {
	    /* ".." */
	    return( 0 );
	}
	/* fall through to default */

    /* "*" */
    default:
	syslog( LOG_WARNING, "Command: unknown file: %s/%s", sd->sd_dir,
		entry->d_name );
	return( 0 );
    }

    sprintf( fname, "%s/%s", sd->sd_dir, entry->d_name );

    if (( snet = snet_open( fname, O_RDWR, 0, 1024 * 1024 )) == NULL ) {
	if ( errno != ENOENT ) {
	    syslog( LOG_ERR, "Liberror: simta_read_command snet_open %s: %m",
		    fname );
	    return( 1 );
	}
	return( 0 );
    }

    acav = acav_alloc( );

    if (( line = snet_getline( snet, NULL )) == NULL ) {
	simta_debuglog( 1, "Command %s: unexpected EOF", entry->d_name );
	ret = 1;
	goto error;
    }

    if (( ac = acav_parse( acav, line, &av )) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_read_command acav_parse: %m" );
	ret = 1;
	goto error;
    }

    if ( av[ 0 ] == NULL ) {
	simta_debuglog( 2, "Command %s: line %d: NULL", entry->d_name, lineno );

    } else if ( strcasecmp( av[ 0 ], S_MESSAGE ) == 0 ) {
	if ( ac == 1 ) {
	    simta_debuglog( 2, "Command %s: Message", entry->d_name );
	    env_log_metrics( simta_env_list );

	} else if ( ac == 2 ) {
	    simta_debuglog( 2, "Command %s: Message %s", entry->d_name,
		    av[ 1 ]);
	    if ( mid_promote( av[ 1 ]) != 0 ) {
		ret = 1;
	    }

	} else {
	    simta_debuglog( 1, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	    ret = 1;
	}

    } else if ( strcasecmp( av[ 0 ], S_SENDER ) == 0 ) {
	if ( ac == 1 ) {
	    simta_debuglog( 2, "Command %s: Sender", entry->d_name );
	    sender_log_metrics( simta_sender_list );

	} else if ( ac == 2 ) {
	    simta_debuglog( 2, "Command %s: Sender %s", entry->d_name, av[ 1 ]);
	    /* JAIL-ADD promote sender's mail */
	    if ( sender_promote( av[ 1 ]) != 0 ) {
		ret++;
	    }
	} else {
	    simta_debuglog( 1, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else if ( strcasecmp( av[ 0 ], S_QUEUE ) == 0 ) {
	if ( ac == 1 ) {
	    simta_debuglog( 2, "Command %s: Queue", entry->d_name );
	    queue_log_metrics( simta_deliver_q );
	} else if ( ac == 2 ) {
	    simta_debuglog( 2, "Command %s: Queue %s", entry->d_name, av[ 1 ]);
	    if (( hq = host_q_lookup( av[ 1 ])) != NULL ) {
		hq_deliver_pop( hq );
		/* hq->hq_priority++; */
		if ( simta_rqueue_policy == RQUEUE_POLICY_JAIL ) {
		    /* promote all the envs in the queue */
		    for ( e = hq->hq_env_head; e != NULL; e = e->e_hq_next ) {
			if ( env_jail_status( e, ENV_JAIL_PAROLEE ) != 0 ) {
			    ret++;
			    syslog( LOG_NOTICE,
				    "Command %s: Queue %s: "
				    "env_jail_status failed for %s",
				    entry->d_name, av[ 1 ], e->e_id );
			}
		    }
		}

		if ( hq_deliver_push( hq, NULL, &tv_nowait ) != 0 ) {
		    syslog( LOG_NOTICE,
			    "Command %s: Queue %s: hq_deliver_push failed",
			    entry->d_name, av[ 1 ] );
		    ret = 1;
		} else {
		    simta_debuglog( 1, "Command %s: Queue %s: promoted",
			    entry->d_name, av[ 1 ] );
		}
	    } else {
		simta_debuglog( 1, "Command %s: Queue %s: not found",
			entry->d_name, av[ 1 ]);
	    }

	} else {
	    simta_debuglog( 1, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else if ( strcasecmp( av[ 0 ], S_DEBUG ) == 0 ) {
	if ( ac == 1 ) {
	    simta_debuglog( 1, "Command %s: Debug: %d", entry->d_name,
		    simta_debug );
	} else if ( ac == 2 ) {
	    int_arg = atoi( av[ 1 ]);
	    if ( int_arg >= 0 ) {
		simta_debug = int_arg;
		simta_debuglog( 2, "Command %s: Debug set: %d", entry->d_name,
			simta_debug );
	    } else {
		ret = 1;
		simta_debuglog( 1, "Command %s: Debug illegal arg: %d",
			entry->d_name, simta_debug );
	    }
	} else {
	    ret = 1;
	    simta_debuglog( 1, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else {
	ret = 1;
	simta_debuglog( 1, "Command %s: line %d: Unknown command: \"%s\"",
		entry->d_name, lineno, av[ 0 ]);
    }

error:
    if ( snet_close( snet ) < 0 ) {
	syslog( LOG_ERR, "Syserror: simta_read_command snet_close %s: %m",
		entry->d_name );
    }

    if ( unlink( fname ) != 0 ) {
	syslog( LOG_ERR, "Syserror: simta_read_command unlink %s: %m", fname );
    }

    acav_free( acav );

    return( ret );
}


    void
env_log_metrics( struct dll_entry *dll_head )
{
    char		filename[ MAXPATHLEN ];
    char		linkname[ MAXPATHLEN ];
    int			fd;
    FILE		*f;
    struct dll_entry	*dll;
    struct envelope	*env;
    struct timeval	tv_now;
    struct stat		st_file;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return;
    }

    sprintf( linkname, "%s/etc/mid_list", simta_base_dir );
    sprintf( filename, "%s.%lX", linkname, (unsigned long)tv_now.tv_sec );

    if (( fd = open( filename, O_WRONLY | O_CREAT | O_TRUNC, 0664 )) < 0 ) {
	syslog( LOG_WARNING, "Syserror: env_log_metrics open %s: %m",
		filename );
	return;
    }

    if (( f = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_WARNING, "Syserror: env_log_metrics fdopen %s: %m",
		filename );
	return;
    }

    fprintf( f, "MID List:\n\n" );

    for ( dll = dll_head; dll != NULL; dll = dll->dll_next ) {
	env = (struct envelope*)dll->dll_data;
	fprintf( f, "%s\t%s\t%s\n", env->e_id, env->e_hostname, env->e_mail );
    }

    fclose( f );

    if (( stat( linkname, &st_file ) == 0 ) && ( unlink( linkname ) != 0 )) {
	syslog( LOG_WARNING, "Syserror: env_log_metrics unlink %s: %m",
		linkname );
    } else if ( link( filename, linkname ) != 0 ) {
	syslog( LOG_WARNING, "Syserror: env_log_metrics link %s %s: %m",
		filename, linkname );
    }

    return;
}

    void
sender_log_metrics( struct dll_entry *dll_head )
{
    char		filename[ MAXPATHLEN ];
    char		linkname[ MAXPATHLEN ];
    int			fd;
    FILE		*f;
    struct dll_entry	*dll;
    struct sender_list	*sl;
    struct timeval	tv_now;
    struct stat		st_file;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return;
    }

    sprintf( linkname, "%s/etc/sender_list", simta_base_dir );
    sprintf( filename, "%s.%lX", linkname, (unsigned long)tv_now.tv_sec );

    if (( fd = open( filename, O_WRONLY | O_CREAT | O_TRUNC, 0664 )) < 0 ) {
	syslog( LOG_WARNING, "Syserror: sender_log_metrics open %s: %m",
		filename );
	return;
    }

    if (( f = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_WARNING, "Syserror: sender_log_metrics fdopen %s: %m",
		filename );
	return;
    }

    fprintf( f, "Sender List:\n\n" );

    for ( dll = dll_head; dll != NULL; dll = dll->dll_next ) {
	sl = (struct sender_list*)dll->dll_data;
	fprintf( f, "%s\t%d\n", dll->dll_key, sl->sl_n_entries );
    }

    fclose( f );

    if (( stat( linkname, &st_file ) == 0 ) && ( unlink( linkname ) != 0 )) {
	syslog( LOG_WARNING, "Syserror: sender_log_metrics unlink %s: %m",
		linkname );
    } else if ( link( filename, linkname ) != 0 ) {
	syslog( LOG_WARNING, "Syserror: sender_log_metrics link %s %s: %m",
		filename, linkname );
    }

    return;
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
