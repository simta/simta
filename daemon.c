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
#include <dirent.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "argcargv.h"
#include "denser.h"
#include "ll.h"
#include "simta.h"
#include "queue.h"
#include "envelope.h"

#ifdef HAVE_LIBSSL
#include "tls.h"
#endif /* HAVE_LIBSSL */

/* XXX testing purposes only, make paths configureable */
#define _PATH_SPOOL	"/var/spool/simta"


struct connection_info		*cinfo_stab = NULL;
struct proc_type		*proc_stab = NULL;
int				simta_pidfd;
int				simsendmail_signal = 0;
int				child_signal = 0;
int				command_signal = 0;
struct sigaction		sa;
struct sigaction		osahup;
struct sigaction		osachld;
struct sigaction		osausr1;
struct sigaction		osausr2;
char				*version = VERSION;
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
int		daemon_waitpid( void );
int		simta_sigaction_reset( void );
int		simta_server( void );
int		simta_daemonize_server( void );
int		simta_child_q_runner( struct host_q* );
int		simta_child_receive( struct simta_socket* );
int		set_rcvbuf( int );
struct simta_socket	*simta_listen( char*, int, int );
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
#ifdef HAVE_LIBSSL
    SSL_CTX		*ssl_ctx = NULL;
#endif /* HAVE_LIBSSL */

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
	    simta_dns_auto_config = 1;
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
#ifndef HAVE_LIBSSL
	syslog( LOG_ERR, "simta_service_smtps set but SSL is not available" );
	exit( 1 );
#else /* HAVE_LIBSSL */
	/* Test whether our SSL config is usable */
	if (( ssl_ctx = tls_server_setup( simta_use_randfile,
		simta_service_smtps, simta_file_ca, simta_dir_ca,
		simta_file_cert, simta_file_private_key )) == NULL ) {
	    syslog( LOG_ERR, "Syserror: tls_server_setup: %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	SSL_CTX_free( ssl_ctx );
	simta_tls = 1;
#endif /* HAVE_LIBSSL */
    }

    if ( simta_tls ) {
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
	simta_openlog( 1 );
	return( simta_server());

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_child_queue_scheduler fork: %m" );
	return( -1 );

    default :
	if ( simta_proc_add( PROCESS_SERVER, pid ) == NULL ) {
	    return( 1 );
	}
	syslog( LOG_NOTICE, "Child Start %d.%ld: simta Server", pid,
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
    u_long			waited;

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
    char			*sleep_reason;
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
        syslog( LOG_ERR, "Syserror: can't fdopen simta_pidfd" );
        exit( 1 );
    }
    fprintf( pf, "%d\n", (int)getpid());
    if ( fflush( pf ) != 0 ) {
	syslog( LOG_ERR, "Syserror: fflush: %m" );
	exit( 1 );
    }
#endif /* Q_SIMULATION */

    simta_process_type = PROCESS_SERVER;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	exit( 1 );
    }

    srandom((unsigned int)tv_now.tv_usec );

    /* main daemon loop */
    syslog( LOG_DEBUG, "Debug: Starting Daemon" );
    for ( ; ; ) {
	/* LOCAL RUNER */
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
		syslog( LOG_DEBUG, "Debug: Local Runner" );
		simsendmail_signal = 0;

		if ( simta_child_q_runner( NULL ) != 0 ) {
		    goto error;
		}
	    } else {
		syslog( LOG_WARNING, "Daemon Delay: MAX_Q_RUNNERS_LOCAL met: "
			"local queue runner launch delayed" );
	    }
	}

	if ( child_signal != 0 ) {
	    child_signal = 0;
	    if ( daemon_waitpid() != 0 ) {
		goto error;
	    }
	}

	if (( command_dirp.sd_dirp != NULL ) || ( command_signal != 0 )) {
	    for ( entries = 1; ; entries++ ) {
		if ( command_dirp.sd_dirp == NULL ) {
		    syslog( LOG_DEBUG, "Debug: Command read start" );
		    command_signal = 0;
		} else {
		    syslog( LOG_DEBUG, "Debug: Command read entry" );
		}
		if ( daemon_commands( &command_dirp ) != 0 ) {
		    goto error;
		}
		if ( command_dirp.sd_dirp == NULL ) {
		    syslog( LOG_DEBUG, "Debug: Command read end" );
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
		    if ( simta_debug > 0 ) {
			syslog( LOG_DEBUG, "Debug: Slow Queue Read Start" );
		    }
		    simta_disk_cycle++;
		} else {
		    if ( simta_debug > 1 ) {
			syslog( LOG_DEBUG, "Debug: Slow Queue Read Entry" );
		    }
		}
		if ( q_read_dir( &slow_dirp ) != 0 ) {
		    goto error;
		}
		if ( slow_dirp.sd_dirp == NULL ) {
		    tv_disk.tv_sec = tv_now.tv_sec + simta_min_work_time;
		    if ( simta_debug > 0 ) {
			syslog( LOG_DEBUG, "Debug: Slow Queue Read End" );
		    }
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
	    syslog( LOG_DEBUG, "Debug: set_sleep_time %s: %d",
		    sleep_reason, sleep_time );
	}

	/* run unexpanded queue if we have entries, and it is time */
	if (( simta_unexpanded_q != NULL ) &&
		( simta_unexpanded_q->hq_env_head != NULL )) {
	    if ( tv_now.tv_sec >= tv_unexpanded.tv_sec ) {
		tv_unexpanded.tv_sec = simta_unexpanded_time + tv_now.tv_sec;
		syslog( LOG_DEBUG, "Debug: Unexpanded Runner" );
		if ( simta_child_q_runner( simta_unexpanded_q ) != 0 ) {
		    goto error;
		}
	    }
	    if ( set_sleep_time( &sleep_time,
		    tv_unexpanded.tv_sec - tv_now.tv_sec ) == 0 ) {
		sleep_reason = S_UNEXPANDED;
		syslog( LOG_DEBUG, "Debug: set_sleep_time %s: %d",
			sleep_reason, sleep_time );
	    }
	}

	/* check to see if we need to launch queue runners */
	for ( launched = 1; simta_deliver_q != NULL; launched++ ) {
	    if ( tv_launch_limiter.tv_sec > tv_now.tv_sec ) {
		if ( set_sleep_time( &sleep_time,
			tv_launch_limiter.tv_sec - tv_now.tv_sec ) == 0 ) {
		    sleep_reason = S_LIMITER;
		    syslog( LOG_DEBUG, "Debug: set_sleep_time %s: %d",
			    sleep_reason, sleep_time );
		}
		break;
	    }

	    if ( simta_deliver_q->hq_next_launch.tv_sec > tv_now.tv_sec ) {
		if ( set_sleep_time( &sleep_time, 
			simta_deliver_q->hq_next_launch.tv_sec -
			tv_now.tv_sec ) == 0 ) {
		    sleep_reason = S_QUEUE;
		    syslog( LOG_DEBUG, "Debug: set_sleep_time %s: %d",
			    sleep_reason, sleep_time );
		}
		syslog( LOG_DEBUG, "Daemon: next queue %s %d",
			simta_deliver_q->hq_hostname,
			(int)(simta_deliver_q->hq_next_launch.tv_sec -
			tv_now.tv_sec) );
		break;
	    }

	    if (( simta_q_runner_slow_max != 0 ) &&
		    ( simta_q_runner_slow >= simta_q_runner_slow_max )) {
		/* queues need to launch but process limit met */
		syslog( LOG_NOTICE, "Daemon Delay: %ld : "
			"Queues are not caught up and "
			"MAX_Q_RUNNERS_SLOW has been met",
			tv_now.tv_sec -
			simta_deliver_q->hq_next_launch.tv_sec );
		break;
	    }

	    syslog( LOG_DEBUG, "Debug: Queue Runner %s",
		    simta_deliver_q->hq_hostname );
	    if ( hq_launch() != 0 ) {
		goto error;
	    }

	    if (( simta_launch_limit > 0 ) &&
		    (( launched % simta_launch_limit ) == 0 )) {
		syslog( LOG_WARNING, "Daemon Delay: MAX_Q_RUNNERS_LAUNCH met: "
			"sleeping for 1 second" );
		tv_launch_limiter.tv_sec = tv_now.tv_sec + 1;
	    }
	}

	if ( command_dirp.sd_dirp != NULL ) {
	    syslog( LOG_DEBUG, "Debug: Reading commands" );
	    sleep_time = 0;
	    sleep_reason = "reading commands";
	}

	if (( simsendmail_signal != 0 ) && 
		( simta_q_runner_local < simta_q_runner_local_max )) {
	    syslog( LOG_DEBUG, "Debug: simsendmail signal " );
	    sleep_time = 0;
	    sleep_reason = "Simsendmail signal";
	}

	if ( child_signal != 0 ) {
	    syslog( LOG_DEBUG, "Debug: child signal" );
	    sleep_time = 0;
	    sleep_reason = "Child signal";
	}

	if ( sleep_time < 0 ) {
	    sleep_time = 0;
	}

	if ( simta_listen_sockets == NULL ) {
	    if ( sleep_time > 0 ) {
		syslog( LOG_DEBUG, "Daemon: sleeping %d: %s", sleep_time,
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

syslog( LOG_DEBUG, "Daemon: selecting %ld: %s", tv_sleep.tv_sec,
	sleep_reason );

	if (( ready = select( fd_max + 1, &fdset, NULL, NULL, &tv_sleep ))
		< 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR,
			"Syserror: simta_child_smtp_daemon select: %m" );
		goto error;
	    }
	}

syslog( LOG_DEBUG, "Debug: select over" );

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

syslog( LOG_DEBUG, "Debug: %d sockets ready", ready );
	if ( ready <= 0 ) {
	    continue;
	}

	for ( ss = simta_listen_sockets; ss != NULL; ss = ss->ss_next ) {
	    if ( FD_ISSET( ss->ss_socket, &fdset )) {
syslog( LOG_DEBUG, "Debug: Connect received" );
		if ( simta_child_receive( ss ) != 0 ) {
		    goto error;
		}
	    }
	}
syslog( LOG_DEBUG, "Debug: listen over" );
    }

error:
    /* Kill queue scheduler */
    for ( p = proc_stab; p != NULL; p = p->p_next ) {
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
daemon_waitpid( void )
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

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return( 1 );
    }

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	for ( p_search = &proc_stab; *p_search != NULL;
		p_search = &((*p_search)->p_next)) {
	    if ((*p_search)->p_id == pid ) {
		break;
	    }
	}

	if ( *p_search == NULL ) {
	    syslog( LOG_ERR, "Child Error %d: unkown child process", pid );
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
			hq->hq_leaky = 1;
			hq_deliver_pop( hq );

			if ( hq_deliver_push( hq, &tv_now, NULL ) != 0 ) {
			    return( 1 );
			}

		    } else {
			syslog( LOG_DEBUG, "Queue %s: Not Found",
				p_remove->p_host );
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
			*(p_remove->p_host) ? p_remove->p_host : S_UNEXPANDED,
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
	    return( 1 );
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
	simta_sigaction_reset();
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

	syslog( LOG_NOTICE, "Child Start %d.%ld: Local %d", pid, p->p_tv.tv_sec,
		*p->p_limit );

    } else {
	p->p_limit = &simta_q_runner_slow;
	(*p->p_limit)++;

	if ( hq->hq_hostname == NULL ) {
	    syslog( LOG_NOTICE, "Child Start %d.%ld: %s %d",
		    pid, p->p_tv.tv_sec, S_UNEXPANDED, *p->p_limit );

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


    int
mid_promote( char *mid )
{
    struct dll_entry		*dll;
    struct envelope		*e;
    struct timeval		tv_nowait = { 0, 0 };

    if (( dll = dll_lookup( simta_env_list, mid )) != NULL ) {
	e = (struct envelope*)dll->dll_data;
	if ( env_jail_status( e, ENV_JAIL_PAROLEE ) != 0 ) {
	    return( 1 );
	}

	if ( e->e_hq != NULL ) {
	    /* e->e_hq->hq_priority++; */
	    hq_deliver_pop( e->e_hq );
	    if ( hq_deliver_push( e->e_hq, NULL, &tv_nowait ) != 0 ) {
		return( 1 );
	    }
	}
	syslog( LOG_DEBUG, "Command: Message %s Paroled", mid );
    } else {
	syslog( LOG_DEBUG, "Command: Message %s not found", mid );
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
	syslog( LOG_DEBUG, "Command: Sender %s found %d messages",
		sl->sl_dll->dll_key, sl->sl_n_entries );
	for ( dll_se = sl->sl_entries; dll_se != NULL;
		dll_se = dll_se->dll_next ) {
	    se = (struct sender_entry*)dll_se->dll_data;
	    /* tag env */
	    if ( env_jail_status( se->se_env, ENV_JAIL_PAROLEE ) != 0 ) {
		return( 1 );
	    }

	    /* re-queue queue */
	    if ( se->se_env->e_hq != NULL ) {
		/* se->se_env->e_hq->hq_priority++; */
		hq_deliver_pop( se->se_env->e_hq );
		if ( hq_deliver_push( se->se_env->e_hq, NULL,
			&tv_nowait ) != 0 ) {
		    return( 1 );
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
	    syslog( LOG_ERR, "Syserror simta_read_command readdir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	if ( closedir( sd->sd_dirp ) != 0 ) {
	    syslog( LOG_ERR, "Syserror simta_read_command closedir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	sd->sd_dirp = NULL;

	if ( simta_gettimeofday( &tv_stop ) != 0 ) {
	    return( 1 );
	}

	syslog( LOG_INFO, "Command Metric: cycle %d Commands %d seconds %d",
		sd->sd_cycle, sd->sd_entries,
		(int)(tv_stop.tv_sec - sd->sd_tv_start.tv_sec));

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
	    syslog( LOG_ERR, "Syserror simta_read_command snet_open %s: %m",
		    fname );
	}
	return( 1 );
    }

    if (( acav = acav_alloc()) == NULL ) {
	syslog( LOG_ERR, "Syserror simta_read_command acav_alloc: %m" );
	goto error;
    }

    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_DEBUG, "Command %s: unexpected EOF", entry->d_name );
	goto error;
    }

    if (( ac = acav_parse( acav, line, &av )) < 0 ) {
	syslog( LOG_ERR, "Syserror simta_read_command acav_parse: %m" );
	goto error;
    }

    if ( av[ 0 ] == NULL ) {
	syslog( LOG_DEBUG, "Command %s: line %d: NULL", entry->d_name, lineno );

    } else if ( strcasecmp( av[ 0 ], S_MESSAGE ) == 0 ) {
	if ( ac == 1 ) {
	    syslog( LOG_DEBUG, "Command %s: Message", entry->d_name );
	    env_log_metrics( simta_env_list );

	} else if ( ac == 2 ) {
	    syslog( LOG_DEBUG, "Command %s: Message %s", entry->d_name,
		    av[ 1 ]);
	    if ( mid_promote( av[ 1 ]) != 0 ) {
		goto error;
	    }

	} else {
	    syslog( LOG_DEBUG, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else if ( strcasecmp( av[ 0 ], S_SENDER ) == 0 ) {
	if ( ac == 1 ) {
	    syslog( LOG_DEBUG, "Command %s: Sender", entry->d_name );
	    sender_log_metrics( simta_sender_list );

	} else if ( ac == 2 ) {
	    syslog( LOG_DEBUG, "Command %s: Sender %s", entry->d_name, av[ 1 ]);
	    /* JAIL-ADD promote sender's mail */
	    if ( sender_promote( av[ 1 ]) != 0 ) {
		goto error;
	    }

	} else {
	    syslog( LOG_DEBUG, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else if ( strcasecmp( av[ 0 ], S_QUEUE ) == 0 ) {
	if ( ac == 1 ) {
	    syslog( LOG_DEBUG, "Command %s: Queue", entry->d_name );
	    queue_log_metrics( simta_deliver_q );
	} else if ( ac == 2 ) {
	    syslog( LOG_DEBUG, "Command %s: Queue %s", entry->d_name, av[ 1 ]);
	    if (( hq = host_q_lookup( av[ 1 ])) != NULL ) {
		hq_deliver_pop( hq );
		/* hq->hq_priority++; */
		/* promote all the envs in the queue */
		for ( e = hq->hq_env_head; e != NULL; e = e->e_hq_next ) {
		    if ( env_jail_status( e, ENV_JAIL_PAROLEE ) != 0 ) {
			return( 1 );
		    }
		}

		if ( hq_deliver_push( hq, NULL, &tv_nowait ) != 0 ) {
		    return( 1 );
		}
	    } else {
		syslog( LOG_DEBUG, "Queue %s: Not Found", av[ 1 ]);
	    }

	} else {
	    syslog( LOG_DEBUG, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else if ( strcasecmp( av[ 0 ], S_DEBUG ) == 0 ) {
	if ( ac == 1 ) {
	    syslog( LOG_DEBUG, "Command %s: Debug: %d", entry->d_name,
		    simta_debug );
	} else if ( ac == 2 ) {
	    int_arg = atoi( av[ 1 ]);
	    if ( int_arg >= 0 ) {
		simta_debug = int_arg;
		syslog( LOG_DEBUG, "Command %s: Debug set: %d", entry->d_name,
			simta_debug );
	    } else {
		syslog( LOG_DEBUG, "Command %s: Debug illegal arg: %d",
			entry->d_name, simta_debug );
	    }
	} else {
	    syslog( LOG_DEBUG, "Command %s: line %d: too many arguments",
		    entry->d_name, lineno );
	}

    } else {
	syslog( LOG_DEBUG, "Command %s: line %d: Unknown command: \"%s\"",
		entry->d_name, lineno, av[ 0 ]);
    }

    if ( snet_close( snet ) < 0 ) {
	syslog( LOG_ERR, "Syserror simta_read_command snet_close %s: %m",
		entry->d_name );
    }

    if ( unlink( fname ) != 0 ) {
	syslog( LOG_ERR, "Syserror simta_read_command unlink %s: %m", fname );
    }

    acav_free( acav );

    return( 0 );

error:
    if ( snet_close( snet ) < 0 ) {
	syslog( LOG_ERR, "Syserror simta_read_command snet_close %s: %m",
		entry->d_name );
    }

    acav_free( acav );

    return( 1 );
}


    void
env_log_metrics( struct dll_entry *dll_head )
{
    char		filename[ MAXPATHLEN ];
    int			fd;
    FILE		*f;
    struct dll_entry	*dll;
    struct envelope	*env;

    sprintf( filename, "%s/etc/mid_list", simta_base_dir );

    if (( fd = creat( filename, 0666 )) < 0 ) {
	syslog( LOG_DEBUG, "metric log file failed: creat %s: %m", filename );
	return;
    }

    if (( f = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_DEBUG, "metric log file failed: fdopen %s: %m", filename );
	return;
    }

    fprintf( f, "MID List:\n\n" );

    for ( dll = dll_head; dll != NULL; dll = dll->dll_next ) {
	env = (struct envelope*)dll->dll_data;
	fprintf( f, "%s\t%s\t%s\n", env->e_id, env->e_hostname, env->e_mail );
    }

    fclose( f );

    return;
}

    void
sender_log_metrics( struct dll_entry *dll_head )
{
    char		filename[ MAXPATHLEN ];
    int			fd;
    FILE		*f;
    struct dll_entry	*dll;
    struct sender_list	*sl;

    sprintf( filename, "%s/etc/sender_list", simta_base_dir );

    if (( fd = creat( filename, 0666 )) < 0 ) {
	syslog( LOG_DEBUG, "metric log file failed: creat %s: %m", filename );
	return;
    }

    if (( f = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_DEBUG, "metric log file failed: fdopen %s: %m", filename );
	return;
    }

    fprintf( f, "Sender List:\n\n" );

    for ( dll = dll_head; dll != NULL; dll = dll->dll_next ) {
	sl = (struct sender_list*)dll->dll_data;
	fprintf( f, "%s\t%d\n", dll->dll_key, sl->sl_n_entries );
    }

    fclose( f );

    return;
}
