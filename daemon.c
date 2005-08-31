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
int		simta_daemon_child( int, int );
int		simta_wait_for_child( int );
int		simta_waitpid( void );

SSL_CTX		*ctx = NULL;

    void
usr1( int sig )
{
    simsendmail_signal = 1;

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
    child_signal++;

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
    struct timeval	tv_sleep;
    struct timeval	tv_now;
    struct timeval	tv_launch;
    struct servent	*se;
    int			launch_seconds;
    int			c, s_smtp, s_submission, err = 0;
#ifdef HAVE_LIBSSL
    int			s_smtps = 0;
#endif /* HAVE_LIBSSL */
    int			dontrun = 0;
    int			reuseaddr = 1;
    int			pidfd;
    int			q_run = 0;
    char		*prog;
    char		*spooldir = _PATH_SPOOL;
    fd_set		fdset;
    FILE		*pf;
    int			use_randfile = 0;
    unsigned short	port = 0;
    extern int		optind;
    extern char		*optarg;
    struct passwd	*simta_pw;
    char		*simta_uname = "simta";
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
	    simta_submission_port = 1;
	    break;

	case 'V' :		/* virgin */
	    printf( "%s\n", version );
	    exit( 0 );

        case 'w' :              /* authlevel 0:none, 1:serv, 2:client & serv */
            simta_authlevel = atoi( optarg );
            if (( simta_authlevel < 0 ) || ( simta_authlevel > 2 )) {
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
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_SIMTA );
#endif /*ultrix */

    if ( simta_read_config( config_fname ) < 0 ) {
        exit( 1 );
    }

    /* ignore SIGPIPE */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = SIG_IGN;
    if ( sigaction( SIGPIPE, &sa, NULL ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
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

    if ( simta_authlevel > 0 ) {
	if ( tls_server_setup( use_randfile, simta_authlevel, ca, cert,
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
	if (( s_smtp = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
	    perror( "socket" );
	    exit( 1 );
	}
	if ( reuseaddr ) {
	    if ( setsockopt( s_smtp, SOL_SOCKET, SO_REUSEADDR,
		    (void*)&reuseaddr, sizeof( int )) < 0 ) {
		perror("setsockopt");
	    }
	}
	memset( &sin, 0, sizeof( struct sockaddr_in ));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = port;
	if ( bind( s_smtp, (struct sockaddr *)&sin,
		sizeof( struct sockaddr_in )) < 0 ) {
	    perror( "bind" );
	    exit( 1 );
	}
	if ( listen( s_smtp, backlog ) < 0 ) {
	    perror( "listen" );
	    exit( 1 );
	}

#ifdef HAVE_LIBSSL
	if ( simta_authlevel > 0 ) {
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
	    if (( s_smtps = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
		perror( "socket" );
		exit( 1 );
	    }
	    if ( reuseaddr ) {
		if ( setsockopt( s_smtps, SOL_SOCKET, SO_REUSEADDR,
			(void*)&reuseaddr, sizeof( int )) < 0 ) {
		    perror("setsockopt");
		}
	    }
	    memset( &sin, 0, sizeof( struct sockaddr_in ));
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port = port;
	    if ( bind( s_smtps, (struct sockaddr *)&sin,
		    sizeof( struct sockaddr_in )) < 0 ) {
		perror( "bind" );
		exit( 1 );
	    }
	    if ( listen( s_smtps, backlog ) < 0 ) {
		perror( "listen" );
		exit( 1 );
	    }
	}
#endif /* HAVE_LIBSSL */

	if ( simta_submission_port ) {
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
	    if (( s_submission = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
		perror( "socket" );
		exit( 1 );
	    }
	    if ( reuseaddr ) {
		if ( setsockopt( s_submission, SOL_SOCKET, SO_REUSEADDR,
			(void*)&reuseaddr, sizeof( int )) < 0 ) {
		    perror("setsockopt");
		}
	    }
	    memset( &sin, 0, sizeof( struct sockaddr_in ));
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port = port;
	    if ( bind( s_submission, (struct sockaddr *)&sin,
		    sizeof( struct sockaddr_in )) < 0 ) {
		perror( "sub bind" );
		exit( 1 );
	    }
	    if ( listen( s_submission, backlog ) < 0 ) {
		perror( "listen" );
		exit( 1 );
	    }
	}

    }

    if ( q_run == 0 ) {
	/* open and truncate the pid file */
	if (( pidfd = open( SIMTA_FILE_PID, O_CREAT | O_WRONLY, 0644 )) < 0 ) {
	    fprintf( stderr, "open %s: ", SIMTA_FILE_PID );
	    perror( NULL );
	    exit( 1 );
	}

	/* lock simta pid fd */
	if ( lockf( pidfd, F_TLOCK, 0 ) != 0 ) {
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

	if ( ftruncate( pidfd, (off_t)0 ) < 0 ) {
	    perror( "ftruncate" );
	    exit( 1 );
	}
    }

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

    if ( q_run ) {
	exit( simta_wait_for_child( PROCESS_Q_SLOW ));
    } else if ( simta_filesystem_cleanup ) {
	exit( simta_wait_for_child( PROCESS_CLEANUP ));
    } else if ( simta_wait_for_child( PROCESS_CLEANUP ) != 0 ) {
	fprintf( stderr, "simta cleanup error, please check the log\n" );
	exit( 1 );
    }

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
	    dt = getdtablesize();
	    for ( i = 0; i < dt; i++ ) {
		/* keep socket & pidfd open */
		if (( i != s_smtp )
#ifdef HAVE_LIBSSL
			&& ( simta_authlevel > 0  && i != s_smtps )
#endif /* HAVE_LIBSSL */
			&& ( simta_submission_port && i != s_submission )
			&& ( i != pidfd )) {
		    (void)close( i );
		}
	    }
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
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_SIMTA );
#endif /*ultrix */

    if (( pf = fdopen( pidfd, "w" )) == NULL ) {
        syslog( LOG_ERR, "can't fdopen pidfd" );
        exit( 1 );
    }
    fprintf( pf, "%d\n", (int)getpid());
    if ( fflush( pf ) != 0 ) {
	syslog( LOG_ERR, "fflush: %m" );
	exit( 1 );
    }

    /* catch SIGHUP */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = hup;
    if ( sigaction( SIGHUP, &sa, &osahup ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    /* catch SIGCHLD */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = chld;
    if ( sigaction( SIGCHLD, &sa, &osachld ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    /* catch SIGUSR1 */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = usr1;
    if ( sigaction( SIGUSR1, &sa, &osausr1 ) < 0 ) {
	syslog( LOG_ERR, "sigaction: %m" );
	exit( 1 );
    }

    syslog( LOG_NOTICE, "restart %s", version );

    /*
     * Begin accepting connections.
     */

    tv_sleep.tv_sec = 0;
    tv_sleep.tv_usec = 0;

    tv_launch.tv_sec = 0;
    tv_launch.tv_usec = 0;

    /* main daemon loop */
    for (;;) {
	FD_ZERO( &fdset );
	FD_SET( s_smtp, &fdset );
#ifdef HAVE_LIBSSL
	if ( simta_authlevel > 0 ) {
	    FD_SET( s_smtps, &fdset );
	}
#endif /* HAVE_LIBSSL */
	if ( simta_submission_port ) {
	    FD_SET( s_submission, &fdset );
	}

	if (( simsendmail_signal == 0 ) && ( child_signal == 0 )) {
#ifdef HAVE_LIBSSL
	    if ( select( MAX( s_smtps, MAX( s_smtp, s_submission )) + 1,
#else /* HAVE_LIBSSL */
	    if ( select( MAX( s_smtp, s_submission ) + 1,
#endif /* HAVE_LIBSSL */
		    &fdset, NULL, NULL, &tv_sleep ) < 0 ) {
		if ( errno != EINTR ) {
		    syslog( LOG_ERR, "select: %m" );
		    abort();
		}
	    }
	}

	if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	    syslog( LOG_ERR, "gettimeofday: %m" );
	    abort();
	}

	/* compute sleep time */
	if (( tv_sleep.tv_sec = tv_launch.tv_sec - tv_now.tv_sec ) < 0 ) {
	    tv_sleep.tv_sec = 0;
	}

	/* check to see if any children need to be accounted for */
	if ( simta_waitpid() != 0 ) {
	    abort();
	}

	if ( child_signal > 0 ) {
	    child_signal = 0;
	    continue;
	}

	if (( tv_now.tv_sec > tv_launch.tv_sec ) ||
		( tv_now.tv_sec == tv_launch.tv_sec )) {
	    tv_launch.tv_sec = tv_now.tv_sec += launch_seconds;
	    tv_sleep.tv_sec = launch_seconds;

	    if ( simta_q_runner_slow < simta_q_runner_slow_max ) {
		simta_daemon_child( PROCESS_Q_SLOW, s_smtp );
	    }

	    continue;
	}

	if ( simsendmail_signal != 0 ) {
	    simsendmail_signal = 0;
	    if ( simta_q_runner_local < simta_q_runner_local_max ) {
		simta_daemon_child( PROCESS_Q_LOCAL, s_smtp );
	    }
	    continue;
	}

	/* check to see if we have any incoming connections */
	if ( FD_ISSET( s_smtp, &fdset )) {
	    simta_daemon_child( PROCESS_RECEIVE_SMTP, s_smtp );
	}
#ifdef HAVE_LIBSSL
	if ( simta_authlevel > 0 && FD_ISSET( s_smtps, &fdset )) {
	    simta_daemon_child( PROCESS_RECEIVE_SMTPS, s_smtps );
	}

#endif /* HAVE_LIBSSL */
	if ( simta_submission_port && FD_ISSET( s_submission, &fdset )) {
	    simta_daemon_child( PROCESS_RECEIVE_SUBMISSION, s_submission );
	}
    }
}


    int
simta_waitpid( void )
{
    int			pid;
    char		*p_name;
    int			status;
    int			exitstatus;
    struct proc_type	**p_search;
    struct proc_type	*p_remove;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	p_search = &proc_stab;

	for ( p_search = &proc_stab; *p_search != NULL;
		p_search = &((*p_search)->p_next)) {
	    if ((*p_search)->p_id == pid ) {
		break;
	    }
	}

	if ( *p_search == NULL ) {
	    syslog( LOG_ERR, "chld %d: unkown child process", pid );
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

	default:
	    syslog( LOG_ERR, "Child %d: done: unknown process type %d",
		    p_remove->p_id, p_remove->p_type );
	    return( 1 );
	}

	free( p_remove );

	if ( WIFEXITED( status )) {
	    exitstatus = WEXITSTATUS( status );

	    switch ( exitstatus ) {
	    case EXIT_OK:
		syslog( LOG_NOTICE, "Child %d: %s exited: %d", pid,
			p_name, exitstatus );
		break;

	    default:
		syslog( LOG_ERR, "Child %d: %s exited: %d", pid,
			p_name, exitstatus );
		return( 1 );
	    }

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child %d: %s died: signal %d", pid,
		    p_name, WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "Child %d: %s died", pid, p_name );
	    return( 1 );
	}
    }

    return( 0 );
}


    int
simta_wait_for_child( int child_type )
{
    int				pid;
    int				status;
    char			*p_name;

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "Syserror: q_cleanup fork: %m" );
	return( 1 );

    case 0 :
	switch ( child_type ) {
	case PROCESS_CLEANUP:
	    exit( q_cleanup());

	case PROCESS_Q_SLOW:
	    exit( q_runner_dir( simta_dir_slow ));

	default:
	    syslog( LOG_ERR,
		    "Syserror: wait_for_child: child_type out of range" );
	    exit( 1 );
	}

    default :
	switch ( child_type ) {
	case PROCESS_CLEANUP:
	    if ( simta_filesystem_cleanup ) {
		p_name = "filesystem clean";
		syslog( LOG_NOTICE, "Child %d: %s start", pid, p_name );
	    } else {
		p_name = "filesystem check";
		syslog( LOG_NOTICE, "Child %d: %s start", pid, p_name );
	    }
	    break;

	case PROCESS_Q_SLOW:
	    p_name = "single q_runner";
	    if ( simta_queue_filter ) {
		syslog( LOG_NOTICE, "Child %d: %s start: %s", pid, p_name,
			simta_queue_filter );
	    } else {
		syslog( LOG_NOTICE, "Child %d: %s start", pid, p_name );
	    }
	    break;

	default:
	    syslog( LOG_ERR, "Syserror: Child %d: start: type %d out of range",
		    pid, child_type );
	    break;
	}

	if ( waitpid( pid, &status, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: q_cleanup waitpid: %m" );
	    return( 1  );
	}

	if ( WIFEXITED( status )) {
	    syslog( LOG_NOTICE, "Child %d: %s exited: %d", pid, p_name,
		    WEXITSTATUS( status ));
	    return( WEXITSTATUS( status ));

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child %d: %s died: signal %d", pid, p_name,
		    WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "Child %d: %s died", pid, p_name );
	    return( 1 );
	}
    }
}


    int
simta_daemon_child( int process_type, int s )
{
    struct sockaddr_in	sin;
    struct proc_type	*p;
    int			pid;
    int			fd;
    int			sinlen;

    switch ( process_type ) {
    case PROCESS_Q_LOCAL:
    case PROCESS_Q_SLOW:
	break;

    case PROCESS_RECEIVE_SMTP:
    case PROCESS_RECEIVE_SMTPS:
    case PROCESS_RECEIVE_SUBMISSION:
	if (( fd = accept( s, (struct sockaddr*)&sin, &sinlen )) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_daemon_child accept: %m" );
	    return( 1 );
	}
	break;

    default:
	syslog( LOG_ERR, "Syserror: simta_daemon_child process_type 3 "
		"out of range: %d", process_type );
	return( 1 );
    }

    switch ( pid = fork()) {
    case 0 :
	close( s );
	/* reset USR1, CHLD and HUP */
	if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_daemon_child sigaction 1: %m" );
	    exit( EXIT_OK );
	}
	if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_daemon_child sigaction 2: %m" );
	    exit( EXIT_OK );
	}
	if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror: simta_daemon_child sigaction 3: %m" );
	    exit( EXIT_OK );
	}

	simta_process_type = process_type;

	switch ( process_type ) {
	case PROCESS_Q_LOCAL:
	    exit( q_runner_dir( simta_dir_local ));
	    break;

	case PROCESS_Q_SLOW:
	    exit( q_runner_dir( simta_dir_slow ));
	    break;

	case PROCESS_RECEIVE_SMTP:
	case PROCESS_RECEIVE_SMTPS:
	case PROCESS_RECEIVE_SUBMISSION:
	    exit( smtp_receive( fd, &sin ));
	    break;

	default:
	    syslog( LOG_ERR, "Syserror: simta_daemon_child process_type 2 "
		    "out of range: %d", process_type );
	    return( 1 );
	}

	syslog( LOG_ERR, "Syserror: simta_daemon_child unreachable code" );
	exit( EXIT_OK );

    case -1 :
	syslog( LOG_ERR, "Syserror: simta_daemon_child fork: %m" );
	abort();

    default :
	/* here we are the server.  this is ok */
	break;
    }

    switch ( process_type ) {
    case PROCESS_Q_LOCAL:
	simta_q_runner_local++;
	syslog( LOG_NOTICE, "Child %d: start: q_runner local", pid );
	break;

    case PROCESS_Q_SLOW:
	simta_q_runner_slow++;
	syslog( LOG_NOTICE, "Child %d: start: q_runner slow", pid );
	break;

    case PROCESS_RECEIVE_SMTP:
	close( fd );
	simta_receive_connections++;
	syslog( LOG_NOTICE, "Child %d: start: receive smtp: %s", pid,
		inet_ntoa( sin.sin_addr ));
	break;

    case PROCESS_RECEIVE_SMTPS:
	close( fd );
	simta_receive_connections++;
	syslog( LOG_NOTICE, "Child %d: start: receive smtps: %s", pid,
		inet_ntoa( sin.sin_addr ));
	break;

    case PROCESS_RECEIVE_SUBMISSION:
	close( fd );
	simta_receive_connections++;
	syslog( LOG_NOTICE, "Child %d: start: receive submission: %s", pid,
		inet_ntoa( sin.sin_addr ));
	break;

    default:
	syslog( LOG_ERR, "Syserror: simta_daemon_child process_type 3 "
		"out of range: %d", process_type );
	return( 1 );
    }

    if (( p = (struct proc_type*)malloc(
	    sizeof( struct proc_type ))) == NULL ) {
	syslog( LOG_ERR, "Syserror: simta_daemon_child malloc: %m" );
	return( 1 );
    }
    memset( p, 0, sizeof( struct proc_type ));

    p->p_id = pid;
    p->p_type = process_type;
    p->p_next = proc_stab;
    proc_stab = p;

    return( 0 );
}
