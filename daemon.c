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

#define CHILD_Q_LOCAL		1
#define CHILD_Q_SLOW		2
#define CHILD_RECEIVE		3

struct proc_type	*proc_stab = NULL;
int		q_runner_local = 0;
int		q_runner_slow = 0;

int		simsendmail_signal = 0;
int		child_signal = 0;
int		backlog = 5;
int		connections = 0;
int		maxconnections = SIMTA_MAXCONNECTIONS;	/* 0 = no limit */
struct sigaction	sa, osahup, osachld, osausr1;

char		*maildomain = NULL;
char		*version = VERSION;

void		usr1( int );
void		hup ( int );
void		chld( int );
int		main( int, char *av[] );
void		simta_daemon_child( int, int );

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

    int
main( int ac, char **av )
{
    struct sockaddr_in	sin;
    struct timeval	tv_sleep;
    struct timeval	tv_now;
    struct timeval	tv_launch;
    struct servent	*se;
    int			pid;
    int			launch_seconds;
    int			q_runner_local_max;
    int			q_runner_slow_max;
    int			c, s, err = 0;
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
    int			authlevel = 0;
    char                *ca = "cert/ca.pem";
    char                *cert = "cert/cert.pem";
    char                *privatekey = "cert/cert.pem";
    int			status;
    int			exitstatus;
    struct proc_type	**p_search;
    struct proc_type	*p_remove;

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

    /* XXX make these options, etc */
    q_runner_local_max = SIMTA_MAX_RUNNERS_LOCAL;
    q_runner_slow_max = SIMTA_MAX_RUNNERS_SLOW;
    launch_seconds = 60 * 10;

    while (( c = getopt( ac, av, " ab:cCdD:f:Im:M:p:qrRs:Vw:x:y:z:" )) != -1 ) {
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
	    simta_filesystem_cleanup++;
	    break;

	case 'd':
	    break;

	case 'D' :
	    config_base_dir = optarg;
	    break;

	case 'f' :
	    config_fname = optarg;
	    break;

	case 'I' :
	    simta_ignore_reverse = 1;
	    break;

	case 'M' :
	    maildomain = optarg;
	    break;

	case 'm' :		/* Max connections */
	    maxconnections = atoi( optarg );
	    break;

	case 'p' :		/* TCP port */
	    port = htons( atoi( optarg ));
	    break;

	case 'q' :
	    /* q_runner option: just run slow queue */
	    q_run++;
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

	case 'S' :		/* don't sync */
	    simta_no_sync = 1;
	    break;

	case 'V' :		/* virgin */
	    printf( "%s\n", version );
	    exit( 0 );

        case 'w' :              /* authlevel 0:none, 1:serv, 2:client & serv */
            authlevel = atoi( optarg );
            if (( authlevel < 0 ) || ( authlevel > 2 )) {
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
	fprintf( stderr, " [ -acdrVq ] [ -b backlog ]" );
	fprintf( stderr, " [ -M maildomain ]" );
	fprintf( stderr, " [ -m max-connections ] [ -p port ]" );
	fprintf( stderr, " [ -s spooldir]" );
	fprintf( stderr, " [ -w authlevel ] [ -x ca-pem-file ]" );
        fprintf( stderr, " [ -y cert-pem-file] [ -z key-pem-file ]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    if ( simta_read_config( config_fname ) < 0 ) {
        exit( 1 );
    }

    if ( maxconnections < 0 ) {
	fprintf( stderr, "%d: invalid max-connections\n", maxconnections );
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

    if ( chdir( spooldir ) < 0 ) {
	perror( spooldir );
	exit( 1 );
    }

    /* init simta config / defaults */
    if ( simta_config( config_base_dir ) != 0 ) {
	exit( 1 );
    }

    if ( authlevel > 0 ) {
	if ( tls_server_setup( use_randfile, authlevel, ca, cert,
		privatekey ) != 0 ) {
	    exit( 1 );
	}
	simta_tls = 1;
	simta_smtp_extension++;
    }

    if ( dontrun ) {
	exit( 0 );
    }

    if ( q_run == 0 ) {
	if ( port == 0 ) {
	    if (( se = getservbyname( "smtp", "tcp" )) == NULL ) {
		fprintf( stderr, "%s: can't find smtp service: continuing\n",
			prog );
		port = htons( 25 );
	    } else {
		port = se->s_port;
	    }
	}

	/*
	 * Set up listener.
	 */
	if (( s = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
	    perror( "socket" );
	    exit( 1 );
	}
	if ( reuseaddr ) {
	    if ( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (void*)&reuseaddr,
		    sizeof( int )) < 0 ) {
		perror("setsockopt");
	    }
	}

	memset( &sin, 0, sizeof( struct sockaddr_in ));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = port;
	if ( bind( s, (struct sockaddr *)&sin,
		sizeof( struct sockaddr_in )) < 0 ) {
	    perror( "bind" );
	    exit( 1 );
	}
	if ( listen( s, backlog ) < 0 ) {
	    perror( "listen" );
	    exit( 1 );
	}

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

    /* close the log fd gracefully before we daemonize */
    /* XXX do this after setgid and setuid for error logging purposes? */
    closelog();

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
		if (( i != s ) && ( i != pidfd )) {
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

    if ( q_cleanup() != 0 ) {
	exit( 1 );
    }

    if ( simta_filesystem_cleanup != 0 ) {
	exit( 0 );
    }

    if ( q_run != 0 ) {
	exit( q_runner_dir( simta_dir_slow ));
    }

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

    /* ignore SIGPIPE */
    memset( &sa, 0, sizeof( struct sigaction ));
    sa.sa_handler = SIG_IGN;
    if ( sigaction( SIGPIPE, &sa, NULL ) < 0 ) {
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
	FD_SET( s, &fdset );

	if (( simsendmail_signal == 0 ) && ( child_signal == 0 )) {
	    if ( select( s + 1, &fdset, NULL, NULL, &tv_sleep ) < 0 ) {
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
		panic( "unknown process" );
	    }

	    p_remove = *p_search;
	    *p_search = p_remove->p_next;

	    switch ( p_remove->p_type ) {
	    case CHILD_Q_LOCAL:
		syslog( LOG_NOTICE, "chld %d: q_runner.local done",
			p_remove->p_id );
		q_runner_local--;
		break;

	    case CHILD_Q_SLOW:
		syslog( LOG_NOTICE, "chld %d: q_runner.slow done",
			p_remove->p_id );
		q_runner_slow--;
		break;

	    case CHILD_RECEIVE:
		syslog( LOG_NOTICE, "chld %d: daemon.receive done",
			p_remove->p_id );
		connections--;
		break;

	    default:
		syslog( LOG_ERR, "chld %d: unknown process type %d",
			p_remove->p_id, p_remove->p_type );
		panic( "bad process type" );
	    }

	    free( p_remove );

	    if ( WIFEXITED( status )) {
		exitstatus = WEXITSTATUS( status );

		switch ( exitstatus ) {
		case EXIT_OK:
		    break;

		default:
		    syslog( LOG_ERR, "chld %d: exited %d", pid, exitstatus );
		    exit( 1 );
		}

	    } else if ( WIFSIGNALED( status )) {
		syslog( LOG_ERR, "chld %d died on signal %d", pid,
			WTERMSIG( status ));
		exit( 1 );

	    } else {
		syslog( LOG_ERR, "chld %d died", pid );
		exit( 1 );
	    }
	}

	if ( child_signal > 0 ) {
	    child_signal = 0;
	    continue;
	}

	if (( tv_now.tv_sec > tv_launch.tv_sec ) ||
		( tv_now.tv_sec == tv_launch.tv_sec )) {
	    tv_launch.tv_sec = tv_now.tv_sec += launch_seconds;
	    tv_sleep.tv_sec = launch_seconds;

	    if ( q_runner_slow < q_runner_slow_max ) {
		simta_daemon_child( CHILD_Q_SLOW, s );
	    }

	    continue;
	}

	if ( simsendmail_signal != 0 ) {
	    simsendmail_signal = 0;
	    if ( q_runner_local < q_runner_local_max ) {
		simta_daemon_child( CHILD_Q_LOCAL, s );
	    }
	    continue;
	}

	/* check to see if we have any incoming connections */
	if ( FD_ISSET( s, &fdset )) {
	    simta_daemon_child( CHILD_RECEIVE, s );
	}
    }
}


    void
simta_daemon_child( int type, int s )
{
    struct sockaddr_in	sin;
    struct proc_type	*p;
    int			pid;
    int			fd;
    int			sinlen;

    if (( p = (struct proc_type*)malloc(
	    sizeof( struct proc_type ))) == NULL ) {
	syslog( LOG_ERR, "malloc: %m" );
	abort();
    }

    memset( p, 0, sizeof( struct proc_type ));

    switch ( type ) {
    case CHILD_Q_LOCAL:
	p->p_type = CHILD_Q_LOCAL;
	break;

    case CHILD_Q_SLOW:
	p->p_type = CHILD_Q_SLOW;
	break;

    case CHILD_RECEIVE:
	p->p_type = CHILD_RECEIVE;
	if (( fd = accept( s, (struct sockaddr*)&sin, &sinlen )) < 0 ) {
	    free( p );
	    return;
	}
	break;

    default:
	panic( "simta_daemon_child type out of range" );
    }

    p->p_next = proc_stab;
    proc_stab = p;

    switch ( pid = fork()) {
    case 0 :
	close( s );
	/* reset USR1, CHLD and HUP */
	if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
	    syslog( LOG_ERR, "sigaction: %m" );
	    exit( EXIT_OK );
	}
	if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
	    syslog( LOG_ERR, "sigaction: %m" );
	    exit( EXIT_OK );
	}
	if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
	    syslog( LOG_ERR, "sigaction: %m" );
	    exit( EXIT_OK );
	}

	switch ( type ) {
	case CHILD_Q_LOCAL:
	    exit( q_runner_dir( simta_dir_local ));
	    break;

	case CHILD_Q_SLOW:
	    exit( q_runner_dir( simta_dir_slow ));
	    break;

	case CHILD_RECEIVE:
	    exit( smtp_receive( fd, &sin ));
	    break;

	default:
	    panic( "simta_daemon_child type out of range" );
	}

    case -1 :
	syslog( LOG_ERR, "fork: %m" );
	abort();

    default :
	switch ( type ) {
	case CHILD_Q_LOCAL:
	    q_runner_local++;
	    syslog( LOG_NOTICE, "q_runner_dir.local child %d", pid );
	    break;

	case CHILD_Q_SLOW:
	    q_runner_slow++;
	    syslog( LOG_NOTICE, "q_runner_dir.slow child %d", pid );
	    break;

	case CHILD_RECEIVE:
	    close( fd );
	    connections++;
	    syslog( LOG_NOTICE, "receive child %d for %s", pid,
		    inet_ntoa( sin.sin_addr ));
	    break;

	default:
	    panic( "simta_daemon_child type out of range" );
	}

	p->p_id = pid;
	break;
    }

    return;
}
