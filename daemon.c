/*
 * Copyright (c) 1999 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include "ll.h"
#include "receive.h"
#include "queue.h"
#include "q_cleanup.h"
#include "envelope.h"
#include "simta.h"

/* XXX testing purposes only, make paths configureable */
#define _PATH_SPOOL	"/var/spool/simta"

struct proc_type {
    struct proc_type	*p_next;
    int			p_id;
    int			p_type;
};

#define Q_LOCAL		1
#define Q_SLOW		2
#define SIMTA_CHILD	3

struct proc_type	*proc_stab = NULL;
int		q_runner_local = 0;
int		q_runner_slow = 0;

int		simsendmail_signal = 0;
int		backlog = 5;
int		connections = 0;
int		maxconnections = SIMTA_MAXCONNECTIONS;	/* 0 = no limit */

char		*maildomain = NULL;
char		*version = VERSION;

void		usr1 ___P(( int ));
void		hup ___P(( int ));
void		chld ___P(( int ));
int		main ___P(( int, char *av[] ));

    void
usr1( sig )
    int			sig;
{
    simsendmail_signal = 1;
}

    void
hup( sig )
    int			sig;
{
    syslog( LOG_INFO, "reload %s", version );
}

    void
chld( sig )
    int			sig;
{
    int			pid, status;
    extern int		errno;
    struct proc_type	**p;
    struct proc_type	*p_remove;

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	p = &proc_stab;

	for ( p = &proc_stab; *p != NULL; p = &((*p)->p_next)) {
	    if ((*p)->p_id == pid ) {
		break;
	    }
	}

	if ( *p != NULL ) {
	    p_remove = *p;
	    *p = p_remove->p_next;

	    switch( p_remove->p_type ) {
	    case Q_LOCAL:
		q_runner_local--;
		break;
	    case Q_SLOW:
		q_runner_slow--;
		break;
	    case SIMTA_CHILD:
		connections--;
		break;
	    default:
		syslog( LOG_ERR, "%d: unknown process type", p_remove->p_type );
		exit( 1 );
	    }

	    free( p_remove );
	} else {
	    syslog( LOG_ERR, "%d: unkown child process", pid );
	    exit( 1 );
	}

	if ( WIFEXITED( status )) {
	    if ( WEXITSTATUS( status )) {
		syslog( LOG_ERR, "child %d exited with %d", pid,
			WEXITSTATUS( status ));
	    } else {
		syslog( LOG_INFO, "child %d done", pid );
	    }
	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "child %d died on signal %d", pid,
		    WTERMSIG( status ));
	} else {
	    syslog( LOG_ERR, "child %d died", pid );
	}
    }

    if ( pid < 0 && errno != ECHILD ) {
	syslog( LOG_ERR, "wait3: %m" );
	exit( 1 );
    }
    return;
}

SSL_CTX		*ctx = NULL;

    int
main( ac, av )
    int		ac;
    char	*av[];
{
    struct sigaction	sa, osahup, osachld, osausr1;
    struct sockaddr_in	sin;
    struct timeval	tv_sleep;
    struct timeval	tv_now;
    struct timeval	tv_launch;
    struct servent	*se;
    struct proc_type	*p;
    int			cleanup = 1;
    int			launch_seconds;
    int			q_runner_local_max;
    int			q_runner_slow_max;
    int			c, s, err = 0, fd, sinlen;
    int			dontrun = 0;
    int			reuseaddr = 1;
    int			pid;
    int			pidfd;
    int			q_run = 0;
    char		*prog;
    char		*spooldir = _PATH_SPOOL;
    char		*cryptofile = NULL;
    fd_set		fdset;
    FILE		*pf;
    int			use_randfile = 0;
    unsigned short	port = 0;
    extern int		optind;
    extern char		*optarg;

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

    /* XXX make these options, etc */
    q_runner_local_max = SIMTA_MAX_RUNNERS_LOCAL;
    q_runner_slow_max = SIMTA_MAX_RUNNERS_SLOW;
    launch_seconds = 60 * 5;

    while (( c = getopt( ac, av, "b:C:cdM:m:p:rs:V" )) != -1 ) {
	switch ( c ) {
	case 'b' :		/* listen backlog */
	    backlog = atoi( optarg );
	    break;

	case 'C' :
	    cryptofile = optarg;
	    break;

	case 'c' :		/* check config files */
	    dontrun++;
	    break;

	case 'd' :		/* simta_debug */
	    simta_debug++;
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
	    q_run++;
	    break;

	case 'r' :
	    use_randfile = 1;
	    break;

	case 's' :		/* spool dir */
	    spooldir = optarg;
	    break;

	case 'V' :		/* virgin */
	    printf( "%s\n", version );
	    exit( 0 );

	default :
	    err++;
	}
    }

    if ( err || optind != ac ) {
	fprintf( stderr, "Usage:\t%s", prog );
	fprintf( stderr, " [ -cdrVq ] [ -b backlog ]" );
	fprintf( stderr, " [ -C cryptofile ] [ -M maildomain ]" );
	fprintf( stderr, " [ -m max-connections ] [ -p port ]" );
	fprintf( stderr, " [ -s spooldir]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    if ( maxconnections < 0 ) {
	fprintf( stderr, "%d: invalid max-connections\n", maxconnections );
    }

    /* openlog now, as some support functions require it. */
#ifdef ultrix
    openlog( prog, LOG_NOWAIT|LOG_PID );
#else /* ultrix */
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_SIMTA );
#endif /*ultrix */

    /*
     * Read config file before chdir(), in case config file is relative path.
     */

    /* init simta config / defaults */
    if ( simta_config() != 0 ) {
	exit( 1 );
    }

    if ( chdir( spooldir ) < 0 ) {
	perror( spooldir );
	exit( 1 );
    }

    if ( cryptofile != NULL ) {
	SSL_load_error_strings();
	SSL_library_init();

	if ( use_randfile ) {
	    char        randfile[ MAXPATHLEN ];

	    if ( RAND_file_name( randfile, sizeof( randfile )) == NULL ) {
		fprintf( stderr, "RAND_file_name: %s\n",
			ERR_error_string( ERR_get_error(), NULL ));
		exit( 1 );
	    }
	    if ( RAND_load_file( randfile, -1 ) <= 0 ) {
		fprintf( stderr, "RAND_load_file: %s: %s\n", randfile,
			ERR_error_string( ERR_get_error(), NULL ));
		exit( 1 );
	    }
	    if ( RAND_write_file( randfile ) < 0 ) {
		fprintf( stderr, "RAND_write_file: %s: %s\n", randfile,
			ERR_error_string( ERR_get_error(), NULL ));
		exit( 1 );
	    }
	}

	if (( ctx = SSL_CTX_new( SSLv23_server_method())) == NULL ) {
	    fprintf( stderr, "SSL_CTX_new: %s\n",
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}

	if ( SSL_CTX_use_PrivateKey_file( ctx, "CERT.pem", SSL_FILETYPE_PEM )
		!= 1 ) {
	    fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		    cryptofile, ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	if ( SSL_CTX_use_certificate_chain_file( ctx, "CERT.pem" ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		    cryptofile, ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	if ( SSL_CTX_check_private_key( ctx ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}

	if ( SSL_CTX_load_verify_locations( ctx, "CA.pem", NULL ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
		    cryptofile, ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	SSL_CTX_set_verify( ctx,
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL );
    }


    if ( dontrun ) {
	exit( 0 );
    }

    if ( q_run != 0 ) {
	exit( q_runner_dir( SIMTA_DIR_SLOW ));
    }

    if ( port == 0 ) {
	if (( se = getservbyname( "smtp", "tcp" )) == NULL ) {
	    fprintf( stderr, "%s: can't find smtp service\n%s: continuing...\n",
		    prog, prog );
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
    if ( bind( s, (struct sockaddr *)&sin, sizeof( struct sockaddr_in )) < 0 ) {
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

    /* lock envelope fd for delivery attempt */
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

    if ( cleanup != 0 ) {
	if ( q_cleanup() != 0 ) {
	    exit( 1 );
	}
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

    if (( pf = fdopen( pidfd, "w" )) == NULL ) {
        syslog( LOG_ERR, "can't fdopen pidfd" );
        exit( 1 );
    }
    fprintf( pf, "%d\n", (int)getpid());
    fclose( pf );

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

    syslog( LOG_INFO, "restart %s", version );

    /*
     * Begin accepting connections.
     */

    tv_sleep.tv_sec = 0;
    tv_sleep.tv_usec = 0;

    tv_launch.tv_sec = 0;
    tv_launch.tv_usec = 0;

    for (;;) {
	if ( simsendmail_signal != 0 ) {
	    simsendmail_signal = 0;

	    if ( q_runner_local < q_runner_local_max ) {
		switch ( pid = fork()) {
		case 0 :
		    close( s );

		    /* reset USR1, CHLD and HUP */
		    if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
			syslog( LOG_ERR, "sigaction: %m" );
			exit( 1 );
		    }
		    if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
			syslog( LOG_ERR, "sigaction: %m" );
			exit( 1 );
		    }
		    if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
			syslog( LOG_ERR, "sigaction: %m" );
			exit( 1 );
		    }

		    exit( q_runner_dir( SIMTA_DIR_LOCAL ));

		case -1 :
		    syslog( LOG_ERR, "fork: %m" );
		    break;

		default :
		    if (( p = (struct proc_type*)malloc(
			    sizeof( struct proc_type ))) == NULL ) {
			syslog( LOG_ERR, "malloc: %m" );
			exit( 1 );
		    }

		    p->p_id = pid;
		    p->p_type = Q_LOCAL;
		    p->p_next = proc_stab;
		    proc_stab = p;

		    syslog( LOG_INFO, "q_runner_dir.local child %d", pid );
		    break;
		}
	    }
	}

	FD_ZERO( &fdset );
	FD_SET( s, &fdset );

	if ( select( s + 1, &fdset, NULL, NULL, &tv_sleep ) < 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR, "select: %m" );
		exit( 1 );

	    } else {
		if ( gettimeofday( &tv_now, NULL ) != 0 ) {
		    syslog( LOG_ERR, "gettimeofday: %m" );
		    exit( 1 );
		}

		if (( tv_sleep.tv_sec = tv_launch.tv_sec - tv_now.tv_sec )
			< 1 ) {
		    tv_sleep.tv_sec = 1;
		}
		tv_sleep.tv_usec = 0;

		continue;
	    }
	}

	/* check to see if we need to launch q_runner_dir( SIMTA_DIR_SLOW ) */
	if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	    syslog( LOG_ERR, "gettimeofday: %m" );
	    exit( 1 );
	}

	if (( tv_now.tv_sec > tv_launch.tv_sec ) ||
		(( tv_now.tv_sec == tv_launch.tv_sec ) &&
		( tv_now.tv_usec >= tv_launch.tv_usec ))) {
	    /* launch q_runner */
	    if ( q_runner_slow < q_runner_slow_max ) {
		switch ( pid = fork()) {
		case 0 :
		    close( s );

		    /* reset USR1, CHLD and HUP */
		    if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
			syslog( LOG_ERR, "sigaction: %m" );
			exit( 1 );
		    }
		    if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
			syslog( LOG_ERR, "sigaction: %m" );
			exit( 1 );
		    }
		    if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
			syslog( LOG_ERR, "sigaction: %m" );
			exit( 1 );
		    }

		    exit( q_runner_dir( SIMTA_DIR_SLOW ));

		case -1 :
		    syslog( LOG_ERR, "fork: %m" );
		    break;

		default :
		    if (( p = (struct proc_type*)malloc(
			    sizeof( struct proc_type ))) == NULL ) {
			syslog( LOG_ERR, "malloc: %m" );
			exit( 1 );
		    }

		    p->p_id = pid;
		    p->p_type = Q_SLOW;
		    p->p_next = proc_stab;
		    proc_stab = p;

		    syslog( LOG_INFO, "q_runner_dir.slow child %d", pid );
		    break;
		}
	    }

	    tv_launch.tv_sec = tv_now.tv_sec += launch_seconds;
	    tv_launch.tv_usec = tv_now.tv_usec;

	    /* XXX continue, or check to see if FD_ISSET? */
	    continue;

	} else {
	    /* compute sleep time */
	    if (( tv_sleep.tv_sec = tv_launch.tv_sec - tv_now.tv_sec ) < 1 ) {
		tv_sleep.tv_sec = 1;
	    }
	    tv_sleep.tv_usec = 0;
	}

	if ( FD_ISSET( s, &fdset )) {
	    sinlen = sizeof( struct sockaddr_in );
	    if (( fd = accept( s, (struct sockaddr*)&sin, &sinlen )) < 0 ) {
		if ( errno != EINTR ) {
		    syslog( LOG_ERR, "accept: %m" );
		}
		continue;
	    }

	    /* start child */
	    switch ( c = fork()) {
	    case 0 :
		close( s );

		/* reset USR1, CHLD and HUP */
		if ( sigaction( SIGCHLD, &osachld, 0 ) < 0 ) {
		    syslog( LOG_ERR, "sigaction: %m" );
		    exit( 1 );
		}
		if ( sigaction( SIGHUP, &osahup, 0 ) < 0 ) {
		    syslog( LOG_ERR, "sigaction: %m" );
		    exit( 1 );
		}
		if ( sigaction( SIGUSR1, &osausr1, 0 ) < 0 ) {
		    syslog( LOG_ERR, "sigaction: %m" );
		    exit( 1 );
		}

		exit( receive( fd, &sin ));

	    case -1 :
		/*
		 * We don't tell the client why we're closing -- they will
		 * queue mail and try later.  We don't sleep() because we'd
		 * like to cause as much mail as possible to queue on remote
		 * hosts, thus spreading out load on our (memory bound) server.
		 */
		close( fd );
		syslog( LOG_ERR, "fork: %m" );
		break;

	    default :
		connections++;

		if (( p = (struct proc_type*)malloc(
			sizeof( struct proc_type ))) == NULL ) {
		    syslog( LOG_ERR," malloc: %m" );
		    /* XXX - should we exit or break? */
		    break;
		}
		p->p_id = c;
		p->p_type = SIMTA_CHILD;
		p->p_next = proc_stab;
		proc_stab = p;

		close( fd );
		syslog( LOG_INFO, "receive child %d for %s", c,
			inet_ntoa( sin.sin_addr ));
		break;
	    }
	}
    }
}
