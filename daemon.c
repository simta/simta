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
#include "simta.h"
#include "queue.h"

/* XXX testing purposes only, make paths configureable */
#define _PATH_SPOOL	"/var/spool/simta"

int		simsendmail_signal = 0;
int		simsendmail_pid = 0;
int		debug = 0;
int		backlog = 5;
int		connections = 0;
int		maxconnections = SIMTA_MAXCONNECTIONS;	/* 0 = no limit */

char			localhost[ MAXHOSTNAMELEN + 1 ];
struct stab_entry 	*hosts = NULL;

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

    while (( pid = waitpid( 0, &status, WNOHANG )) > 0 ) {
	/* if the pid isn't simsendmail's q runner, it's a connection */
	if ( pid == simsendmail_pid ) {
	    simsendmail_pid = 0;

	} else {
	    connections--;

	    if ( connections < 0 ) {
		/* XXX connections should never be less than 0 */
	    }
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
    struct servent	*se;
    int			c, s, err = 0, fd, sinlen;
    int			dontrun = 0;
    int			reuseaddr = 1;
    int			pidfd;
    char		*prog;
    char		*spooldir = _PATH_SPOOL;
    char		*cryptofile = NULL;
    fd_set		fdset;
    FILE		*pf;
    int			use_randfile = 0;
    unsigned short	port = 0;
    struct host		*host;
    extern int		optind;
    extern char		*optarg;

    if (( prog = strrchr( av[ 0 ], '/' )) == NULL ) {
	prog = av[ 0 ];
    } else {
	prog++;
    }

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

	case 'd' :		/* debug */
	    debug++;
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
	fprintf( stderr, " [ -cdrV ] [ -b backlog ]" );
	fprintf( stderr, " [ -C cryptofile ] [ -M maildomain ]" );
	fprintf( stderr, " [ -m max-connections ] [ -p port ]" );
	fprintf( stderr, " [ -s spooldir]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    if ( maxconnections < 0 ) {
	fprintf( stderr, "%d: invalid max-connections\n", maxconnections );
    }

    /*
     * Read config file before chdir(), in case config file is relative path.
     */

    if ( gethostname( localhost, MAXHOSTNAMELEN + 1 ) !=0 ) {
	perror( "gethostname" );
	exit( 1 );
    }

    /* Add localhost to hosts list */
    if (( host = malloc( sizeof( struct host ))) == NULL ) {
	perror( "malloc" );
	exit( 1 );
    }
    host->h_type = HOST_LOCAL;
    host->h_expansion = NULL;

    /* Add list of expansions */
    if ( ll_insert_tail( &(host->h_expansion), "alias", "alias" ) != 0 ) {
	perror( "ll_insert_tail" );
	exit( 1 );
    }
    if ( ll_insert_tail( &(host->h_expansion), "password", "password" ) != 0 ) {
	perror( "ll_insert_tail" );
	exit( 1 );
    }

    if ( ll_insert( &hosts, localhost, host, NULL ) != 0 ) {
	perror( "ll_insert" );
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
    if (( pidfd = open( SIMTA_PATH_PIDFILE, O_CREAT | O_WRONLY, 0644 )) < 0 ) {
	fprintf( stderr, "open %s: ", SIMTA_PATH_PIDFILE );
        perror( NULL );
        exit( 1 );
    }

    /* XXX LOCK pidfd */

    if ( ftruncate( pidfd, (off_t)0 ) < 0 ) {
        perror( "ftruncate" );
        exit( 1 );
    }

    /*
     * Disassociate from controlling tty.
     */
    if ( !debug ) {
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

    /*
     * Start logging.
     */
#ifdef ultrix
    openlog( prog, LOG_NOWAIT|LOG_PID );
#else /* ultrix */
    openlog( prog, LOG_NOWAIT|LOG_PID, LOG_SIMTA );
#endif /* ultrix */

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
    for (;;) {
	if ( simsendmail_signal != 0 ) {
	    /* XXX only one simsendmail q handler for now */
	    simsendmail_signal = 0;
	    if ( simsendmail_pid == 0 ) {
		switch ( simsendmail_pid = fork()) {
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

		    exit( q_runner( Q_RUNNER_LOCAL ));

		case -1 :
		    syslog( LOG_ERR, "fork: %m" );
		    break;

		default :
		    syslog( LOG_INFO, "q_runner local child %d for %s", c,
			    inet_ntoa( sin.sin_addr ));
		    break;
		}
	    } else {
		/* do nothing: simsendmail queue handler already running */
		/* XXX check to see if sendmail_pid is alive? */
	    }

	    if ( debug ) {
		printf( "simsendmail signaled\n" );
	    }
	}

	FD_ZERO( &fdset );
	FD_SET( s, &fdset );

	if ( select( s + 1, &fdset, NULL, NULL, NULL ) < 0 ) {
	    if ( errno != EINTR ) {
		syslog( LOG_ERR, "select: %m" );
		exit( 1 );

	    } else {
		continue;
	    }
	}

	if ( FD_ISSET( s, &fdset )) {
	    sinlen = sizeof( struct sockaddr_in );
	    if (( fd = accept( s, (struct sockaddr*)&sin, &sinlen )) < 0 ) {
		if ( errno != EINTR ) {
		    syslog( LOG_ERR, "accept: %m" );
		}
		continue;
	    }

	    connections++;
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
		close( fd );
		syslog( LOG_INFO, "receive child %d for %s", c,
			inet_ntoa( sin.sin_addr ));
		break;
	    }
	}
    }
}
