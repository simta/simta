/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <dirent.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "envelope.h"
#include "header.h"
#include "simta.h"
#include "queue.h"


    int
main( int argc, char *argv[] )
{
    int						usage = 0;
    int						c;
    int						pidfd;
    int						server_pid;
    int						pid;
    FILE					*pf;
    struct timeval				tv_now;

    int						fd;
    FILE					*tff;
    char					tf[ MAXPATHLEN + 1 ];
    char					cf[ MAXPATHLEN + 1 ];
    char					*command = NULL;
    char					*arg1 = NULL;

    opterr = 0;

    simta_openlog( 0 );

    while (( c = getopt( argc, argv, "dmqs" )) != -1 ) {
	switch ( c ) {
	default:
	    usage++;
	    break;

	case 'd':
	    if ( command != NULL ) {
		usage++;
	    }
	    command = S_DEBUG;
	    break;

	case 'm':
	    if ( command != NULL ) {
		usage++;
	    }
	    command = S_MESSAGE;
	    break;

	case 'q':
	    if ( command != NULL ) {
		usage++;
	    }
	    command = S_QUEUE;
	    break;

	case 's':
	    if ( command != NULL ) {
		usage++;
	    }
	    command = S_SENDER;
	    break;
	}
    }

    if ( argc - optind == 0 ) {
	arg1 = NULL;
    } else if ( argc - optind == 1 ) {
	arg1 = argv[ optind ];
    } else {
	usage++;
    }

    if (( usage != 0 ) || ( command == NULL )) {
	fprintf( stderr, "Usage: %s -d | -m | -s | -q [ arg ] \n", argv[ 0 ] );
	exit( EX_USAGE );
    }

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	exit( EX_TEMPFAIL );
    }

    /* init simta config / defaults */
    if ( simta_config( ) != 0 ) {
	exit( EX_TEMPFAIL );
    }

    if (( pid = getpid()) < 0 ) {
	syslog( LOG_ERR, "env_id getpid: %m" );
	perror( "getpid" );
	exit( EX_TEMPFAIL );
    }

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	perror( "gettimeofday" );
	exit( EX_TEMPFAIL );
    }

    snprintf( tf, MAXPATHLEN, "%s/c%lX.%lX.%d", simta_dir_command, 
	    (unsigned long)tv_now.tv_sec, (unsigned long)tv_now.tv_usec, pid );

    snprintf( cf, MAXPATHLEN, "%s/C%lX.%lX.%d", simta_dir_command, 
	    (unsigned long)tv_now.tv_sec, (unsigned long)tv_now.tv_usec, pid );

    /* make tfile */
    if (( fd = open( tf, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	syslog( LOG_ERR, "%s open %s: %m", argv[ 0 ], tf );
	exit( EX_TEMPFAIL );
    }

    if (( tff = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "fdopen: %m" );
	close( fd );
	unlink( tf );
	exit( EX_TEMPFAIL );
    }

    if ( arg1 == NULL ) {
	printf( "%s\n", command );
	if ( fprintf( tff, "%s\n", command ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    perror( "fprintf" );
	    close( fd );
	    unlink( tf );
	    exit( EX_TEMPFAIL );
	}

    } else {
	printf( "%s %s\n", command, arg1 );
	if ( fprintf( tff, "%s %s\n", command, arg1 ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    perror( "fprintf" );
	    close( fd );
	    unlink( tf );
	    exit( EX_TEMPFAIL );
	}
    }

    if ( fclose( tff ) != 0 ) {
	syslog( LOG_ERR, "%m" );
	unlink( tf );
	exit( EX_TEMPFAIL );
    }

    if ( rename( tf, cf ) < 0 ) {
	syslog( LOG_ERR, "Syserror: rename %s %s: %m", tf, cf );
	perror( "rename" );
	unlink( tf );
	exit( EX_TEMPFAIL );
    }

    /* signal server */
    if (( pidfd = open( simta_file_pid, O_RDONLY, 0 )) < 0 ) {
	syslog( LOG_NOTICE, "open %s: %m", simta_file_pid );
	exit( EX_TEMPFAIL );
    }

    if (( pf = fdopen( pidfd, "r" )) == NULL ) {
	syslog( LOG_NOTICE, "fdopen %s: %m", simta_file_pid );
	exit( EX_TEMPFAIL );
    }

    fscanf( pf, "%d\n", &server_pid );

    if ( server_pid <= 0 ) {
	syslog( LOG_NOTICE, "illegal pid %s: %d", simta_file_pid, server_pid );
	exit( EX_TEMPFAIL );
    }

    if ( kill( server_pid, SIGUSR2 ) < 0 ) {
	syslog( LOG_NOTICE, "kill %d: %m", server_pid );
	exit( EX_TEMPFAIL );
    }

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
