/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <sysexits.h>
#include <utime.h>

#include <denser.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "envelope.h"
#include "dns.h"
#include "simta.h"

#define SIMRBL_EXIT_NOT_BLOCKED	0
#define SIMRBL_EXIT_BLOCKED	1
#define SIMRBL_EXIT_ERROR	2

const char	    *simta_progname = "simrbl";

    int
main( int argc, char *argv[])
{
    extern int          optind;
    extern char         *optarg;
    int			c;
    char		*server = NULL;
    char		*rbl_msg = NULL;
    int			rc;
    int			err = 0;
    int			quiet = 0;
    int			nolog = 0;
    int			exclusive = 0;
    int			check_text = 0;
    struct addrinfo	hints;
    struct addrinfo	*ai;
    struct rbl		*rbl_found;
    struct timeval	tv_now;

    while(( c = getopt( argc, argv, "dil:ns:tq" )) != -1 ) {
	switch( c ) {
	case 'd':
	    simta_debug++;
	    break;

	case 'i':
	    if ( exclusive != 0 ) {
		err++;
		break;
	    }
	    exclusive++;
	    break;

	case 'l':
	    rbl_add( &simta_rbls, RBL_BLOCK, optarg, "none" );
	    break;

	case 'n':
	    nolog = 1;
	    break;

	case 'q':
	    quiet++;
	    break;

	case 's':
	    server = optarg;
	    break;

	case 't':
	    if ( exclusive != 0 ) {
		err++;
		break;
	    }
	    exclusive++;
	    check_text = 1;
	    break;

	default:
	    err++;
	    break;
	}
    }

    if (( argc - optind ) != 1 ) {
	err++;
    }

    if ( err ) {
	fprintf( stderr, "Usage: %s ", argv[ 0 ] );
	fprintf( stderr, "[ -dq ] " );
	fprintf( stderr, "[ -l rbl-domain ] " );
	fprintf( stderr, "[ -s server ] " );
	fprintf( stderr, "([ -i ] address | -t text )\n" );
	exit( EX_USAGE );
    }

    if ( server != NULL ) {
	if (( simta_dnsr = dnsr_new( )) == NULL ) {
	    perror( "dnsr_new" );
	    exit( SIMRBL_EXIT_ERROR );
	}
	if (( rc = dnsr_nameserver( simta_dnsr, server )) != 0 ) {
	    dnsr_perror( simta_dnsr, "dnsr_nameserver" );
	    exit( SIMRBL_EXIT_ERROR );
	}
	if ( simta_debug > 1 ) {
	    fprintf( stderr, "using nameserver: %s\n", server );
	}
    }

    if ( nolog == 0 ) {
	/* call simta_gettimeofday() to initialize simta_tv_now */
	simta_gettimeofday( &tv_now );
	simta_openlog( 0, 0 );
    }

    if ( simta_rbls == NULL ) {
	rbl_add( &simta_rbls, RBL_BLOCK, "mx-deny.dnsbl", "none" );
    }

    if ( check_text == 0 ) {
	memset( &hints, 0, sizeof( struct addrinfo ));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	if (( rc = getaddrinfo( argv[ optind ], NULL, &hints, &ai )) != 0 ) {
	    fprintf( stderr, "Syserror: getaddrinfo: %s\n", gai_strerror( rc ));
	    exit( SIMRBL_EXIT_ERROR );
	}

	if (( rc = rbl_check( simta_rbls, ai->ai_addr, NULL, NULL, &rbl_found,
		&rbl_msg )) == RBL_ERROR ) {
	    if ( !quiet ) fprintf( stderr, "check_rbl failed\n" );
	    exit( SIMRBL_EXIT_ERROR );
	}
    } else {
	if (( rc = rbl_check( simta_rbls, NULL, argv[ optind ], NULL,
		&rbl_found, &rbl_msg )) == RBL_ERROR ) {
	    if ( !quiet ) fprintf( stderr, "check_rbl failed\n" );
	    exit( SIMRBL_EXIT_ERROR );
	}
    }

    if ( rc == RBL_BLOCK ) {
	if ( !quiet ) printf( "found in %s: %s\n", rbl_found->rbl_domain,
		rbl_msg );
	exit( SIMRBL_EXIT_BLOCKED );
    } else {
	if ( !quiet ) printf( "not found\n" );
	exit( SIMRBL_EXIT_NOT_BLOCKED );
    }
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
