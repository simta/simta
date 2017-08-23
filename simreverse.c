/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include "dns.h"
#include "simta.h"

#define SIMREVERSE_EXIT_VALID		0
#define SIMREVERSE_EXIT_INVALID		1
#define SIMREVERSE_EXIT_DNS_ERROR	2
#define SIMREVERSE_EXIT_ERROR		3

const char	*simta_progname = "simreverse";

    int
main( int argc, char *argv[])
{
    int			rc;
    struct addrinfo	hints;
    struct addrinfo	*ai;

    if ( argc != 2 ) {
	fprintf( stderr, "Usage: %s address\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    memset( &hints, 0, sizeof( struct addrinfo ));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    if (( rc = getaddrinfo( argv[ 1 ], NULL, &hints, &ai )) != 0 ) {
	fprintf( stderr, "Syserror: getaddrinfo: %s\n", gai_strerror( rc ));
	exit( SIMREVERSE_EXIT_ERROR );
    }

    switch ( check_reverse( argv[ 1 ], ai->ai_addr )) {
    case REVERSE_MATCH:
	printf( "valid reverse\n" );
	exit( SIMREVERSE_EXIT_VALID );

    case REVERSE_UNKNOWN:
    case REVERSE_MISMATCH:
	printf( "invalid reverse\n" );
	exit( SIMREVERSE_EXIT_INVALID );

    default:
    case REVERSE_ERROR:
	if (( simta_dnsr == NULL )
		|| ( dnsr_errno( simta_dnsr ) == DNSR_ERROR_SYSTEM )) {
	    perror( "system error" );
	    exit( SIMREVERSE_EXIT_ERROR );
	} else {
	    fprintf( stderr, "DNS error: %s\n",
		dnsr_err2string( dnsr_errno( simta_dnsr )));
	    exit( SIMREVERSE_EXIT_DNS_ERROR );
	}
    }
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
