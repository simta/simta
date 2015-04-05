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

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "denser.h"
#include "envelope.h"
#include "dns.h"
#include "simta.h"

#define SIMREVERSE_EXIT_VALID		0
#define SIMREVERSE_EXIT_INVALID		1
#define SIMREVERSE_EXIT_DNS_ERROR	2
#define SIMREVERSE_EXIT_ERROR		3

    int
main( int argc, char *argv[])
{
    int			rc;
    struct in_addr	addr;

    if ( argc != 2 ) {
	fprintf( stderr, "Usage: %s address\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    rc = inet_pton( AF_INET, argv[ 1 ], &addr );
    if ( rc < 0 ) {
	perror( "inet_pton" );
	exit( SIMREVERSE_EXIT_ERROR );
    } else if ( rc == 0 ) {
	fprintf( stderr, "%s: invalid address\n", argv[ 1 ] );
	exit( SIMREVERSE_EXIT_ERROR );
    }

    switch ( check_reverse( argv[ 1 ], &addr )) {
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
