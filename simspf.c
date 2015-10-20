/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <syslog.h>

#include <denser.h>
#include <yasl.h>

#include "spf.h"
#include "simta.h"

const char	*simta_progname = "simspf";

    int
main( int ac, char *av[ ] )
{
    struct addrinfo	*addrinfo;
    struct addrinfo	hints;
    const char		*addrlookup, *ehlo;
    int			spf_result;

    if ( ac < 2 ) {
	fprintf( stderr, "Usage:\t\t%s <email> [ip]\n", av[ 0 ] );
	exit( 1 );
    }

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	exit( 1 );
    }

    if ( simta_config( ) != 0 ) {
	exit( 1 );
    }

    simta_openlog( 0, LOG_PERROR );

    simta_debug = 8;

    if ( ac < 3 ) {
	addrlookup = "255.255.255.255";
    } else {
	addrlookup = av[ 2 ];
    }

    if ( ac < 4 ) {
	ehlo = "tallis.marwnad.com";
    } else {
	ehlo = av[ 3 ];
    }

    memset( &hints, 0, sizeof( struct addrinfo ));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICSERV;
    getaddrinfo( addrlookup, NULL, &hints, &addrinfo );

    spf_result = spf_lookup( ehlo, av[ 1 ], addrinfo->ai_addr );
    printf( "SPF result: %s\n", spf_result_str( spf_result ));

    exit( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
