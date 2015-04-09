/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <syslog.h>

#include <denser.h>
#include <yasl.h>

#include "dmarc.h"
#include "simta.h"

    int
main( int ac, char *av[ ] )
{
    yastr		record_str;
    yastr		test_str;
    struct dmarc	*d;

    if (( ac < 2 ) || ( ac > 5 )) {
	fprintf( stderr, "Usage:\t\t%s hostname [ 5322.From domain ] [ SPF domain ] [ DKIM domain ]\n", av[ 0 ] );
	exit( 1 );
    }

    openlog( "simdmarc", LOG_NOWAIT | LOG_PERROR, LOG_SIMTA );

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	exit( 1 );
    }

    if ( simta_config( ) != 0 ) {
	exit( 1 );
    }

    dmarc_init( &d );

    dmarc_lookup( d, av[ 1 ] );

    printf( "DMARC lookup result: policy %s, percent %d, result %s\n",
	    dmarc_result_str( d->policy ), d->pct,
	    dmarc_result_str( d->result ));

    if ( ac > 2 ) {
	d->domain = av[ 2 ];
    }

    test_str = yaslauto( d->domain );

    if ( ac > 3 ) {
	dmarc_spf_result( d, av[ 3 ] );
	test_str = yaslcat( test_str, "/" );
	test_str = yaslcat( test_str, av[ 3 ] );
    }
    if ( ac > 4 ) {
	dmarc_dkim_result( d, av[ 4 ] );
	test_str = yaslcat( test_str, "/" );
	test_str = yaslcat( test_str, av[ 4 ] );
    }

    printf( "DMARC policy result for %s: %s\n", test_str,
	    dmarc_result_str( dmarc_result( d )));

    exit( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
