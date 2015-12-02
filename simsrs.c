/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <syslog.h>

#include <denser.h>
#include <yasl.h>

#include "srs.h"
#include "simta.h"

const char	*simta_progname = "simsrs";

    int
main( int ac, char *av[ ] )
{
    struct  envelope	*env;
    char		*p;

    if ( ac != 2 ) {
	fprintf( stderr, "Usage:\t\t%s address\n", av[ 0 ] );
	exit( 1 );
    }

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	exit( 1 );
    }

    if ( simta_config( ) != 0 ) {
	exit( 1 );
    }

    simta_openlog( 0, LOG_PERROR );

    if (( p = strrchr( av[ 1 ], '@' )) == NULL ) {
	fprintf( stderr, "Bad address\n" );
	exit( 1 );
    }

    if ( strcasecmp(( p + 1 ), simta_srs_domain ) == 0 ) {
	if ( srs_reverse( av[ 1 ], &p, simta_srs_secret ) == SRS_OK ) {
	    printf( "%s\n", p );
	} else {
	    printf( "srs_reverse failed\n" );
	}
    } else {
	env = env_create( NULL, "srs", av[ 1 ], NULL );
	srs_forward( env );
	printf( "%s\n", env->e_mail );
    }

    exit( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
