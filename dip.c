/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     dip.c     *****/
#include "config.h"

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <inttypes.h>
#include <sysexits.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>

#include <snet.h>

#include "queue.h"
#include "line_file.h"
#include "envelope.h"
#include "smtp.h"
#include "denser.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "simta.h"
#include "mx.h"

int simta_debug = 1;
struct stab_entry	*simta_hosts = NULL;

    int
main( int argc, char *argv[])
{
    int 			i, valid_result = 0;
    struct sockaddr_in		sin;
    DNSR			*dnsr;
    struct dnsr_result		*result;

    if ( argc != 2 ) {
	fprintf( stderr, "usage: %s hostname\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    if (( dnsr = dnsr_new( )) == NULL ) {
	syslog( LOG_ERR, "dnsr_new: %m" );
	return( SMTP_ERR_REMOTE );
    }

    if (( result = get_mx( dnsr, argv[ 1 ])) == NULL ) {
	if ( simta_debug ) fprintf( stderr, "smtp_connect: get_mx failed\n" );
	return( SMTP_ERR_REMOTE );
    }


    if ( simta_debug ) fprintf( stderr, "got %d results\n", result->r_ancount );
    for ( i = 0; i < result->r_ancount; i++ ) {
	if ( simta_debug ) fprintf( stderr, "checking result %i:\n", i );

        switch( result->r_answer[ i ].rr_type ) {
        case DNSR_TYPE_MX:
	    if ( simta_debug ) fprintf( stderr, "\tMX\n" );
	    memcpy( &(sin.sin_addr.s_addr),
		&(result->r_answer[ i ].rr_ip->ip_ip ),
		sizeof( struct in_addr ));
	    valid_result++;
            break;

        case DNSR_TYPE_A:
	    if ( simta_debug ) fprintf( stderr, "\tA\n" );
            memcpy( &(sin.sin_addr.s_addr), &(result->r_answer[ i ].rr_a ),
                sizeof( struct in_addr ));
	    valid_result++;
            break;

        default:
	    if ( simta_debug ) fprintf( stderr, "\tskipping non MX/A\n" );
            continue;
        }
	if ( valid_result ) {
	    break;
	}
    }

    printf( "%s\n", inet_ntoa( sin.sin_addr ));

    return( 0 );
}
