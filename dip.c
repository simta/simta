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
    struct sockaddr_in		sin;
    DNSR			*dnsr;
    struct dnsr_result		*result;

    if ( argc != 2 ) {
	fprintf( stderr, "usage: %s hostname\n", argv[ 0 ]);
	exit( 1 );
    }

    if (( dnsr = dnsr_new( )) == NULL ) {
	syslog( LOG_ERR, "dnsr_new: %m" );
	return( SMTP_ERR_REMOTE );
    }

    if (( result = get_mx( dnsr, argv[ 1 ])) == NULL ) {
	if ( simta_debug ) fprintf( stderr, "smtp_connect: get_mx failed\n" );
	return( SMTP_ERR_REMOTE );
    }

    if ( result->r_answer[ 0 ].rr_ip == NULL ) {
	printf( "dnsr is broke\n" );
	return( 1 );
    }

    if ( result->r_answer[ 0 ].rr_type == DNSR_TYPE_MX ) {
	memcpy( &(sin.sin_addr.s_addr), &(result->r_answer[ 0 ].rr_ip->ip_ip ),
	    sizeof( struct in_addr ));
    } else {
	memcpy( &(sin.sin_addr.s_addr), &(result->r_answer[ 0 ].rr_a ),
	    sizeof( struct in_addr ));
    }

    printf( "%s\n", inet_ntoa( sin.sin_addr ));

    return( 0 );
}
