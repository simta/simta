#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "denser.h"
#include "internal.h"

/*
 * Creates a new DNSR structure which will be used for all future denser
 * calls.  This only fails on system error.  Other functions have been moved
 * out of this routine so they can provide better error reporting via
 * the DNSR->d_errno.
 * 
 * returned dnsr handle is configured for recursion.  Can be changed with
 * dnsr_config( ).
 * 
 * Return Values:
 *	DNSR *	success
 *	NULL 	error - check errno
 */

    DNSR *
dnsr_new( void )
{
    DNSR 		*dnsr;
    struct timeval	tv;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	return( NULL );
    }
    srand( (unsigned int)getpid( ) ^ tv.tv_usec ^ tv.tv_sec );

    if (( dnsr = malloc( sizeof( DNSR ))) == NULL ) {
	return( NULL );
    }

    memset( dnsr, 0, sizeof( DNSR ));
    dnsr->d_nsresp = -1;

    if (( dnsr->d_fd = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 ) {
	DEBUG( perror( "dnsr_open: socket" ));
	free( dnsr );
	return( NULL );
    }

    /* XXX - do we need to check error here? */
    dnsr_config( dnsr, DNSR_FLAG_RECURSION, DNSR_FLAG_ON );

    return( dnsr );
}

    int
dnsr_free( DNSR *dnsr )
{
    if ( dnsr == NULL ) {
	return( 0 );
    }
    if ( close( dnsr->d_fd ) != 0 ) {
	DEBUG( perror( "dnsr_free: close" ));
	return( -1 );
    }
    free( dnsr );

    return( 0 );
}
