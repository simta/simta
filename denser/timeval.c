#include <sys/time.h>

#include "timeval.h"

    int
tv_add( struct timeval *tp1, struct timeval *tp2, struct timeval *result )
{

    /* Add */
    result->tv_sec = tp1->tv_sec + tp2->tv_sec;
    result->tv_usec = tp1->tv_usec + tp2->tv_usec;

    /* Check and correct usec overflow */
    if ( result->tv_usec >= 1000000 ) {
	result->tv_sec += 1;
	result->tv_usec -= 1000000;
    }
    return( 0 );
}

    int
tv_sub( struct timeval *tp1, struct timeval *tp2, struct timeval *result )
{
    result->tv_sec = tp1->tv_sec;
    result->tv_usec = tp1->tv_usec;

    /* Borrow */
    if ( tp1->tv_usec < tp2->tv_usec ) {
	result->tv_sec -= 1;
	result->tv_usec += 1000000;
    }

    /* Subtract */
    result->tv_sec = result->tv_sec - tp2->tv_sec;
    result->tv_usec = result->tv_usec - tp2->tv_usec;

    /* Check for negative result */
    if ( result->tv_sec < 0 ) {
	result->tv_sec = 0;
	result->tv_usec = 0;
	return( -1 );
    }

    return( 0 );
}

    int 
tv_lt( struct timeval *tp1, struct timeval *tp2 )
{
    if (( tp1->tv_sec < tp2->tv_sec ) ||
	    (( tp1->tv_sec == tp2->tv_sec ) && ( tp1->tv_usec <
	    tp2->tv_usec ))) {
	return( 1 );
    } else {
	return( 0 );
    }
}

    int 
tv_gt( struct timeval *tp1, struct timeval *tp2 )
{
    if (( tp1->tv_sec < tp2->tv_sec ) ||
	    (( tp1->tv_sec == tp2->tv_sec ) && ( tp1->tv_usec <
	    tp2->tv_usec ))) {
	return( 0 );
    } else {
	return( 1 );
    }
}
