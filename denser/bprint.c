#define BPXLEN	50
#define BPALEN	18
#include <ctype.h>
#include <strings.h>
#include <stdio.h>

#include "bprint.h"

char	hexdig[] = "0123456789ABCDEF";

    void
bprint( char* data, int len )
{
    char	xout[ BPXLEN ], aout[ BPALEN ];
    int		i = 0;

    bzero( xout, BPXLEN );
    bzero( aout, BPALEN );

    for ( i = 0; len; len-- ) {
	if ( i == 16 ) {
	    printf( "%-48s\t%-16s\n", xout, aout );
	    bzero( xout, BPXLEN );
	    bzero( aout, BPALEN );
	    i = 0;
	}

	if ( isascii( (unsigned char)*data ) &&
		isprint( (unsigned char)*data )) {
	    aout[ i ] = *data;
	} else {
	    aout[ i ] = '.';
	}

	xout[ (i*3) ] = hexdig[ ( *data & 0xf0 ) >> 4 ];
	xout[ (i*3) + 1 ] = hexdig[ *data & 0x0f ];
	xout[ (i*3) + 2 ] = ' ';

	data++;
	i++;
    }

    if ( i ) {
	printf( "%-48s\t%-16s\n", xout, aout );
    }
    printf( "%s\n", "(end)" );

    return;
}
