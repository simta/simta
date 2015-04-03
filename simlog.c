/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "simta.h"


    int
main( int argc, char *argv[] )
{
    SNET		*in;
    SNET		*out;
    char		*line;
    int			x;
    struct timeval	tv;
    char		path[ MAXPATHLEN ];
    int			c;

    if ( simta_gettimeofday( &tv ) != 0 ) {
	perror( "gettimeofday" );
	return( 1 );
    }

    /* XXX hard path */
    sprintf( path, "%s/%ld.%ld", "/var/simta/log", tv.tv_sec, tv.tv_usec );

    if (( in = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    if (( out = snet_open( path, O_CREAT | O_WRONLY,
	    S_IRUSR | S_IRGRP | S_IROTH, 1024 * 1024 )) == NULL ) {
	perror( "snet_open" );
	exit( 1 );
    }

    snet_writef( out, "%s", argv[ 0 ] );

    for ( x = 1; x < argc; x++ ) {
	snet_writef( out, " %s", argv[ x ] );
    }
    snet_writef( out, "\n\n" );

    opterr = 0;

    while (( c = getopt( argc, argv, "b:" )) != -1 ) {
	switch ( c ) {
	case 'b':
	    if ( strlen( optarg ) == 1 ) {
		switch ( *optarg ) {
		case 'a':
		    /* -ba ARPANET mode */
		case 'd':
		    /* -bd Daemon mode, background */
		case 's':
		    /* 501 Permission denied */
		    printf( "501 Mode not supported\r\n" );
		    exit( 1 );
		}
	    }
	    break;

	default:
	    break;
	}
    }

    while (( line = snet_getline( in, NULL )) != NULL ) {
	snet_writef( out, "%s\n", line );
    }

    if ( snet_close( in ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    if ( snet_close( out ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
