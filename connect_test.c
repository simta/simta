#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <strings.h>
#include <unistd.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include "envelope.h"
#include "smtp.h"

void                 (*logger)(char *) = NULL;

    int
main( int argc, char* argv[] )
{
    char			c;
    extern int			denser_debug, optind;
    int				err = 0;	
    SNET			*snet;

    while (( c = getopt( argc, argv, "d" )) != EOF ) {
	switch( c ) {
	case 'd':
	    denser_debug = 1;
	    break;

	default:
	    err++;
	}
    }

    if ( argc - optind != 2 ) {
	err++;
    }

    if ( err ) {
	fprintf( stderr, "usage: %s [ -d ] <HOST> <PORT>\n", argv[ 0 ] );
	exit( 1 );
    }

    logger = stdout_logger;

    printf( "calling smtp_connect\n" );
    if (( snet = smtp_connect( argv[ 1 ], atoi( argv[ 2 ] ))) == NULL ) {
       fprintf( stderr, "smtp_connect failed\n" );
       exit( 1 );
    }
    printf( "calling smtp_helo\n" );

    if ( smtp_helo( snet, logger ) != 0 ) {
       fprintf( stderr, "smtp_helo failed\n" );
       exit( 1 );
    }

    exit( 0 );
}
