#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <sysexits.h>
#include <utime.h>

#include <snet.h>

#include "denser.h"
#include "envelope.h"
#include "mx.h"
#include "ll.h"
#include "simta.h"

    int
main( int argc, char *argv[])
{
    extern int          optind;
    extern char         *optarg;

    struct in_addr	addr;

    if ( argc < 1 ) {
	fprintf( stderr, "Usage: %s address\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    if ( inet_pton( AF_INET, argv[ 1 ], &addr ) <= 0 ) {
	perror( "inet_pton" );
	exit( 1 );
    }

    switch ( check_reverse( argv[ 1 ], &addr )) {
    case 0:
	printf( "valid reverse\n" );
	exit( 0 );

    case 1:
	printf( "invalid reverse\n" );
	exit( 1 );

    default:
	fprintf( stderr, "check_reverse failed\n" );
	exit( 1 );
    }
}
