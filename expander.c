#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

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

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "line_file.h"
#include "ml.h"
#include "smtp.h"
#include "expand.h"
#include "simta.h"


    int
main( int argc, char *argv[])
{
    struct host_q	*hq = NULL;
    struct envelope	*env;

    char   *sender	= "sender@expansion.test";
    int    c;
    int	   nextargc	= 1;

    extern int          optind;
    extern char         *optarg;

    simta_debug 	= 1;
    simta_expand_debug	= 1;

    while ((c = getopt(argc, argv, "f:")) != EOF)
    {
	switch (c)
	{
	case 'f':
	    sender = strdup (optarg);
	    nextargc = nextargc + 2;
	    break;
	default:
	    fprintf( stderr, "Usage: %s conf_file address\n", argv[ 0 ]);
	    exit( EX_USAGE );
	}
    }
    if ( argc < 3 ) {
	fprintf( stderr, "Usage: %s [-f sendermail] conf_file address\n", 
		argv[ 0 ]);
	exit( EX_USAGE );
    }

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    if ( simta_read_config( argv[ nextargc ] ) < 0 ) {
	fprintf( stderr, "simta_read_config error: %s\n", argv[ nextargc ] );
	exit( EX_DATAERR );
    }

    /* init simta config / defaults */
    if ( simta_config( simta_base_dir ) != 0 ) {
	fprintf( stderr, "simta_config error\n" );
	exit( EX_DATAERR );
    }

    do {
	nextargc++;

	if (( env = env_create( sender )) == NULL ) {
	    perror( "malloc" );
	    return( 1 );
	}

	if ( env_recipient( env, argv[ nextargc ]) != 0 ) {
	    perror( "malloc" );
	    return( 1 );
	}

	if ( expand( &hq, env ) != 0 ) {
	    return( 1 );
	}
    } while ( nextargc < argc - 1 );

    return( 0 );
}
