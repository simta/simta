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

    /* init simta config / defaults */
    if ( simta_config( argv[ nextargc ], NULL ) != 0 ) {
	fprintf( stderr, "simta_config error\n" );
	exit( EX_DATAERR );
    }

    if (( env = env_create( sender )) == NULL ) {
	perror( "malloc" );
	return( 1 );
    }

    if ( env_sender( env, NULL ) != 0 ) {
	perror( "malloc" );
	return( 1 );
    }

    if ( env_recipient( env, argv[ nextargc + 1 ]) != 0 ) {
	perror( "malloc" );
	return( 1 );
    }

    return( expand( &hq, env ));
}
