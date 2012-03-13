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
    struct envelope	*env;

    char   *sender	= "sender@expansion.test";
    int    c;
    int	   nextargc	= 1;
    int	   exp_level    = 0;
    int	   error	= 0;

    extern int          optind;
    extern char         *optarg;

    simta_debug 	= 1;
    simta_expand_debug	= 1;

    while ((c = getopt(argc, argv, "f:x:")) != EOF)
    {
	switch (c)
	{
	case 'x':
	    if (( exp_level = atoi( optarg )) < 0 ) {
		error++;
	    }
	    nextargc = nextargc + 2;
	    break;

	case 'f':
	    sender = strdup (optarg);
	    nextargc = nextargc + 2;
	    break;

	default:
	    error++;
	    nextargc++;
	    break;
	}
    }
    if (( argc < 3 ) | ( error )) {
	fprintf( stderr, "Usage: %s [ -x level ] [-f sendermail] conf_file "
		"address\n", argv[ 0 ]);
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

    if (( env = env_create( sender, NULL )) == NULL ) {
	perror( "malloc" );
	return( 1 );
    }

    if (( env->e_id = strdup( "Test" )) == NULL ) {
	perror( "malloc" );
	return( 1 );
    }

    env->e_n_exp_level = exp_level;

    do {
	nextargc++;

	printf( "Original Recipient: %s\n", argv[ nextargc ]);
	if ( env_recipient( env, argv[ nextargc ]) != 0 ) {
	    perror( "malloc" );
	    return( 1 );
	}

    } while ( nextargc < argc - 1 );

    if ( expand( env ) != 0 ) {
	return( 1 );
    }
    env_free( env );

    return( 0 );
}
