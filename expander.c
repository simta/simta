/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

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

#include "envelope.h"
#include "expand.h"
#include "simta.h"
#include "queue.h"
#include "ml.h"
#include "smtp.h"


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
	    sender = strdup( optarg );
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

    simta_openlog( 0 );

    if ( simta_read_config( argv[ nextargc ] ) < 0 ) {
	fprintf( stderr, "simta_read_config error: %s\n", argv[ nextargc ] );
	exit( EX_DATAERR );
    }

    /* init simta config / defaults */
    if ( simta_config( ) != 0 ) {
	fprintf( stderr, "simta_config error\n" );
	exit( EX_DATAERR );
    }

    env = env_create( NULL, "Expander", sender, NULL );

    env->e_n_exp_level = exp_level;

    do {
	nextargc++;

	printf( "Original Recipient: %s\n", argv[ nextargc ]);
	env_recipient( env, argv[ nextargc ]);

    } while ( nextargc < argc - 1 );

    if ( expand( env ) != 0 ) {
	return( 1 );
    }
    env_free( env );

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
