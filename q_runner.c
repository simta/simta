#include "config.h"

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

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

#include "ll.h"
#include "queue.h"
#include "q_cleanup.h"
#include "envelope.h"
#include "line_file.h"
#include "ml.h"
#include "smtp.h"
#include "address.h"
#include "simta.h"


    int
main( int argc, char *argv[] )
{
    char			*conf_file = NULL;
    char			*op;

    simta_debug = 1;

    if (( argc != 4 ) && ( argc != 3 )) {
	fprintf( stderr,
		"Usage: %s conf_file [ base_dir ] ( LOCAL | SLOW | CLEAN )\n",
		argv[ 0 ]);
	exit( EX_USAGE );
    }

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    if ( argc == 4 ) {
	conf_file = argv[ 2 ];
	op = argv[ 3 ];
    } else {
	op = argv[ 2 ];
    }

    /* init simta config / defaults */
    if ( simta_config( argv[ 1 ], conf_file ) != 0 ) {
	fprintf( stderr, "simta_config error\n" );
	exit( EX_DATAERR );
    }

    if ( strcasecmp( op, "LOCAL" ) == 0 ) {
	exit( q_runner_dir( simta_dir_local ));

    } else if ( strcasecmp( op, "SLOW" ) == 0 ) {
	exit( q_runner_dir( simta_dir_slow ));

    } else if ( strcasecmp( op, "CLEAN" ) == 0 ) {
	exit( q_cleanup());

    } else {
	fprintf( stderr,
		"Usage: %s conf_file [ base_dir ] ( LOCAL | SLOW | CLEAN )\n",
		argv[ 0 ]);
	exit( EX_USAGE );
    }
}
