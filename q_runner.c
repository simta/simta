#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

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
#include "envelope.h"
#include "line_file.h"
#include "ml.h"
#include "smtp.h"
#include "simta.h"
#include "address.h"

int			debug = 0;
struct stab_entry       *hosts = NULL;

    int
main( int argc, char *argv[] )
{
    char			*dir;

    if ( argc != 2 ) {
	fprintf( stderr, "Usage: %s ( LOCAL | SLOW )\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    if ( strcasecmp( argv[ 1 ], "LOCAL" ) == 0 ) {
	dir = SIMTA_DIR_LOCAL;

    } else if ( strcasecmp( argv[ 1 ], "SLOW" ) == 0 ) {
	dir = SIMTA_DIR_SLOW;

    } else {
	fprintf( stderr, "Usage: %s ( LOCAL | SLOW )\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    return( q_runner_dir( dir ));
}
