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
#include "envelope.h"
#include "queue.h"
#include "line_file.h"
#include "ml.h"
#include "smtp.h"
#include "simta.h"

struct host_q		*null_queue;


    int
main( int argc, char *argv[] )
{
    int				r;

    if ( argc != 2 ) {
	fprintf( stderr, "Usage: %s mode\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    r = q_runner( atoi( argv[ 1 ]));

    printf( "return %d\n", r );

    return( r );
}
