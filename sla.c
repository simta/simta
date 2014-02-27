#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>
#include <assert.h>
#include <fcntl.h>
#include <utime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>

#include "denser.h"
#include "envelope.h"
#include "expand.h"
#include "ll.h"
#include "simta.h"
#include "line_file.h"
#include "queue.h"

    int
main( int argc, char *argv[] )
{
    SNET			*snet;
    char			*hold = NULL;
    char			*line;

    if (( snet = snet_open( argv[ 1 ], O_RDONLY, 0,
	    1024 * 1024 )) == NULL ) {
	fprintf( stderr, "%s: snet_open %s: ", argv[ 0 ], argv[ 1 ] );
	perror( NULL );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if (( hold != NULL ) && ( strncmp( hold, line, 16 ) != 0 )) {
	    if ( strcmp( hold, line ) != 0 ) {
		printf( "%s\n", hold );
	    }

	    printf( "%s\n", line );
	}

	free( hold );
	hold = strdup( line );
    }

    exit( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
