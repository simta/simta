#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <stdio.h>
#include <netdb.h>
#include <string.h>

#include <snet.h>

#include "message.h"
#include "envelope.h"
#include "smtp.h"

#define	TEST_ID		"3E6FB9B0.1E30A"
#define	TEST_HOSTNAME	"terminator.rsug.itd.umich.edu"
#define	TEST_PORT	25


    int
main( int argc, char *argv[] )
{
    struct message		*m;
    void			(*logger)(char *) = NULL;

#ifdef DEBUG
    logger = stdout_logger;
    printf( "%s: Message-ID: %s\n\n", argv[ 0 ], TEST_ID );
#endif /* DEBUG */

    /* XXX ERROR CHECKING */

    if (( m = message_infiles( "tmp", TEST_ID )) == NULL ) {
	perror( "message_infile" );
	exit( 1 );
    }

#ifdef DEBUG
    message_stdout( m );
#endif /* DEBUG */

    if ( smtp_send_single_message( TEST_HOSTNAME, TEST_PORT, m, logger )
	    != 0 ) {
	perror( "smtp_send_single_message" );
	exit( 1 );
    }

    return( 0 );
}
