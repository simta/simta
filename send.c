#include <sys/param.h>

#include <stdio.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include "message.h"
#include "envelope.h"

#define	TEST_ID		"3E6FB9B0.1E30A"


    int
main( int argc, char *argv[] )
{
    struct message		*m;

    printf( "Send: Message-ID: %s\n\n", TEST_ID );

    if (( m = message_file( "tmp", TEST_ID )) == NULL ) {
	perror( "message_file" );
	exit( 1 );
    }

    message_stdout( m );

    return( 0 );
}
