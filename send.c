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

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

void		stdout_logger ___P(( char * ));


    void
stdout_logger( char *line )
{
    printf( "<-- %s\n", line );
    return;
}


    int
main( int argc, char *argv[] )
{
    struct message		*m;
    SNET			*snet;
    void			(*logger)(char *) = NULL;

#ifdef DEBUG
    logger = stdout_logger;
    printf( "%s: Message-ID: %s\n\n", argv[ 0 ], TEST_ID );
#endif /* DEBUG */

    /* XXX ERROR CHECKING */

    if (( m = message_infile( "tmp", TEST_ID )) == NULL ) {
	perror( "message_infile" );
	exit( 1 );
    }

#ifdef DEBUG
    message_stdout( m );
#endif /* DEBUG */

    if (( snet = smtp_connect( TEST_HOSTNAME, TEST_PORT, logger )) == NULL ) {
	perror( "smtp_connect" );
	exit( 1 );
    }

    if ( smtp_send_message( snet, m, logger ) != 0 ) {
	perror( "smtp_send_message" );
	exit( 1 );
    }

    if ( smtp_rset( snet, logger ) != 0 ) {
	perror( "smtp_rset" );
	exit( 1 );
    }

    if ( smtp_send_message( snet, m, logger ) != 0 ) {
	perror( "smtp_send_message" );
	exit( 1 );
    }

    if ( smtp_quit( snet, logger ) != 0 ) {
	perror( "smtp_send_message" );
	exit( 1 );
    }

    return( 0 );
}
