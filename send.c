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

#define	SMTP_DISCONNECT	"221"
#define	SMTP_CONNECT	"220"
#define	SMTP_OK		"250"

#define	TEST_ID		"3E6FB9B0.1E30A"
#define	TEST_MACHINE	"terminator.rsug.itd.umich.edu"
#define	TEST_PORT	25

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

void		smtp_logger ___P(( char * ));


    void
smtp_logger( char *line )
{
    printf( "<-- %s\n", line );
    return;
}


    int
main( int argc, char *argv[] )
{
    int				s;
    struct sockaddr_in		sin;
    struct message		*m;
    struct hostent		*hp;
    SNET			*snet;
    char			*line;
    void			(*logger)(char *) = NULL;

#ifdef DEBUG
    logger = smtp_logger;
    printf( "Send: Message-ID: %s\n\n", TEST_ID );
#endif /* DEBUG */

    if (( m = message_infile( "tmp", TEST_ID )) == NULL ) {
	perror( "message_infile" );
	exit( 1 );
    }

#ifdef DEBUG
    message_stdout( m );
#endif /* DEBUG */

    if (( hp = gethostbyname( TEST_MACHINE )) == NULL ) {
	perror( "gethostbyname" );
	exit( 1 );
    }

#ifdef DEBUG
    printf( "[%s]\n", hp->h_name );
#endif /* DEBUG */

    memcpy( &(sin.sin_addr.s_addr), hp->h_addr_list[ 0 ],
	    (unsigned int)hp->h_length );

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	perror( "socket" );
	exit( 1 );
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons( TEST_PORT );

    if ( connect( s, (struct sockaddr*)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	perror( "connect" );
	exit( 1 );
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    /* read connect banner */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	perror( "snet_getline_multi" );
	exit( 1 );
    }

    if ( strncmp( line, SMTP_CONNECT, 3 ) != 0 ) {
	fprintf( stderr, "bad banner: %s\n", line );
	exit( 1 );
    }

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", m->m_env->e_hostname ) < 0 ) {
	perror( "snet_writef" );
	exit( 1 );
    }

#ifdef DEBUG
    printf( "--> HELO %s\r\n", m->m_env->e_hostname );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	perror( "snet_getline_multi" );
	exit( 1 );
    }

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
	fprintf( stderr, "bad banner: %s\n", line );
	exit( 1 );
    }

    if ( message_smtp_send( snet, m ) != 0 ) {
	perror( "message_smtp_send" );
	exit( 1 );
    }

    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	perror( "snet_writef" );
	exit( 1 );
    }

#ifdef DEBUG
    printf( "--> QUIT\r\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	perror( "snet_getline_multi" );
	exit( 1 );
    }

    if ( strncmp( line, SMTP_DISCONNECT, 3 ) != 0 ) {
	fprintf( stderr, "bad banner: %s\n", line );
	exit( 1 );
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    return( 0 );
}
