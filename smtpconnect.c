#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <snet.h>

#include "denser.h"
#include "envelope.h"
#include "expand.h"
#include "simta.h"
#include "queue.h"
#include "smtp.h"


    int
main( int ac, char *av[] )
{
    int			c, err = 0, r, s;
    unsigned short	port = 25;
    char                *hostname;
    struct host_q       *hq;
    struct deliver      d;

    while (( c = getopt( ac, av, "C:rp:" )) != EOF ) {
	switch ( c ) {
	case 'p' :
	    port = htons( atoi( optarg ));
	    break;

	case '?' :
	default :
	    err++;
	    break;
	}
    }

    if ( err || ( optind == ac )) {
	fprintf( stderr, "Usage:\t%s -p port hostname\n", av[ 0 ] );
	exit( 1 );
    }

    openlog( "smtpconnect", LOG_NOWAIT | LOG_PERROR, LOG_SIMTA );

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	exit( 1 );
    }

    if ( simta_config( SIMTA_BASE_DIR ) != 0 ) {
	exit( 1 );
    }

    hostname = av[ optind ];

    hq = host_q_create_or_lookup( hostname );
    memset( &d, 0, sizeof( struct deliver ));

    /* Dummy up some values so we don't crash */
    hq->hq_status = HOST_DOWN;
    d.d_env = env_create( NULL, "smtpconnect", "simta@umich.edu", NULL );

    if ( next_dnsr_host_lookup( &d, hq ) != 0 ) {
	exit( 1 );
    }

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "%s: socket: %m", hq->hq_hostname );
    }

    if ( connect( s, (struct sockaddr*)&(d.d_sin),
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "[%s] %s: connect: %m",
		inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );
	close( s );
	exit( 1 );
    }

    if (( d.d_snet_smtp = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "[%s] %s: snet_attach: %m",
		inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );
	close( s );
	exit( 1 );
    }

    r = smtp_connect( hq, &d );
    if ( r == SMTP_OK || r == SMTP_ERROR ) {
	smtp_quit( hq, &d );
    }

    snet_close( d.d_snet_smtp );

    exit( 0 );
}
