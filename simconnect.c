/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

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

#include <denser.h>
#include <snet.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include "envelope.h"
#include "expand.h"
#include "simta.h"
#include "queue.h"
#include "red.h"
#include "smtp.h"

int     next_dnsr_host_lookup( struct deliver *, struct host_q * );

    int
main( int ac, char *av[] )
{
    int			s, r;
    char                *hostname;
    struct host_q       *hq;
    struct deliver      d;

    if ( ac != 2 ) {
	fprintf( stderr, "Usage:\t\t%s hostname\n", av[ 0 ] );
	exit( 1 );
    }

    openlog( "simconnect", LOG_NOWAIT | LOG_PERROR, LOG_SIMTA );

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	exit( 1 );
    }

    if ( simta_config( ) != 0 ) {
	exit( 1 );
    }

    hostname = av[ 1 ];

    hq = host_q_create_or_lookup( hostname );
    memset( &d, 0, sizeof( struct deliver ));

    /* Dummy up some values so we don't crash */
    hq->hq_status = HOST_DOWN;
    d.d_env = env_create( NULL, hostname, "simta@umich.edu", NULL );

    for ( ; ; ) {
	if ( next_dnsr_host_lookup( &d, hq ) != 0 ) {
	    exit( 0 );
	}

retry:
	if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	    syslog( LOG_ERR, "[%s] %s: socket: %m",
		    inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );
	}

	if ( connect( s, (struct sockaddr*)&(d.d_sin),
		sizeof( struct sockaddr_in )) < 0 ) {
	    syslog( LOG_ERR, "[%s] %s: connect: %m",
		    inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );
	    close( s );
	    continue;
	}

	syslog( LOG_DEBUG, "[%s] %s: connect: Success",
		inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );

	if (( d.d_snet_smtp = snet_attach( s, 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "[%s] %s: snet_attach: %m",
		    inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );
	    close( s );
	    continue;
	}

	r = smtp_connect( hq, &d );
	if ( r == SMTP_BAD_TLS ) {
	    snet_close( d.d_snet_smtp );
	    if ( hq->hq_red == NULL ) {
		hq->hq_red = red_host_add( hq->hq_hostname );
	    }
	    syslog( LOG_INFO, "[%s] %s: disabling TLS",
		    inet_ntoa( d.d_sin.sin_addr ), hq->hq_hostname );
	    hq->hq_red->red_policy_tls = TLS_POLICY_DISABLED;
	    goto retry;
	}

	if ( r == SMTP_OK || r == SMTP_ERROR ) {
	    smtp_quit( hq, &d );
	}

	snet_close( d.d_snet_smtp );
    }

    exit( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
