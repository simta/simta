#include <sys/types.h>
#include <sys/socket.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif TLS

#include <stdio.h>

#include <snet.h>

#include "message.h"

    int
main( int argc, char *argv[] )
{
    SNET		*snet;
    char		*line;
    struct message	*m;
    struct line		*l;
    int			i = 0;

    if (( m = message_create()) == NULL ) {
	perror( "message_create" );
	exit( 1 );
    }

    if (( snet = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( message_line( m, line ) != 0 ) {
	    perror( "message_line" );
	    exit( 1 );
	}
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    for ( l = m->m_first; l != NULL; l = l->line_next ) {
	i++;
	printf( "%d: %s\n", i, l->line_data );
    }

    return( 0 );
}
