/*
 * RFC's of interest:
 *
 * RFC 822  "Standard for the format of ARPA Internet text messages"
 * RFC 1123 "Requirements for Internet Hosts -- Application and Support"
 * RFC 2476 "Message Submission"
 *
 */
#include <sys/types.h>
#include <sys/socket.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif TLS

#include <stdio.h>
#include <string.h>

#include <snet.h>

#include "message.h"

struct nlist header_nl[] = {
    { "Sender",		NULL },
    { "Date",		NULL },
    { "Message-ID",	NULL },
    { NULL,		NULL }
};

    int
main( int argc, char *argv[] )
{
    SNET		*snet;
    char		*line;
    struct message	*m;
    struct line		*l;
    struct nlist	*nl;
    int			data = 0;
    char		*c;

#ifdef DEBUG
    int			i = 0;
#endif /* DEBUG */

    if (( m = message_create()) == NULL ) {
	perror( "message_create" );
	exit( 1 );
    }

    if (( snet = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if (( l = message_line( m, line )) == NULL ) {
	    perror( "message_line" );
	    exit( 1 );
	}

	/* RFC 822: The body...is seperated from the headers by a null line. */
	if ( data == 0 ) {
	    if ( *(l->line_data) == '\0' ) {
		data = 1;

	    } else {
		if (( c = strchr( l->line_data, ':' )) != NULL ) {
		    for ( nl = header_nl; nl->n_key != NULL; nl++ ) {
		    }
		}
	    }
	}
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

#ifdef DEBUG
    printf( "HEADER\n" );

    data = 0;

    for ( l = m->m_first; l != NULL; l = l->line_next ) {
	i++;
	printf( "%d: %s\n", i, l->line_data );
	if (( *(l->line_data) == '\0' ) && ( data == 0 )) {
	    printf( "DATA\n" );
	    data = 1;
	}
    }
#endif /* DEBUG */

    return( 0 );
}
