/*
 * RFC's of interest:
 *
 * RFC 822  "Standard for the format of ARPA Internet text messages"
 * RFC 1123 "Requirements for Internet Hosts -- Application and Support"
 * RFC 2476 "Message Submission"
 * RFC 2822 "Internet Message Format"
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
    { "Date",			NULL },
#define HEAD_ORIG_DATE		0
    { "From",			NULL },
#define HEAD_FROM		1
    { "Sender",			NULL },
#define HEAD_SENDER		2
    { "To",			NULL },
#define HEAD_TO			3
    { "Message-ID",		NULL },
#define HEAD_MESSAGE_ID		4
    { "Reply-To",		NULL },
#define HEAD_REPLY_TO		5
    { "cc",			NULL },
#define HEAD_CC			6
    { "bcc",			NULL },
#define HEAD_BCC		7
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
    char		*header;
    char		*colon;
    int			header_len;

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
		/* null line means that message data begins */
		data = 1;

	    } else {
		/* RFC 2822:
		 * Header fields are lines composed of a field name,
		 * followed by a colon (":"), followed by a field body,
		 * and terminated by CRLF.  A field name MUST be composed
		 * of printable US-ASCII characters (i.e., characters that
		 * have values between 33 and 126, inclusive), except
		 * colon.
		 */

		header = l->line_data;
		header_len = 0;

		for ( colon = l->line_data; *colon != ':'; colon++ ) {
		    /* colon ascii value is 58 */
		    if (( *colon < 33 ) || ( *colon > 126 )) {
			break;
		    }
		}

		if ( *colon == ':' ) {
		    header_len = colon - l->line_data;
		}

		if ( header_len > 0 ) {
		    /* correct field name */
		    for ( nl = header_nl; nl->n_key != NULL; nl++ ) {
			if ( strncasecmp( nl->n_key, header, header_len )
				== 0 ) {
			    /* XXX here we have a header */

			    /* RFC 2822:
			     * A field body may be composed of any
			     * US-ASCII characters, except for CR
			     * and LF.  However, a field body may
			     * contain CRLF when used in header
			     * "folding" and  "unfolding".
			     */

			    /* XXX wrong */
			    nl->n_data = colon;
			}
		    }
		}
	    }
	}
    }

    if ( header_nl[ HEAD_ORIG_DATE ].n_data == NULL ) {
	/* no date header */
	if ( message_prepend_line( m, "Date: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    exit( 1 );
	}
    }

    if ( header_nl[ HEAD_FROM ].n_data == NULL ) {
	if ( message_prepend_line( m, "From: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    exit( 1 );
	}

    } else if ( header_nl[ HEAD_SENDER ].n_data == NULL ) {

	if ( message_prepend_line( m, "Sender: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    exit( 1 );
	}
    }

    if ( header_nl[ HEAD_TO ].n_data == NULL ) {
	if ( message_prepend_line( m, "To: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    exit( 1 );
	}
    }

    if ( header_nl[ HEAD_MESSAGE_ID ].n_data == NULL ) {
	if ( message_prepend_line( m, "Message-ID: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    exit( 1 );
	}
    }

    if ( header_nl[ HEAD_REPLY_TO ].n_data == NULL ) {
	/* XXX action */
    }

    if ( header_nl[ HEAD_CC ].n_data == NULL ) {
	/* XXX action */
    }

    if ( header_nl[ HEAD_BCC ].n_data == NULL ) {
	/* XXX action */
    }

    if ( message_prepend_line( m, "Received: default" ) == NULL ) {
	perror( "message_prepend_line" );
	exit( 1 );
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    message_stdout( m );

    return( 0 );
}
