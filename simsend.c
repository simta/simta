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
#endif /* TLS */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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
    { NULL,			NULL }
};

int header_exceptions( struct message * );
int headers( struct message * );


    /* Some mail clents exhibit bad behavior when generating headers.
     *
     * return 0 if all went well.
     * return 1 if we reject the message.
     * die -1 if there was a serious error.
     */

    int
header_exceptions( struct message *m )
{
    char		*c;
    char		*end;
    int			len;
    char		*line;

    if ( m->m_first_line == NULL ) {
	/* empty message */
	return( 0 );
    }

    /* mail(1) on Solaris gives non-RFC compliant first header line */
    c = m->m_first_line->line_data;

    if ( strncasecmp( m->m_first_line->line_data, "From ", 5 ) == 0 ) {
	c += 5;
	for ( end = c; ( *end > 33 ) && ( *end < 126 ); end++ )
		;

	/* rewrite the header if we find a word after "From " */
	if (( len = end - c ) > 0 ) {
	    if (( line = (char*)malloc((size_t)(7 + len ))) == NULL ) {
		perror( "malloc" );
		exit( 1 );
	    }
	    strcpy( line, "From: " );
	    strncat( line, c, (size_t)(len + 1 ));
	    free( m->m_first_line->line_data );
	    m->m_first_line->line_data = line;
	}
    }

    return( 0 );
}


    /* return 0 if all went well.
     * return 1 if we reject the message.
     * return -1 if there was a serious error.
     */

    int
headers( struct message *m )
{
    struct line		*l;
    struct nlist	*nl;
    char		*header;
    char		*colon;
    size_t		header_len;

    if ( header_exceptions( m ) != 0 ) {
	return( 1 );
    }

    for ( l = m->m_first_line; l != NULL ; l = l->line_next ) {
	if ( *(l->line_data) == '\0' ) {
	    /* null line means that message data begins */
	    break;
	}

	/* RFC 2822:
	 * Header fields are lines composed of a field name, followed
	 * by a colon (":"), followed by a field body, and terminated
	 * by CRLF.  A field name MUST be composed of printable
	 * US-ASCII characters (i.e., characters that have values
	 * between 33 and 126, inclusive), except colon.
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
	    for ( nl = header_nl; nl->n_key != NULL; nl++ ) {
		if ( strncasecmp( nl->n_key, header, header_len ) == 0 ) {
		    /* correct field name */
		    nl->n_data = l;
		}
	    }
	}
    }

    if ( header_nl[ HEAD_FROM ].n_data == NULL ) {
	if ( message_prepend_line( m, "From: default" ) == NULL ) {
	    return( -1 );
	}
    }

    if ( header_nl[ HEAD_SENDER ].n_data == NULL ) {
	/* XXX action */
    }

    if ( header_nl[ HEAD_ORIG_DATE ].n_data == NULL ) {
	/* no date header */
	if ( message_prepend_line( m, "Date: default" ) == NULL ) {
	    return( -1 );
	}
    }

    if ( header_nl[ HEAD_MESSAGE_ID ].n_data == NULL ) {
	if ( message_prepend_line( m, "Message-ID: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    return( -1 );
	}
    }

    if ( header_nl[ HEAD_TO ].n_data == NULL ) {
	/* XXX action */
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
	return( -1 );
    }

    return( 0 );
}


    int
main( int argc, char *argv[] )
{
    SNET		*snet;
    char		*line;
    struct message	*m;
    struct line		*l;
    int			usage = 0;
    int			c;
    int			ignore_dot = 0;

    /* ignore a good many options */
    opterr = 0;

    while (( c = getopt( argc, argv, "b:io:" )) != -1 ) {
	switch ( c ) {
	case 'b':
	    if ( strlen( optarg ) == 1 ) {
		switch ( *optarg ) {
		case 'a':
		    /* -ba ARPANET mode */
		case 'd':
		    /* -bd Daemon mode, background */
		case 's':
		    /* 501 Permission denied */
		    printf( "501 Mode not supported\n" );
		    exit( 1 );
		    break;

		case 'D':
		    /* -bD Daemon mode, foreground */
		case 'i':
		    /* -bi init the alias db */
		case 'p':
		    /* -bp surmise the mail queue*/
		case 't':
		    /* -bt address test mode */
		case 'v':
		    /* -bv verify names only */
		    printf( "Mode not supported\n" );
		    exit( 1 );
		    break;

		case 'm':
		    /* -bm deliver mail the usual way */
		default:
		    /* ignore all other flags */
		    break;
		}
	    }
	    break;


	case 'i':
	    /* Ignore a single dot on a line as an end of message marker */
    	    ignore_dot = 1;
	    break;

	case 'o':
	    if ( strcmp( optarg, "i" ) == 0 ) {
		/* -oi ignore dots */
		ignore_dot = 1;
	    }
	    break;

	default:
	    /* ignore command line options we don't understand */
	    /* XXX maybe log these? */
	    break;
	}
    }

    /* optind = first to-address */

    /* XXX error handling for command line options? */
    if ( usage != 0 ) {
	fprintf( stderr, "Usage: %s "
		"[ -b option ] "
		"[ -i ] "
		"[ -o option ] "
		"[[ -- ] to-address ...]\n", argv[ 0 ] );
	exit( 1 );
    }

    if (( m = message_create()) == NULL ) {
	perror( "message_create" );
	exit( 1 );
    }

    if (( snet = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( ignore_dot == 0 ) {
	    if (( line[ 0 ] == '.' ) && ( line[ 1 ] =='\0' )) {
		/* single dot on a line */
		break;
	    }
	}

	if (( l = message_line( m, line )) == NULL ) {
	    perror( "message_line" );
	    exit( 1 );
	}
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    switch ( headers( m )) {
    default:
    case -1:
	/* serious error */
	perror( "headers" );
	exit( 1 );
	break;

    case 1:
	/* reject message */

    case 0:
	/* everything fine, fall through */
	break;
    }

    message_stdout( m );

    return( 0 );
}
