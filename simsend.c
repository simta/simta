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
#include <unistd.h>

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

int headers( struct message * );


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
    int			errs = 0;
    int			c;
    int			ignore_dot = 0;

    while (( c = getopt( argc, argv, "b:io:" )) != -1 ) {
	switch ( c ) {
	case 'b':
	    /* XXX we do not support many -b options, do we need to fail? */
	    /* -bs SMTP protocol, implies -ba */
	    /* -ba ARPANET mode */
	    break;

	case 'i':
	    /* Ignore a single dot on a line as an end of message marker */
    	    ignore_dot = 1;
	    break;

	case 'o':
	    if ( strcmp( optarg, "db" ) == 0 ) {
		/* -odb deliver in background */
	    } else if ( strcmp( optarg, "em" ) == 0 ) {
		/* -oem mail back errors */
	    } else if ( strcmp( optarg, "i" ) == 0 ) {
		/* -oi ignore dots */
		ignore_dot = 1;
	    } else if ( strcmp( optarg, "m" ) == 0 ) {
		/* -om send to me if I'm in an alias expansion */
	    } else {
		errs++;
	    }
	    break;

	default:
	    errs++;
	    break;
	}
    }

    /* optind = first to-address */

    /* XXX error handling for command line options? */
    if ( errs != 0 ) {
	fprintf( stderr, "Usage: %s ", argv[ 0 ] );
	fprintf( stderr, "[ -b option ] " );
	fprintf( stderr, "[ -i ] " );
	fprintf( stderr, "[ -o option ] " );
	fprintf( stderr, "[[ -- ] to-address ...]\n" );
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
