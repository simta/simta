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
#include <sys/param.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>

#include <snet.h>

#include "message.h"
#include "envelope.h"

struct header header_list[] = {
    { "Date",			NULL,		NULL },
#define HEAD_ORIG_DATE		0
    { "From",			NULL,		NULL },
#define HEAD_FROM		1
    { "Sender",			NULL,		NULL },
#define HEAD_SENDER		2
    { "To",			NULL,		NULL },
#define HEAD_TO			3
    { "Message-ID",		NULL,		NULL },
#define HEAD_MESSAGE_ID		4
    { "Reply-To",		NULL,		NULL },
#define HEAD_REPLY_TO		5
    { "cc",			NULL,		NULL },
#define HEAD_CC			6
    { "bcc",			NULL,		NULL },
#define HEAD_BCC		7
    { NULL,			NULL,		NULL }
};

int header_exceptions( struct message * );
int headers( struct message * );
int count_words( char * );


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


    int
count_words( char *l )
{
    int			space = 1;
    int			words = 0;
    char		*c;

    for ( c = l; *c != '\0'; c++ ) {
	if ( isspace( *c ) == 0 ) {
	    /* not space */
	    if ( space == 1 ) {
		words++;
		space = 0;
	    }
	} else {
	    /* space */
	    space = 1;
	}
    }

    return( words );
}

    /* return 0 if all went well.
     * return 1 if we reject the message.
     * return -1 if there was a serious error.
     */

    int
headers( struct message *m )
{
    int			words;
    struct line		*l;
    struct line		*bl;
    struct header	*h;
    char		*colon;
    size_t		header_len;
    struct passwd	*pw;
    char		*from_line;

    if ( header_exceptions( m ) != 0 ) {
	return( 1 );
    }

    /* put header information in to data structures for later processing */
    /* put a blank line between the message headers and body, if needed */
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

	if ( isspace( *l->line_data ) != 0 ) {
	    /* line contains folded white space */
	    continue;
	}

	for ( colon = l->line_data; *colon != ':'; colon++ ) {
	    /* colon ascii value is 58 */
	    if (( *colon < 33 ) || ( *colon > 126 )) {
		break;
	    }
	}

	if (( *colon == ':' ) && (( header_len = colon - l->line_data ) > 0 )) {
	    /* proper field name followed by a colon */
	    for ( h = header_list; h->h_key != NULL; h++ ) {
		if ( strncasecmp( h->h_key, l->line_data, header_len ) == 0 ) {
		    /* correct field name */
		    h->h_line = l;
		}
	    }

	} else {
	    /* not a valid header */
	    /* no colon, or colon was the first thing on the line */
	    /* add a blank line between headers and the body */
	    if (( bl = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
		return( -1 );
	    }

	    if (( bl->line_data = (char*)malloc( 1 )) == NULL ) {
		return( -1 );
	    }

	    *bl->line_data = '\0';
	    bl->line_next = l;

	    if (( bl->line_prev = l->line_prev ) == NULL ) {
		m->m_first_line = bl;
	    } else {
		l->line_prev->line_next = bl;
	    }

	    l->line_prev = bl;
	    break;
	}
    }

    /* examine header data structures */

    /* "From:" header */
    if ( header_list[ HEAD_FROM ].h_line == NULL ) {
	/* generate header */

	if (( pw = getpwuid( getuid())) == NULL ) {
	    perror( "getpwuid" );
	    return( 1 );
	}

	if (( from_line = (char*)malloc( strlen( pw->pw_name ) +
		strlen( m->m_env->e_hostname ) + 9 )) == NULL ) {
	    return( -1 );
	}

	sprintf( from_line, "From: %s@%s", pw->pw_name, m->m_env->e_hostname );

	if (( header_list[ HEAD_FROM ].h_line =
		message_prepend_line( m, from_line )) == NULL ) {
	    return( -1 );
	}
	m->m_env->e_mail = header_list[ HEAD_FROM ].h_line->line_data + 6;

    } else {
	/* handle following cases from doc/sendmail/headers:
	 * From: user
	 * From: user@domain
	 * From: Firstname Lastname <user@domain>
	 * From: "Firstname Lastname" <user@domian>
	 *
	 * FWS
	 * (comments)
	 */

	/* XXX totally fucked */

	words = count_words( h->h_line->line_data + 5 );

	if ( words == 0 ) {
	    return( 1 );

	} else if ( words == 1 ) {
	} else {
	}
    }

    if ( header_list[ HEAD_SENDER ].h_line == NULL ) {
	/* XXX action */
    }

    if ( header_list[ HEAD_ORIG_DATE ].h_line == NULL ) {
	/* no date header */
	if ( message_prepend_line( m, "Date: default" ) == NULL ) {
	    return( -1 );
	}
    }

    if ( header_list[ HEAD_MESSAGE_ID ].h_line == NULL ) {
	if ( message_prepend_line( m, "Message-ID: default" ) == NULL ) {
	    perror( "message_prepend_line" );
	    return( -1 );
	}
    }

    if ( header_list[ HEAD_TO ].h_line == NULL ) {
	/* XXX action */
    }

    if ( header_list[ HEAD_REPLY_TO ].h_line == NULL ) {
	/* XXX action */
    }

    if ( header_list[ HEAD_CC ].h_line == NULL ) {
	/* XXX action */
    }

    if ( header_list[ HEAD_BCC ].h_line == NULL ) {
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

    /* message_stdout( m ); */

    if ( message_store( m ) != 0 ) {
	/* XXX error */
	exit( 1 );
    }

    return( 0 );
}
