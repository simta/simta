/**********          header.c          **********/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>

#include "line_file.h"
#include "envelope.h"
#include "header.h"
#include "receive.h"


struct header simta_headers[] = {
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


    void
header_stdout( struct header h[])
{
    while ( h->h_key != NULL ) {
	printf( "%s:", h->h_key );

	if ( h->h_line != NULL ) {
	    printf( "%s\n", h->h_line->line_data );

	} else {
	    printf( "NULL\n" );
	}

	h++;
    }
}

    int
count_words( char *l )
{
    int			space = 1;
    int			words = 0;
    char		*c;

    for ( c = l; *c != '\0'; c++ ) {
	if ( isspace( (int)*c ) == 0 ) {
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


    /* Some mail clents exhibit bad behavior when generating headers.
     *
     * return 0 if all went well.
     * return 1 if we reject the message.
     * die -1 if there was a serious error.
     */

    int
header_exceptions( struct line_file *lf )
{
    char		*c;
    char		*end;

    if ( lf->l_first == NULL ) {
	/* empty message */
	return( 0 );
    }

    /* mail(1) on Solaris gives non-RFC compliant first header line */
    c = lf->l_first->line_data;

    if ( strncasecmp( c, "From ", 5 ) == 0 ) {
	c += 5;
	for ( end = c; ( *end > 33 ) && ( *end < 126 ); end++ )
		;

	/* if "From "word ..., rewrite header "From:"word'\0' */
	if (( end - c ) > 0 ) {
	    *(lf->l_first->line_data + 4) = ':';
	    *end = '\0';
	}
    }

    return( 0 );
}


    int
header_file_out( struct line_file *lf, FILE *file )
{
    struct line			*l;

    for ( l = lf->l_first; l != NULL; l = l->line_next ) {
	fprintf( file, "%s\n", l->line_data );
    }

    return( 0 );
}


    int
header_timestamp( struct envelope *env, FILE *file )
{
    struct sockaddr_in		sin;
    time_t			clock;
    struct tm			*tm;
    char			daytime[ 30 ];

    memset( &sin, 0, sizeof( struct sockaddr_in ));

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;

    if ( time( &clock ) < 0 ) {
	return( -1 );
    }

    if (( tm = localtime( &clock )) == NULL ) {
	return( -1 );
    }

    if ( strftime( daytime, sizeof( daytime ), "%e %b %Y %T", tm ) == 0 ) {
	return( -1 );
    }

    /* XXX Received header */
    if ( fprintf( file, "Received: FROM %s ([%s])\n\tBY %s ID %s ;\n\t%s %s\n",
	    "user@localhost",
	    inet_ntoa( sin.sin_addr ), "localhost",
	    env->e_id, daytime, tz( tm )) < 0 ) {
	return( -1 );
    }

    return( 0 );
}


    /* return 0 if line is the next line in header block lf */

    int
header_end( struct line_file *lf, char *line )
{
    char		*colon;

    /* null line means that message data begins */
    if (( *line ) == '\0' ) {
	return( 1 );
    }

    /* if line could be folded whitespace and lf->l_first != NULL, return 0 */
    if ( lf->l_first != NULL ) {
	/* XXX need to check for non-whitespace? */
	if ( isspace( (int)*line ) != 0 ) {
	    /* line contains folded white space */
	    return( 0 );
	}
    }

    /* if line syntax is a header, return 0 */
    for ( colon = line; *colon != ':'; colon++ ) {
	/* colon ascii value is 58 */
	if (( *colon < 33 ) || ( *colon > 126 )) {
	    break;
	}
    }

    if (( *colon == ':' ) && (( colon - line ) > 0 )) {
	/* proper field name followed by a colon */
	return( 0 );
    }

    return( 1 );
}


    /* return 0 if all went well.
     * return 1 if we reject the message.
     * return -1 if there was a serious error.
     */

    int
header_correct( struct line_file *lf, struct envelope *env )
{
    int			words;
    struct line		*l;
    struct header	*h;
    char		*colon;
    size_t		header_len;
    struct passwd	*pw;
    char		*from_line;

    if ( header_exceptions( lf ) != 0 ) {
	return( -1 );
    }

    /* put header information in to data structures for later processing */
    for ( l = lf->l_first; l != NULL ; l = l->line_next ) {

	/* RFC 2822:
	 * Header fields are lines composed of a field name, followed
	 * by a colon (":"), followed by a field body, and terminated
	 * by CRLF.  A field name MUST be composed of printable
	 * US-ASCII characters (i.e., characters that have values
	 * between 33 and 126, inclusive), except colon.
	 */

	/* XXX need to check for non-whitespace chars? */
	if ( isspace( (int)*l->line_data ) != 0 ) {
	    /* line contains folded white space */
	    continue;
	}

	for ( colon = l->line_data; *colon != ':'; colon++ )
		;

	header_len = ( colon - ( l->line_data ));

	/* field name followed by a colon */
	for ( h = simta_headers; h->h_key != NULL; h++ ) {
	    if ( strncasecmp( h->h_key, l->line_data, header_len ) == 0 ) {
		/* correct field name */
		h->h_line = l;
	    }
	}
    }

    /* examine header data structures */

    header_stdout( simta_headers );

    return( 0 );

    /* "From:" header */
    if ( simta_headers[ HEAD_FROM ].h_line == NULL ) {
	/* generate header */

	if (( pw = getpwuid( getuid())) == NULL ) {
	    perror( "getpwuid" );
	    return( -1 );
	}

	if (( from_line = (char*)malloc( strlen( pw->pw_name ) +
		strlen( env->e_hostname ) + 9 )) == NULL ) {
	    return( -1 );
	}

	/* XXX need localhostname */
	sprintf( from_line, "From: %s@%s", pw->pw_name, "localhost" );

	/*
	if (( simta_headers[ HEAD_FROM ].h_line =
		line_prepend( lf, from_line )) == NULL ) {
	    return( -1 );
	}
	env->e_mail = simta_headers[ HEAD_FROM ].h_line->line_data + 6;
	*/

    } else {
	/* handle following cases from doc/sendmail/headers:
	 * From: user
	 * From: user@domain
	 * From: Firstname Lastname <user@domain>
	 * From: "Firstname Lastname" <user@domian>
	 * From: user@domian (Firstname Lastname)
	 *
	 * To: blah: woof woof;
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

    return( 0 );

    if ( simta_headers[ HEAD_SENDER ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_ORIG_DATE ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_MESSAGE_ID ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_TO ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_REPLY_TO ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_CC ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_BCC ].h_line == NULL ) {
	/* XXX action */
    }

    return( 0 );
}
