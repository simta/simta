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
#define HEAD_DATE		0
    { "From",			NULL,		NULL },
#define HEAD_FROM		1
    { "Sender",			NULL,		NULL },
#define HEAD_SENDER		2
    { "To",			NULL,		NULL },
#define HEAD_TO			3
    { "Message-ID",		NULL,		NULL },
#define HEAD_MESSAGE_ID		4
    { "cc",			NULL,		NULL },
#define HEAD_CC			5
    { "bcc",			NULL,		NULL },
#define HEAD_BCC		6
    { NULL,			NULL,		NULL }
};


    void
header_stdout( struct header h[])
{
    while ( h->h_key != NULL ) {
	/* print key */
	printf( "%s: ", h->h_key );

	if ( h->h_line != NULL ) {
	    printf( "%s", h->h_line->line_data );

	    if ( h->h_data != NULL ) {
		printf( "\n%s data: %s", h->h_key, h->h_data );
	    }

	} else {
	    printf( "NULL" );
	}

	printf( "\n" );

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

    /* mail(1) on Solaris gives non-rfc compliant first header line */
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

    if ( env->e_sin != NULL ) {
	memcpy( &sin, env->e_sin, sizeof( struct sockaddr_in )); 

    } else {
	/* XXX local IP addr? */
	memset( &sin, 0, sizeof( struct sockaddr_in ));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
    }

    if ( time( &clock ) < 0 ) {
	return( -1 );
    }

    if (( tm = localtime( &clock )) == NULL ) {
	return( -1 );
    }

    if ( strftime( daytime, sizeof( daytime ), "%e %b %Y %T", tm ) == 0 ) {
	return( -1 );
    }

    /* Received header */
    if ( fprintf( file, "Received: FROM %s ([%s])\n\tBY %s ID %s ;\n\t%s %s\n",
	    env->e_mail, inet_ntoa( sin.sin_addr ), env->e_hostname,
	    env->e_id, daytime, tz( tm )) < 0 ) {
	return( -1 );
    }

    return( 0 );
}


    /* return 0 if line is the next line in header block lf */
    /* rfc2822, 2.1 General Description:
     * A message consists of header fields (collectively called "the header
     * of the message") followed, optionally, by a body.  The header is a
     * sequence of lines of characters with special syntax as defined in
     * this standard. The body is simply a sequence of characters that
     * follows the header and is separated from the header by an empty line
     * (i.e., a line with nothing preceding the CRLF).
     */

    /* rfc 2822, 2.2.2. Structured Header Field Bodies:
     * SP, ASCII value 32) and horizontal tab (HTAB, ASCII value 9)
     * characters (together known as the white space characters, WSP
     */

    int
header_end( struct line_file *lf, char *line )
{
    char		*c;

    /* null line means that message data begins */
    if (( *line ) == '\0' ) {
	return( 1 );
    }

    if (( *line == ' ' ) || ( *line == '\t' )) {

	/* line could be FWS if it's not the first line */
	if ( lf->l_first != NULL ) {

	    /* line could be FWS if there's something on it (rfc2822 3.2.3) */
	    for ( c = line + 1; *c != '\0'; c++ ) {
		if (( *line != ' ' ) || ( *line != '\t' )) {
		    return( 0 );
		}
	    }
	}

    } else {

	/* if line syntax is a header, return 0 */
	for ( c = line; *c != ':'; c++ ) {
	    /* colon ascii value is 58 */
	    if (( *c < 33 ) || ( *c > 126 )) {
		break;
	    }
	}

	if (( *c == ':' ) && (( c - line ) > 0 )) {
	    /* proper field name followed by a colon */
	    return( 0 );
	}
    }

    return( 1 );
}


    /* return 0 if all went well.
     * return 1 if we reject the message.
     * return -1 if there was a serious error.
     */

    /* all errors out to stderr, as you should only be correcting headers
     * from simsendmail, for now.
     */

    int
header_correct( struct line_file *lf, struct envelope *env )
{
    struct line			*l;
    struct header		*h;
    char			*colon;
    char			*l_angle;
    char			*r_angle;
    char			*comma;
    size_t			header_len;
    struct passwd		*pw;
    int				result;
    char			*sender;
    char			*prepend_line = NULL;
    size_t			prepend_len = 0;
    size_t			len;
    time_t			clock;
    struct tm			*tm;
    char			daytime[ 35 ];

    if (( result = header_exceptions( lf )) != 0 ) {
	fprintf( stderr, "header_exceptions error\n" );
	return( result );
    }

    /* put header information in to data structures for later processing */
    for ( l = lf->l_first; l != NULL ; l = l->line_next ) {

	/* rfc 2822:
	 * Header fields are lines composed of a field name, followed
	 * by a colon (":"), followed by a field body, and terminated
	 * by CRLF.  A field name MUST be composed of printable
	 * US-ASCII characters (i.e., characters that have values
	 * between 33 and 126, inclusive), except colon.
	 */

	/* line is FWS if first character of the line is whitespace */
	if ( isspace( (int)*l->line_data ) != 0 ) {
	    continue;
	}

	for ( colon = l->line_data; *colon != ':'; colon++ )
		;

	header_len = ( colon - ( l->line_data ));

	/* field name followed by a colon */
	for ( h = simta_headers; h->h_key != NULL; h++ ) {
	    if ( strncasecmp( h->h_key, l->line_data, header_len ) == 0 ) {
		/* correct field name */
		if ( h->h_line == NULL ) {
		    h->h_line = l;

		} else {
		    /* header h->h_key appears at least twice */
		    fprintf( stderr, "Illegal duplicate header: %s\n",
			    h->h_key );
		    return( 1 );
		}
	    }
	}
    }

    /* unfold & uncomment all the structured headers we care about */
    for ( h = simta_headers; h->h_key != NULL; h++ ) {
	if ( h->h_line != NULL ) {
	    if (( h->h_data = header_unfold( h->h_line )) == NULL ) {
		perror( "header_unfold realloc" );
		return( -1 );
	    }

	    if (( result = header_uncomment( &(h->h_data))) != 0 ) {
		if ( result < 0 ) {
		    perror( "header_uncomment realloc" );

		} else {
		    fprintf( stderr, "Header %s: Illegal parenthesis\n",
			    h->h_key );
		}

		return( result );
	    }
	}
    }

    /* examine header data structures */

    if (( pw = getpwuid( getuid())) == NULL ) {
	perror( "getpwuid" );
	return( -1 );
    }

    if (( sender = (char*)malloc( strlen( pw->pw_name ) +
	    strlen( env->e_hostname ) + 2 )) == NULL ) {
	perror( "malloc" );
	return( -1 );
    }

    sprintf( sender, "%s@%s", pw->pw_name, env->e_hostname );

    if ( simta_headers[ HEAD_FROM ].h_line == NULL ) {
	/* generate header */

	if (( len = ( strlen( simta_headers[ HEAD_FROM ].h_key ) +
		strlen( sender ) + 3 )) > prepend_len ) {
	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		perror( "realloc" );
		return( -1 );
	    }

	    prepend_len = len;

	}

	sprintf( prepend_line, "%s: %s",
		simta_headers[ HEAD_FROM ].h_key, sender );

	if (( simta_headers[ HEAD_FROM ].h_line =
		line_prepend( lf, prepend_line )) == NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}

	env->e_mail = simta_headers[ HEAD_FROM ].h_line->line_data + 6;

    } else {
	/*
	 * From: user
	 * From: user@domain
	 * From: Firstname Lastname <user@domain>
	 * From: "Firstname Lastname" <user@domian>
	 * From: user@domian (Firstname Lastname)
	 */

	/* from            =   "From:" mailbox-list CRLF
	 *
	 * mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
	 *
	 * mailbox         =   name-addr / addr-spec
	 *
	 * name-addr       =   [display-name] angle-addr
	 *
	 * display-name    =   phrase
	 *
	 * phrase          =   1*word / obs-phrase
	 *
	 * word            =   atom / quoted-string
	 *
	 * atom            =   [CFWS] 1*atext [CFWS]
	 *
	 * atext           =   ALPHA / DIGIT / ; Any character except controls,
	 *			"!" / "#" /     ;  SP, and specials.
	 *			"$" / "%" /     ;  Used for atoms
	 *			"&" / "'" /
	 *			"*" / "+" /
	 *			"-" / "/" /
	 *			"=" / "?" /
	 *			"^" / "_" /
	 *			"`" / "{" /
	 *			"|" / "}" /
	 *			"~"
	 *
	 * angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
	 *
	 * addr-spec       =   local-part "@" domain
	 *
	 * local-part      =   dot-atom / quoted-string / obs-local-part
	 *
	 * domain          =   dot-atom / domain-literal / obs-domain
	 *
	 * domain-literal  =   [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
	 *
	 * dcontent        =   dtext / quoted-pair
	 *
	 * dtext           =   NO-WS-CTL /     ; Non white space controls
	 *
	 *			%d33-90 /       ; The rest of the US-ASCII
	 *			%d94-126        ;  characters not including "[",
	 *					;  "]", or "\"
	 *
	 * dot-atom        =   [CFWS] dot-atom-text [CFWS]
	 *
	 * dot-atom-text   =   1*atext *("." 1*atext)
	 */

	/* use first addr, addrs are seperated by commas */
	for ( comma = simta_headers[ HEAD_FROM ].h_data; comma != '\0';
		comma++ ) {
	    if ( *comma == ',' ) {
		break;
	    }
	}

	if ( *comma == ',' ) {
	    *comma = '\0';
	}

	/* check for angle-addr */
	for ( l_angle = simta_headers[ HEAD_FROM ].h_data; l_angle != '\0';
		l_angle++ ) {
	    if ( *l_angle == '<' ) {
		break;
	    }
	}

	if ( *l_angle == '<' ) {
	    for ( r_angle = l_angle; r_angle != '\0'; r_angle++ ) {
		if ( *r_angle == '>' ) {
		    break;
		}
	    }

	    if ( *l_angle != '<' ) {
		fprintf( stderr, "Illegal header angle-addr syntax: %s\n",
			simta_headers[ HEAD_FROM ].h_key );
		return( 1 );
	    }

	    /* XXX check for illegal syntax before l_angle, after r_angle? */

	} else {
	    /* no angle_addr */
	}

	/* XXX wrong */
	env->e_mail = simta_headers[ HEAD_FROM ].h_data;
    }

    if ( simta_headers[ HEAD_SENDER ].h_line == NULL ) {
	if ( simta_headers[ HEAD_FROM ].h_data != NULL ) {
	    /* From header wasn't generated, check for conflict */
	    if ( strcasecmp( env->e_mail, sender ) != 0 ) {
		if (( len = ( strlen( simta_headers[ HEAD_SENDER ].h_key ) +
			strlen( sender ) + 3 )) > prepend_len ) {
		    if (( prepend_line = (char*)realloc( prepend_line, len ))
			    == NULL ) {
			perror( "realloc" );
			return( -1 );
		    }

		    prepend_len = len;
		}

		sprintf( prepend_line, "%s: %s",
			simta_headers[ HEAD_SENDER ].h_key, sender );

		if (( simta_headers[ HEAD_SENDER ].h_line =
			line_prepend( lf, prepend_line )) == NULL ) {
		    perror( "malloc" );
		    return( -1 );
		}
	    }
	}

    } else {
	/* XXX sufficient check? */
	if ( strcasecmp( env->e_mail, sender ) != 0 ) {
	    fprintf( stderr, "Header %s: Illegal value\n",
		    simta_headers[ HEAD_SENDER ].h_key );
	}
    }

    if ( simta_headers[ HEAD_DATE ].h_line == NULL ) {
	if ( time( &clock ) < 0 ) {
	    perror( "time" );
	    return( -1 );
	}

	if (( tm = localtime( &clock )) == NULL ) {
	    perror( "localtime" );
	    return( -1 );
	}

	if ( strftime( daytime, sizeof( daytime ), "%a, %e %b %Y %T", tm )
		== 0 ) {
	    perror( "strftime" );
	    return( -1 );
	}

	if (( len = ( strlen( simta_headers[ HEAD_DATE ].h_key ) +
		strlen( daytime ) + 3 )) > prepend_len ) {

	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		perror( "realloc" );
		return( -1 );
	    }

	    prepend_len = len;
	}

	sprintf( prepend_line, "%s: %s",
		simta_headers[ HEAD_DATE ].h_key, daytime );

	if (( simta_headers[ HEAD_DATE ].h_line =
		line_prepend( lf, prepend_line )) == NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}
    }

    if ( simta_headers[ HEAD_MESSAGE_ID ].h_line == NULL ) {
	if (( len = ( strlen( simta_headers[ HEAD_MESSAGE_ID ].h_key ) +
		strlen( env->e_id ) + 3 )) > prepend_len ) {
	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		perror( "realloc" );
		return( -1 );
	    }

	    prepend_len = len;
	}

	sprintf( prepend_line, "%s: %s",
		simta_headers[ HEAD_MESSAGE_ID ].h_key, env->e_id );

	if (( simta_headers[ HEAD_MESSAGE_ID ].h_line =
		line_prepend( lf, prepend_line )) == NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}
    }

    if ( simta_headers[ HEAD_TO ].h_line == NULL ) {
	/* XXX action */
	/* To: blah: woof woof; */
    }

    if ( simta_headers[ HEAD_CC ].h_line == NULL ) {
	/* XXX action */
    }

    if ( simta_headers[ HEAD_BCC ].h_line == NULL ) {
	/* XXX action */
    }

#ifdef DEBUG
    header_stdout( simta_headers );
#endif /* DEBUG */

    if ( prepend_line != NULL ) {
	free( prepend_line );
    }

    return( 0 );
}


    char *
header_unfold( struct line *line )
{
    char		*unfolded;
    char		*c;
    struct line		*l;

    for ( c = line->line_data; *c != ':'; c++ )
	    ;

    /* eliminate all leading WSP */
    c++;

    while (( *c == ' ' ) || ( *c == '\t' )) {
	c++;
    }

    if (( unfolded = (char*)malloc( strlen( c ) + 1 )) == NULL ) {
	return( NULL );
    }

    strcpy( unfolded, c );

    for ( l = line->line_next; l != NULL; l = l->line_next ) {
	/* is the line FWS? */
	if (( *l->line_data == ' ' ) || ( *l->line_data == '\t' )) {

	    /* eliminate all WSP except the last one */
	    c = l->line_data;

	    while (( *(c + 1) == ' ' ) || ( *(c + 1) == '\t' )) {
		c++;
	    }

	    if (( unfolded = (char*)realloc( unfolded, strlen( unfolded ) +
		    strlen( c ) + 1 )) == NULL ) {
		return( NULL );
	    }

	    strcat( unfolded, c );

	} else {
	    break;
	}
    }

    return( unfolded );
}


    /* return -1 on syserror
     * return 0 on success
     * return 1 if the headers can't be uncommented
     */

    int
header_uncomment( char **line )
{
    size_t		before;
    size_t		after;
    int			comment = 0;
    char		*r;
    char		*w;

    before = strlen( *line );

    r = *line;
    w = *line;

    while ( *r != '\0' ) {
	if ( *r == '\\' ) {
	    if ( comment == 0 ) {
		*w = *r;
		w++;
	    }

	    r++;

	    if ( *r == '\0' ) {
		break;
	    }

	    if ( comment == 0 ) {
		*w = *r;
		w++;
	    }
	    r++;

	} else if ( *r == '(' ) {
	    /* start comment */
	    comment++;

	} else if ( *r == ')' ) {
	    comment--;

	    if ( comment < 0 ) {
		/* comment out of order */
		return( 1 );
	    }

	} else {
	    if ( comment == 0 ) {
		*w = *r;
		w++;
	    }
	}

	r++;
    }

    *w = '\0';

    after = strlen( *line );

    if ( before > after ) {
	if (( *line = (char*)realloc( *line, after + 1 )) == NULL ) {
	    return( -1 );
	}
    }

    return( 0 );
}
