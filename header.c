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


    /* return 0 if line is the next line in header block lf */

    int
header_end( struct line_file *lf, char *line )
{
    /* if line syntax is a header, return 0 */
    /* if line could be folded whitespace and lf->l_first != NULL, return 0 */
    return( 0 );
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

	/* if "From "word..., rewrite header "From:"word'\0' */
	if (( end - c ) > 0 ) {
	    *(lf->l_first->line_data + 4) = ':';
	    *end = '\0';
	}
    }

    return( 0 );
}


    int
header_correct( struct line_file *lf, struct envelope *env )
{
    if ( header_exceptions( lf ) != 0 ) {
	return( -1 );
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
