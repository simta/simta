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

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>

#include <snet.h>

#include "line_file.h"
#include "envelope.h"

#define	TEST_DIR	"local"

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

int		count_words ___P(( char * ));

int		header_end ___P(( struct line_file *, char * ));
int		header_exceptions ___P(( struct line_file * ));
int		header_correct ___P(( struct line_file * ));


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


    /* return 0 if line is the next line in header block lf */

    int
header_end( struct line_file *lf, char *line )
{
    /* if line syntax is a header, return 0 */
    /* if line could be folded whitespace and lf->l_first != NULL, return 0 */
    return( 1 );
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
	    *(lf->l_first->line_data) = ':';
	    *end = '\0';
	}
    }

    return( 0 );
}


    int
header_correct( struct line_file *lf )
{
    if ( header_exceptions( lf ) != 0 ) {
	return( -1 );
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


    int
main( int argc, char *argv[] )
{
    SNET		*snet_stdin;
    char		*line;
    struct line_file	*lf;
    struct line		*l;
    struct envelope	*env;
    int			usage = 0;
    int			c;
    int			ignore_dot = 0;
    int			x;
    int			header;

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

    if ( usage != 0 ) {
	fprintf( stderr, "Usage: %s "
		"[ -b option ] "
		"[ -i ] "
		"[ -o option ] "
		"[[ -- ] to-address ...]\n", argv[ 0 ] );
	exit( 1 );
    }

    /* create envelope */
    if (( env = env_create( NULL )) == NULL ) {
	perror( "env_create" );
	exit( 1 );
    }

    /* optind = first to-address */
    for ( x = optind; x < argc; x++ ) {
	if ( env_recipient( env, argv[ x ] ) != 0 ) {
	    perror( "env_recipient" );
	    exit( 1 );
	}
    }

    /* create line_file for headers */
    if (( lf = line_file_create()) == NULL ) {
	perror( "line_file_create" );
	exit( 1 );
    }

    /* need to read stdin in a line-oriented fashon */
    if (( snet_stdin = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    /* start in header mode */
    header = 1;

    while (( line = snet_getline( snet_stdin, NULL )) != NULL ) {
	if ( ignore_dot == 0 ) {
	    if (( line[ 0 ] == '.' ) && ( line[ 1 ] =='\0' )) {
		/* single dot on a line */
		break;
	    }
	}

	if ( header == 1 ) {
	    if ( header_end( lf, line ) != 0 ) {
		if (( x = header_correct( lf )) < 0 ) {
		    perror( "header_correct" );
		    exit( 1 );

		} else if ( x > 0 ) {
		    /* headers couldn't be corrected */
		    fprintf( stderr, "Message rejected: Bad headers\n" );
		    exit( 1 );
		}

		/* open Dfile */
		/* print headers to Dfile */
		/* print line to Dfile */
		header = 0;

	    } else {
		if (( l = line_append( lf, line )) == NULL ) {
		    perror( "line_append" );
		    exit( 1 );
		}
	    }

	} else {
	    /* print line to Dfile */
	}
    }

    if ( snet_close( snet_stdin ) != 0 ) {
	perror( "snet_close" );
	exit( 1 );
    }

    if ( header == 1 ) {
	if (( x = header_correct( lf )) < 0 ) {
	    perror( "header_correct" );
	    exit( 1 );

	} else if ( x > 0 ) {
	    /* headers couldn't be corrected */
	    fprintf( stderr, "Message rejected: Bad headers\n" );
	    exit( 1 );
	}

	/* open Dfile */
	/* print headers to Dfile */
    }

    /* close Dfile */

    /* store Efile */

    return( 0 );
}
