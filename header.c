/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <time.h>

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <dirent.h>

#include "line_file.h"
#include "envelope.h"
#include "header.h"
#include "simta.h"
#include "queue.h"

#define	TOKEN_UNDEFINED			0
#define	TOKEN_QUOTED_STRING		1
#define	TOKEN_DOT_ATOM			2
#define	TOKEN_DOMAIN_LITERAL		3

#define	MAILBOX_FROM_VERIFY		1
#define	MAILBOX_FROM_CORRECT		2
#define	MAILBOX_SENDER			3
#define	MAILBOX_TO_CORRECT		4
#define	MAILBOX_RECIPIENTS_CORRECT	5
#define	MAILBOX_GROUP_CORRECT		6


struct line_token {
    int			t_type;
    char		*t_start;
    struct line		*t_start_line;
    char		*t_end;
    struct line		*t_end_line;
    char		*t_unfolded;
};


char	*skip_ws( char * );
int	line_token_dot_atom( struct line_token *, struct line *, char * );
int	line_token_quoted_string( struct line_token *, struct line *, char * );
int	line_token_domain_literal( struct line_token *, struct line *, char * );
void	header_stdout( struct header[] );
void	header_exceptions( struct line_file * );
char	*skip_cfws( struct line **, char ** );
int	is_dot_atom_text( int );
int	parse_addr( struct envelope *, struct line **, char **, int );
int	parse_mailbox_list( struct envelope *, struct line *, char *, int );
int	parse_recipients( struct envelope *, struct line *, char * );
int	match_sender( struct line_token *, struct line_token *, char * );
int	line_token_unfold( struct line_token * );
int	header_lines( struct line_file *, struct header * );
int	mid_text( struct receive_headers *, char *, char ** );
int	seen_text( struct receive_headers *, char *, char ** );
int	is_unquoted_atom_text( int );
char	*token_unquoted_atom( char * );
void	make_more_seen( struct receive_headers * );
char	*append_seen( struct receive_headers *, char *, int );

int				simta_generate_sender;


    int
match_sender( struct line_token *local, struct line_token *domain, char *addr )
{
    char			*a;
    char			*b;

    /* only try to match dot atext for sender */
    if (( local->t_type != TOKEN_DOT_ATOM ) ||
	    ( domain->t_type != TOKEN_DOT_ATOM )) {
	return( 0 );
    }

    a = addr;
    b = local->t_start;

    while ( b != local->t_end + 1 ) {
	if ( *a != *b ) {
	    return( 0 );
	}

	a++;
	b++;
    }

    if ( *a != '@' ) {
	return( 0 );
    }

    a++;
    b = domain->t_start;

    while ( b != domain->t_end + 1 ) {
	if ( *a != *b ) {
	    return( 0 );
	}

	a++;
	b++;
    }

    if ( *a != '\0' ) {
	return( 0 );
    }

    return( 1 );
}


    /* 
     * return non-zero if the headers can't be uncommented
     * return 0 on success
     *	-c will be on next word, or NULL
     *	-l will be on c's line, or NULL
     */

    char *
skip_cfws( struct line **l, char **c )
{
    int				comment = 0;
    struct line			*comment_line = NULL;

    for ( ; ; ) {
	switch ( **c ) {
	case ' ':
	case '\t':
	    break;

	case '(':
	    if ( comment_line == NULL ) {
		comment_line = *l;
	    }

	    comment++;
	    break;

	case ')':
	    comment--;

	    if ( comment == 0 ) {
		comment_line = NULL;

	    } else if ( comment < 0 ) {
		return( "unbalanced )" );
	    }
	    break;

	case '\\':
	    (*c)++;

	    if ( **c == '\0' ) {
		/* trailing '\' is illegal */
		return( "trailing '\\' is illegal" );
	    }
	    break;

	case '\0':
	    /* end of line.  if next line starts with WSP, continue */
	    if (((*l)->line_next != NULL ) &&
		    (( *((*l)->line_next->line_data) == ' ' ) ||
		    ( *((*l)->line_next->line_data) == '\t' ))) {

		*l = (*l)->line_next;
		*c = (*l)->line_data;
		break;

	    } else {
		/* End of header */

		*c = NULL;

		if ( comment_line != NULL ) {
		    *l = comment_line;
		    return( "unbalanced \(" );

		} else {
		    return( NULL );
		}
	    }


	default:
	    if ( comment == 0 ) {
		return( NULL );
	    }
	}

	(*c)++;
    }
}


    void
header_stdout( struct header h[])
{
    while ( h->h_key != NULL ) {
	if ( h->h_line != NULL ) {
	    printf( "%s\n", h->h_line->line_data );

	    if ( h->h_data != NULL ) {
		printf( "\tdata: %s\n", h->h_data );
	    }

	} else {
	    printf( "%s NULL\n", h->h_key );
	}

	h++;
    }
}



    /* Some mail clents exhibit bad behavior when generating headers.
     *
     * return 0 if all went well.
     * return 1 if we reject the message.
     * die -1 if there was a serious error.
     */

    void
header_exceptions( struct line_file *lf )
{
    char		*c;
    char		*end;

    if ( lf->l_first == NULL ) {
	/* empty message */
	return;
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
}


    int
header_file_out( struct line_file *lf, FILE *file )
{
    struct line			*l;
    int				rc, data_written = 0;

    for ( l = lf->l_first; l != NULL; l = l->line_next ) {
	if (( rc = fprintf( file, "%s\n", l->line_data )) < 0 ) {
	    return( rc );
	}
	data_written += rc;
    }

    return( data_written );
}


    int
header_timestamp( struct envelope *env, FILE *file )
{
    char	daytime[ RFC822_TIMESTAMP_LEN ];

    if ( rfc822_timestamp( daytime ) != 0 ) {
	return( -1 );
    }

    /* Received header */
    if ( fprintf( file, "Received: FROM %s\n\tBY %s ID %s ;\n\t%s\n",
	    env->e_mail, simta_hostname, env->e_id, daytime ) < 0 ) {
	return( -1 );
    }

    return( 0 );
}

/* RFC 5322 3.3 Date and Time Specification
 * date-time       =   [ day-of-week "," ] date time [CFWS]
 * day-of-week     =   ([FWS] day-name) / obs-day-of-week
 * day-name        =   "Mon" / "Tue" / "Wed" / "Thu" /
 *                     "Fri" / "Sat" / "Sun"
 * date            =   day month year
 * day             =   ([FWS] 1*2DIGIT FWS) / obs-day
 * month           =   "Jan" / "Feb" / "Mar" / "Apr" /
 *                     "May" / "Jun" / "Jul" / "Aug" /
 *                     "Sep" / "Oct" / "Nov" / "Dec"
 * year            =   (FWS 4*DIGIT FWS) / obs-year
 * time            =   time-of-day zone
 * time-of-day     =   hour ":" minute [ ":" second ]
 * zone            =   (FWS ( "+" / "-" ) 4DIGIT) / obs-zone
 *
 * %T and %z are defined in ISO C99; C89 compilers might
 * not support them.
 */
    int
rfc822_timestamp( char *daytime )
{
    time_t		clock;
    struct tm		*tm;

    if ( time( &clock ) < 0 ) {
	syslog( LOG_ERR, "Syserror rfc822_timestamp time: %m" );
	return( 1 );
    }

    if (( tm = localtime( &clock )) == NULL ) {
	syslog( LOG_ERR, "Syserror rfc822_timestamp localtime: %m" );
	return( 1 );
    }

    if ( strftime( daytime, RFC822_TIMESTAMP_LEN,
	    "%a, %d %b %Y %T %z", tm ) == 0 ) {
	syslog( LOG_ERR, "Syserror rfc822_timestamp strftime: %m" );
	return( 1 );
    }

    return( 0 );
}

    int
mid_text( struct receive_headers *r, char *line, char **msg )
{
    char			*start;
    char			*end;

    if (( start = skip_cws( line )) != NULL ) {
	if ( r->r_mid != NULL ) {
	    free( r->r_mid );
	    r->r_mid = NULL;
	    r->r_state = R_HEADER_READ;
	    if ( msg != NULL ) {
		*msg = "Illegal Message-ID Header: illegal extra content";
	    }
	    return( 0 );
	}

	if ( *start != '<' ) {
	    r->r_state = R_HEADER_READ;
	    if ( msg != NULL ) {
		*msg = "Illegal Message-ID Header: expected '<' character";
	    }
	    return( 0 );
	}

	start++;

	if ( *start == '"' ) {
	    if (( end = token_quoted_string( start )) == NULL ) {
		r->r_state = R_HEADER_READ;
		if ( msg != NULL ) {
		    *msg = "Illegal Message-ID Header: bad LHS quoted string";
		}
		return( 0 );
	    }

	} else {
	    if (( end = token_dot_atom( start )) == NULL ) {
		r->r_state = R_HEADER_READ;
		if ( msg != NULL ) {
		    *msg = "Illegal Message-ID Header: bad LHS dot atom text";
		}
		return( 0 );
	    }
	}

	end++;

	if ( *end != '@' ) {
	    r->r_state = R_HEADER_READ;
	    if ( msg != NULL ) {
		*msg = "Illegal Message-ID Header: expected '@'";
	    }
	    return( 0 );
	}

	end++;

	if ( *end == '[' ) {
	    if (( end = token_domain_literal( end )) == NULL ) {
		r->r_state = R_HEADER_READ;
		if ( msg != NULL ) {
		    *msg = "Illegal Message-ID Header: bad RHS domain literal";
		}
		return( 0 );
	    }

	} else {
	    if (( end = token_dot_atom( end )) == NULL ) {
		r->r_state = R_HEADER_READ;
		if ( msg != NULL ) {
		    *msg = "Illegal Message-ID Header: bad RHS dot atom text";
		}
		return( 0 );
	    }
	}

	end++;

	if ( *end != '>' ) {
	    r->r_state = R_HEADER_READ;
	    if ( msg != NULL ) {
		*msg = "Illegal Message-ID Header: expected '>'";
	    }
	    return( 0 );
	}

	*end = '\0';
	if (( r->r_mid = strdup( start )) == NULL ) {
	    *end = '>';
	    syslog( LOG_ERR, "mid_text strdup: %m" );
	    return( -1 );
	}
	*end = '>';

	if ( skip_cws( end + 1 ) != NULL ) {
	    free( r->r_mid );
	    r->r_mid = NULL;
	    r->r_state = R_HEADER_READ;
	    if ( msg != NULL ) {
		*msg = "Illegal Message-ID Header: illegal extra content";
	    }
	    return( 0 );
	}
    }

    return( 0 );
}

    void
make_more_seen( struct receive_headers *r )
{
    int				n = 0;
    int				i;
    char			**cpp;

    if ( !r ) {
	return;
    }
    if ( r->r_all_seen_before ) {
	for ( i = 0 ; r->r_all_seen_before[ i ] ; ++i ) {
	}
	n = i;
    }
    cpp = malloc( (n+2) * sizeof *cpp );
    if ( cpp ) {
	if ( r->r_all_seen_before ) {
	    memcpy( cpp, r->r_all_seen_before, n * sizeof *cpp );
	    free( r->r_all_seen_before );
	}
	cpp[ n ] = strdup( "" );
	cpp[ n+1 ] = 0;
	r->r_all_seen_before = cpp;
	syslog( LOG_ERR, "make_more_seen: n=%d", n);
    }
}

    char *
append_seen( struct receive_headers *r, char *msg, int l2 )
{
    int				i;
    int				l1;
    char			*cp;
    char			*new;

    if ( !r || ! r->r_all_seen_before) {
	errno = EDOM;
	return( 0 );
    }
    for ( i = 0 ; r->r_all_seen_before[ i ] ; ++i ) {
    }
    if ( !i ) {
	errno = EDOM;
	return( 0 );
    }
    --i;
    cp = r->r_all_seen_before[ i ];
    l1 = strlen( cp );
    if ( (new = malloc( l1 + l2 + 1 + !!*cp )) ) {
	if ( *cp ) {
	    memcpy( new, cp, l1 );
	    new[ l1++ ] = ' ';
	    if ( r->r_seen_before == cp ) {
		r->r_seen_before = new;
	    }
	} else {
	    int l3 = strlen( simta_seen_before_domain );
	    if ( l3 == l2 && !memcmp( msg, simta_seen_before_domain, l3 )) {
		r->r_seen_before = new;
	    }
	}
	memcpy( new + l1, msg, l2 );
	new[ l1 + l2 ] = 0;
	free(cp);
	r->r_all_seen_before[ i ] = new;
    }
    return( new );
}

    int
seen_text( struct receive_headers *r, char *line, char **msg )
{
    char			*start;
    char			*end;
    char			*t;

    while (( start = skip_cws( line )) != NULL ) {

	if ( *start == '"' ) {
	    t = "Illegal " STRING_SEEN_BEFORE " Header: bad quoted string";
	    end = token_quoted_string( start );
	} else {
	    t = "Illegal " STRING_SEEN_BEFORE " Header: bad unquoted atom text";
	    end = token_unquoted_atom( start );
	}

	if ( end == NULL ) {
	    r->r_state = R_HEADER_READ;
	    if ( msg != NULL ) {
		*msg = t;
	    }
	    return( 0 );
	}

	end++;

	if (!(append_seen( r, start, end - start ))) {
	    syslog( LOG_ERR, "seen_text strdup: %m" );
	    return( 1 );
	}

	line = end;
    }

    return( 0 );
}


    /* return 0 if line is the next line in header block lf */
    /* RFC 5322 2.1 General Description
     * A message consists of header fields (collectively called "the header
     * section of the message") followed, optionally, by a body.  The header
     * section is a sequence of lines of characters with special syntax as
     * defined in this specification. The body is simply a sequence of
     * characters that follows the header section and is separated from the
     * header section by an empty line (i.e., a line with nothing preceding
     * the CRLF).
     */

    /* RFC 5322 2.2 Header Fields
     * space (SP, ASCII value 32) and horizontal tab (HTAB, ASCII value 9)
     * characters (together known as the white space characters, WSP)
     */
    /* this only takes two header types in to account, so it is currently
     * a state machine.  If additional headers need to be added, a better
     * strategy might be to cache header lines in core and do analysis on
     * complete header fields one at a time.
     */


    int
header_text( int line_no, char *line, struct receive_headers *r, char **msg )
{
    char		*c;
    int			header_len;

    /* null line means that message data begins */
    if ((( *line ) == '\0' ) ||
	    (( r != NULL ) && ( r->r_state == R_HEADER_END ))) {
	/* blank line, or headers already over */
	if ( r != NULL ) {
	    r->r_state = R_HEADER_END;
	}
	return( 1 );

    } else if (( *line == ' ' ) || ( *line == '\t' )) {
	/* if line is not the first line it could be header FWS */
	if ( line_no == 1 ) {
	    if ( r != NULL ) {
		r->r_state = R_HEADER_END;
	    }
	    return( 1 );

	} else if (( r != NULL ) && ( r->r_state == R_HEADER_MID )) {
	    return( mid_text( r, line, msg ));
	} else if (( r != NULL ) && ( r->r_state == R_HEADER_SEEN )) {
	    return( seen_text( r, line, msg ));
	}

    } else {
	/* line could be started with a new header */
	if ( r != NULL ) {
	    r->r_state = R_HEADER_READ;
	}

	for ( c = line; *c != ':'; c++ ) {
	    /* colon ascii value is 58 */
	    if (( *c < 33 ) || ( *c > 126 )) {
		break;
	    }
	}

	/* check to e if it's a proper field name followed by a colon */
	if (( *c == ':' ) && (( header_len = ( c - line )) > 0 )) {
	    if ( r == NULL ) {
		return( 0 );
	    }

	    if (( header_len == STRING_MID_LEN ) &&
		    ( strncasecmp( line, STRING_MID, STRING_MID_LEN ) == 0 )) {
		if ( r->r_mid_set != 0 ) {
		    if ( msg != NULL ) {
			*msg = "Illegal Duplicate Message-ID Headers";
		    }
		    if ( r->r_mid != NULL ) {
			free( r->r_mid );
			r->r_mid = NULL;
		    }
		    return( 0 );
		}
		r->r_mid_set = 1;
		r->r_state = R_HEADER_MID;
		return( mid_text( r, c + 1, msg ));

	    } else if (( header_len == STRING_RECEIVED_LEN ) &&
		    ( strncasecmp( line, STRING_RECEIVED,
		    STRING_RECEIVED_LEN ) == 0 )) {
		r->r_received_count++;
	    } else if (( header_len == STRING_SEEN_BEFORE_LEN ) &&
		    ( strncasecmp( line, STRING_SEEN_BEFORE,
		    STRING_SEEN_BEFORE_LEN ) == 0 )) {
		r->r_state = R_HEADER_SEEN;
		make_more_seen( r );
		return( seen_text( r, c + 1, msg ));
	    } else if (( header_len == STRING_MIME_VERSION_LEN ) &&
		    ( strncasecmp( line, STRING_MIME_VERSION,
		    STRING_MIME_VERSION_LEN ) == 0 )) {
		r->r_env->e_attributes |= ENV_ATTR_8BITMIME;
	    }

	} else {
	    /* not a proper header */
	    if ( r != NULL ) {
		r->r_state = R_HEADER_END;
	    }
	    return( 1 );
	}
    }

    return( 0 );
}


    int
header_lines( struct line_file *lf, struct header headers[] )
{
    struct line			*l;
    struct header		*h;
    char			*colon;
    size_t			header_len;

    /* put header information in to data structures for later processing */
    for ( l = lf->l_first; l != NULL ; l = l->line_next ) {

	/* RFC 5322 2.2 Header Fields
	 * Header fields are lines beginning with a field name, followed
	 * by a colon (":"), followed by a field body, and terminated
	 * by CRLF.  A field name MUST be composed of printable
	 * US-ASCII characters (i.e., characters that have values
	 * between 33 and 126, inclusive), except colon.
	 */

	/* Lines starting with whitespace are continuations, we don't
	 * want to look at them. */
	if (( *l->line_data == ' ' ) || ( *l->line_data == '\t' )) {
	    continue;
	}

	for ( colon = l->line_data; *colon != ':'; colon++ );
	header_len = ( colon - ( l->line_data ));

	for ( h = headers; h->h_key != NULL; h++ ) {
	    /* Check whether the current line (up to the colon) matches */
	    if ( strncasecmp( h->h_key, l->line_data, header_len ) == 0 ) {
		/* The current line (up to the colon) matches h */
		if ( h->h_line == NULL ) {
		    /* We haven't seen this header before */
		    h->h_line = l;

		} else {
		    /* This is the second time this header has occurred,
		     * so the message is not RFC compliant.
		     */
		    syslog( LOG_INFO, "header_lines: illegal duplicate header "
			    "%s on line %d", h->h_key, l->line_no );

		    return( 1 );
		}
	    }
	}
    }

    return( 0 );
}


    /* return 0 if all went well.
     * return 1 if we reject the message.
     * return -1 if there was a serious error.
     */

    int
header_correct( int read_headers, struct line_file *lf, struct envelope *env )
{
    struct line			*l;
    struct line			**lp;
    int				rc;
    int				ret = 0;
    char			*prepend_line = NULL;
    size_t			prepend_len = 0;
    size_t			len;
    char			daytime[ RFC822_TIMESTAMP_LEN ];
    struct envelope		*to_env = NULL;

/* RFC 5322 3.6 Field definitions
 *  Field           Min number      Max number      Notes
 *
 *  orig-date       1               1
 *
 *  from            1               1               See sender and 3.6.2
 *
 *  sender          0*              1               MUST occur with multi-
 *                                                  address from - see 3.6.2
 *
 *  reply-to        0               1
 *
 *  to              0               1
 *
 *  cc              0               1
 *
 *  bcc             0               1
 *
 *  message-id      0*              1               SHOULD be present - see
 *                                                  3.6.4
 *
 *  in-reply-to     0*              1               SHOULD occur in some
 *                                                  replies - see 3.6.4
 *
 *  references      0*              1               SHOULD occur in some
 *                                                  replies - see 3.6.4
 *
 *  subject         0               1
 *
 * header_lines() will enforce max number.
 * header_correct() will add missing fields.
 */
    struct header headers_rfc5322[] = {
	{ "Date",		NULL,		NULL },
#define HEAD_DATE		0
	{ "From",		NULL,		NULL },
#define HEAD_FROM		1
	{ "Sender",		NULL,		NULL },
#define HEAD_SENDER		2
	{ "Reply-To",		NULL,		NULL },
#define HEAD_REPLY_TO		3
	{ "To",			NULL,		NULL },
#define HEAD_TO			4
	{ "Cc",			NULL,		NULL },
#define HEAD_CC			5
	{ "Bcc",		NULL,		NULL },
#define HEAD_BCC		6
	{ "Message-ID",         NULL,           NULL },
#define HEAD_MESSAGE_ID		7
	{ "In-Reply-To",	NULL,		NULL },
#define HEAD_IN_REPLY_TO	8
	{ "References",		NULL,		NULL },
#define HEAD_REFERENCES		9
	{ "Subject",		NULL,		NULL },
#define HEAD_SUBJECT		10
	{ NULL,			NULL,		NULL }
    };


    if ( read_headers != 0 ) {
	to_env = env;
    }

    /* check headers for known mail clients behaving badly */
    if ( simta_submission_mode == SUBMISSION_MODE_SIMSEND ) {
	header_exceptions( lf );
    }

    if (( ret = header_lines( lf, headers_rfc5322 )) != 0 ) {
	goto error;
    }

    simta_generate_sender = 0;

    /* examine & correct header data */

    /* From: */
    if (( l = headers_rfc5322[ HEAD_FROM ].h_line ) != NULL ) {
	if (( rc = parse_mailbox_list( NULL, l, l->line_data + 5,
		MAILBOX_FROM_CORRECT )) != 0 ) {
	    ret = rc;
	    if ( rc < 0 ) {
		goto error;
	    }
	}

    } else if ( simta_submission_mode == SUBMISSION_MODE_MTA_STRICT ) {
	ret = 1;
	goto error;
    } else {
	/* generate From: header */
	if (( len = ( strlen( headers_rfc5322[ HEAD_FROM ].h_key ) +
		strlen( env->e_mail ) + 3 )) > prepend_len ) {
	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		syslog( LOG_ERR, "header_correct realloc: %m" );
		ret = -1;
		goto error;
	    }

	    prepend_len = len;
	}

	sprintf( prepend_line, "%s: %s",
		headers_rfc5322[ HEAD_FROM ].h_key, env->e_mail );

	if (( headers_rfc5322[ HEAD_FROM ].h_line =
		line_prepend( lf, prepend_line, COPY )) == NULL ) {
	    syslog( LOG_ERR, "header_correct malloc: %m" );
	    ret = -1;
	    goto error;
	}
    }

    /* Sender: */
    if (( l = headers_rfc5322[ HEAD_SENDER ].h_line ) != NULL ) {
	if ( simta_submission_mode == SUBMISSION_MODE_SIMSEND ) {
	    if (( rc = parse_mailbox_list( env, l, l->line_data + 7,
		    MAILBOX_SENDER )) != 0 ) {
		ret = rc;
		if ( rc < 0 ) {
		    goto error;
		}
	    }
	}

    } else if ((( simta_submission_mode == SUBMISSION_MODE_SIMSEND ) ||
	    ( simta_submission_mode == SUBMISSION_MODE_MSA )) &&
	    ( simta_generate_sender != 0 ) &&
	    ( simta_simsend_strict_from != 0 )) {
	if (( len = ( strlen( headers_rfc5322[ HEAD_SENDER ].h_key ) +
		strlen( env->e_mail ) + 3 )) > prepend_len ) {
	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		syslog( LOG_ERR, "header_correct realloc: %m" );
		ret = -1;
		goto error;
	    }

	    prepend_len = len;
	}

	sprintf( prepend_line, "%s: %s",
		headers_rfc5322[ HEAD_SENDER ].h_key, env->e_mail );

	if (( headers_rfc5322[ HEAD_SENDER ].h_line =
		line_prepend( lf, prepend_line, COPY )) == NULL ) {
	    syslog( LOG_ERR, "header_correct malloc: %m" );
	    ret = -1;
	    goto error;
	}
    }

    if ( headers_rfc5322[ HEAD_DATE ].h_line == NULL ) {
	if ( simta_submission_mode == SUBMISSION_MODE_MTA_STRICT ) {
	    ret = 1;
	    goto error;
	}

	if ( rfc822_timestamp( daytime ) != 0 ) {
	    ret = -1;
	    goto error;
	}

	if (( len = ( strlen( headers_rfc5322[ HEAD_DATE ].h_key ) +
		strlen( daytime ) + 3 )) > prepend_len ) {

	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		syslog( LOG_ERR, "header_correct realloc: %m" );
		ret = -1;
		goto error;
	    }

	    prepend_len = len;
	}

	sprintf( prepend_line, "%s: %s",
		headers_rfc5322[ HEAD_DATE ].h_key, daytime );

	if (( headers_rfc5322[ HEAD_DATE ].h_line =
		line_prepend( lf, prepend_line, COPY )) == NULL ) {
	    syslog( LOG_ERR, "header_correct malloc: %m" );
	    ret = -1;
	    goto error;
	}
    }

    if (( headers_rfc5322[ HEAD_MESSAGE_ID ].h_line == NULL ) &&
	    (( simta_submission_mode == SUBMISSION_MODE_SIMSEND ) ||
	    ( simta_submission_mode == SUBMISSION_MODE_MSA ))) {
	if (( len = ( strlen( headers_rfc5322[ HEAD_MESSAGE_ID ].h_key ) +
		strlen( env->e_id ) + 6 + strlen( simta_hostname ))) >
		prepend_len ) {
	    if (( prepend_line = (char*)realloc( prepend_line, len ))
		    == NULL ) {
		syslog( LOG_ERR, "header_correct realloc: %m" );
		ret = -1;
		goto error;
	    }

	    prepend_len = len;
	}

	sprintf( prepend_line, "%s: <%s@%s>",
		headers_rfc5322[ HEAD_MESSAGE_ID ].h_key, env->e_id,
		simta_hostname );

	if (( headers_rfc5322[ HEAD_MESSAGE_ID ].h_line =
		line_prepend( lf, prepend_line, COPY )) == NULL ) {
	    syslog( LOG_ERR, "header_correct malloc: %m" );
	    ret = -1;
	    goto error;
	}
    }

    if (( l = headers_rfc5322[ HEAD_TO ].h_line ) != NULL ) {
	if (( rc = parse_recipients( to_env, l, l->line_data + 3 )) != 0 ) {
	    ret = rc;
	    if ( rc < 0 ) {
		goto error;
	    }
	}
    }

    if (( l = headers_rfc5322[ HEAD_CC ].h_line ) != NULL ) {
	if (( rc = parse_recipients( to_env, l, l->line_data + 3 )) != 0 ) {
	    ret = rc;
	    if ( rc < 0 ) {
		goto error;
	    }
	}
    }

    if (( l = headers_rfc5322[ HEAD_BCC ].h_line ) != NULL ) {
	if (( rc = parse_recipients( to_env, l, l->line_data + 4 )) != 0 ) {
	    ret = rc;
	    if ( rc < 0 ) {
		goto error;
	    }
	}

	if ( simta_submission_mode == SUBMISSION_MODE_SIMSEND ) {
	    /* remove bcc lines */
	    if ( l->line_prev != NULL ) {
		lp = &(l->line_prev->line_next);

	    } else {
		lp = &(lf->l_first);
	    }

	    for ( l = l->line_next; l != NULL; l = l->line_next ) {
		if (( *(l->line_data) != ' ' ) && ( *(l->line_data) != '\t' )) {
		    break;
		}
	    }

	    *lp = l;

	    /* XXX free bcc lines if we're anal */
	}
    }

error:

    if ( prepend_line != NULL ) {
	free( prepend_line );
    }

    return( ret );
}


    /* return 0 if all went well.
     * return 1 if we reject the message.
     * return -1 if there was a serious error.
     */

    /* RFC 5322 3.2.1 Quoted characters
     * quoted-pair     =   ("\" (VCHAR / WSP)) / obs-qp
     *
     * RFC 5322 3.2.2 Folding White Space and Comments
     * FWS             =   ([*WSP CRLF] 1*WSP) /  obs-FWS
     * ctext           =   %d33-39 /          ; Printable US-ASCII
     *                     %d42-91 /          ;  characters not including
     *                     %d93-126 /         ;  "(", ")", or "\"
     *                     obs-ctext
     * ccontent        =   ctext / quoted-pair / comment
     * comment         =   "(" *([FWS] ccontent) [FWS] ")"
     * CFWS            =   (1*([FWS] comment) [FWS]) / FWS
     *
     * RFC 5322 3.2.3 Atom
     * atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
     *                     "!" / "#" /        ;  characters not including
     *                     "$" / "%" /        ;  specials.  Used for atoms.
     *                     "&" / "'" /
     *                     "*" / "+" /
     *                     "-" / "/" /
     *                     "=" / "?" /
     *                     "^" / "_" /
     *                     "`" / "{" /
     *                     "|" / "}" /
     *                     "~"
     * atom            =   [CFWS] 1*atext [CFWS]
     * dot-atom-text   =   1*atext *("." 1*atext)
     * dot-atom        =   [CFWS] dot-atom-text [CFWS]
     * specials        =   "(" / ")" /        ; Special characters that do
     *                     "<" / ">" /        ;  not appear in atext
     *                     "[" / "]" /
     *                     ":" / ";" /
     *                     "@" / "\" /
     *                     "," / "." /
     *                     DQUOTE
     *
     * RFC 5322 3.2.4 Quoted Strings
     * qtext           =   %d33 /             ; Printable US-ASCII
     *                     %d35-91 /          ;  characters not including
     *                     %d93-126 /         ;  "\" or the quote character
     *                     obs-qtext
     * qcontent        =   qtext / quoted-pair
     * quoted-string   =   [CFWS]
     *                     DQUOTE *([FWS] qcontent) [FWS] DQUOTE
     *                     [CFWS]
     *
     * RFC 5322 3.2.5 Miscellaneous Tokens
     * word            =   atom / quoted-string
     * phrase          =   1*word / obs-phrase
     *
     * RFC 5322 3.4 Address Specification:
     *
     * address         =   mailbox / group
     * mailbox         =   name-addr / addr-spec
     * name-addr       =   [display-name] angle-addr
     * angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS]
     *                     obs-angle-addr
     * group           =   display-name ":" [group-list] ";" [CFWS]
     * display-name    =   phrase
     * mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
     * address-list    =   (address *("," address)) / obs-addr-list
     * group-list      =   mailbox-list / CFWS / obs-group-list
     *
     * RFC 5322 3.4.1 Addr-Spec Specification 
     *
     * addr-spec       =   local-part "@" domain
     * local-part      =   dot-atom / quoted-string / obs-local-part
     * domain          =   dot-atom / domain-literal / obs-domain
     * domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
     * dtext           =   %d33-90 /          ; Printable US-ASCII
     *                     %d94-126 /         ;  characters not including
     *                     obs-dtext          ;  "[", "]", or "\"
     */


    /*
     * ( dot-atom-text | quoted-string )
     *
     * ( dot-atom-text | quoted-string ) '@' ( dot-atom-text | domain-literal )
     *
     * return 0 if address is not syntactically correct
     * return 1 if address was correct
     */

    int
is_emailaddr( char *addr )
{
    if ( parse_emailaddr( EMAIL_ADDRESS_NORMAL, addr, NULL, NULL ) == 0 ) {
	return( 1 );
    }

    return( 0 );
}


    int
parse_emailaddr( int mode, char *addr, char **user, char **domain )
{
    char				*u;
    char				*d;
    char				*end;
    char				*at;
    char				*eol;
    char				swap;

    /* make sure mode is in range */
    switch ( mode ) {
    case RFC_821_MAIL_FROM:
    case RFC_821_RCPT_TO:
    case EMAIL_ADDRESS_NORMAL:
	break;

    default:
	return( 1 );
    }

    u = addr;

    if ( u == NULL ) {
	return( 1 );
    }

    if ( mode != EMAIL_ADDRESS_NORMAL ) {
	if ( *u != '<' ) {
	    return( 1 );
	}
	u++;
    }

    if ( *u == '\0' ) {
	if ( mode == EMAIL_ADDRESS_NORMAL ) {
	    return( 0 );
	}
	return( 1 );

    } else if ( *u == '@' ) {
	if ( mode == EMAIL_ADDRESS_NORMAL ) {
	    return( 1 );
	}

	/* do at-domain-literal - consume domain */
	u++;
	if ( *u == '[' ) {
	    if (( end = token_domain_literal( u )) == NULL ) {
		return( 1 );
	    }
	} else {
	    if (( end = token_domain( u )) == NULL ) {
		return( 1 );
	    }
	}
	end++;

	while ( *end == ',' ) {
	    u = end + 1;

	    if ( *u != '@' ) {
		return( 1 );
	    }

	    /* consume domain */
	    u++;
	    if ( *u == '[' ) {
		if (( end = token_domain_literal( u )) == NULL ) {
		    return( 1 );
		}
	    } else {
		if (( end = token_domain( u )) == NULL ) {
		    return( 1 );
		}
	    }
	    end++;
	}

	if ( *end != ':' ) {
	    return( 1 );
	}

	u = end + 1;
    }

    if ( mode != EMAIL_ADDRESS_NORMAL ) {
	*user = u;
    }

    /* consume the user portion of the address */

    /* <> is a valid address for MAIL FROM commands */
    if ( *u == '>' ) {
	if (( mode == RFC_821_MAIL_FROM ) && ( *( u + 1 ) == '\0' )) {
	    *u = '\0';
	    *domain = NULL;
	    return( 0 );
	}

	return( 1 );

    } else if ( *u == '"' ) {
	if (( end = token_quoted_string( u )) == NULL ) {
	    return( 1 );
	}

    } else {
	if (( end = token_dot_atom( u )) == NULL ) {
	    return( 1 );
	}
    }

    at = end + 1;

    /* RFC 5321 2.3.5 Domain Names
     * The reserved mailbox name "postmaster" may be used in a RCPT
     * command without domain qualification (see section 4.1.1.3) and
     * MUST be accepted if so used.
     */

    if ((( *at == '\0' ) && ( mode == EMAIL_ADDRESS_NORMAL )) ||
	    (( *at == '>' ) && ( mode == RFC_821_RCPT_TO ))) {
	swap = *at;
	*at = '\0';
	if ( strcasecmp( u, STRING_POSTMASTER ) != 0 ) {
	    *at = swap;
	    return( 1 );
	}

	if ( mode == RFC_821_RCPT_TO ) {
	    *domain = NULL;
	}

	return( 0 );
    }

    if ( *at != '@' ) {
	return( 1 );
    }

    /* consume the domain portion of the address */

    d = at + 1;

    if ( strlen( d ) > SIMTA_MAX_HOST_NAME_LEN ) {
	return( 1 );
    }

    if ( mode != EMAIL_ADDRESS_NORMAL ) {
	*domain = d;
    }

    if ( *d == '[' ) {
	if (( end = token_domain_literal( d )) == NULL ) {
	    return( 1 );
	}

    } else {
	if (( end = token_dot_atom( d )) == NULL ) {
	    return( 1 );
	}
    }

    eol = end + 1;

    if ( mode != EMAIL_ADDRESS_NORMAL ) {
	if (( *eol != '>' ) || ( *( eol + 1 ) != '\0' ))  {
	    return( 1 );
	}

	*eol = '\0';

    } else if ( *eol != '\0' ) {
	return( 1 );
    }

    return( 0 );
}


    /*
     * ( dot-atom-text | quoted-string )
     *
     * ( dot-atom-text | quoted-string ) '@' ( dot-atom-text | domain-literal )
     *
     * return -1 on syserror
     * return 0 if address is not syntactically correct, or correctable
     * return 1 if address was correct, or corrected
     *
     */

    int
correct_emailaddr( char **addr )
{
    char				*start;
    char				*end;
    char				*at;
    char				*eol;
    char				*new;
    char				*r;
    char				*w;
    size_t				len;

    /* find start and end of local part */

    start = *addr;

    if ( *start == '"' ) {
	if (( end = token_quoted_string( start )) == NULL ) {
	    return( 0 );
	}

    } else {
	if (( end = token_dot_atom( start )) == NULL ) {
	    return( 0 );
	}
    }

    /* next token can be '@' followed by a domain, or '\0' and we'll
     * append simta_domain. anything else return 0.
     */

    at = end + 1;

    if ( *at == '@' ) {
	start = at + 1;

	if ( *start == '[' ) {
	    if (( end = token_domain_literal( start )) == NULL ) {
		return( 0 );
	    }

	} else {
	    if (( end = token_dot_atom( start )) == NULL ) {
		return( 0 );
	    }
	}

	eol = end + 1;

	if ( *eol != '\0' ) {
	    return( 0 );
	}

    } else if ( *at == '\0' ) {
	len = end - start;
	len += 3;
	len += strlen( simta_domain );

	if (( new = (char*)malloc( len )) == NULL ) {
	    return( -1 );
	}
	memset( new, 0, len );

	w = new;

	for ( r = start; r != end + 1; r++ ) {
	    *w = *r;
	    w++;
	}

	*w = '@';
	w++;

	for ( r = simta_domain; *r != '\0'; r++ ) {
	    *w = *r;
	    w++;
	}

	*w = '\0';

	free( *addr );
	*addr = new;

    } else {
	return( 0 );
    }

    return( 1 );
}


    char *
skip_cws( char *start )
{
    char		*c;
    int			comment_mode = 0;

    for ( c = start; ; c++ ) {
	switch ( *c ) {
	case ' ':
	case '\t':
	    break;

	case '\0':
	    return( NULL );

	case '(':
	    comment_mode++;
	    break;

	case ')':
	    if ( comment_mode != 0 ) {
		comment_mode = 0;
	    } else {
		return( c );
	    }
	    break;

	default:
	    if ( comment_mode == 0 ) {
		return( c );
	    }
	    break;
	}
    }
}


    char *
skip_ws( char *start )
{
    while (( *start == ' ' ) || ( *start == '\t' )) {
	start++;
    }

    return( start );
}

    int
is_unquoted_atom_text( int c )
{
    switch ( c ) {
    case 0:
    case '(': case ' ': case '\t': case '"':
	return 0;

    default:
	return( 1 );
    }
}


    char *
token_unquoted_atom( char *start )
{
    if ( is_unquoted_atom_text( *start ) == 0 ) {
	return( NULL );
    }

    for ( ; ; ) {
	if ( is_unquoted_atom_text( *(start + 1)) == 0 ) {
	    return( start );
	}

	start++;
    }
}

    int
parse_addr( struct envelope *env, struct line **start_line, char **start,
	int mode )
{
    char				*addr;
    size_t				addr_len;
    char				*next_c;
    char				*r;
    char				*w;
    struct line				*next_l;
    char				*local_domain;
    char				*buf;
    size_t				buf_len;
    struct line_token			local;
    struct line_token			domain;
    char				*err_str;

    if (( mode != MAILBOX_FROM_CORRECT ) && ( mode != MAILBOX_SENDER ) &&
	    ( mode != MAILBOX_RECIPIENTS_CORRECT ) &&
	    ( mode != MAILBOX_GROUP_CORRECT )) {
	syslog( LOG_DEBUG, "parse_addr: unsupported mode" );
	return( -1 );
    }

    if ( **start == '<' ) {
	next_c = (*start) + 1;

    } else {
	next_c = *start;
    }

    domain.t_start = NULL;

    next_l = *start_line;

    if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
	syslog( LOG_DEBUG, "parse_addr: line %d: %s",
		next_l->line_no, err_str );
	syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	return( 1 );
    }

    if ( next_c == NULL ) {
	syslog( LOG_DEBUG, "parse_addr: line %d: address expected",
		next_l->line_no );
	syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	return( 1 );

    } else if ( *next_c == '"' ) {
	if ( line_token_quoted_string( &local, next_l, next_c ) != 0 ) {
	    syslog( LOG_DEBUG, "parse_addr: line %d: unbalanced \"",
		    next_l->line_no );
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );
	}

    } else {
	if ( line_token_dot_atom( &local, next_l, next_c ) != 0 ) {
	    syslog( LOG_DEBUG, "parse_addr: line %d: bad token: %c",
		    next_l->line_no, *next_c );
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );
	}
    }

    next_c = local.t_end + 1;
    next_l = local.t_end_line;

    if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
	syslog( LOG_DEBUG, "parse_addr: line %d: %s",
		next_l->line_no, err_str );
	syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	return( 1 );
    }

    if (( next_c == NULL ) || ( *next_c == ',' ) ||
	    (( *next_c == '>' ) && ( **start == '<' )) ||
	    (( mode == MAILBOX_GROUP_CORRECT ) && ( *next_c == ';' ))) {
	/* single addr completion */
	local_domain = simta_domain;

	buf_len = strlen( local_domain );
	buf_len += 2; /* @ & \0 */
	buf_len += strlen( local.t_end_line->line_data );

	if (( buf = (char*)malloc( buf_len )) == NULL ) {
	    syslog( LOG_ERR, "parse_addr malloc: %m" );
	    return( -1 );
	}
	memset( buf, 0, buf_len );

	r = local.t_end_line->line_data;
	w = buf;

	while ( r != local.t_end + 1 ) {
	    if ( r == local.t_start ) {
		local.t_start = w;
	    }

	    if ( r == *start ) {
		*start = w;
	    }

	    *w = *r;
	    w++;
	    r++;
	}

	local.t_end = w - 1;

	*w = '@';
	w++;

	domain.t_type = TOKEN_DOT_ATOM;
	domain.t_start = w;
	domain.t_start_line = local.t_start_line;
	domain.t_end_line = local.t_start_line;

	while ( *local_domain != '\0' ) {
	    *w = *local_domain;
	    w++;
	    local_domain++;
	}

	domain.t_end = w - 1;

	while ( *r != '\0' ) {
	    *w = *r;
	    w++;
	    r++;
	}

	*w = *r;

	free( local.t_end_line->line_data );
	local.t_end_line->line_data = buf;

    } else if ( *next_c == '@' ) {
	next_c++;

	if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
	    syslog( LOG_DEBUG, "parse_addr: line %d: %s",
		    next_l->line_no, err_str );
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );
	}

	if ( next_c == NULL ) {
	    syslog( LOG_DEBUG, "parse_addr: line %d: domain expected",
		    next_l->line_no );
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );

	} else if ( *next_c == '[' ) {
	    if ( line_token_domain_literal( &domain, next_l, next_c ) != 0 ) {
		syslog( LOG_DEBUG, "parse_addr: line %d: unmatched [",
			next_l->line_no );
		syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
		return( 1 );
	    }

	} else {
	    if ( line_token_dot_atom( &domain, next_l, next_c ) != 0 ) {
		syslog( LOG_DEBUG, "parse_addr: line %d: bad token: %c",
			next_l->line_no, *next_c );
		syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
		return( 1 );
	    }
	}

    } else {
	syslog( LOG_DEBUG, "parse_addr: line %d: '@' expected",
		next_l->line_no );
	syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	return( 1 );
    }

    next_c = domain.t_end + 1;
    next_l = domain.t_end_line;

    if ( **start == '<' ) {
	if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
	    syslog( LOG_DEBUG, "parse_addr: line %d: %s",
		    next_l->line_no, err_str );
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );
	}

	if (( next_c == NULL ) || ( *next_c != '>' )) {
	    syslog( LOG_DEBUG, "parse_addr: line %d: '>' expected",
		    next_l->line_no );
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );
	}

	next_c++;
    }

    *start = next_c;
    *start_line = next_l;

    if ( mode == MAILBOX_SENDER ) {
	if ( match_sender( &local, &domain, simta_sender()) == 0 ) {
	    syslog( LOG_DEBUG,
		    "parse_addr: line %d: sender address should be <%s>",
		    next_l->line_no,
		    simta_sender());
	    syslog( LOG_DEBUG, "parse_addr: line: %s", next_l->line_data );
	    return( 1 );
	}

    } else if ( mode == MAILBOX_FROM_CORRECT ) {
	/* if addresses don't match, need to generate sender */
	if (( simta_submission_mode == SUBMISSION_MODE_SIMSEND ) &&
		( match_sender( &local, &domain, simta_sender()) == 0 )) {
	    simta_generate_sender = 1;
	}
    }

    if ( env != NULL ) {
	if ( line_token_unfold( &local ) != 0 ) {
	    return( -1 );
	}

	if ( line_token_unfold( &domain ) != 0 ) {
	    return( -1 );
	}

	addr_len = strlen( local.t_unfolded );
	addr_len += strlen( domain.t_unfolded );
	addr_len += 2;

	if (( addr = (char*)malloc( addr_len )) == NULL ) {
	    syslog( LOG_ERR, "parse_addr malloc: %m" );
	    return( -1 );
	}
	sprintf( addr, "%s@%s", local.t_unfolded, domain.t_unfolded );

	if ( env_recipient( env, addr ) != 0 ) {
	    syslog( LOG_ERR, "parse_addr malloc: %m" );
	    return( -1 );
	}

	free( addr );
	free( local.t_unfolded );
	free( domain.t_unfolded );
    }

    return( 0 );
}


    int
parse_mailbox_list( struct envelope *env, struct line *l, char *c, int mode )
{
    char				*err_str;
    char				*next_c;
    struct line				*next_l;
    struct line_token			local;
    int					result;

    if (( mode != MAILBOX_FROM_CORRECT ) && ( mode != MAILBOX_SENDER ) &&
	    ( mode != MAILBOX_RECIPIENTS_CORRECT ) &&
	    ( mode != MAILBOX_GROUP_CORRECT )) {
	syslog( LOG_DEBUG, "parse_mailbox_list: unsupported mode" );
	return( -1 );
    }

    /* is there data on the line? */
    if (( err_str = skip_cfws( &l, &c )) != NULL ) {
	syslog( LOG_DEBUG, "parse_mailbox_list: line %d: %s",
		l->line_no, err_str );
	syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	return( 1 );
    }

    for ( ; ; ) {

	/*
	 * START: ( NULL )->NULL_ADDR
	 * START: ( .A | QS )->LOCAL_PART
	 * START: ( < )->AA_LEFT
	 */

	if ( c == NULL ) {
	    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: missing address",
		    l->line_no );
	    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	    return( 1 );

	} else if ( *c != '<' ) {

	    /*
	     * LOCAL_PART: ( QS | DA ) ( NULL | , | @ ) -> SINGLE_ADDR
	     * LOCAL_PART: ( QS | DA ) ( < ) -> AA_LEFT
	     * LOCAL_PART: ( QS | DA ) ( .A | QS ) -> DISPLAY_NAME
	     */

	    if ( *c == '"' ) {
		if ( line_token_quoted_string( &local, l, c ) != 0 ) {
		    syslog( LOG_DEBUG,
			    "parse_mailbox_list: line %d: unbalanced \"",
			    l->line_no );
		    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			    l->line_data );
		    return( 1 );
		}

	    } else {
		if ( line_token_dot_atom( &local, l, c ) != 0 ) {
		    syslog( LOG_DEBUG,
			    "parse_mailbox_list: line %d: bad token: %c",
			    l->line_no, *c );
		    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			    l->line_data );
		    return( 1 );
		}
	    }

	    next_c = local.t_end + 1;
	    next_l = local.t_end_line;

	    if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
		syslog( LOG_DEBUG, "parse_mailbox_list: line %d: %s",
			next_l->line_no, err_str );
		syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			next_l->line_data );
		return( 1 );
	    }
	
	    if (( next_c == NULL ) || ( *next_c == ',' ) ||
		    ( *next_c == '@' ) || (( mode == MAILBOX_GROUP_CORRECT ) &&
		    ( *next_c == ';' ))) {

		/* SINGLE_ADDR: email_addr ( NULL ) -> AA_LEFT ) */
	
		c = local.t_start;
		l = local.t_start_line;

	    } else {
		while (( next_c != NULL ) && ( *next_c != '<' )) {

		    /*
		     * DISPLAY_NAME: ( QS | DA )* ( < ) -> AA_LEFT
		     */

		    if ( *next_c == '"' ) {
			if ( line_token_quoted_string( &local, next_l, next_c )
				!= 0 ) {
			    syslog( LOG_DEBUG,
				    "parse_mailbox_list: line %d: unbalanced \"",
				    next_l->line_no );
			    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
				    next_l->line_data );
			    return( 1 );
			}

		    } else {
			if ( line_token_dot_atom( &local, next_l, next_c )
				!= 0 ) {
			    syslog( LOG_DEBUG,
				    "parse_mailbox_list: line %d: bad token: %c",
				    next_l->line_no, *next_c );
			    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
				    next_l->line_data );
			    return( 1 );
			}
		    }

		    next_c = local.t_end + 1;
		    next_l = local.t_end_line;

		    if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
			syslog( LOG_DEBUG, "parse_mailbox_list: line %d: %s",
				next_l->line_no, err_str );
			syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
				next_l->line_data );
			return( 1 );
		    }
		}

		if ( next_c == NULL ) {
		    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: "
			    "unexpected end of header",
			    next_l->line_no );
		    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			    next_l->line_data );
		    return( 1 );
		}

		/* set c, l, fall through to AA_LEFT */
		c = next_c;
		l = next_l;
	    }
	}

	/*
	 * AA_LEFT: email_addr ( NULL ) -> AA_LEFT_DONE )
	 * AA_LEFT: email_addr [ ( , ) -> START ] )
	 */

	if (( result = parse_addr( env, &l, &c, mode )) != 0 ) {
	    return( result );
	}

	if (( err_str = skip_cfws( &l, &c )) != NULL ) {
	    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: %s",
		    l->line_no, err_str );
	    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	    return( 1 );
	}

	if ( c == NULL ) {
	    if ( mode == MAILBOX_GROUP_CORRECT ) {
		syslog( LOG_DEBUG, "parse_mailbox_list: line %d: ';' expected",
			l->line_no );
		syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			l->line_data );
		return( 1 );
	    }

	    return( 0 );
	} 

	if ( *c != ',' ) {
	    if (( mode == MAILBOX_GROUP_CORRECT ) && ( *c == ';' )) {
		c++;

		if (( err_str = skip_cfws( &l, &c )) != NULL ) {
		    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: %s",
			    l->line_no, err_str );
		    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			    l->line_data );
		    return( 1 );
		}

		if ( c != NULL ) {
		    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: illegal "
			    "token after group address: %c",
			    l->line_no, *c );
		    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s",
			    l->line_data );
		    return( 1 );
		}

		return( 0 );
	    }

	    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: "
		    "illegal token after address: %c",
		    l->line_no, *c );
	    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	    return( 1 );
	}

	c++;

	if (( err_str = skip_cfws( &l, &c )) != NULL ) {
	    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: %s",
		    l->line_no, err_str );
	    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	    return( 1 );
	}

	if ( c == NULL ) {
	    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: "
		    "address expected after ','",
		    l->line_no );
	    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	    return( 1 );
	}

	/* c != NULL means more than one address on the line */
	if ( mode == MAILBOX_SENDER ) {
	    syslog( LOG_DEBUG, "parse_mailbox_list: line %d: "
		    "illegal second address in Sender header",
		    l->line_no );
	    syslog( LOG_DEBUG, "parse_mailbox_list: line: %s", l->line_data );
	    return( 1 );

	} else if ( mode == MAILBOX_FROM_CORRECT ) {
	    simta_generate_sender = 1;
	}
    }
}


    /* RFC 5322 3.4 Address Specification
     *
     * address         =   mailbox / group
     * mailbox         =   name-addr / addr-spec
     * name-addr       =   [display-name] angle-addr
     * angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
     * group           =   display-name ":" [group-list] ";" [CFWS]
     * display-name    =   phrase
     * mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
     * address-list    =   (address *("," address)) / obs-addr-list
     * group-list      =   mailbox-list / CFWS / obs-group-list
     */

    int
parse_recipients( struct envelope *env, struct line *l, char *c )
{
    char				*err_str;
    char				*next_c;
    struct line				*next_l;
    struct line_token			local;

    /* is there data on the line? */
    if (( err_str = skip_cfws( &l, &c )) != NULL ) {
	syslog( LOG_DEBUG, "parse_recipients: line %d: %s",
		l->line_no, err_str );
	syslog( LOG_DEBUG, "parse_recipients: line: %s", l->line_data );
	return( 1 );
    }

    if ( c == NULL ) {
	syslog( LOG_DEBUG, "parse_recipients: line %d: Missing address",
		l->line_no );
	syslog( LOG_DEBUG, "parse_recipients: line: %s", l->line_data );
	return( 1 );

    } else if ( *c == ':' ) {
	syslog( LOG_DEBUG, "parse_recipients: line %d: bad token: %c",
		l->line_no, *c );
	syslog( LOG_DEBUG, "parse_recipients: line: %s", l->line_data );
	return( 1 );

    } else if ( *c == '<' ) {
	return( parse_mailbox_list( env, l, c, MAILBOX_RECIPIENTS_CORRECT ));
    }

    /* at least one word on the line */
    if ( *c == '"' ) {
	if ( line_token_quoted_string( &local, l, c ) != 0 ) {
	    syslog( LOG_DEBUG, "parse_recipients: line %d: unbalanced \"",
		    l->line_no );
	    syslog( LOG_DEBUG, "parse_recipients: line: %s", l->line_data );
	    return( 1 );
	}

    } else {
	if ( line_token_dot_atom( &local, l, c ) != 0 ) {
	    syslog( LOG_DEBUG, "parse_recipients: line %d: bad token: %c",
		    l->line_no, *c );
	    syslog( LOG_DEBUG, "parse_recipients: line: %s", l->line_data );
	    return( 1 );
	}
    }

    next_c = local.t_end + 1;
    next_l = local.t_end_line;

    if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
	syslog( LOG_DEBUG, "parse_recipients: line %d: %s",
		next_l->line_no, err_str );
	syslog( LOG_DEBUG, "parse_recipients: line: %s", l->line_data );
	return( 1 );
    }

    if (( next_c == NULL ) || ( *next_c == ',' ) ||
	    ( *next_c == '@' )) {
	/* first word was a single email addr */
	return( parse_mailbox_list( env, local.t_start_line, local.t_start,
		MAILBOX_RECIPIENTS_CORRECT ));
    }

    while ( next_c != NULL ) {
	if ( *next_c == ':' ) {
	    /* previous tokens were group name, next are addresses */
	    return( parse_mailbox_list( env, next_l, next_c + 1,
		    MAILBOX_GROUP_CORRECT ));

	} else if ( *next_c == '<' ) {
	    /* previous tokens were display name for this address */
	    return( parse_mailbox_list( env, next_l, next_c,
		    MAILBOX_RECIPIENTS_CORRECT ));
	}

	/* skip to next token */
	if ( *next_c == '"' ) {
	    if ( line_token_quoted_string( &local, next_l, next_c ) != 0 ) {
		syslog( LOG_DEBUG, "parse_recipients: line %d: unbalanced \"",
			next_l->line_no );
		syslog( LOG_DEBUG, "parse_recipients: line: %s",
			next_l->line_data );
		return( 1 );
	    }

	} else {
	    if ( line_token_dot_atom( &local, next_l, next_c ) != 0 ) {
		syslog( LOG_DEBUG, "parse_recipients: line %d: bad token: %c",
			next_l->line_no, *next_c );
		syslog( LOG_DEBUG, "parse_recipients: line: %s", 
			next_l->line_data );
		return( 1 );
	    }
	}

	next_c = local.t_end + 1;
	next_l = local.t_end_line;

	if (( err_str = skip_cfws( &next_l, &next_c )) != NULL ) {
	    syslog( LOG_DEBUG, "parse_recipients: line %d: %s",
		    next_l->line_no, err_str );
	    syslog( LOG_DEBUG, "parse_recipients: line: %s",
		    next_l->line_data );
	    return( 1 );
	}
    }

    syslog( LOG_DEBUG, "parse_recipients: line %d: unexpected end of header",
	    next_l->line_no );
    syslog( LOG_DEBUG, "parse_recipients: line: %s", next_l->line_data );
    return( 1 );
}


    int
line_token_quoted_string( struct line_token *token, struct line *l,
	char *start )
{
    if ( *start != '"' ) {
	return( 1 );
    }

    token->t_start = start;
    token->t_start_line = l;
    token->t_type = TOKEN_QUOTED_STRING;

    for ( ; ; ) {
	start++;

	switch( *start ) {

	case '"':
	    /* end of quoted string */
	    token->t_end = start;
	    token->t_end_line = l;
	    return( 0 );

	case '\\':
	    start++;

	    if ( *start == '\0' ) {
		/* trailing '\' is illegal */
		return( 1 );
	    }
	    break;

	case '\0':
	    /* end of line.  if next line starts with WSP, continue */
	    l = l->line_next;

	    if (( l != NULL ) &&
		    ((( *(l->line_data)) == ' ' ) ||
		    (( *(l->line_data)) == '\t' ))) {
		start = l->line_data;
		break;

	    } else {
		/* End of header, no matching '"' */
		return( 1 );
	    }

	default:
	    /* everything else */
	    break;

	}
    }
}


    char *
token_quoted_string( char *start )
{
    if ( *start != '"' ) {
	return( NULL );
    }

    for ( ; ; ) {
	start++;

	switch( *start ) {

	case '"':
	    /* end of quoted string */
	    return( start );

	case '\\':
	    start++;

	    if ( *start == '\0' ) {
		/* eol */
		return( NULL );
	    }
	    break;

	case '\0':
	    /* eol */
	    return( NULL );

	default:
	    /* everything else */
	    break;
	}
    }
}


    int
line_token_domain_literal( struct line_token *token, struct line *l,
	char *start )
{
    if ( *start != '[' ) {
	return( 1 );
    }

    token->t_start = start;
    token->t_start_line = l;
    token->t_type = TOKEN_DOMAIN_LITERAL;

    for ( ; ; ) {
	start++;

	switch( *start ) {

	case ']':
	    /* end of domain literal */
	    token->t_end = start;
	    token->t_end_line = l;
	    return( 0 );

	case '\\':
	    start++;

	    if ( *start == '\0' ) {
		/* trailing '\' is illegal */
		return( -1 );
	    }
	    break;

	case '\0':
	    /* end of line.  if next line starts with WSP, continue */
	    l = l->line_next;

	    if (( l != NULL ) &&
		    ((( *(l->line_data)) == ' ' ) ||
		    (( *(l->line_data)) == '\t' ))) {
		start = l->line_data;
		break;

	    } else {
		/* End of header, no matching ']' */
		return( 1 );
	    }

	default:
	    /* everything else */
	    break;

	}
    }
}


    char *
token_domain_literal( char *i )
{
    if ( *i != '[' ) {
	return( NULL );
    }

    for ( ; ; ) {
	i++;

	switch( *i ) {

	case ']':
	    /* end of domain literal */
	    return( i );

	case '\\':
	    i++;

	    if ( *i == '\0' ) {
		/* eol */
		return( NULL );
	    }
	    break;

	case '\0':
	    /* eol */
	    return( NULL );

	default:
	    /* everything else */
	    break;
	}
    }
}


    int
is_dot_atom_text( int c )
{
    if ( isalpha( c ) != 0 ) {
	return( 1 );
    }

    if ( isdigit( c ) != 0 ) {
	return( 1 );
    }

    switch ( c ) {

    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '/':
    case '=':
    case '?':
    case '^':
    case '_':
    case '`':
    case '{':
    case '|':
    case '}':
    case '~':
    case '.':
	return( 1 );

    default:
	return( 0 );
    }
}


    char *
token_domain( char *i )
{
    if (( isalpha( *i ) == 0 ) && ( isdigit( *i ) == 0 )) {
	return( NULL );
    }

    for ( ; ; ) {
	if (( isalpha(*( i + 1 )) == 0 ) && ( isdigit(*( i + 1 )) == 0 ) &&
		(*( i + 1 ) != '.' ) && (*( i + 1 ) != '-' )) {
	    return( i );
	}

	i++;
    }
}


    char *
token_dot_atom( char *start )
{
    if ( is_dot_atom_text( *start ) == 0 ) {
	return( NULL );
    }

    for ( ; ; ) {
	if ( is_dot_atom_text( *(start + 1)) == 0 ) {
	    return( start );
	}

	start++;
    }
}


    int
line_token_unfold( struct line_token *token )
{
    size_t			len;
    struct line			*line;
    char			*tmp;
    char			*c;

    if ( token->t_start_line == token->t_end_line ) {
	/* header not folded, simple case */
	len = token->t_end - token->t_start + 2;

	if (( token->t_unfolded = (char*)malloc( len )) == NULL ) {
	    syslog( LOG_ERR, "line_token_unfold malloc: %m" );
	    return( -1 );
	}
	memset( token->t_unfolded, 0, len );

	strncpy( token->t_unfolded, token->t_start, len - 1 );

	return( 0 );
    }

    /* header folded */
    len = strlen( token->t_start ) + 1;

    if (( token->t_unfolded = (char*)malloc( len )) == NULL ) {
	syslog( LOG_ERR, "line_token_unfold malloc: %m" );
	return( -1 );
    }
    strcpy( token->t_unfolded, token->t_start );

    line = token->t_start_line;

    for ( ; ; ) {
	line = line->line_next;

	c = line->line_data;

	while (( *c == ' ' ) || ( *c == '\t' )) {
	    c++;
	}

	if ( line == token->t_end_line ) {
	    len += token->t_end - c + 1;

	    if (( tmp = (char*)malloc( len )) == NULL ) {
		syslog( LOG_ERR, "line_token_unfold malloc: %m" );
		return( -1 );
	    }
	    sprintf( tmp, "%s ", token->t_unfolded );
	    free( token->t_unfolded );
	    strncat( tmp, c, (size_t)(token->t_end - c + 1));
	    token->t_unfolded = tmp;

	    return( 0 );

	} else {
	    len += strlen( c ) + 1;

	    if (( tmp = (char*)malloc( len )) == NULL ) {
		syslog( LOG_ERR, "line_token_unfold malloc: %m" );
		return( -1 );
	    }
	    sprintf( tmp, "%s %s", token->t_unfolded, c );
	    free( token->t_unfolded );
	    token->t_unfolded = tmp;
	}
    }
}


    int
line_token_dot_atom( struct line_token *token, struct line *l, char *start )
{
    token->t_start = start;
    token->t_start_line = l;
    token->t_end_line = l;
    token->t_type = TOKEN_DOT_ATOM;

    if (( token->t_end = token_dot_atom( start )) == NULL ) {
	return( 1 );
    }

    return( 0 );
}


    struct string_address *
string_address_init( char *string )
{
    struct string_address		*sa;

    if (( sa = (struct string_address*)malloc(
	    sizeof( struct string_address ))) == NULL ) {
	return( NULL );
    }
    memset( sa, 0, sizeof( struct string_address ));

    if (( sa->sa_string = strdup( string )) == NULL ) {
	return( NULL );
    }

    return( sa );
}


    void
string_address_free( struct string_address *sa )
{
    free( sa->sa_string );
    free( sa );
    return;
}


    char *
string_address_parse( struct string_address *sa )
{
    char				*comma;
    char				*end;
    char				*email_start;

    if ( sa->sa_start == NULL ) {
	sa->sa_start = sa->sa_string;

    } else {
	if ( sa->sa_swap != 0 ) {
	    *(sa->sa_start) = sa->sa_swap_char;
	    sa->sa_swap = 0;
	}

	if (( comma = skip_cws( sa->sa_start )) == NULL ) {
	    return( NULL );
	}

	if ( *comma != ',' ) {
	    return( NULL );
	}

	sa->sa_start = comma + 1;
    }

    if (( sa->sa_start = skip_cws( sa->sa_start )) == NULL ) {
	return( NULL );
    }

    for ( ; ; ) {
	if (( *(sa->sa_start) != '"' ) && ( *(sa->sa_start) != '<' )) {
	    if (( end = token_dot_atom( sa->sa_start )) == NULL ) {
		return( NULL );
	    }

	    if ( *(end+1) == '@' ) {
		/* Consume sender@domain [,]*/
		email_start = sa->sa_start;
		sa->sa_start = end + 2;

		if ( *sa->sa_start == '[' ) {
		    if (( end =
			    token_domain_literal( sa->sa_start )) == NULL ) {
			return( NULL );
		    }
		} else {
		    if (( end = token_domain( sa->sa_start )) == NULL ) {
			return( NULL );
		    }
		}

		end++;
		sa->sa_start = end;
		sa->sa_swap_char = *end;
		sa->sa_swap = 1;
		*end = '\0';

		if ( is_emailaddr( email_start ) == 0 ) {
		    return( NULL );
		}

		return( email_start );

	    } else if (( sa->sa_start = skip_cws( end + 1 )) == NULL ) {
		return( NULL );
	    }
	}

	while ( *sa->sa_start != '<' ) {
	    if ( *sa->sa_start == '"' ) {
		if (( end = token_quoted_string( sa->sa_start )) == NULL ) {
		    return( NULL );
		}

	    } else {
		if (( end = token_dot_atom( sa->sa_start )) == NULL ) {
		    return( NULL );
		}
	    }

	    if (( sa->sa_start = skip_cws( end + 1 )) == NULL ) {
		return( NULL );
	    }
	}

	email_start = sa->sa_start + 1;
	for ( end = email_start; *end != '>'; end++ ) {
	    if ( *end == '\0' ) {
		return( NULL );
	    }
	}

	*end = '\0';
	sa->sa_start = end + 1;

	if ( is_emailaddr( email_start ) == 0 ) {
	    return( NULL );
	}

	return( email_start );
    }

    return( NULL );
}

    void
header_free( struct receive_headers *r )
{
    int				i;

    if ( r->r_mid != NULL ) {
	free( r->r_mid );
	r->r_mid = NULL;
    }

    if ( r->r_all_seen_before ) {
	for ( i = 0 ; r->r_all_seen_before[ i ] ; ++i ) {
	    free( r->r_all_seen_before[ i ] );
	}
	free( r->r_all_seen_before );
	r->r_all_seen_before = 0;
    }
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
