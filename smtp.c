/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
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

#include <snet.h>

#include <ctype.h>
#include <assert.h>
#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <dirent.h>

#include "line_file.h"
#include "envelope.h"
#include "header.h"
#include "simta.h"
#include "queue.h"
#include "smtp.h"
#include "dns.h"
#include "expand.h"
#include "red.h"

#ifdef HAVE_LIBSSL
#include "tls.h"
#endif /* HAVE_LIBSSL */

#define S_8BITMIME  "8BITMIME"
#define S_SIZE	    "SIZE"
#define S_STARTTLS  "STARTTLS"

#ifdef DEBUG
void	(*smtp_logger)(char *) = stdout_logger;
#else /* DEBUG */
void	(*smtp_logger)(char *) = NULL;
#endif /* DEBUG */

static void smtp_snet_eof( struct deliver *, const char * );
static int smtp_check_banner_line( struct deliver *, char * );

    int
smtp_check_banner_line( struct deliver *d, char *line ) {

    if ( strlen( line ) < 3 ) {
	syslog( LOG_INFO, "Deliver.SMTP env <%s>: bad banner syntax: %s",
		d->d_env ? d->d_env->e_id : "null", line );
	return( SMTP_ERROR );
    }

    if ( !isdigit( (int)line[ 0 ] ) ||
	    !isdigit( (int)line[ 1 ] ) ||
	    !isdigit( (int)line[ 2 ] )) {
	syslog( LOG_INFO, "Deliver.SMTP env <%s>: bad banner syntax: %s",
		d->d_env ? d->d_env->e_id : "null", line );
	return( SMTP_ERROR );
    }

    if ( line[ 3 ] != '\0' &&
	    line[ 3 ] != ' ' &&
	    line [ 3 ] != '-' ) {
	syslog( LOG_INFO, "Deliver.SMTP env <%s>: bad banner syntax: %s",
		d->d_env ? d->d_env->e_id : "null", line );
	return( SMTP_ERROR );
    }

    return( SMTP_OK );
}

    int
smtp_consume_banner( struct line_file **err_text, struct deliver *d,
	char *line, char *error )
{
    int				ret = SMTP_ERROR;

    if ( err_text != NULL ) {
	if ( *err_text == NULL ) {
	    if (( *err_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "Syserror: smtp_consume_banner "
			"line_file_create: %m" );
		goto consume;
	    }

	} else {
	    if ( line_append( *err_text, "", COPY ) == NULL ) {
		syslog( LOG_ERR, "Syserror: smtp_consume_banner "
			"line_append: %m" );
		goto consume;
	    }
	}

	if ( line_append( *err_text, error, COPY ) == NULL ) {
	    syslog( LOG_ERR, "Syserror: smtp_consume_banner line_append: %m" );
	    goto consume;
	}

	if ( line_append( *err_text, line, COPY ) == NULL ) {
	    syslog( LOG_ERR, "Syserror: smtp_consume_banner line_append: %m" );
	    goto consume;
	}
    }

    if (( err_text != NULL )) { 
	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( d->d_snet_smtp, NULL )) == NULL ) {
		smtp_snet_eof( d, "smtp_consume_banner: snet_getline" );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( smtp_check_banner_line( d, line ) == SMTP_ERROR ) {
		return ( SMTP_BAD_CONNECTION );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if (( err_text != NULL ) &&
		    ( line_append( *err_text, line, COPY ) == NULL )) {
		syslog( LOG_ERR, "Syserror: smtp_consume_banner "
			"line_append: %m" );
		goto consume;
	    }
	}

	return( SMTP_OK );
    }

    ret = SMTP_OK;

consume:
    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( d->d_snet_smtp, smtp_logger, NULL ))
		== NULL ) {
	    smtp_snet_eof( d, "smtp_consume_banner: snet_getline_multi" );
	    return( SMTP_BAD_CONNECTION );
	}
    }

    return( ret );
}

    int
smtp_parse_ehlo_banner( struct deliver *d, char *line ) {
    char	*c;
    int		size;

    while (*(line + 3) == '-' ) {
	if (( line = snet_getline( d->d_snet_smtp, NULL )) == NULL ) {
	    smtp_snet_eof( d, "smtp_parse_ehlo_banner: snet_getline" );
	    return( SMTP_BAD_CONNECTION );
	}

	if ( smtp_check_banner_line( d, line ) == SMTP_ERROR ) {
	    return( SMTP_BAD_CONNECTION );
	}

	/* Parse SMTP extensions that we care about */
	c = line + 4;

	if (( strncasecmp( S_8BITMIME, c, strlen( S_8BITMIME )) == 0 )) {
	    for ( c += strlen( S_8BITMIME ); isspace( *c ) ; c++ );
	    if ( *c == '\0' ) {
		simta_debuglog( 1, "Deliver.SMTP env <%s>: 8BITMIME supported",
			d->d_env->e_id );
		d->d_esmtp_8bitmime = 1;
	    }
	} else if (( strncasecmp( S_SIZE, c, strlen( S_SIZE )) == 0 )) {
	    for ( c += strlen( S_SIZE ); isspace( *c ) ; c++ );
	    if ( *c == '\0' ) {
		simta_debuglog( 1, "Deliver.SMTP env <%s>: SIZE supported",
			d->d_env->e_id );
		d->d_esmtp_size = -1;
	    } else {
		/* Quirk: handle broken simta versions */
		if ( *c == '=' ) {
		    c++;
		}
		errno = 0;
		size = strtol( c, NULL, 0 );
		if (( errno == EINVAL ) || ( errno == ERANGE )) {
		    syslog( LOG_WARNING, "Deliver.SMTP env <%s>: "
			    "error parsing SIZE parameter: %s",
			    d->d_env->e_id, c );
		} else {
		    simta_debuglog( 1,
			    "Deliver.SMTP env <%s>: SIZE supported: %d",
			    d->d_env->e_id, size );
		    d->d_esmtp_size = size;
		}
	    }
	} else if (( strncasecmp( S_STARTTLS, c, strlen( S_STARTTLS )) == 0 )) {
	    for ( c += strlen( S_STARTTLS ); isspace( *c ) ; c++ );
	    if ( *c == '\0' ) {
		simta_debuglog( 1, "Deliver.SMTP env <%s>: STARTTLS supported",
			d->d_env->e_id );
		d->d_esmtp_starttls = 1;
	    }
	}
    }

    return( SMTP_OK );
}


    void
stdout_logger( char *line )
{
    printf( "<-- %s\n", line );
    return;
}


    int
smtp_reply( int smtp_command, struct host_q *hq, struct deliver *d )
{
    int				smtp_reply;
    char			*line;
    char			*c;
    char			old;

    if (( line = snet_getline( d->d_snet_smtp, NULL )) == NULL ) {
	smtp_snet_eof( d, "smtp_reply: snet_getline" );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    switch ( *line ) {
    /* 2xx responses indicate success */
    case '2':
	switch ( smtp_command ) {
	case SMTP_CONNECT:
	    /* Loop detection 
	     * RFC 5321 4.2 SMTP Replies
	     * Greeting = "220 " ( Domain / address-literal )
	     *            [ SP textstring ] CRLF /
	     *            ( "220-" (Domain / address-literal)
	     *            [ SP textstring ] CRLF
	     *            *( "220-" [ textstring ] CRLF )
	     *            "220" [ SP textstring ] CRLF )
	     * 
	     * "Greeting" appears only in the 220 response that announces that
	     * the server is opening its part of the connection.
	     * 
	     * RFC 5321 4.3.1 Sequencing Overview
	     * Note: all the greeting-type replies have the official name (the
	     * fully-qualified primary domain name) of the server host as the
	     * first word following the reply code.  Sometimes the host will
	     * have no meaningful name.  See Section 4.1.3 for a discussion of
	     * alternatives in these situations.
	     *
	     * RFC 5321 4.1.2 Command Argument Syntax
	     * Domain         = sub-domain *("." sub-domain)
	     * sub-domain     = Let-dig [Ldh-str]
	     * Let-dig        = ALPHA / DIGIT
	     * Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
	     * address-literal  = "[" ( IPv4-address-literal /
	     *                    IPv6-address-literal /
	     *                    General-address-literal ) "]"
	     *                    ; See Section 4.1.3
	     */

	    free( hq->hq_smtp_hostname );

	    if ( strlen( line ) > 4 ) {
		c = line + 4;

		if ( *c == '[' ) {
		    /* Make sure there's a closing bracket */
		    for ( c++; *c != ']'; c++ ) {
			if ( *c == '\0' ) {
			    syslog( LOG_ERR, "Connect.out [%s] %s: Failed: "
				    "illegal hostname in SMTP banner: %s",
				    d->d_ip, hq->hq_hostname, line );
			    if (( smtp_reply = smtp_consume_banner(
				    &(hq->hq_err_text), d, line,
				    "Illegal hostname in banner" )) != SMTP_OK ) {
				return( smtp_reply );
			    }

			    return( SMTP_ERROR );
			}
		    }

		}
		for ( c++; *c != '\0'; c++ ) {
		    if (( *c == ']' ) || ( isspace( *c ) != 0 )) {
			break;
		    }
		}

		old = *c;
		*c = '\0';
		if (( hq->hq_smtp_hostname = strdup( line + 4 )) == NULL ) {
		    syslog( LOG_ERR, "Syserror: smtp_reply strdup: %m" );
		    return( SMTP_ERROR );
		}
		*c = old;
	    } else if (( hq->hq_smtp_hostname = strdup( S_UNKNOWN_HOST ))
                    == NULL ) {
                syslog( LOG_ERR, "Syserror: smtp_reply strdup: %m" );
                return( SMTP_ERROR );
            }

	    if ( strcmp( hq->hq_smtp_hostname, simta_hostname ) == 0 ) {
		syslog( LOG_ERR,
			"Connect.out [%s] %s: Failed: banner mail loop: %s",
			d->d_ip, hq->hq_hostname, line );

		/* Loop - connected to self */
		if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text),
			d, line, "Mail loop detected" )) != SMTP_OK ) {
		    return( smtp_reply );
		}

		return( SMTP_ERROR );
	    }

	    syslog( LOG_NOTICE, "Connect.out [%s] %s: Accepted: %s: %s",
		    d->d_ip, hq->hq_hostname,
		    hq->hq_smtp_hostname, line );

	    break;

	case SMTP_RSET:
	case SMTP_QUIT:
	    break;

	case SMTP_HELO:
	    syslog( LOG_INFO, "Deliver.SMTP env <%s>: HELO reply: %s",
		    d->d_env->e_id, line );
	    break;

	case SMTP_EHLO:
	    syslog( LOG_INFO, "Deliver.SMTP env <%s>: EHLO reply: %s",
		    d->d_env->e_id, line );
	    return smtp_parse_ehlo_banner( d, line );
	    break;

	case SMTP_STARTTLS:
	    syslog( LOG_INFO, "Deliver.SMTP env <%s>: STARTTLS reply: %s",
		    d->d_env->e_id, line );
	    break;

	case SMTP_MAIL:
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: From <%s> Accepted: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    break;

	case SMTP_RCPT:
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: To <%s> From <%s> Accepted: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    d->d_rcpt->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    break;

	/* 2xx is actually an error for DATA */
	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: Message Tempfailed: [%s] %s: %s",
		    d->d_env->e_id, d->d_ip, hq->hq_smtp_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_delivered = 1;
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: "
		    "Message Accepted [%s] %s: transmitted %ld/%ld: %s",
		    d->d_env->e_id, d->d_ip, hq->hq_smtp_hostname, d->d_sent,
		    d->d_size, line );
	    break;

	default:
	    panic( "smtp_reply smtp_command out of range" );
	}

	return( smtp_consume_banner( NULL, d, line, NULL ));

    /* 3xx is success for DATA,
     * fall through to case default for all other commands
     */
    case '3':
	if ( smtp_command == SMTP_DATA ) {
	    /* consume success banner */
	    return( smtp_consume_banner( NULL, d, line, NULL ));
	}

    default:
	/* note that we treat default as a tempfail and fall through */

    /* 4xx responses indicate temporary failure */
    case '4':
	switch ( smtp_command ) {
	case SMTP_CONNECT:
	    syslog( LOG_NOTICE,
		    "Connect.out [%s] %s: Tempfailed: SMTP banner: %s",
		    d->d_ip, hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP CONNECT reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_WARNING,
		    "Deliver.SMTP env <%s>: Tempfail HELO reply: %s",
		    d->d_env->e_id, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP HELO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_EHLO:
	    syslog( LOG_WARNING,
		    "Deliver.SMTP env <%s>: Tempfail EHLO reply: %s",
		    d->d_env->e_id, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP EHLO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_STARTTLS:
	    syslog( LOG_WARNING,
		    "Deliver.SMTP env <%s>: Tempfail STARTTLS reply: %s",
		    d->d_env->e_id, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP STARTTLS reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: From <%s> Tempfailed: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfailed++;
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: To <%s> From <%s> Tempfailed: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), d,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: Tempfailed %s [%s]: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, d->d_ip, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: Tempfailed %s [%s]: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, d->d_ip, d->d_sent,
		    d->d_size, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_WARNING, "Deliver.SMTP env <%s>: Tempfail RSET reply: %s",
		    d->d_env ? d->d_env->e_id : "null", line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP RSET reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_WARNING, "Deliver.SMTP env <%s>: Tempfail QUIT reply: %s",
		    d->d_env ? d->d_env->e_id : "null", line );
	    return( smtp_consume_banner( NULL, d, line, NULL ));

	default:
	    panic( "smtp_reply smtp_command out of range" );
	}

    /* all other responses are hard failures */
    case '5':
	switch ( smtp_command ) {
	case SMTP_CONNECT:
	    if ( hq->hq_status == HOST_DOWN ) {
		hq->hq_status = HOST_BOUNCE;
		syslog( LOG_NOTICE,
			"Connect.out [%s] %s: Failed: SMTP banner: %s",
			d->d_ip, hq->hq_hostname, line );
	    } else {
		syslog( LOG_WARNING,
			"Deliver.SMTP env <%s>: punt Fail CONNECT reply: %s",
			d->d_env->e_id, line );
	    }

	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP CONNECT reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: Fail HELO reply: %s",
		    d->d_env->e_id, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP HELO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_EHLO:
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: Fail EHLO reply: %s",
		    d->d_env->e_id, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP EHLO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_STARTTLS:
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: Fail STARTTLS reply: %s",
		    d->d_env->e_id, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP STARTTLS reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: From <%s> Failed: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: To <%s> From <%s> Failed: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), d,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_NOTICE,
		    "Deliver.SMTP env <%s>: Message Failed: [%s] %s: %s",
		    d->d_env->e_id, d->d_ip, hq->hq_smtp_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: Failed %s [%s]: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, d->d_ip, d->d_sent,
		    d->d_size, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_WARNING, "Deliver.SMTP env <%s>: Fail RSET reply: %s",
		    d->d_env ? d->d_env->e_id : "null", line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP RSET reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_WARNING, "Deliver.SMTP env <%s>: Fail QUIT reply: %s",
		    d->d_env ? d->d_env->e_id : "null", line );
	    return( smtp_consume_banner( NULL, d, line, NULL ));

	default:
	    panic( "smtp_reply smtp_command out of range" );
	}
    }

    /* this is here to suppress a compiler warning */
    abort();
}


    int
smtp_connect( struct host_q *hq, struct deliver *d )
{
    int				r;
    struct timeval		tv_wait;
    int				rc;
#ifdef HAVE_LIBSSL
    int				tls_required = 0;
    int				tls_cert_required = 0;
    char			*ciphers;
    SSL_CTX			*ssl_ctx = NULL;
    const SSL_CIPHER		*ssl_cipher;
#endif /* HAVE_LIBSSL */

    tv_wait.tv_sec = simta_outbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( d->d_snet_smtp,
	    SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

#ifdef HAVE_LIBSSL
    if ( simta_outbound_ssl_connect_timer != 0 ) {
	tv_wait.tv_sec = simta_outbound_ssl_connect_timer;
	snet_timeout( d->d_snet_smtp, SNET_SSL_CONNECT_TIMEOUT, &tv_wait );
    }
#endif /* HAVE_LIBSSL */

    if (( r = smtp_reply( SMTP_CONNECT, hq, d )) != SMTP_OK ) {
	return( r );
    }

    /* say EHLO */
    if ( snet_writef( d->d_snet_smtp, "EHLO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: EHLO: snet_writef failed: %m",
		d->d_env->e_id );
	return( SMTP_BAD_CONNECTION );
    }

#ifdef HAVE_LIBSSL
    switch ( simta_policy_tls ) {
    default:
	/* no change */
	break;

    case TLS_POLICY_REQUIRED:
	tls_required = 1;
	break;

    case TLS_POLICY_DISABLED:
	tls_required = -1;
	break;
    }

    if ( hq->hq_red != NULL ) {
	switch ( hq->hq_red->red_policy_tls ) {
	default:
	case TLS_POLICY_DEFAULT:
	    /* no change */
	    break;

	case TLS_POLICY_OPTIONAL:
	    tls_required = 0;
	    break;

	case TLS_POLICY_REQUIRED:
	    tls_required = 1;
	    break;

	case TLS_POLICY_DISABLED:
	    tls_required = -1;
	    break;
	}
    }
#endif /* HAVE_LIBSSL */

    r = smtp_reply( SMTP_EHLO, hq, d );

    switch ( r ) {
    default:
	panic( "smtp_connect: smtp_reply out of range" );

    case SMTP_BAD_CONNECTION:
	break;

    case SMTP_OK:
#ifdef HAVE_LIBSSL
	if ( tls_required == -1 ) {
	    break;
	}

	if ( ! d->d_esmtp_starttls ) {
	    if ( tls_required > 0 ) {
		syslog( LOG_ERR, "Deliver.SMTP env <%s>: "
			"TLS required, STARTTLS not available",
			d->d_env->e_id );
		return( SMTP_ERROR );
	    } else {
		break;
	    }
	}

	simta_debuglog( 3, "Deliver.SMTP: smtp_connect snet_starttls" );

	if ( snet_writef( d->d_snet_smtp, "%s\r\n", S_STARTTLS ) < 0 ) {
	    syslog( LOG_ERR,
		    "Deliver.SMTP env <%s>: STARTTLS: snet_writef failed: %m",
		    d->d_env->e_id );
	    return( SMTP_BAD_CONNECTION );
	}

	if (( rc = smtp_reply( SMTP_STARTTLS, hq, d )) != SMTP_OK ) {
	    return( rc );
	}

	if ( simta_tls_ciphers_outbound != NULL ) {
	    ciphers = simta_tls_ciphers_outbound;
	} else {
	    ciphers = simta_tls_ciphers;
	}

	if ( hq->hq_red != NULL ) {
	    if ( hq->hq_red->red_tls_ciphers != NULL ) {
		ciphers = hq->hq_red->red_tls_ciphers;
	    }
	}

	if (( ssl_ctx = tls_client_setup( 0, simta_file_ca, simta_dir_ca,
		NULL, NULL, ciphers )) == NULL ) {
	    syslog( LOG_ERR, "Liberror: smtp_connect tls_client_setup: %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    if ( tls_required > 0 ) {
		syslog( LOG_WARNING, "Deliver.SMTP env <%s>: "
			"TLS required, tls_client_setup error",
			d->d_env->e_id );
		return( SMTP_ERROR );
	    } else {
		return( SMTP_BAD_TLS );
	    }

	} else if (( rc = snet_starttls( d->d_snet_smtp, ssl_ctx, 0 )) != 1 ) {
	    syslog( LOG_ERR, "Liberror: smtp_connect snet_starttls: %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    SSL_CTX_free( ssl_ctx );
	    if ( tls_required > 0 ) {
		return( SMTP_BAD_CONNECTION );
	    } else {
		return( SMTP_BAD_TLS );
	    }

	} else if ( tls_client_cert( hq->hq_hostname, d->d_snet_smtp->sn_ssl )) {
	    switch ( simta_policy_tls_cert ) {
	    default:
	    case TLS_POLICY_DEFAULT:
	    case TLS_POLICY_OPTIONAL:
		tls_cert_required = 0;
		break;

	    case TLS_POLICY_REQUIRED:
		tls_cert_required = 1;
		break;
	    }

	    if ( hq->hq_red != NULL ) {
		switch ( hq->hq_red->red_policy_tls_cert ) {
		default:
		case TLS_POLICY_DEFAULT:
		    /* no change */
		    break;

		case TLS_POLICY_OPTIONAL:
		    tls_cert_required = 0;
		    break;

		case TLS_POLICY_REQUIRED:
		    tls_cert_required = 1;
		    break;
		}
	    }

	    if ( tls_cert_required != 0 ) {
		SSL_CTX_free( ssl_ctx );
		syslog( LOG_WARNING, "Deliver.SMTP env <%s>: "
			"TLS cert required, tls_client_cert error",
			d->d_env->e_id );
		return( SMTP_ERROR );
	    }
	}

	if (( ssl_cipher = SSL_get_current_cipher( d->d_snet_smtp->sn_ssl ))
		!= NULL ) {
	    syslog( LOG_INFO, "Deliver.SMTP env <%s>: "
		    "TLS established. Protocol: %s Cipher: %s",
		    d->d_env->e_id,
		    SSL_get_version( d->d_snet_smtp->sn_ssl ),
		    SSL_CIPHER_get_name( ssl_cipher ));
	}

	SSL_CTX_free( ssl_ctx );

	/* RFC 3207 4.2
	 *
	 * Upon completion of the TLS handshake, the SMTP protocol is reset to
	 * the initial state (the state in SMTP after a server issues a 220
	 * service ready greeting).  The server MUST discard any knowledge
	 * obtained from the client, such as the argument to the EHLO command,
	 * which was not obtained from the TLS negotiation itself.  The client
	 * MUST discard any knowledge obtained from the server, such as the list
	 * of SMTP service extensions, which was not obtained from the TLS
	 * negotiation itself.  The client SHOULD send an EHLO command as the
	 * first command after a successful TLS negotiation.
	 */

	d->d_esmtp_8bitmime = 0;
	d->d_esmtp_size = 0;
	d->d_esmtp_starttls = 0;
	/* ZZZ reset state? */

	/* Resend EHLO */
	if ( snet_writef( d->d_snet_smtp, "EHLO %s\r\n", simta_hostname ) < 0 ) {
	    syslog( LOG_ERR,
		    "Deliver.SMTP env <%s>: EHLO: snet_writef failed: %m",
		    d->d_env->e_id );
	    return( SMTP_BAD_CONNECTION );
	}

	r = smtp_reply( SMTP_EHLO, hq, d );

#endif /* HAVE_LIBSSL */
	break;

    case SMTP_ERROR:
#ifdef HAVE_LIBSSL
	if ( tls_required > 0 ) {
	    syslog( LOG_ERR,
		    "Deliver.SMTP env <%s>: TLS required, EHLO unsupported",
		    d->d_env->e_id );
	    return( SMTP_ERROR );
	}
#endif /* HAVE_LIBSSL */
	/* say HELO */
	/* RFC 5321 2.2.1 Background
	 * (However, for compatibility with older conforming implementations,
	 * SMTP clients and servers MUST support the original HELO mechanisms
	 * as a fallback.)
	 *
	 * RFC 5321 3.2 Client Initiation
	 * For a particular connection attempt, if the server returns a
	 * "command not recognized" response to EHLO, the client SHOULD be
	 * able to fall back and send HELO.
	 */

	if ( snet_writef( d->d_snet_smtp, "HELO %s\r\n",
		simta_hostname ) < 0 ) {
	    syslog( LOG_ERR,
		    "Deliver.SMTP env <%s>: HELO: snet_writef failed: %m",
		    d->d_env->e_id );
	    return( SMTP_BAD_CONNECTION );
	}
	r = smtp_reply( SMTP_HELO, hq, d );
    }

    return( r );
}

    int
smtp_send( struct host_q *hq, struct deliver *d )
{
    int			smtp_result, rc;
    char		*line;
    char		*timer_type;
    struct timeval	tv_session = { 0, 0 };
    struct timeval	tv_now;
    struct timeval	tv_wait;

    tv_wait.tv_sec = simta_outbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( d->d_snet_smtp,
	    SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

    if (( d->d_esmtp_size > 0 ) && ( d->d_size > d->d_esmtp_size )) {
	syslog( LOG_NOTICE,
		"Deliver.SMTP env <%s>: Message is too large for %s",
		d->d_env->e_id, hq->hq_smtp_hostname );

	/* Set the error message */
	if ( d->d_env->e_err_text == NULL ) {
	    d->d_env->e_err_text = line_file_create();
	}
	if ( line_append( d->d_env->e_err_text, "", COPY ) == NULL ) {
	    syslog( LOG_ERR, "smtp_send line_append failed" );
	    return ( SMTP_ERROR );
	}
	if ( line_append( d->d_env->e_err_text,
		"This message exceeds the size limit for the recipient domain.",
		COPY ) == NULL ) {
	    syslog( LOG_ERR, "smtp_send line_append failed" );
	    return ( SMTP_ERROR );
	}

	d->d_env->e_flags |= ENV_FLAG_BOUNCE;
	return( SMTP_OK );
    }

    syslog( LOG_INFO,
	    "Deliver.SMTP env <%s>: Attempting remote delivery: %s (%s)",
	    d->d_env->e_id, hq->hq_hostname, hq->hq_smtp_hostname );

    /* MAIL FROM: */
    /* RFC 6152 2 Framework for the 8-bit MIME Transport Extension
     *  one optional parameter using the keyword BODY is added to the
     *  MAIL command.  The value associated with this parameter is a
     *  keyword indicating whether a 7-bit message (in strict compliance
     *  with [RFC5321]) or a MIME message (in strict compliance with
     *  [RFC2046] and [RFC2045]) with arbitrary octet content is being
     *  sent.  The syntax of the value is as follows, using the ABNF
     *  notation of [RFC5234]:
     *
     *  body-value = "7BIT" / "8BITMIME"	
     */

    if ( d->d_esmtp_8bitmime && ( d->d_env->e_attributes & ENV_ATTR_8BITMIME )) {
	simta_debuglog( 1, "Deliver.SMTP env <%s>: Delivering as 8BITMIME",
		d->d_env->e_id );
	rc = snet_writef( d->d_snet_smtp,
		"MAIL FROM:<%s> BODY=8BITMIME\r\n", d->d_env->e_mail );
    } else {
	rc = snet_writef( d->d_snet_smtp, "MAIL FROM:<%s>\r\n",
		d->d_env->e_mail );
    }

    if ( rc < 0 ) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: MAIL: snet_writef failed: %m",
		d->d_env->e_id );
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_MAIL, hq, d )) != SMTP_OK ) {
	return( smtp_result );
    }

    /* check to see if the sender failed */
    if (( d->d_env->e_flags & ENV_FLAG_BOUNCE ) ||
	    ( d->d_env->e_flags & ENV_FLAG_TEMPFAIL )) {
	return( SMTP_OK );
    }

    /* RCPT TOs: */
    assert( d->d_env->e_rcpt != NULL );

    for ( d->d_rcpt = d->d_env->e_rcpt; d->d_rcpt != NULL;
	    d->d_rcpt = d->d_rcpt->r_next ) {
	if ( *(d->d_rcpt->r_rcpt) != '\0' ) {
	    rc = snet_writef( d->d_snet_smtp, "RCPT TO:<%s>\r\n",
		    d->d_rcpt->r_rcpt );
	} else {
	    rc = snet_writef( d->d_snet_smtp, "RCPT TO:<postmaster>\r\n" );
	}
	if ( rc < 0 ) {
	    syslog( LOG_ERR,
		    "Deliver.SMTP env <%s>: RCPT: snet_writef failed: %m",
		    d->d_env->e_id );
	    return( SMTP_BAD_CONNECTION );
	}

	if (( smtp_result = smtp_reply( SMTP_RCPT, hq, d )) != SMTP_OK ) {
	    return( smtp_result );
	}

	if (( hq->hq_status == HOST_PUNT_DOWN ) &&
		( d->d_rcpt->r_status != R_ACCEPTED )) {
	    /* punt hosts must accept all rcpts */
	    syslog( LOG_WARNING,
		    "Deliver.SMTP env <%s>: punt host refused address %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt );
	    return( SMTP_OK );
	}
    }

    if ( d->d_n_rcpt_accepted == 0 ) {
	/* no rcpts succeded */
	d->d_delivered = 1;
	syslog( LOG_NOTICE, "Deliver.SMTP env <%s>: no valid recipients",
		d->d_env->e_id );
	return( SMTP_OK );
    }

    simta_debuglog( 1, "Deliver.SMTP env <%s>: Sending DATA", d->d_env->e_id );

    /* say DATA */
    if ( snet_writef( d->d_snet_smtp, "DATA\r\n" ) < 0 ) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: DATA: snet_writef failed: %m",
		d->d_env->e_id );
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_DATA, hq, d )) != SMTP_OK ) {
	return( smtp_result );
    }

    /* check to see if DATA failed */
    if (( d->d_env->e_flags & ENV_FLAG_BOUNCE ) ||
	    ( d->d_env->e_flags & ENV_FLAG_TEMPFAIL )) {
	return( SMTP_OK );
    }

    if (( d->d_env->e_attributes & ENV_ATTR_ARCHIVE_ONLY )) {
	/* send SIMTA-Seen-Before trace header for poison pill */
	/* FIXME: is this really where we should do this? */
	if (( rc = snet_writef( d->d_snet_smtp,
		"%s: %s id=%s origin=%s destination=%s smtp_destination=%s\r\n",
		STRING_SEEN_BEFORE, simta_seen_before_domain, d->d_env->e_id,
		simta_hostname, hq->hq_hostname, hq->hq_smtp_hostname )) < 0 ) {
	    syslog( LOG_ERR,
		    "Deliver.SMTP env <%s>: seen: snet_writef failed: %m",
		    d->d_env->e_id );
	    return( SMTP_BAD_CONNECTION );
	}
    }

    for ( ; ; ) {
	/* compute timeout */
	if ( simta_outbound_data_session_timer > 0 ) {
	    if ( simta_gettimeofday( &tv_now ) != 0 ) {
		return( SMTP_ERROR );
	    }
	    if ( tv_session.tv_sec == 0 ) {
		tv_session.tv_sec =
			tv_now.tv_sec + simta_outbound_data_session_timer;
	    }
	    if ( tv_now.tv_sec >= tv_session.tv_sec ) {
		syslog( LOG_NOTICE,
			"Deliver.SMTP env <%s>: Message: Timeout %s",
			d->d_env->e_id, S_DATA_SESSION );
		return( SMTP_BAD_CONNECTION );
	    }
	    if ( simta_outbound_data_line_timer >
		    ( tv_session.tv_sec - tv_now.tv_sec )) {
		timer_type = S_DATA_SESSION;
		tv_wait.tv_sec = tv_session.tv_sec - tv_now.tv_sec;
	    } else {
		timer_type = S_DATA_LINE;
		tv_wait.tv_sec = simta_outbound_data_line_timer;
	    }
	} else {
	    timer_type = S_DATA_LINE;
	    tv_wait.tv_sec = simta_outbound_data_line_timer;
	}
	tv_wait.tv_usec = 0;
	snet_timeout( d->d_snet_smtp,
		SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

	/* read DFile */
	if (( line = snet_getline( d->d_snet_dfile, &tv_wait )) == NULL ) {
	    break;
	}

	/* transmit message, do not transmit premature SMTP EOF */
	if ( *line == '.' ) {
	    /* don't send EOF */
	    rc = snet_writef( d->d_snet_smtp, ".%s\r\n", line );
	} else {
	    rc = snet_writef( d->d_snet_smtp, "%s\r\n", line );
	}

	if ( rc < 0 ) {
	    if ( errno == ETIMEDOUT ) {
		syslog( LOG_ERR, "Deliver.SMTP env <%s>: Message: Timeout %s",
			d->d_env->e_id, timer_type );
		return( SMTP_BAD_CONNECTION );
	    } else {
		syslog( LOG_ERR, "Deliver.SMTP env <%s>: Message: "
			"snet_writef failed: %m", d->d_env->e_id );
	    }
	    return( SMTP_BAD_CONNECTION );
	}

	d->d_sent += strlen( line ) + 1;
    }

    /* send SMTP EOF */
    if ( snet_writef( d->d_snet_smtp, ".\r\n", &tv_wait ) < 0 ) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: EOF: snet_writef failed: %m",
		d->d_env->e_id );
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_DATA_EOF, hq, d )) != SMTP_OK ) {
	return( smtp_result );
    }

    return( SMTP_OK );
}


    int
smtp_rset( struct host_q *hq, struct deliver *d )
{
    struct timeval		tv_wait;

    tv_wait.tv_sec = simta_outbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( d->d_snet_smtp,
	    SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

    /* say RSET */
    if ( snet_writef( d->d_snet_smtp, "RSET\r\n" ) < 0 ) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: RSET: snet_writef failed: %m",
		d->d_env ? d->d_env->e_id : "null" );
	return( SMTP_BAD_CONNECTION );
    }

    return( smtp_reply( SMTP_RSET, hq, d ));
}


    void
smtp_quit( struct host_q *hq, struct deliver *d )
{
    struct timeval		tv_wait;

    tv_wait.tv_sec = simta_outbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( d->d_snet_smtp,
	    SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

    /* say QUIT */
    if ( snet_writef( d->d_snet_smtp, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: QUIT: snet_writef failed: %m",
		d->d_env ? d->d_env->e_id : "null" );
	return;
    }

    smtp_reply( SMTP_QUIT, hq, d );

    return;
}

    static void
smtp_snet_eof( struct deliver *d, const char *infix ) {
    if ( snet_eof( d->d_snet_smtp )) {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: %s: unexpected EOF",
		d->d_env ? d->d_env->e_id : "null", infix );
    } else {
	syslog( LOG_ERR, "Deliver.SMTP env <%s>: %s failed: %m",
		d->d_env ? d->d_env->e_id : "null", infix );
    }
}

/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
