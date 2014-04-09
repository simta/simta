/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.c     *****/
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
#include <db.h>

#include <ctype.h>
#include <assert.h>
#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <dirent.h>

#include "denser.h"
#include "line_file.h"
#include "envelope.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "header.h"
#include "simta.h"
#include "queue.h"
#include "smtp.h"
#include "mx.h"
#include "expand.h"
#include "red.h"

#ifdef HAVE_LIBSSL
#include "tls.h"
#define S_STARTTLS "STARTTLS"
#endif /* HAVE_LIBSSL */

#ifdef DEBUG
void	(*smtp_logger)(char *) = stdout_logger;
#else /* DEBUG */
void	(*smtp_logger)(char *) = NULL;
#endif /* DEBUG */


    int
smtp_consume_banner( struct line_file **err_text, struct deliver *d,
	char *line, char *error )
{
    int				ret = SMTP_ERROR;
    char			*c;

    if ( err_text != NULL ) {
	if ( *err_text == NULL ) {
	    if (( *err_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "Syserror smtp_consume_banner: "
			"line_file_create: %m" );
		goto consume;
	    }

	} else {
	    if ( line_append( *err_text, "", COPY ) == NULL ) {
		syslog( LOG_ERR, "Syserror smtp_consume_banner: "
			"line_append: %m" );
		goto consume;
	    }
	}

	if ( line_append( *err_text, error, COPY ) == NULL ) {
	    syslog( LOG_ERR, "Syserror smtp_consume_banner: line_append: %m" );
	    goto consume;
	}

	if ( line_append( *err_text, line, COPY ) == NULL ) {
	    syslog( LOG_ERR, "Syserror smtp_consume_banner: line_append: %m" );
	    goto consume;
	}
    }

    if (( err_text != NULL ) 
#ifdef HAVE_LIBSSL
	    || ( d->d_tls_banner_check != 0 )
#endif /* HAVE_LIBSSL */
	    ) {
	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( d->d_snet_smtp, NULL )) == NULL ) {
		syslog( LOG_DEBUG, "Deliver smtp_consume_banner: "
			"snet_getline: unexpected EOF" );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( strlen( line ) < 3 ) {
		syslog( LOG_DEBUG, "Deliver smtp_consume_banner: "
			"snet_getline: bad banner syntax: %s", line );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( !isdigit( (int)line[ 0 ] ) ||
		    !isdigit( (int)line[ 1 ] ) ||
		    !isdigit( (int)line[ 2 ] )) {
		syslog( LOG_DEBUG, "Deliver smtp_consume_banner: "
			"snet_getline: bad banner syntax: %s", line );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( line[ 3 ] != '\0' &&
		    line[ 3 ] != ' ' &&
		    line [ 3 ] != '-' ) {
		syslog( LOG_DEBUG, "Deliver smtp_consume_banner: "
			"snet_getline: bad banner syntax: %s", line );
		return( SMTP_BAD_CONNECTION );
	    }

#ifdef HAVE_LIBSSL
	    if (( d->d_tls_banner_check != 0 ) && ( d->d_tls_supported == 0 )) {
		c = line + 4;
		if (( strncasecmp( S_STARTTLS, c,
			strlen( S_STARTTLS )) == 0 )) {
		    c += strlen( S_STARTTLS );
		    while ( *c != '\0') {
			if ( isspace( *c ) == 0 ) {
			    break;
			}
			c++;
		    }
		    if ( *c == '\0' ) {
			d->d_tls_supported = 1;
		    }
		}
	    }
#endif /* HAVE_LIBSSL */

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if (( err_text != NULL ) &&
		    ( line_append( *err_text, line, COPY ) == NULL )) {
		syslog( LOG_ERR, "Syserror smtp_consume_banner: "
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
	    syslog( LOG_DEBUG, "Deliver smtp_consume_banner: unexpected EOF" );
	    return( SMTP_BAD_CONNECTION );
	}
    }

    return( ret );
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
	syslog( LOG_DEBUG, "Deliver %s: unexpected EOF", hq->hq_hostname );
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
	     * RFC 2821 4.2 SMTP Replies
	     * Greeting = "220 " Domain [ SP text ] CRLF
	     * 
	     * "Greeting" appears only in the 220 response that announces that
	     * the server is opening its part of the connection.
	     * 
	     * RFC 2821 4.3.1 Sequencing Overview
	     * Note: all the greeting-type replies have the official name (the
	     * fully-qualified primary domain name) of the server host as the
	     * first word following the reply code.  Sometimes the host will
	     * have no meaningful name.  See 4.1.3 for a discussion of
	     * alternatives in these situations.
	     *
	     * RFC 2821 4.1.2 Command Argument Syntax
	     * Domain = (sub-domain 1*("." sub-domain)) / address-literal
	     * sub-domain = Let-dig [Ldh-str]
	     * address-literal = "[" IPv4-address-literal /
	     * 		IPv6-address-literal /
	     *		General-address-literal "]"
	     *		; See section 4.1.3
	     * 
	     */

	    free( hq->hq_smtp_hostname );

	    if ( strlen( line ) > 4 ) {
		c = line + 4;

		if ( *c == '[' ) {
		    /* Make sure there's a closing bracket */
		    for ( c++; *c != ']'; c++ ) {
			if ( *c == '\0' ) {
			    syslog( LOG_NOTICE, "Connect.out [%s] %s: Failed: "
				    "illegal hostname in SMTP banner: %s",
				    inet_ntoa( d->d_sin.sin_addr ),
				    hq->hq_hostname, line );
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
		    syslog( LOG_ERR, "Syserror smtp_reply: strdup: %m" );
		    return( SMTP_ERROR );
		}
		*c = old;
	    } else if (( hq->hq_smtp_hostname = strdup( S_UNKNOWN_HOST ))
                    == NULL ) {
                syslog( LOG_ERR, "Syserror smtp_reply: strdup: %m" );
                return( SMTP_ERROR );
            }

	    if ( strcmp( hq->hq_smtp_hostname, simta_hostname ) == 0 ) {
		syslog( LOG_WARNING,
			"Connect.out [%s] %s: Failed: banner mail loop: %s",
			inet_ntoa( d->d_sin.sin_addr ), hq->hq_hostname, line );

		/* Loop - connected to self */
		if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text),
			d, line, "Mail loop detected" )) != SMTP_OK ) {
		    return( smtp_reply );
		}

		return( SMTP_ERROR );
	    }

	    syslog( LOG_INFO, "Connect.out [%s] %s: Accepted: %s: %s",
		    inet_ntoa( d->d_sin.sin_addr ), hq->hq_hostname,
		    hq->hq_smtp_hostname, line );

	    break;

	case SMTP_RSET:
	case SMTP_QUIT:
	    break;

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s HELO: %s", hq->hq_hostname,
		line );
	    break;

	case SMTP_EHLO:
	    syslog( LOG_NOTICE, "smtp_reply %s EHLO: %s", hq->hq_hostname,
		line );
	    break;

	case SMTP_STARTTLS:
	    syslog( LOG_NOTICE, "smtp_reply %s STARTTLS: %s", hq->hq_hostname,
		    line );
	    break;

	case SMTP_MAIL:
	    syslog( LOG_INFO, "Deliver.SMTP %s: From <%s> Accepted: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    break;

	case SMTP_RCPT:
	    syslog( LOG_INFO, "Deliver.SMTP %s: To <%s> From <%s> Accepted: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    d->d_rcpt->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    break;

	/* 2xx is actually an error for DATA */
	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Message Tempfailed: [%s] %s: %s",
		    d->d_env->e_id, inet_ntoa( d->d_sin.sin_addr ),
		    hq->hq_smtp_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_delivered = 1;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Message Accepted [%s] %s: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, inet_ntoa( d->d_sin.sin_addr ),
		    hq->hq_smtp_hostname, d->d_sent, d->d_size, line );
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
		    inet_ntoa( d->d_sin.sin_addr ), hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP CONNECT reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail HELO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP HELO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_EHLO:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail EHLO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP EHLO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_STARTTLS:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail STARTTLS reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP STARTTLS reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO, "Deliver.SMTP %s: From <%s> Tempfailed: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfailed++;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: To <%s> From <%s> Tempfailed: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), d,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Tempfailed %s [%s]: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, 
		    inet_ntoa( d->d_sin.sin_addr ), line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO, "Deliver.SMTP %s: Tempfailed %s [%s]: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, 
		    inet_ntoa( d->d_sin.sin_addr ), d->d_sent, d->d_size,
		    line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail RSET reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP RSET reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail QUIT reply: %s",
		    hq->hq_hostname, line );
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
			inet_ntoa( d->d_sin.sin_addr ), hq->hq_hostname, line );
	    } else {
		syslog( LOG_WARNING,
			"smtp_reply %s punt failed CONNECT reply: %s",
			hq->hq_hostname, line );
	    }

	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP CONNECT reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s failed HELO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP HELO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_EHLO:
	    syslog( LOG_NOTICE, "smtp_reply %s failed EHLO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP EHLO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_STARTTLS:
	    syslog( LOG_NOTICE, "smtp_reply %s failed STARTTLS reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP STARTTLS reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_INFO, "Deliver.SMTP %s: From <%s> Failed: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
	    syslog( LOG_INFO, "Deliver.SMTP %s: To <%s> From <%s> Failed: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), d,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Message Failed: [%s] %s: %s",
		    d->d_env->e_id, inet_ntoa( d->d_sin.sin_addr ),
		    hq->hq_smtp_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Failed %s [%s]: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, 
		    inet_ntoa( d->d_sin.sin_addr ), d->d_sent, d->d_size,
		    line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_NOTICE, "smtp_reply %s failed RSET reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    line, "Bad SMTP RSET reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_NOTICE, "smtp_reply %s failed QUIT reply: %s",
		    hq->hq_hostname, line );
	    return( smtp_consume_banner( NULL, d, line, NULL ));

	default:
	    syslog( LOG_DEBUG, "smtp_reply %d out of range", smtp_command );
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
    int				tls_required;
    int				tls_cert_required;
    char			*ciphers;
    SSL_CTX			*ssl_ctx = NULL;
#endif /* HAVE_LIBSSL */

    tv_wait.tv_sec = simta_outbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( d->d_snet_smtp,
	    SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

    if ( simta_outbound_ssl_connect_timer != 0 ) {
	tv_wait.tv_sec = simta_outbound_ssl_connect_timer;
	snet_timeout( d->d_snet_smtp, SNET_SSL_CONNECT_TIMEOUT, &tv_wait );
    }

    if (( r = smtp_reply( SMTP_CONNECT, hq, d )) != SMTP_OK ) {
	return( r );
    }

    /* say EHLO */
    if ( snet_writef( d->d_snet_smtp, "EHLO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: EHLO",
		hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

#ifdef HAVE_LIBSSL
    d->d_tls_banner_check = 1;

    switch ( simta_policy_tls ) {
    case TLS_POLICY_DISABLED:
	d->d_tls_banner_check = 0;
	/* fall through */
    default:
    case TLS_POLICY_DEFAULT:
    case TLS_POLICY_OPTIONAL:
	tls_required = 0;
	break;

    case TLS_POLICY_REQUIRED:
	tls_required = 1;
	break;
    }

    if ( hq->hq_red != NULL ) {
	switch ( hq->hq_red->red_policy_tls ) {
	default:
	case TLS_POLICY_DEFAULT:
	    /* no change */
	    break;

	case TLS_POLICY_OPTIONAL:
	    d->d_tls_banner_check = 1;
	    tls_required = 0;
	    break;

	case TLS_POLICY_REQUIRED:
	    d->d_tls_banner_check = 1;
	    tls_required = 1;
	    break;

	case TLS_POLICY_DISABLED:
	    d->d_tls_banner_check = 0;
	    tls_required = 0;
	    break;
	}
    }

    d->d_tls_supported = 0;
#endif /* HAVE_LIBSSL */

    r = smtp_reply( SMTP_EHLO, hq, d );

#ifdef HAVE_LIBSSL
    d->d_tls_banner_check = 0;
#endif /* HAVE_LIBSSL */

    switch ( r ) {
    default:
	panic( "smtp_connect: smtp_reply out of range" );

    case SMTP_BAD_CONNECTION:
	break;

    case SMTP_OK:
#ifdef HAVE_LIBSSL
	if ( ! d->d_tls_supported ) {
	    if ( tls_required != 0 ) {
		syslog( LOG_INFO, "Deliver.SMTP %s (%s): TLS required: %s",
			hq->hq_hostname, hq->hq_smtp_hostname,
			"not offered as EHLO extension" );
		return( SMTP_ERROR );
	    } else {
		break;
	    }
	}

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: smtp_connect snet_starttls" );
	}

	if ( snet_writef( d->d_snet_smtp, "%s\r\n", S_STARTTLS ) < 0 ) {
	    syslog( LOG_DEBUG, "Deliver: snet_writef failed: %s",
		    S_STARTTLS );
	    return( SMTP_BAD_CONNECTION );
	}

	if (( rc = smtp_reply( SMTP_STARTTLS, hq, d )) != SMTP_OK ) {
	    return( rc );
	}

	ciphers = simta_tls_ciphers;

	if ( hq->hq_red != NULL ) {
	    if ( hq->hq_red->red_tls_ciphers != NULL ) {
		ciphers = hq->hq_red->red_tls_ciphers;
	    }
	}

	if (( ssl_ctx = tls_client_setup( 0, 0, simta_file_ca, simta_dir_ca,
		NULL, NULL, ciphers )) == NULL ) {
	    syslog( LOG_ERR, "Syserror: smtp_connect: tls_client_setup %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    if ( tls_required != 0 ) {
		syslog( LOG_INFO, "Deliver.SMTP %s (%s): TLS required: %s",
			hq->hq_hostname, hq->hq_smtp_hostname,
			"tls_client_setup error" );
		return( SMTP_ERROR );
	    }

	} else if (( rc = snet_starttls( d->d_snet_smtp, ssl_ctx, 0 )) != 1 ) {
	    syslog( LOG_ERR, "Syserror smtp_connect: snet_starttls: %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    SSL_CTX_free( ssl_ctx );
	    return( SMTP_BAD_CONNECTION );

	} else if ( tls_client_cert( hq->hq_hostname,
		d->d_snet_smtp->sn_ssl ) != 0 ) {
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
		syslog( LOG_INFO, "Deliver.SMTP %s (%s): TLS Cert required: %s",
			hq->hq_hostname, hq->hq_smtp_hostname,
			"tls_client_cert error" );
		return( SMTP_ERROR );
	    }
	} else {
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s (%s): TLS established. Cipher: %s",
		    hq->hq_hostname, hq->hq_smtp_hostname,
	SSL_CIPHER_get_name( SSL_get_current_cipher( d->d_snet_smtp->sn_ssl )));
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

	/* ZZZ reset state? */

	/* Resend EHLO */
	if ( snet_writef( d->d_snet_smtp, "EHLO %s\r\n", simta_hostname ) < 0 ) {
	    syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: EHLO",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}

	r = smtp_reply( SMTP_EHLO, hq, d );

#endif /* HAVE_LIBSSL */
	break;

    case SMTP_ERROR:
#ifdef HAVE_LIBSSL
	if ( tls_required != 0 ) {
	    syslog( LOG_INFO, "Deliver.SMTP %s (%s): %s",
		    hq->hq_hostname, hq->hq_smtp_hostname,
		    "TLS required: EHLO unsupported" );
	    return( SMTP_ERROR );
	}
#endif /* HAVE_LIBSSL */
	/* say HELO */
	/* RFC 2821 2.2.1
	 * (However, for compatibility with older conforming implementations,
	 * SMTP clients and servers MUST support the original HELO mechanisms
	 * as a fallback.)
	 *
	 * RFC 2821 3.2
	 * For a particular connection attempt, if the server returns a
	 * "command not recognized" response to EHLO, the client SHOULD be
	 * able to fall back and send HELO.
	 */

	if ( snet_writef( d->d_snet_smtp, "HELO %s\r\n", simta_hostname )
		< 0 ) {
	    syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: HELO",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}
	r = smtp_reply( SMTP_HELO, hq, d );
    }

    return( r );
}

    static char *
make_seen_before_line( struct host_q *hq, struct deliver *d )
{
    char temp[512];

    snprintf ( temp, sizeof temp,
	    "%s: %s id %s origin %s destination %s (%s)",
	    STRING_SEEN_BEFORE, simta_seen_before_domain,
	    d->d_env->e_id, simta_hostname,
	    hq->hq_hostname, hq->hq_smtp_hostname );
    return strdup( temp );
}


    int
smtp_send( struct host_q *hq, struct deliver *d )
{
    int			smtp_result;
    char		*line;
    struct timeval	tv_session = { 0, 0 };
    struct timeval	tv_now;
    struct timeval	tv_wait;

    tv_wait.tv_sec = simta_outbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( d->d_snet_smtp,
	    SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

    syslog( LOG_INFO, "Deliver.SMTP %s: Attempting remote delivery: %s (%s)",
	    d->d_env->e_id, hq->hq_hostname, hq->hq_smtp_hostname );

    /* MAIL FROM: */
    if ( snet_writef( d->d_snet_smtp, "MAIL FROM:<%s>\r\n",
	    d->d_env->e_mail ) < 0 ) {
	syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: MAIL FROM",
		hq->hq_hostname );
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
	if( *(d->d_rcpt->r_rcpt) != '\0' ) {
	    if ( snet_writef( d->d_snet_smtp, "RCPT TO:<%s>\r\n",
		    d->d_rcpt->r_rcpt ) < 0 ) {
		syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: RCPT TO",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( d->d_snet_smtp, "RCPT TO:<postmaster>\r\n" )
		    < 0 ) {
		syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: RCPT TO",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}

	if (( smtp_result = smtp_reply( SMTP_RCPT, hq, d )) != SMTP_OK ) {
	    return( smtp_result );
	}

	if (( hq->hq_status == HOST_PUNT_DOWN ) &&
		( d->d_rcpt->r_status != R_ACCEPTED )) {
	    /* punt hosts must accept all rcpts */
	    syslog( LOG_WARNING,
		    "smtp_send %s %s %s: punt host refused address",
		    d->d_env->e_id, hq->hq_hostname, d->d_rcpt->r_rcpt );
	    return( SMTP_OK );
	}
    }

    if ( d->d_n_rcpt_accepted == 0 ) {
	/* no rcpts succeded */
	d->d_delivered = 1;
	syslog( LOG_NOTICE, "smtp_send %s %s: no valid recipients",
		d->d_env->e_id, hq->hq_hostname );
	return( SMTP_OK );
    }

    syslog( LOG_DEBUG, "Deliver %s: Sending DATA", d->d_env->e_id );

    /* say DATA */
    if ( snet_writef( d->d_snet_smtp, "DATA\r\n" ) < 0 ) {
	syslog( LOG_DEBUG, "Deliver %s: snet_writef failed: DATA",
		hq->hq_hostname );
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
	int r;

	if ( !( line = make_seen_before_line( hq, d )) ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed malloc",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}
	r = snet_writef( d->d_snet_smtp, "%s\r\n", line );
	free( line );
	if ( r < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
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
		syslog( LOG_NOTICE, "smtp_send %s: data session timeout",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	    if ( simta_outbound_data_line_timer >
		    ( tv_session.tv_sec - tv_now.tv_sec )) {
		tv_wait.tv_sec = tv_session.tv_sec - tv_now.tv_sec;
	    } else {
		tv_wait.tv_sec = simta_outbound_data_line_timer;
	    }
	} else {
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
	    if ( snet_writef( d->d_snet_smtp, ".%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "Deliver %s: snet_writef failed: Message",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( d->d_snet_smtp, "%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "Deliver %s: snet_writef failed: Message",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}

	d->d_sent += strlen( line ) + 1;
    }

    /* send SMTP EOF */
    if ( snet_writef( d->d_snet_smtp, ".\r\n", &tv_wait ) < 0 ) {
	syslog( LOG_NOTICE, "Deliver %s: snet_writef failed: EOF",
		hq->hq_smtp_hostname );
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
	syslog( LOG_NOTICE, "Deliver %s: snet_writef failed: RSET",
		hq->hq_hostname );
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
	syslog( LOG_NOTICE, "Deliver %s: snet_writef failed: QUIT",
		hq->hq_hostname );
	return;
    }

    smtp_reply( SMTP_QUIT, hq, d );

    return;
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
