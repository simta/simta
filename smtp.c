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

#include <ctype.h>
#include <assert.h>
#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>

#include "denser.h"
#include "queue.h"
#include "line_file.h"
#include "envelope.h"
#include "smtp.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "simta.h"
#include "mx.h"

#ifdef DEBUG
void	(*smtp_logger)(char *) = stdout_logger;
#else /* DEBUG */
void	(*smtp_logger)(char *) = NULL;
#endif /* DEBUG */


    int
smtp_consume_banner( struct line_file **err_text, struct deliver *d,
	struct timeval *tv, char *line, char *error )
{
    int				ret = SMTP_ERROR;

    if ( err_text != NULL ) {
	if ( *err_text == NULL ) {
	    if (( *err_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "smtp_consume_banner line_file_create: %m" );
		goto consume;
	    }

	} else {
	    if ( line_append( *err_text, "", COPY ) == NULL ) {
		syslog( LOG_ERR, "smtp_consume_banner line_append: %m" );
		goto consume;
	    }
	}

	if ( line_append( *err_text, error, COPY ) == NULL ) {
	    syslog( LOG_ERR, "smtp_consume_banner line_append: %m" );
	    goto consume;
	}

	if ( line_append( *err_text, line, COPY ) == NULL ) {
	    syslog( LOG_ERR, "smtp_consume_banner line_append: %m" );
	    goto consume;
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( d->d_snet_smtp, tv )) == NULL ) {
		syslog( LOG_ERR,
			"smtp_consume_banner snet_getline: unexpected EOF" );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( strlen( line ) < 3 ) {
		syslog( LOG_ERR,
			"smtp_consume_banner snet_getline: bad line syntax: %s",
			line );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( !isdigit( (int)line[ 0 ] ) ||
		    !isdigit( (int)line[ 1 ] ) ||
		    !isdigit( (int)line[ 2 ] )) {
		syslog( LOG_ERR,
			"smtp_consume_banner snet_getline: bad line syntax: %s",
			line );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( line[ 3 ] != '\0' &&
		    line[ 3 ] != ' ' &&
		    line [ 3 ] != '-' ) {
		syslog( LOG_ERR,
			"smtp_consume_banner snet_getline: bad line syntax: %s",
			line );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( *err_text, line, COPY ) == NULL ) {
		syslog( LOG_ERR,
			"smtp_consume_banner line_append: unexpected EOF" );
		goto consume;
	    }
	}

	return( SMTP_OK );
    }

    ret = SMTP_OK;

consume:
    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( d->d_snet_smtp, smtp_logger, tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_consume_banner: unexpected EOF" );
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
    struct timeval		tv;

    tv.tv_usec = 0;

    switch ( smtp_command ) {
    case SMTP_CONNECT:
	tv.tv_sec = SMTP_TIME_CONNECT;
	break;

    case SMTP_HELO:
    case SMTP_EHLO:
	tv.tv_sec = SMTP_TIME_HELO;
	break;

    case SMTP_MAIL:
	tv.tv_sec = SMTP_TIME_MAIL;
	break;

    case SMTP_RCPT:
	tv.tv_sec = SMTP_TIME_RCPT;
	break;

    case SMTP_DATA:
	tv.tv_sec = SMTP_TIME_DATA;
	break;

    case SMTP_DATA_EOF:
	tv.tv_sec = SMTP_TIME_DATA_EOF;
	break;

    case SMTP_RSET:
	tv.tv_sec = SMTP_TIME_RSET;
	break;

    case SMTP_QUIT:
	tv.tv_sec = SMTP_TIME_QUIT;
	break;

    default:
	panic( "smtp_reply smtp_command out of range" );
    }

    if (( line = snet_getline( d->d_snet_smtp, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_reply %s: unexpected EOF", hq->hq_hostname );
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

	    c = line + 4;

	    if ( *c == '[' ) {
		for ( c++; *c != ']'; c++ ) {
		    if ( *c == '\0' ) {
			syslog( LOG_NOTICE, "Connect.out [%s] %s: Failed: "
				"illlegal hostname in SMTP banner: %s",
				inet_ntoa( d->d_sin.sin_addr ),
				hq->hq_hostname, line );
			if (( smtp_reply = smtp_consume_banner(
				&(hq->hq_err_text), d, &tv, line,
				"Illegal hostname in banner" )) != SMTP_OK ) {
			    return( smtp_reply );
			}

			return( SMTP_ERROR );
		    }
		}

		c++;

	    } else {
		for ( c++; *c != '\0'; c++ ) {
		    if ( isspace( *c ) != 0 ) {
			break;
		    }
		}
	    }

	    old = *c;
	    *c = '\0';
	    free( hq->hq_smtp_hostname );
	    if (( hq->hq_smtp_hostname = strdup( line + 4 )) == NULL ) {
		syslog( LOG_ERR, "smtp_reply: strdup %m" );
		return( SMTP_ERROR );
	    }
	    *c = old;

	    if ( strcmp( hq->hq_smtp_hostname, simta_hostname ) == 0 ) {
		syslog( LOG_WARNING,
			"Connect.out [%s] %s: Failed: banner mail loop: %s",
			inet_ntoa( d->d_sin.sin_addr ), hq->hq_hostname, line );

		/* Loop - connected to self */
		if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text),
			d, &tv, line, "Mail loop detected" )) != SMTP_OK ) {
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
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
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

	return( smtp_consume_banner( NULL, d, &tv, line, NULL ));

    /* 3xx is success for DATA,
     * fall through to case default for all other commands
     */
    case '3':
	if ( smtp_command == SMTP_DATA ) {
	    /* consume success banner */
	    return( smtp_consume_banner( NULL, d, &tv, line, NULL ));
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
		    &tv, line, "Bad SMTP CONNECT reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail HELO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    &tv, line, "Bad SMTP HELO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_EHLO:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail EHLO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    &tv, line, "Bad SMTP EHLO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO, "Deliver.SMTP %s: From <%s> Tempfailed: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfail++;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: To <%s> From <%s> Tempfailed: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), d, &tv,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Tempfailed %s [%s]: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, 
		    inet_ntoa( d->d_sin.sin_addr ), line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
	    syslog( LOG_INFO, "Deliver.SMTP %s: Tempfailed %s [%s]: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, 
		    inet_ntoa( d->d_sin.sin_addr ), d->d_sent, d->d_size,
		    line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail RSET reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    &tv, line, "Bad SMTP RSET reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail QUIT reply: %s",
		    hq->hq_hostname, line );
	    return( smtp_consume_banner( NULL, d, &tv, line, NULL ));

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
		    &tv, line, "Bad SMTP CONNECT reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s failed HELO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    &tv, line, "Bad SMTP HELO reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_EHLO:
	    syslog( LOG_NOTICE, "smtp_reply %s failed EHLO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( NULL, d,
		    &tv, line, NULL )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_INFO, "Deliver.SMTP %s: From <%s> Failed: %s",
		    d->d_env->e_id, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
	    syslog( LOG_INFO, "Deliver.SMTP %s: To <%s> From <%s> Failed: %s",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail, line );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), d, &tv,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Message Failed: [%s] %s: %s",
		    d->d_env->e_id, inet_ntoa( d->d_sin.sin_addr ),
		    hq->hq_smtp_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
	    syslog( LOG_INFO,
		    "Deliver.SMTP %s: Failed %s [%s]: "
		    "transmitted %ld/%ld: %s",
		    d->d_env->e_id, hq->hq_smtp_hostname, 
		    inet_ntoa( d->d_sin.sin_addr ), d->d_sent, d->d_size,
		    line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), d, &tv,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_NOTICE, "smtp_reply %s failed RSET reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), d,
		    &tv, line, "Bad SMTP RSET reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_NOTICE, "smtp_reply %s failed QUIT reply: %s",
		    hq->hq_hostname, line );
	    return( smtp_consume_banner( NULL, d, &tv, line, NULL ));

	default:
	    syslog( LOG_DEBUG, "smtp_reply %d out of range", smtp_command );
	    panic( "smtp_reply smtp_command out of range" );
	}
    }

    /* this is here to supress a compiler warning */
    abort();
}


    int 
smtp_connect( struct host_q *hq, struct deliver *d )
{
    int		r;

    if (( r = smtp_reply( SMTP_CONNECT, hq, d )) != SMTP_OK ) {
	return( r );
    }

    /* say EHLO */
    if ( snet_writef( d->d_snet_smtp, "EHLO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_connect %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if (( r = smtp_reply( SMTP_EHLO, hq, d )) == SMTP_OK ) {
	return( SMTP_OK );
    }

    if ( r == SMTP_ERROR ) {
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
	    syslog( LOG_NOTICE, "smtp_connect %s: failed writef",
		hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}
	r = smtp_reply( SMTP_HELO, hq, d );
    }

    return( r );
}


    int
smtp_send( struct host_q *hq, struct deliver *d )
{
    int			smtp_result;
    char		*line;
    struct timeval	tv;

    syslog( LOG_INFO, "Deliver.SMTP %s: Attempting remote delivery: %s (%s)",
	    d->d_env->e_id, hq->hq_hostname, hq->hq_smtp_hostname );

    /* MAIL FROM: */
    if ( snet_writef( d->d_snet_smtp, "MAIL FROM:<%s>\r\n",
	    d->d_env->e_mail ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
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
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( d->d_snet_smtp, "RCPT TO:<postmaster>\r\n" )
		    < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
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

    /* say DATA */
    if ( snet_writef( d->d_snet_smtp, "DATA\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
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

    /* send message */
    while (( line = snet_getline( d->d_snet_dfile, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( d->d_snet_smtp, ".%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( d->d_snet_smtp, "%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}

	d->d_sent += strlen( line ) + 1;
    }

    memset( &tv, 0, sizeof( struct timeval ));
    tv.tv_sec = 10 * 60;
    snet_timeout( d->d_snet_smtp, SNET_WRITE_TIMEOUT, &tv );

    if ( snet_writef( d->d_snet_smtp, ".\r\n" ) < 0 ) {
	syslog( LOG_INFO,
		"Deliver.SMTP %s: Message Failed [%s] %s: "
		"transmitted %ld/%ld: failed writef: %m",
		d->d_env->e_id, inet_ntoa( d->d_sin.sin_addr ),
		hq->hq_smtp_hostname, d->d_sent, d->d_size );
	return( SMTP_BAD_CONNECTION );
    }

    memset( &tv, 0, sizeof( struct timeval ));
    tv.tv_sec = 5 * 60;
    snet_timeout( d->d_snet_smtp, SNET_WRITE_TIMEOUT, &tv );

    if (( smtp_result = smtp_reply( SMTP_DATA_EOF, hq, d )) != SMTP_OK ) {
	return( smtp_result );
    }

    return( SMTP_OK );
}


    int
smtp_rset( struct host_q *hq, struct deliver *d )
{
    /* say RSET */
    if ( snet_writef( d->d_snet_smtp, "RSET\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_rset %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    return( smtp_reply( SMTP_RSET, hq, d ));
}


    void
smtp_quit( struct host_q *hq, struct deliver *d )
{
    /* say QUIT */
    if ( snet_writef( d->d_snet_smtp, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_quit %s: failed writef", hq->hq_hostname );
	return;
    }

    smtp_reply( SMTP_QUIT, hq, d );

    return;
}
