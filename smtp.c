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

#include <snet.h>

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
smtp_grab( struct line_file **err_text, SNET *snet, struct timeval *tv,
	char *line, char *error )
{
    if ( *err_text == NULL ) {
	if (( *err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_grab line_file_create: %m" );
	    goto consume;
	}

    } else {
	if ( line_append( *err_text, "" ) == NULL ) {
	    syslog( LOG_ERR, "smtp_grab line_append: %m" );
	    goto consume;
	}
    }

    if ( line_append( *err_text, error ) == NULL ) {
	syslog( LOG_ERR, "smtp_grab line_append: %m" );
	goto consume;
    }

    if ( line_append( *err_text, line ) == NULL ) {
	syslog( LOG_ERR, "smtp_grab line_append: %m" );
	goto consume;
    }

    while (*(line + 3) == '-' ) {
	if (( line = snet_getline( snet, tv )) == NULL ) {
	    syslog( LOG_ERR, "smtp_grab snet_getline: unexpected EOF" );
	    return( SMTP_BAD_CONNECTION );
	}

	if ( smtp_logger != NULL ) {
	    (*smtp_logger)( line );
	}

	if ( line_append( *err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_grab line_append: unexpected EOF" );
	    goto consume;
	}
    }

    return( SMTP_OK );

consume:
    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, tv )) == NULL ) {
	    syslog( LOG_NOTICE, "smtp_grab: unexpected EOF" );
	    return( SMTP_BAD_CONNECTION );
	}
    }

    return( SMTP_ERROR );
}

    void
stdout_logger( char *line )
{
    printf( "<-- %s\n", line );
    return;
}


    int
smtp_connect( SNET **snetp, struct host_q *hq )
{
    int				i;
    int				s;
    int				dnsr_count = 0;
    int				smtp_result;
    char			*line;
    char			*remote_host;
    char			*c;
    SNET			*snet;
    struct dnsr_result		*result;
    struct sockaddr_in		sin;
    struct timeval		tv;

    /* mark it down for now, mark it up if we actually succeed */
    hq->hq_status = HOST_DOWN;

    if ( simta_dnsr == NULL ) {
	if (( simta_dnsr = dnsr_new( )) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect %s dnsr_new: %m", hq->hq_hostname );
	    return( SMTP_ERROR );
	}
    }

    if (( result = get_mx( simta_dnsr, hq->hq_hostname )) == NULL ) {
	syslog( LOG_ERR, "smtp_connect %s get_mx: failed", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    for ( i = 0; i < result->r_ancount; i++ ) {
	if ( result->r_answer[ i ].rr_ip == NULL ) {
	    continue;
	}
        switch( result->r_answer[ i ].rr_type ) {
        case DNSR_TYPE_MX:
            memcpy( &(sin.sin_addr.s_addr),
		    &(result->r_answer[ i ].rr_ip->ip_ip ),
		    sizeof( struct in_addr ));
            dnsr_count++;
            break;

        case DNSR_TYPE_A:
            memcpy( &(sin.sin_addr.s_addr),
		    &(result->r_answer[ i ].rr_a ),
		    sizeof( struct in_addr ));
            dnsr_count++;
            break;

        default:
            continue;
        }

        if ( dnsr_count != 0 ) {
            break;
        }
    }

    dnsr_free_result( result );

    if ( dnsr_count == 0 ) {
	syslog( LOG_ERR, "smtp_connect %s get_mx: no valid result",
		hq->hq_hostname );
	return( SMTP_ERROR );
    }

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "smtp_connect %s socket: %m", hq->hq_hostname );
	return( SMTP_ERROR );
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons( SIMTA_SMTP_PORT );

    if ( connect( s, (struct sockaddr*)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "smtp_connect %s connect: %m", hq->hq_hostname );
	if ( close( s ) != 0 ) {
	    syslog( LOG_ERR, "smtp_connect %s close: %m", hq->hq_hostname );
	}
	return( SMTP_BAD_CONNECTION );
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "smtp_connect %s snet_attach: %m", hq->hq_hostname );
	if ( close( s ) != 0 ) {
	    syslog( LOG_ERR, "smtp_connect %s close: %m", hq->hq_hostname );
	}
	return( SMTP_ERROR );
    }

    *snetp = snet;
    tv.tv_sec = SMTP_TIME_CONNECT;
    tv.tv_usec = 0;

    /* read connect banner */
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect %s snet_getline: unexpected EOF",
		hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* CONNECTION ESTABLISHMENT
     *	    S: 2*
     *		- analyse & consume
     *
     *	    perm: *, detect mail loop
     *		- bounce queue
     *		- capture error message in hq->hq_err_text
     *
     *	    tmp: 4*
     *		- capture error message in hq->hq_err_text
     */

    switch ( *line ) {
    case '2':
	break;

    case '4':
	hq->hq_status = HOST_BOUNCE;
    default:
	syslog( LOG_NOTICE, "smtp_connect %s: bad connection banner: %s",
		hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"Bad SMTP connection banner" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );
    }

    /* check for remote hostname in connect banner */
    remote_host = line + 3;
    if ( *remote_host == '-' ) {
	remote_host++;
    }
    while (( *remote_host == ' ' ) || ( *remote_host == '\t' )) {
	remote_host++;
    }
    if ( *remote_host == '\0' ) {
	hq->hq_status = HOST_BOUNCE;
	syslog( LOG_NOTICE, "smtp_connect %s: bad connection banner, "
		"expecting remote hostname: %s", hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"SMTP connection banner: No remote hostname" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );
    }

    /* mail loop detection: check if remote hostname matches local hostname */
    c = remote_host;
    while (( *c != ' ' ) && ( *c != '\t' )) {
	c++;
    }
    if ( strncasecmp( simta_hostname, remote_host,
	    (size_t)(c - remote_host) ) == 0 ) {
	hq->hq_status = HOST_BOUNCE;
	syslog( LOG_WARNING, "smtp_connect %s: mail loop", hq->hq_hostname );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"SMTP connection banner: Mail loop detected" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );
    }

    /* consume banner */
    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}
    }

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_connect %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    /* read helo reply banner */
    tv.tv_sec = SMTP_TIME_HELO;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
		hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* EHLO or HELO
     *	    S: 2*
     *		- consume
     *
     *	    perm: *
     *		- bounce queue
     *		- capture message in struct host_q
     *
     *	    tmp: 4*
     *		- capture message in struct host_q
     */

    switch ( *line ) {
    case '2':
	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}
	hq->hq_status = HOST_MX;
	return( SMTP_OK );

    default:
	hq->hq_status = HOST_BOUNCE;
    case '4':
	syslog( LOG_NOTICE, "smtp_connect %s bad HELO response: %s",
		hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"Bad SMTP HELO reply" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );
    }
}


    int
smtp_send( SNET *snet, struct host_q *hq, struct deliver *d )
{
    int			smtp_result;
    char		*line;
    struct recipient	*r;
    struct timeval	tv;

    /* mark it down for now, mark it up if we actually succeed */
    hq->hq_status = HOST_DOWN;

    /* MAIL FROM: */
    if ( *(d->d_env->e_mail) == '\0' ) {
	if ( snet_writef( snet, "MAIL FROM: <>\r\n" ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}

    } else {
	if ( snet_writef( snet, "MAIL FROM: <%s>\r\n",
		d->d_env->e_mail ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}
    }

    /* read reply banner */
    tv.tv_sec = SMTP_TIME_MAIL;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* MAIL FROM:<address>
     *	    S: 2*
     *		- consume
     *
     *	    tmp: 4*: tmp system failure
     *		- capture error message in struct hq
     *
     *	    perm: *
     *		- bounce current mesage
     *		- capture error text in struct envelope
     */

    switch ( *line ) {
    case '2':
	if ( *(d->d_env->e_mail) == '\0' ) {
	    syslog( LOG_INFO, "smtp_send %s %s MAIL FROM <> OK", d->d_env->e_id,
		    hq->hq_hostname );
	} else {
	    syslog( LOG_INFO, "smtp_send %s %s MAIL FROM <%s> OK",
		    d->d_env->e_id, hq->hq_hostname, d->d_env->e_mail );
	}

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}
	break;

    default:
	syslog( LOG_NOTICE, "smtp_send %s %s bad MAIL FROM reply: %s",
		d->d_env->e_id, hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(d->d_env->e_err_text), snet, &tv, line,
		"Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
	    hq->hq_status = HOST_MX;
	}
	return( smtp_result );

    case '4':
	syslog( LOG_NOTICE, "smtp_send %s %s bad MAIL FROM banner: %s",
		d->d_env->e_id, hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"Bad SMTP MAIL FROM banner" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );
    }

    /* RCPT TOs: */
    for ( r = d->d_env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: <%s>\r\n", r->r_rcpt ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}

	/* read reply banner */
	tv.tv_sec = SMTP_TIME_RCPT;
	tv.tv_usec = 0;

	if (( line = snet_getline( snet, &tv )) == NULL ) {
	    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		    hq->hq_hostname );
	    return( SMTP_BAD_CONNECTION );
	}

	if ( smtp_logger != NULL ) {
	    (*smtp_logger)( line );
	}

	/* RCPT TO:<address>
	 *	    S: 2* (but see section 3.4 for discussion of 251 and 551)
	 *		- consume
	 *
	 *	    perm: *
	 *		- bounce rcpt
	 *		- capture error text in struct rcpt
	 *		- try next rcpt
	 *
	 *	    tmp: 552, 4*
	 *		- capture error text in struct rcpt
	 *		- try next rcpt
	 *
	 */

	if ( *line == '2' ) {
	    syslog( LOG_INFO, "smtp_send %s %s RCPT TO <%s> OK: %s",
		    d->d_env->e_id, hq->hq_hostname, r->r_rcpt, line );
	    r->r_delivered = R_DELIVERED;
	    d->d_success++;

	    if ( *(line + 3) == '-' ) {
		if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
			== NULL ) {
		    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			    hq->hq_hostname );
		    return( SMTP_BAD_CONNECTION );
		}
	    }

	} else {
	    syslog( LOG_NOTICE, "smtp_send %s %s bad RCPT TO <%s> banner: %s",
		    d->d_env->e_id, hq->hq_hostname, r->r_rcpt, line );
	    if (( strncmp( line, "552", (size_t)3 ) == 0 ) ||
		    ( *line == '4' )) {
		/* note RFC 2821 response code 552 exception */
		r->r_delivered = R_TEMPFAIL;
		d->d_tempfail++;

	    } else {
		r->r_delivered = R_FAILED;
		d->d_failed++;
	    }

	    if (( smtp_result = smtp_grab( &(r->r_err_text), snet, &tv, line,
		    "Bad RCPT TO banner" )) != SMTP_OK ) {
		return( smtp_result );
	    }
	}
    }

    if ( d->d_success == 0 ) {
	/* no rcpts succeded */
	syslog( LOG_INFO, "smtp_send %s %s %s: no valid recipients",
		d->d_env->e_id, hq->hq_hostname, d->d_env->e_id );
	hq->hq_status = HOST_MX;
	return( SMTP_OK );
    }

    /* say DATA */
    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    tv.tv_sec = SMTP_TIME_DATA_INIT;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* DATA
     *	    S: 3*
     *		- consume
     *
     *	    perm: *
     *		- bounce current mesage
     *		- capture
     *		- try next message
     *
     *	    tmp: 4*
     *		- capture
     *		- try next message
     */

    switch ( *line ) {
    case '3':
	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}
	break;

    default:
	d->d_env->e_flags = d->d_env->e_flags | ENV_BOUNCE;
    case '4':
	syslog( LOG_NOTICE, "smtp_send %s %s: bad DATA reply: %s",
		d->d_env->e_id, hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(d->d_env->e_err_text), snet, &tv, line,
		"Bad DATA banner" )) == SMTP_OK ) {
	    hq->hq_status = HOST_MX;
	}
	return( smtp_result );
    }

    /* send message */
    while (( line = snet_getline( d->d_dfile_snet, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( snet, "%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    tv.tv_sec = SMTP_TIME_DATA_EOF;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* DATA_EOF
     *	    S: 2*
     *		- consume
     *
     *	    tmp: 4*
     *		- capture in host_q
     *
     *	    perm: *
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    switch ( *line ) {
    case '4':
	syslog( LOG_NOTICE, "smtp_send %s %s SMTP banner: %s", d->d_env->e_id,
		hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"Bad DATA_EOF banner" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );

    case '2':
	syslog( LOG_NOTICE, "smtp_send %s %s message delivered: %s",
		d->d_env->e_id, hq->hq_hostname, line );
	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}
	break;

    default:
	d->d_env->e_flags = d->d_env->e_flags | ENV_BOUNCE;
	syslog( LOG_NOTICE, "smtp_send %s %s: bad DATA_EOF reply: %s",
		d->d_env->e_id, hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(d->d_env->e_err_text), snet, &tv, line,
		"Bad DATA banner" )) != SMTP_OK ) {
	    return( smtp_result );
	}
	break;
    }

    hq->hq_status = HOST_MX;
    return( SMTP_OK );
}


    int
smtp_rset( SNET *snet, struct host_q *hq )
{
    int				smtp_result;
    char			*line;
    struct timeval		tv;

    /* mark it down for now, mark it up if we actually succeed */
    hq->hq_status = HOST_DOWN;

    /* say RSET */
    if ( snet_writef( snet, "RSET\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_rset %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    /* read reply banner */
    tv.tv_sec = SMTP_TIME_RSET;
    tv.tv_usec = 0;
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_rset %s: unexpected EOF", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }
    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* RSET
     *	    S: 2*
     *		- consume
     *
     *	    perm: *
     *		- bounce queue
     *		- capture message in struct host_q
     */

    switch ( *line ) {
    case '2':
	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		syslog( LOG_NOTICE, "smtp_rset %s: unexpected EOF",
			hq->hq_hostname );
		return( SMTP_BAD_CONNECTION );
	    }
	}
	hq->hq_status = HOST_MX;
	return( SMTP_OK );

    default:
	syslog( LOG_NOTICE, "smtp_rset %s bad RSET reply: %s",
		hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"Bad SMTP RSET reply" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
	return( smtp_result );
    }
}


    void
smtp_quit( SNET *snet, struct host_q *hq )
{
    int				smtp_result;
    char			*line;
    struct timeval		tv;

    /* mark it down unless it's a BOUNCE, mark it up if we actually succeed */
    if ( hq->hq_status == HOST_MX ) {
	hq->hq_status = HOST_DOWN;
    }

    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_quit %s: failed writef", hq->hq_hostname );
    }

    /* read reply banner */
    tv.tv_sec = SMTP_TIME_QUIT;
    tv.tv_usec = 0;
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_quit %s: unexpected EOF",
		hq->hq_hostname );
	return;
    }
    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* QUIT
     *	    S: 2*
     *		- consume
     *
     *	    tmp: *
     *		- capture error message in host_q
     */

    switch ( *line ) {
    case '2':
	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		syslog( LOG_NOTICE, "smtp_quit %s: unexpected EOF",
			hq->hq_hostname );
		return;
	    }
	}

	if ( hq->hq_status == HOST_DOWN ) {
	    /* we're up if we're not BOUNCEing */
	    hq->hq_status = HOST_MX;
	}
	return;

    default:
	syslog( LOG_NOTICE, "smtp_quit %s bad QUIT reply: %s",
		hq->hq_hostname, line );
	if (( smtp_result = smtp_grab( &(hq->hq_err_text), snet, &tv, line,
		"Bad SMTP QUIT reply" )) == SMTP_OK ) {
	    smtp_result = SMTP_ERROR;
	}
    }
}
