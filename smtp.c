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
smtp_consume_banner( struct line_file **err_text, SNET *snet,
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
	    if ( line_append( *err_text, "" ) == NULL ) {
		syslog( LOG_ERR, "smtp_consume_banner line_append: %m" );
		goto consume;
	    }
	}

	if ( line_append( *err_text, error ) == NULL ) {
	    syslog( LOG_ERR, "smtp_consume_banner line_append: %m" );
	    goto consume;
	}

	if ( line_append( *err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_consume_banner line_append: %m" );
	    goto consume;
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, tv )) == NULL ) {
		syslog( LOG_ERR,
			"smtp_consume_banner snet_getline: unexpected EOF" );
		return( SMTP_BAD_CONNECTION );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( *err_text, line ) == NULL ) {
		syslog( LOG_ERR,
			"smtp_consume_banner line_append: unexpected EOF" );
		goto consume;
	    }
	}

	return( SMTP_OK );
    } else {
	ret = SMTP_OK;
    }

consume:
    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, tv )) == NULL ) {
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
smtp_reply( int smtp_command, SNET *snet, struct host_q *hq, struct deliver *d )
{
    int				smtp_reply;
    char			*line;
    struct timeval		tv;

    tv.tv_usec = 0;

    switch ( smtp_command ) {
    case SMTP_CONNECT:
	tv.tv_sec = SMTP_TIME_CONNECT;
	break;

    case SMTP_HELO:
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
	abort();
    }

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_reply %s: unexpected EOF", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    switch ( *line ) {
    /* 2xx responses indicate success */
    case '2':
	/* add positive logging for MAIL, RCPT, and DATA_EOF here */
	switch ( smtp_command ) {
	case SMTP_CONNECT:
	case SMTP_HELO:
	case SMTP_RSET:
	case SMTP_QUIT:
	    break;

	case SMTP_MAIL:
	    if ( *(d->d_env->e_mail) == '\0' ) {
		syslog( LOG_INFO, "smtp_reply %s %s MAIL FROM:<> OK: %s",
			d->d_env->e_id, hq->hq_hostname, line );
	    } else {
		syslog( LOG_INFO, "smtp_reply %s %s MAIL FROM:<%s> OK: %s",
			d->d_env->e_id, hq->hq_hostname, d->d_env->e_mail,
			line );
	    }
	    break;

	case SMTP_RCPT:
	    syslog( LOG_INFO, "smtp_reply %s %s RCPT TO:<%s> OK: %s",
		    d->d_env->e_id, hq->hq_hostname, d->d_rcpt->r_rcpt, line );
	    d->d_rcpt->r_delivered = R_DELIVERED;
	    d->d_success++;
	    break;

	/* 2xx is actually an error for DATA */
	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_BOUNCE;
	    syslog( LOG_INFO, "smtp_reply %s %s DATA FAILED: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    syslog( LOG_NOTICE, "smtp_send %s %s message delivered: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    break;

	default:
	    abort();
	}

	return( smtp_consume_banner( NULL, snet, &tv, line, NULL ));

    /* 4xx responses indicate temporary failure */
    case '4':
	switch ( smtp_command ) {
	case SMTP_CONNECT:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail CONNECT reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), snet,
		    &tv, line, "Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail HELO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), snet,
		    &tv, line, "Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_TEMPFAIL;
	    syslog( LOG_NOTICE, "smtp_reply %s %s tempfail MAIL FROM reply: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_delivered = R_TEMPFAIL;
	    d->d_tempfail++;
	    syslog( LOG_INFO, "smtp_reply %s %s RCPT TO:<%s> TEMPFAIL",
		    d->d_env->e_id, hq->hq_hostname, d->d_rcpt->r_rcpt );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), snet, &tv,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_TEMPFAIL;
	    syslog( LOG_INFO, "smtp_reply %s %s DATA TEMPFAILED: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_TEMPFAIL;
	    syslog( LOG_NOTICE, "smtp_reply %s %s tempfail DATA_EOF reply: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RSET:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail RSET reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), snet,
		    &tv, line, "Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_NOTICE, "smtp_reply %s tempfail QUIT reply: %s",
		    hq->hq_hostname, line );
	    return( smtp_consume_banner( NULL, snet, &tv, line, NULL ));

	default:
	    abort();
	}

    /* 3xx is success for DATA,
     * fall through to case default for all other commands
     */
    case '3':
	if ( smtp_command == SMTP_DATA ) {
	    /* consume success banner */
	    return( smtp_consume_banner( NULL, snet, &tv, line, NULL ));
	}

    /* all other responses are hard failures */
    default:
	switch ( smtp_command ) {
	case SMTP_CONNECT:
	    hq->hq_status = HOST_BOUNCE;
	    syslog( LOG_NOTICE, "smtp_reply %s failed CONNECT reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), snet,
		    &tv, line, "Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_HELO:
	    syslog( LOG_NOTICE, "smtp_reply %s failed HELO reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), snet,
		    &tv, line, "Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_MAIL:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_BOUNCE;
	    syslog( LOG_NOTICE, "smtp_reply %s %s failed MAIL FROM reply: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP MAIL FROM reply" ));

	case SMTP_RCPT:
	    d->d_rcpt->r_delivered = R_FAILED;
	    d->d_failed++;
	    syslog( LOG_INFO, "smtp_reply %s %s RCPT TO:<%s> FAILED",
		    d->d_env->e_id, hq->hq_hostname, d->d_rcpt->r_rcpt );
	    return( smtp_consume_banner( &(d->d_rcpt->r_err_text), snet, &tv,
		    line, "Bad SMTP RCPT TO reply" ));

	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_BOUNCE;
	    syslog( LOG_INFO, "smtp_reply %s %s DATA FAILED: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_BOUNCE;
	    syslog( LOG_INFO, "smtp_reply %s %s DATA_EOF FAILED: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP DATA_EOF reply" ));

	case SMTP_RSET:
	    syslog( LOG_INFO, "smtp_reply %s failed RSET reply: %s",
		    hq->hq_hostname, line );
	    if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text), snet,
		    &tv, line, "Bad SMTP MAIL FROM reply" )) == SMTP_OK ) {
		return( SMTP_ERROR );
	    }
	    return( smtp_reply );

	case SMTP_QUIT:
	    syslog( LOG_INFO, "smtp_reply %s failed QUIT reply: %s",
		    hq->hq_hostname, line );
	    return( smtp_consume_banner( NULL, snet, &tv, line, NULL ));

	default:
	    abort();
	}
    }
}


    int
smtp_connect( SNET **snetp, struct host_q *hq )
{
    int				i;
    int				s;
    int				dnsr_count = 0;
    int				smtp_result;
    SNET			*snet;
    struct dnsr_result		*result;
    struct sockaddr_in		sin;

    hq->hq_status = HOST_DOWN;

    if (( result = get_mx( hq->hq_hostname )) == NULL ) {
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

    if (( smtp_result = smtp_reply( SMTP_CONNECT, snet, hq, NULL ))
	    != SMTP_OK ) {
	return( smtp_result );
    }

    /* XXX MAIL LOOP DETECTION */

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_connect %s: failed writef", hq->hq_hostname );
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_HELO, snet, hq, NULL )) == SMTP_OK ) {
	hq->hq_status = HOST_MX;
    }

    return( smtp_result );
}


    int
smtp_send( SNET *snet, struct host_q *hq, struct deliver *d )
{
    int			smtp_result;
    char		*line;

    /* MAIL FROM: */
    if ( *(d->d_env->e_mail) == '\0' ) {
	if ( snet_writef( snet, "MAIL FROM:<>\r\n" ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
	    hq->hq_status = HOST_DOWN;
	    return( SMTP_BAD_CONNECTION );
	}

    } else {
	if ( snet_writef( snet, "MAIL FROM:<%s>\r\n",
		d->d_env->e_mail ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
	    hq->hq_status = HOST_DOWN;
	    return( SMTP_BAD_CONNECTION );
	}
    }

    if (( smtp_result = smtp_reply( SMTP_MAIL, snet, hq, d )) != SMTP_OK ) {
	hq->hq_status = HOST_DOWN;
	return( smtp_result );
    }

    /* check to see if the sender failed */
    if (( d->d_env->e_flags & ENV_BOUNCE ) ||
	    ( d->d_env->e_flags & ENV_TEMPFAIL )) {
	return( SMTP_OK );
    }

    /* RCPT TOs: */
    assert( d->d_env->e_rcpt != NULL );

    for ( d->d_rcpt = d->d_env->e_rcpt; d->d_rcpt != NULL;
	    d->d_rcpt = d->d_rcpt->r_next ) {
	if ( snet_writef( snet, "RCPT TO:<%s>\r\n", d->d_rcpt->r_rcpt ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );
	    hq->hq_status = HOST_DOWN;
	    return( SMTP_BAD_CONNECTION );
	}

	if (( smtp_result = smtp_reply( SMTP_RCPT, snet, hq, d )) != SMTP_OK ) {
	    hq->hq_status = HOST_DOWN;
	    return( smtp_result );
	}
    }

    if ( d->d_success == 0 ) {
	/* no rcpts succeded */
	syslog( LOG_INFO, "smtp_send %s %s %s: no valid recipients",
		d->d_env->e_id, hq->hq_hostname, d->d_env->e_id );
	return( SMTP_OK );
    }

    /* say DATA */
    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
	hq->hq_status = HOST_DOWN;
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_DATA, snet, hq, d )) != SMTP_OK ) {
	hq->hq_status = HOST_DOWN;
	return( smtp_result );
    }

    /* check to see if DATA failed */
    if (( d->d_env->e_flags & ENV_BOUNCE ) ||
	    ( d->d_env->e_flags & ENV_TEMPFAIL )) {
	return( SMTP_OK );
    }

    /* send message */
    while (( line = snet_getline( d->d_dfile_snet, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		hq->hq_status = HOST_DOWN;
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( snet, "%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		hq->hq_status = HOST_DOWN;
		return( SMTP_BAD_CONNECTION );
	    }
	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
	hq->hq_status = HOST_DOWN;
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_DATA_EOF, snet, hq, d )) != SMTP_OK ) {
	hq->hq_status = HOST_DOWN;
	return( smtp_result );
    }

    return( SMTP_OK );
}


    int
smtp_rset( SNET *snet, struct host_q *hq )
{
    int				smtp_result;

    /* say RSET */
    if ( snet_writef( snet, "RSET\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_rset %s: failed writef", hq->hq_hostname );
	hq->hq_status = HOST_DOWN;
	return( SMTP_BAD_CONNECTION );
    }

    if (( smtp_result = smtp_reply( SMTP_RSET, snet, hq, NULL )) != SMTP_OK ) {
	hq->hq_status = HOST_DOWN;
    }

    return( smtp_result );
}


    void
smtp_quit( SNET *snet, struct host_q *hq )
{
    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_quit %s: failed writef", hq->hq_hostname );
	return;
    }

    smtp_reply( SMTP_QUIT, snet, hq, NULL );

    return;
}
