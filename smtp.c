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
_smtp_connect_try( SNET **snetp, struct sockaddr_in *sin, struct host_q *hq )
{

    int	    ret;

    if (( *snetp = _smtp_connect_snet( sin, hq->hq_hostname )) == NULL ) {
	/* XXX - When do we retrun SMTP_BAD_CNNECTION or SMTP_ERROR? */
	return( SMTP_BAD_CONNECTION );
    }

    if (( ret = smtp_reply( SMTP_CONNECT, *snetp, hq, NULL ))
	    != SMTP_OK ) {
	goto error;
    }

    /* say EHLO */
    if ( snet_writef( *snetp, "EHLO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_NOTICE, "_smtp_connect_try %s: failed writef",
	    hq->hq_hostname );
	goto error;
    }

    if (( ret = smtp_reply( SMTP_EHLO, *snetp, hq, NULL )) != SMTP_OK ) {
	goto error;
    }
    return( SMTP_OK );

error:
    if ( snet_close( *snetp ) != 0 ) {
	syslog( LOG_WARNING, "_smtp_connect_try %s: snet_close: %m",
	    hq->hq_hostname );
    }
    *snetp = NULL;

    return( ret );
}

    SNET *
_smtp_connect_snet( struct sockaddr_in *sin, char *hostname )
{
    int		s;
    SNET 	*snet;

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "_smtp_connect_snet %s socket: %m", hostname );
	return( NULL );
    }

    if ( connect( s, (struct sockaddr*)sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "_smtp_connect_snet %s connect: %m", hostname );
	goto error;
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "_smtp_connect_snet %s snet_attach: %m", hostname );
	goto error;
    }

    return( snet );

error:
    if ( close( s ) != 0 ) {
	syslog( LOG_ERR, "_smtp_connect_snet %s close: %m", hostname );
    }
    return( NULL );
}


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
	    if (( line = snet_getline( snet, tv )) == NULL ) {
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

	    if (( *(line + 4 ) != '[' )
		    && ( strcmp( line + 4, simta_hostname ) == 0 )) {
		/* Loop - connected to self */
		if (( smtp_reply = smtp_consume_banner( &(hq->hq_err_text),
			snet, &tv, line, "Mail loop detected" )) != SMTP_OK ) {
		    return( smtp_reply );
		}
		syslog( LOG_NOTICE,
		    "smtp_reply %s mail loop detected in banner: %s",
		    hq->hq_hostname, line );

		return( SMTP_ERROR );
	    }

	    break;


	case SMTP_RSET:
	case SMTP_QUIT:
	    break;

	case SMTP_HELO:
	    syslog( LOG_INFO, "smtp_reply %s HELO: %s", hq->hq_hostname, line );
	    break;

	case SMTP_EHLO:
	    syslog( LOG_INFO, "smtp_reply %s EHLO: %s", hq->hq_hostname, line );
	    break;

	case SMTP_MAIL:
	    syslog( LOG_INFO, "smtp_reply %s %s MAIL FROM:<%s> OK: %s",
		    d->d_env->e_id, hq->hq_hostname, d->d_env->e_mail, line );
	    break;

	case SMTP_RCPT:
	    syslog( LOG_INFO, "smtp_reply %s %s RCPT TO:<%s> OK: %s",
		    d->d_env->e_id, hq->hq_hostname, d->d_rcpt->r_rcpt, line );
	    d->d_rcpt->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    break;

	/* 2xx is actually an error for DATA */
	case SMTP_DATA:
	    d->d_env->e_flags = d->d_env->e_flags | ENV_TEMPFAIL;
	    syslog( LOG_INFO, "smtp_reply %s %s DATA TEMPFAILED: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    return( smtp_consume_banner( &(d->d_env->e_err_text), snet, &tv,
		    line, "Bad SMTP DATA reply" ));

	case SMTP_DATA_EOF:
	    d->d_delivered = 1;
	    syslog( LOG_NOTICE, "smtp_send %s %s message delivered: %s",
		    d->d_env->e_id, hq->hq_hostname, line );
	    break;

	default:
	    panic( "smtp_reply smtp_command out of range" );
	}

	return( smtp_consume_banner( NULL, snet, &tv, line, NULL ));

    /* 3xx is success for DATA,
     * fall through to case default for all other commands
     */
    case '3':
	if ( smtp_command == SMTP_DATA ) {
	    /* consume success banner */
	    return( smtp_consume_banner( NULL, snet, &tv, line, NULL ));
	}

    default:
	/* note that we treat default as a tempfail and fall through */

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
	    d->d_rcpt->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfail++;
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
	    panic( "smtp_reply smtp_command out of range" );
	}

    /* all other responses are hard failures */
    case '5':
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
	    d->d_rcpt->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
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
	    panic( "smtp_reply smtp_command out of range" );
	}
    }

    /* this is here to supress a compiler warning */
    abort();
}


    int
smtp_connect( SNET **snetp, struct host_q *hq )
{
    int				i, j;
    SNET			*snet = NULL;
    struct dnsr_result		*result, *result_ip;
    struct sockaddr_in		sin;

    hq->hq_status = HOST_DOWN;

    if (( result = get_dnsr_result( hq->hq_hostname )) == NULL ) {
        return( SMTP_ERROR );
    }

    for ( i = 0; i < result->r_ancount; i++ ) {
	memset( &sin, 0, sizeof( struct sockaddr_in ));
	sin.sin_family = AF_INET;
	sin.sin_port = htons( SIMTA_SMTP_PORT );

        switch( result->r_answer[ i ].rr_type ) {
        case DNSR_TYPE_MX:
            if ( result->r_answer[ i ].rr_ip != NULL ) {
                memcpy( &(sin.sin_addr.s_addr),
                    &(result->r_answer[ i ].rr_ip->ip_ip ),
                    sizeof( struct in_addr ));
		if ( _smtp_connect_try( &snet, &sin, hq ) == SMTP_OK ) {
		    goto done;
		}
            } else {  
                if (( result_ip =
                        get_a( result->r_answer[ i ].rr_mx.mx_exchange ))
                        == NULL ) {
                    continue;
                }
                for ( j = 0; j < result_ip->r_ancount; j++ ) {
		    /* XXX - How to loop over this? */
                    memcpy( &(sin.sin_addr.s_addr),
                        &(result_ip->r_answer[ j ].rr_a ),
                        sizeof( struct in_addr ));
		    if ( _smtp_connect_try( &snet, &sin, hq ) == SMTP_OK ) {
			dnsr_free_result( result_ip );
			goto done;
		    }
                }       
                dnsr_free_result( result_ip );
            }
            break;

        case DNSR_TYPE_A:
            memcpy( &(sin.sin_addr.s_addr), &(result->r_answer[ i ].rr_a ),
                sizeof( struct in_addr ));
	    if ( _smtp_connect_try( &snet, &sin, hq ) == SMTP_OK ) {
		goto done;
	    }
	    break;

        default:
            syslog( LOG_WARNING, "dnsr_connect %s: unknown dnsr result: %d",
                hq->hq_hostname, result->r_answer[ i ].rr_type );
            continue;
        }
    }

done:
    dnsr_free_result( result );
    if ( snet != NULL ) {
	hq->hq_status = HOST_MX;
	*snetp = snet;
	return( SMTP_OK );
    } else {
	return( SMTP_BAD_CONNECTION );
    }
}



    int
smtp_send( SNET *snet, struct host_q *hq, struct deliver *d )
{
    int			smtp_result;
    char		*line;

    /* MAIL FROM: */
    if ( snet_writef( snet, "MAIL FROM:<%s>\r\n", d->d_env->e_mail ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );
	hq->hq_status = HOST_DOWN;
	return( SMTP_BAD_CONNECTION );
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
	if( *(d->d_rcpt->r_rcpt) != '\0' ) {
	    if ( snet_writef( snet, "RCPT TO:<%s>\r\n",
		    d->d_rcpt->r_rcpt ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		hq->hq_status = HOST_DOWN;
		return( SMTP_BAD_CONNECTION );
	    }

	} else {
	    if ( snet_writef( snet, "RCPT TO:<postmaster>\r\n" ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );
		hq->hq_status = HOST_DOWN;
		return( SMTP_BAD_CONNECTION );
	    }
	}

	if (( smtp_result = smtp_reply( SMTP_RCPT, snet, hq, d )) != SMTP_OK ) {
	    hq->hq_status = HOST_DOWN;
	    return( smtp_result );
	}
    }

    if ( d->d_n_rcpt_accepted == 0 ) {
	/* no rcpts succeded */
	d->d_delivered = 1;
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

    if ( snet_writef( snet, ".\r\n" ) < 0 ) {
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
