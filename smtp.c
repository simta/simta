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

#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>

#include <snet.h>

#include "queue.h"
#include "line_file.h"
#include "envelope.h"
#include "smtp.h"
#include "denser.h"
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
    int				valid_result = 0;
    char			*line;
    char			*remote_host;
    char			*c;
    SNET			*snet;
    DNSR			*dnsr;
    struct dnsr_result		*result;
    struct sockaddr_in		sin;
    struct timeval		tv;

    syslog( LOG_DEBUG, "smtp_connect starting" );

    if (( dnsr = dnsr_new( )) == NULL ) {
	syslog( LOG_ERR, "smtp_connect dnsr_new: %m" );
	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if (( result = get_mx( dnsr, hq->hq_hostname )) == NULL ) {
	hq->hq_status = HOST_DOWN;
	syslog( LOG_ERR, "smtp_connect get_mx failed" );
	return( SMTP_ERR_REMOTE );
    }

    for ( i = 0; i < result->r_ancount; i++ ) {
        switch( result->r_answer[ i ].rr_type ) {
        case DNSR_TYPE_MX:
            memcpy( &(sin.sin_addr.s_addr),
		    &(result->r_answer[ i ].rr_ip->ip_ip ),
		    sizeof( struct in_addr ));
            valid_result++;
            break;

        case DNSR_TYPE_A:
            memcpy( &(sin.sin_addr.s_addr),
		    &(result->r_answer[ i ].rr_a ),
		    sizeof( struct in_addr ));
            valid_result++;
            break;

        default:
            continue;
        }

        if ( valid_result != 0 ) {
            break;
        }
    }

    if ( valid_result == 0 ) {
	syslog( LOG_ERR, "smtp_connect: get_mx: no valid result" );
	return( SMTP_ERR_SYSCALL );
    }

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "smtp_connect: socket: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons( SIMTA_SMTP_PORT );

    if ( connect( s, (struct sockaddr*)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "smtp_connect: connect: %m" );
	return( SMTP_ERR_REMOTE );
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "smtp_connect: snet_attach: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    tv.tv_sec = SMTP_TIME_CONNECT;
    tv.tv_usec = 0;

    /* read connect banner */
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
		hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* CONNECTION ESTABLISHMENT
     *	    S: 2*
     *
     *	    tmp: 4*
     *		- close connection
     *		- clear queue
     *
     *	    perm: *, detect mail loop
     *		- capture message in struct host_q
     *		- close connection
     *		- bounce queue
     */

    if ( *line == '4' ) {
	hq->hq_status = HOST_DOWN;

	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}

    } else if ( *line != '2' ) {
	hq->hq_status = HOST_BOUNCE;

	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	/* capture error message */
	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, "Bad SMTP connection banner" )
		== NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( hq->hq_err_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_connect: line_append %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_REMOTE );
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

	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner, "
		"expecting remote hostname: %s", hq->hq_hostname, line );

	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	/* XXX message content */
	if ( line_append( hq->hq_err_text, "Missing remote hostname" )
		== NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}
    }

    c = remote_host;

    while (( *c != ' ' ) && ( *c != '\t' )) {
	c++;
    }

    /* mail loop detection: check if remote hostname matches local hostname */

    if ( strncasecmp( simta_hostname, remote_host,
	    (size_t)(c - remote_host) ) == 0 ) {
	hq->hq_status = HOST_BOUNCE;

	syslog( LOG_WARNING, "smtp_connect %s: mail loop", hq->hq_hostname );

	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	/* XXX message content */
	if ( line_append( hq->hq_err_text, "Mail loop detected" ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}
    }

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    /* CONNECT END */

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_connect %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_connect snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    tv.tv_sec = SMTP_TIME_HELO;
    tv.tv_usec = 0;

    /* read helo reply banner */
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
		hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* EHLO or HELO
     *	    S: 2*
     *
     *	    tmp: 4*
     *		- close connection
     *		- clear queue
     *
     *	    perm: *
     *		- capture message in struct host_q
     *		- close connection
     *		- bounce queue
     */

    if ( *line == '4' ) {
	hq->hq_status = HOST_DOWN;

	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}

    } else if ( *line != '2' ) {
	hq->hq_status = HOST_BOUNCE;

	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	/* capture error message */
	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, "Bad SMTP helo reply" ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( hq->hq_err_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_connect: line_append %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_REMOTE );
    }

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    *snetp = snet;

    return( 0 );
}


    int
smtp_send( SNET *snet, struct host_q *hq, struct envelope *env, SNET *message )
{
    char		*line;
    struct recipient	*r;
    struct timeval	tv;

    syslog( LOG_DEBUG, "smtp_send starting" );

    /* MAIL FROM: */
    if (( env->e_mail == NULL ) || ( *env->e_mail == '\0' )) {
	if ( snet_writef( snet, "MAIL FROM: <>\r\n" ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}

    } else {
	if ( snet_writef( snet, "MAIL FROM: <%s>\r\n", env->e_mail ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    /* read reply banner */

    tv.tv_sec = SMTP_TIME_MAIL;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* MAIL
     *	    S: 2*
     *
     *	    tmp: 4*: tmp system failure
     *		- close connection
     *		- clear queue
     *
     *	    perm: *
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    if ( *line == '4' ) {
	hq->hq_status = HOST_DOWN;

	syslog( LOG_NOTICE, "smtp_send %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}

    } else if ( *line != '2' ) {

	syslog( LOG_NOTICE, "smtp_send %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	/* capture error message */
	if (( env->e_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( env->e_err_text, "Bad SMTP MAIL FROM reply" )
		== NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( env->e_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		hq->hq_status = HOST_DOWN;
		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( env->e_err_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_send: line_append %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	/* MAIL FROM failed, env->e_err_text is set */
	return( 0 );
    }

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    /* RCPT TOs: */

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: <%s>\r\n", r->r_rcpt ) < 0 ) {
	    syslog( LOG_NOTICE, "smtp_send %s: failed writef",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_REMOTE );
	}

	/* read reply banner */

	tv.tv_sec = SMTP_TIME_RCPT;
	tv.tv_usec = 0;

	if (( line = snet_getline( snet, &tv )) == NULL ) {
	    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}

	if ( smtp_logger != NULL ) {
	    (*smtp_logger)( line );
	}

	/* RCPT
	 *	    S: 2* (but see section 3.4 for discussion of 251 and 551)
	 *
	 *	    tmp: 552, 4*
	 *		- if old dfile, capture error text in struct rcpt
	 *		- if old dfile, bounce current rcpt in struct rcpt
	 *		- try next rcpt
	 *
	 *	    perm: *
	 *		- capture error text in struct rcpt
	 *		- bounce current rcpt
	 *		- try next rcpt
	 */

	if ( *line == '2' ) {
	    r->r_delivered = R_DELIVERED;
	    env->e_success++;

	} else if ((( strncmp( line, "552", (size_t)3 ) == 0 ) ||
		( *line == '4' )) && ( env->e_old_dfile == 0 )) {
	    /* note RFC 2821 response code 552 exception */

	    r->r_delivered = R_TEMPFAIL;
	    env->e_tempfail++;

	} else {
	    r->r_delivered = R_FAILED;
	    env->e_failed++;
	}

	if ( r->r_delivered == R_FAILED ) {
	    if (( r->r_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "smtp_send: line_file_create: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    if ( line_append( r->r_text, "Bad SMTP RCPT TO reply" ) == NULL ) {
		syslog( LOG_ERR, "smtp_send: line_append: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    if ( line_append( r->r_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_send: line_append: %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	while ( *(line + 3) == '-' ) {
	    /* read reply banner */
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		hq->hq_status = HOST_DOWN;
		return( SMTP_ERR_REMOTE );
	    }

	    if ( r->r_delivered == R_FAILED ) {
		if ( line_append( r->r_text, line ) == NULL ) {
		    syslog( LOG_ERR, "smtp_send: line_append: %m" );
		    return( SMTP_ERR_SYSCALL );
		}
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }
	}
    }

    if ( env->e_success == 0 ) {
	/* no rcpts succeded */
	return( 0 );
    }

    /* say DATA */

    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_send snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    tv.tv_sec = SMTP_TIME_DATA_INIT;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* DATA
     *	    S: 3*
     *
     *	    tmp: 4*
     *		- close connection
     *		- clear queue
     *
     *	    perm: *
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    if ( *line == '4' ) {
	hq->hq_status = HOST_DOWN;

	syslog( LOG_NOTICE, "smtp_send %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}

    } else if ( *line != '3' ) {

	syslog( LOG_NOTICE, "smtp_send %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	/* capture error message */
	if (( env->e_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( env->e_err_text, "Bad SMTP DATA reply" ) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( env->e_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		hq->hq_status = HOST_DOWN;
		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( env->e_err_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_send: line_append %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	/* DATA failed, env->e_err_text is set */
	return( 0 );
    }

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    /* send message */

    while (( line = snet_getline( message, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }

	} else {
	    if ( snet_writef( snet, "%s\r\n", line ) < 0 ) {
		syslog( LOG_NOTICE, "smtp_send %s: failed writef",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_REMOTE );
    }

    tv.tv_sec = SMTP_TIME_DATA_EOF;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* DATA_EOF
     *	    S: 2*
     *
     *	    tmp: 4*
     *		- close connection
     *		- clear queue
     *
     *	    perm: *
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    if ( *line == '4' ) {
	hq->hq_status = HOST_DOWN;

	syslog( LOG_NOTICE, "smtp_send %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}

    } else if ( *line != '2' ) {

	syslog( LOG_NOTICE, "smtp_send %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	/* capture error message */
	if (( env->e_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( env->e_err_text, "Bad SMTP DATA_EOF reply" )
		== NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( env->e_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_send: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		hq->hq_status = HOST_DOWN;
		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( env->e_err_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_send: line_append %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_send: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	/* DATA_EOF failed, env->e_err_text is set */
	return( 0 );
    }

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_send: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    return( 0 );
}


    int
smtp_rset( SNET *snet, struct host_q *hq )
{
    char			*line;
    struct timeval		tv;

    syslog( LOG_DEBUG, "smtp_rset starting" );

    /* say RSET */
    if ( snet_writef( snet, "RSET\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_rset %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_rset snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    /* read reply banner */

    tv.tv_sec = SMTP_TIME_RSET;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_rset %s: unexpected EOF", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_rset: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* RSET
     *	    S: 2*
     *
     *	    perm: *
     *		- capture message in struct host_q
     *		- close connection
     *		- bounce queue
     */

    if ( *line != '2' ) {
	hq->hq_status = HOST_BOUNCE;

	syslog( LOG_NOTICE, "smtp_rset %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	/* capture error message */
	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, "Bad SMTP RSET reply" ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	if ( line_append( hq->hq_err_text, line ) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_append %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	while (*(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, &tv )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }

	    if ( smtp_logger != NULL ) {
		(*smtp_logger)( line );
	    }

	    if ( line_append( hq->hq_err_text, line ) == NULL ) {
		syslog( LOG_ERR, "smtp_connect: line_append %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	if ( smtp_quit( snet, hq ) == SMTP_ERROR_SYSCALL ) {
	    return( SMTP_ERR_SYSCALL );
	} else {
	    return( SMTP_ERR_REMOTE );
	}
    }

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv )) == NULL ) {
	    syslog( LOG_NOTICE, "smtp_rset %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_rset: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    return( 0 );
}


    int
smtp_quit( SNET *snet, struct host_q *hq )
{
    char			*line;
    struct timeval		tv;

    syslog( LOG_DEBUG, "smtp_quit starting" );

    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_quit %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_quit snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	syslog( LOG_NOTICE, "smtp_quit: returning" );
	return( SMTP_ERR_REMOTE );
    }

    /* read reply banner */

    tv.tv_sec = SMTP_TIME_QUIT;
    tv.tv_usec = 0;

    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_quit %s: unexpected EOF",
		hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_quit: snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( smtp_logger != NULL ) {
	(*smtp_logger)( line );
    }

    /* QUIT
     *	    S: 2*
     *
     *	    tmp: *
     *		- close connection
     *		- clear queue
     */

    if ( *line != '2' ) {
	hq->hq_status = HOST_DOWN;

	syslog( LOG_NOTICE, "smtp_quit %s: bad SMTP banner: %s",
		hq->hq_hostname, line );

	if ( *(line + 3) == '-' ) {
	    if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		    == NULL ) {
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_quit: snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	return( SMTP_ERR_REMOTE );
    } 

    if ( *(line + 3) == '-' ) {
	if (( line = snet_getline_multi( snet, smtp_logger, &tv ))
		== NULL ) {
	    syslog( LOG_NOTICE, "smtp_quit %s: unexpected EOF",
		    hq->hq_hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "smtp_quit: snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    hq->hq_status = HOST_DOWN;
	    return( SMTP_ERR_REMOTE );
	}
    }

    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_NOTICE, "snet_close: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    return( 0 );
}
