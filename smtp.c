/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.c     *****/

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <netdb.h>
#include <unistd.h>
#include <strings.h>
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

#undef	DNSR_WORKS

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


    /* return 0 if the begenning characters of line match code */
    int
smtp_eval( char *code, char *line )
{
    int			x;

    for ( x = 0; *(code + x) != '\0'; x++ ) {
	if ( *(code + x) != *(line + x) ) {
	    return( 1 );
	}
    }

    return( 0 );
}


    int
smtp_rset( SNET *snet, char *hostname, void (*logger)(char *))
{
    char			*line;

    /* say RSET */
    if ( snet_writef( snet, "RSET\r\n" ) < 0 ) {
	if ( errno != EIO ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	syslog( LOG_NOTICE, "smtp_rset %s: failed writef", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

#ifdef DEBUG
    printf( "--> RSET\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_rset %s: unexpected EOF", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_rset %s: bad banner: %s", hostname, line );

	if ( smtp_quit( snet, hostname, logger ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    return( 0 );
}


    int
smtp_quit( SNET *snet, char *hostname, void (*logger)(char *))
{
    char			*line;

    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	if ( errno != EIO ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	syslog( LOG_NOTICE, "smtp_quit %s: failed writef", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

#ifdef DEBUG
    printf( "--> QUIT\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_quit %s: unexpected EOF", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( smtp_eval( SMTP_DISCONNECT, line ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_quit %s: bad banner: %s", hostname, line );
    }

    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_NOTICE, "snet_close: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    return( 0 );
}


    int
smtp_send( SNET *snet, char *hostname, struct envelope *env, SNET *message,
	void (*logger)(char *))
{
    char		*line;
    struct recipient	*r;

    /* MAIL FROM: */
    if (( env->e_mail == NULL ) || ( *env->e_mail == '\0' )) {
	if ( snet_writef( snet, "MAIL FROM: <>\r\n" ) < 0 ) {
	    if ( errno != EIO ) {
		syslog( LOG_ERR, "snet_writef: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}

#ifdef DEBUG
    printf( "--> MAIL FROM: <>\n" );
#endif /* DEBUG */

    } else {
	if ( snet_writef( snet, "MAIL FROM: <%s>\r\n", env->e_mail ) < 0 ) {
	    if ( errno != EIO ) {
		syslog( LOG_ERR, "snet_writef: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}

#ifdef DEBUG
    printf( "--> MAIL FROM: <%s>\n", env->e_mail );
#endif /* DEBUG */
    }

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	if ( smtp_eval( SMTP_FAILED_FROM, line ) == 0 ) {
	    return( SMTP_ERR_BOUNCE_MESSAGE );

	} else {
	    syslog( LOG_NOTICE, "smtp_send %s: bad banner: %s", hostname,
		    line );

	    if ( smtp_quit( snet, hostname, logger ) < 0 ) {
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}
    }

    /* RCPT TO: */
    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: %s\r\n", r->r_rcpt ) < 0 ) {
	    if ( errno != EIO ) {
		syslog( LOG_ERR, "snet_writef: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}

#ifdef DEBUG
    printf( "--> RCPT TO: %s\n", r->r_rcpt );
#endif /* DEBUG */

	/* read reply banner */
	if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	    syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}

	if ( smtp_eval( SMTP_OK, line ) == 0 ) {
	    r->r_delivered = R_DELIVERED;
	    env->e_success++;

	} else if ( smtp_eval( SMTP_USER_UNKNOWN, line ) == 0 ) {
	    r->r_delivered = R_FAILED;
	    env->e_failed++;

	} else if ( smtp_eval( SMTP_TEMPFAIL, line ) == 0 ) {
	    if ( env->e_old_dfile != 0 ) {
		r->r_delivered = R_FAILED;
		env->e_failed++;

	    } else {
		r->r_delivered = R_TEMPFAIL;
		env->e_tempfail++;
	    }

	} else {
	    syslog( LOG_NOTICE, "host %s: bad banner: %s", env->e_expanded,
		    line );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}

	if ( r->r_delivered == R_FAILED ) {
	    if (( r->r_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "line_file_create: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    if ( line_append( r->r_text, line ) == NULL ) {
		syslog( LOG_ERR, "line_append: %m" );
		return( SMTP_ERR_SYSCALL );
	    }
	}

	while ( *(line + 3) == '-' ) {
	    /* read reply banner */
	    if (( line = snet_getline( snet, NULL )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_NO_BOUNCE );
	    }

	    if ( r->r_delivered == R_FAILED ) {
		if ( line_append( r->r_text, line ) == NULL ) {
		    syslog( LOG_ERR, "line_append: %m" );
		    return( SMTP_ERR_SYSCALL );
		}
	    }

	    if ( logger != NULL ) {
		(*logger)( line );
	    }
	}
    }

    if ( env->e_success == 0 ) {
	/* no one to send message to */
	return( 0 );
    }

    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	if ( errno != EIO ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

#ifdef DEBUG
    printf( "--> DATA\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( smtp_eval( SMTP_DATAOK, line ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_send %s: bad banner: %s", hostname, line );

	if ( smtp_quit( snet, hostname, logger ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    /* send message */
    while (( line = snet_getline( message, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", line ) < 0 ) {
		if ( errno != EIO ) {
		    syslog( LOG_ERR, "snet_writef: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_NO_BOUNCE );
	    }

#ifdef DEBUG
	    printf( "--> .%s\n", line );
#endif /* DEBUG */

	} else {
	    if ( snet_writef( snet, "%s\r\n", line ) < 0 ) {
		if ( errno != EIO ) {
		    syslog( LOG_ERR, "snet_writef: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_NO_BOUNCE );
	    }

#ifdef DEBUG
	    printf( "--> %s\n", line );
#endif /* DEBUG */

	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	if ( errno != EIO ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	syslog( LOG_NOTICE, "smtp_send %s: failed writef", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

#ifdef DEBUG
    printf( "--> .\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_send %s: unexpected EOF", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	/* XXX check for message failure */

	syslog( LOG_NOTICE, "smtp_send %s: bad banner: %s", hostname, line );

	if ( smtp_quit( snet, hostname, logger ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    return( 0 );
}


    int
smtp_connect( SNET **snetp, struct host_q *hq )
{
    SNET			*snet;
    char			*line;
    char			*local_host;
    char			*remote_host;
    char			*c;
    struct sockaddr_in		sin;
    int				s;
    struct timeval		tv;
#ifdef DNSR_WORKS
    int				i;
    DNSR			*dnsr;
#else /* DNSR_WORKS */
    struct hostent		*hp;
#endif /* DNSR_WORKS */

#ifdef DNSR_WORKS

    if (( dnsr = dnsr_open( )) == NULL ) {
	syslog( LOG_ERR, "smtp_connect: dnsr_open failed" );
	return( SMTP_ERR_SYSCALL );
    }

    /* Try to get MX */
    if (( dnsr_query( dnsr, DNSR_TYPE_MX, DNSR_CLASS_IN,
	    hq->hq_hostname )) < 0 ) {
        syslog( LOG_ERR, "smtp_connect: dnsr_query %s failed",
		hq->hq_hostname );
	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    if ( dnsr_result( dnsr, NULL ) != 0 ) {

        /* No MX - Try to get A */
        if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN,
		hq->hq_hostname )) < 0 ) {    
            syslog( LOG_ERR, "smtp_connect: dnsr_query %s failed",
		    hq->hq_hostname );
	    hq->hq_status = HOST_DOWN;
            return( SMTP_ERR_REMOTE );
        }       
        if ( dnsr_result( dnsr, NULL ) != 0 ) {
            syslog( LOG_ERR, "smtp_connect: dnsr_query %s failed",
		    hq->hq_hostname );
	    hq->hq_status = HOST_DOWN;
            return( SMTP_ERR_REMOTE );
        }

	/* Got an A record */
	memcpy( &(sin.sin_addr.s_addr),
		&(dnsr->d_result->answer[ 0 ].r_a.address), sizeof( int ));
    } else {

	/* Got an MX record */
        /* Check for valid A record in MX */
        /* XXX - Should we search for A if no A returned in MX? */
        for ( i = 0; i < dnsr->d_result->ancount; i++ ) {
            if ( dnsr->d_result->answer[ i ].r_ip != NULL ) {
                break;
            }
        }
        if ( i > dnsr->d_result->ancount ) {
            syslog( LOG_ERR, "smtp_connect: %s: no valid A record for MX",
		    hq->hq_hostname );
	    hq->hq_status = HOST_DOWN;
            return( SMTP_ERR_REMOTE );
        }

#ifdef DEBUG
	if ( dnsr->d_result->answer[ i ].r_ip == NULL ) {
	    printf( "dnsr is broke\n" );
	}
#endif /* DEBUG */

	memcpy( &(sin.sin_addr.s_addr),
		&(dnsr->d_result->answer[ i ].r_ip->ip ),
		sizeof( struct in_addr ));
    }

#else /* DNSR_WORKS */

    if (( hp = gethostbyname( hq->hq_hostname )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect: gethostbyname %s: %s",
		hq->hq_hostname, hstrerror( h_errno ));
	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

    memcpy( &(sin.sin_addr.s_addr), hp->h_addr_list[ 0 ],
	    (unsigned int)hp->h_length );

#endif /* DNSR_WORKS */

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "smtp_connect: socket: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons( SIMTA_SMTP_PORT );

    if ( connect( s, (struct sockaddr*)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "smtp_connect: connect: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "smtp_connect: snet_attach: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    *snetp = snet;

    if (( local_host = simta_gethostname()) == NULL ) {
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
     *	    E: 4*: tmp failure
     *		- close connection
     *		- clear queue
     *
     *	    E: 5*, *, detect mail loop: perm failure
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

	if ( _smtp_quit( snet, hq ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_REMOTE );

    } else if ( *line != '2' ) {
	hq->hq_status = HOST_BOUNCE;

	/* capture error message */
	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
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

	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner, "
		"expecting remote hostname: %s", hq->hq_hostname, line );

	if ( _smtp_quit( snet, hq ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_REMOTE );
    }

    c = remote_host;

    while (( *c != ' ' ) && ( *c != '\t' )) {
	c++;
    }

    /* mail loop detection: check if remote hostname matches local hostname */

    if ( strncasecmp( local_host, remote_host,
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
	    if (( line = snet_getline( snet, NULL )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hq->hq_hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "smtp_connect snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( _smtp_quit( snet, hq ) < 0 ) {
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

    /* CONNECT END */

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", local_host ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_connect %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_connect snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

#ifdef DEBUG
    printf( "--> HELO %s\n", local_host );
#endif /* DEBUG */

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
     *	    E: 4*: tmp system failure
     *		- close connection
     *		- clear queue
     *
     *	    E: *, 5*: tmp system failure
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

		hq->hq_status = HOST_DOWN;
		return( SMTP_ERR_REMOTE );
	    }
	}

	if ( _smtp_quit( snet, hq ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_REMOTE );

    } else if ( *line != '2' ) {
	hq->hq_status = HOST_BOUNCE;

	/* capture error message */
	if (( hq->hq_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "smtp_connect: line_file_create %m" );
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

    return( 0 );
}


    int
_smtp_send ( SNET *snet, struct host_q *hq, struct envelope *env,
	SNET *snet_dfile )
{

    /* MAIL
     *	    S: 2*
     *
     *	    E: 4*: tmp system failure
     *		- close connection
     *		- clear queue
     *
     *	    E: *, 5*: perm address failure
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    /* RCPT
     *	    S: 2* (but see section 3.4 for discussion of 251 and 551)
     *
     *	    E: 552, 4* : tmp system failure
     *		- if old dfile, capture error text in struct rcpt
     *		- if old dfile, bounce current rcpt in struct rcpt
     *		- try next rcpt
     *
     *	    E: 5*, *: perm address failure
     *		- capture error text in struct rcpt
     *		- bounce current rcpt
     *		- try next rcpt
     */

    /* DATA
     *	    S: 3*
     *
     *	    E: 4*: tmp system failure
     *		- close connection
     *		- clear queue
     *
     *	    E: 5*, *: perm system failure
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    /* DATA_EOF
     *	    S: 2*
     *
     *	    E: 4*: tmp system failure
     *		- close connection
     *		- clear queue
     *
     *	    E: 5*, *: perm system failure
     *		- capture error text in struct envelope
     *		- bounce current mesage
     *		- try next message
     */

    return( 0 );
}


    int
_smtp_rset ( SNET *snet, struct host_q *hq )
{
    /* RSET
     *	    S: 2*
     *
     *	    E: *: perm system failure
     *		- capture message in struct host_q
     *		- close connection
     *		- bounce queue
     */

    return( 0 );
}


    int
_smtp_quit ( SNET *snet, struct host_q *hq )
{
    char			*line;
    struct timeval		tv;

    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_NOTICE, "smtp_quit %s: failed writef", hq->hq_hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "smtp_quit snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	hq->hq_status = HOST_DOWN;
	return( SMTP_ERR_REMOTE );
    }

#ifdef DEBUG
    printf( "--> QUIT\n" );
#endif /* DEBUG */

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
     *	    E: *: tmp system failure
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
