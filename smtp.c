/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.c     *****/

#include <sys/param.h>
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

#define	DNSR_WORKS


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
smtp_connect( SNET **snetp, char *hostname, int port, void (*logger)(char *))
{
    SNET			*snet;
    char			*line;
    char			*local_host;
    char			*remote_host;
    char			*c;
    struct sockaddr_in		sin;
    int				s;
#ifdef DNSR_WORKS
    int				i;
    DNSR			*dnsr;
#else /* DNSR_WORKS */
    struct hostent		*hp;
#endif /* DNSR_WORKS */

#ifdef DNSR_WORKS
    if (( dnsr = dnsr_open( )) == NULL ) {
	syslog( LOG_ERR, "dnsr_open failed" );
	return( SMTP_ERR_SYSCALL );
    }

    /* Try to get MX */
    if (( dnsr_query( dnsr, DNSR_TYPE_MX, DNSR_CLASS_IN, hostname )) < 0 ) {
        syslog( LOG_ERR, "dnsr_query %s failed", hostname );
	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( dnsr_result( dnsr, NULL ) != 0 ) {

        /* No MX - Try to get A */
        if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN,
		hostname )) < 0 ) {    
            syslog( LOG_ERR, "dnsr_query %s failed", hostname );
            return( SMTP_ERR_NO_BOUNCE );
        }       
        if ( dnsr_result( dnsr, NULL ) != 0 ) {
            syslog( LOG_ERR, "dnsr_query %s failed", hostname );
            return( SMTP_ERR_NO_BOUNCE );
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
            syslog( LOG_ERR, "%s: no valid A record for MX", hostname );
            return( SMTP_ERR_NO_BOUNCE );
        }

#ifdef DEBUG
if ( dnsr->d_result->answer[ i ].r_ip == NULL ) {
    printf( "dnsr is broke\n" );
}
#endif /* DEBUG */

	memcpy( &(sin.sin_addr.s_addr),
		&(dnsr->d_result->answer[ i ].r_ip->ip ), sizeof( struct in_addr ));
    }

#else /* DNSR_WORKS */
    if (( hp = gethostbyname( hostname )) == NULL ) {
	if (( h_errno == HOST_NOT_FOUND ) || ( h_errno == TRY_AGAIN ) ||
		( h_errno == NO_DATA )) {
	    syslog( LOG_NOTICE, "gethostbyname %s: %m", hostname );
	    return( SMTP_ERR_NO_BOUNCE );

	} else {
	    syslog( LOG_ERR, "gethostbyname %s: %m", hostname );
	    return( SMTP_ERR_SYSCALL );
	}
    }

    memcpy( &(sin.sin_addr.s_addr), hp->h_addr_list[ 0 ],
	    (unsigned int)hp->h_length );
#endif /* DNSR_WORKS */

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "socket: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons( port );

    if ( connect( s, (struct sockaddr*)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "connect: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    *snetp = snet;

    if (( local_host = simta_gethostname()) == NULL ) {
	return( SMTP_ERR_SYSCALL );
    }

    /* read connect banner */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect: unexpected EOF" );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( logger != NULL ) {
	(*logger)( line );
    }

    if ( smtp_eval( SMTP_CONNECT, line ) != 0 ) {
	if ( smtp_eval( SMTP_FAILED, line ) == 0 ) {
	    syslog( LOG_NOTICE, "smtp_connect %s: no SMTP server: %s", hostname,
		    line );

	    if ( smtp_quit( snet, hostname, logger ) < 0 ) {
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_BOUNCE_Q );

	} else {
	    syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner: %s",
		    hostname, line );

	    if ( smtp_quit( snet, hostname, logger ) < 0 ) {
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}
    }

    remote_host = line + 3;

    if ( *remote_host == '-' ) {
	remote_host++;
    }

    while (( *remote_host == ' ' ) || ( *remote_host == '\t' )) {
	remote_host++;
    }

    /* check for remote hostname existance */
    if ( *remote_host == '\0' ) {
	syslog( LOG_NOTICE, "smtp_connect %s: bad SMTP banner, "
		"expecting remote hostname: %s", hostname, line );

	if ( smtp_quit( snet, hostname, logger ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    c = remote_host;

    while (( *c != ' ' ) && ( *c != '\t' )) {
	c++;
    }

    /* check to see if remote smtp server is actually the local machine */
    if ( strncasecmp( local_host, remote_host,
	    (size_t)(c - remote_host) ) == 0 ) {
	while ( *(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, NULL )) == NULL ) {
		syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF",
			hostname );

		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( SMTP_ERR_SYSCALL );
		}

		return( SMTP_ERR_NO_BOUNCE );
	    }

	    if ( logger != NULL ) {
		(*logger)( line );
	    }
	}

	syslog( LOG_WARNING, "smtp_connect %s: mail loop", hostname );

	if ( smtp_quit( snet, hostname, logger ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_BOUNCE_Q );
    }

    while ( *(line + 3) == '-' ) {
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF", hostname );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

	    return( SMTP_ERR_NO_BOUNCE );
	}

	if ( logger != NULL ) {
	    (*logger)( line );
	}
    }

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", local_host ) < 0 ) {
	if ( errno != EIO ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	syslog( LOG_NOTICE, "smtp_connect %s: failed writef", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

#ifdef DEBUG
    printf( "--> HELO %s\n", local_host );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_NOTICE, "smtp_connect %s: unexpected EOF", hostname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_connect %s: bad banner: %s", hostname, line );

	if ( smtp_quit( snet, hostname, logger ) < 0 ) {
	    return( SMTP_ERR_SYSCALL );
	}

	return( SMTP_ERR_NO_BOUNCE );
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

	if ( logger != NULL ) {
	    (*logger)( line );
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
