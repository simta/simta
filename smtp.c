/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.c     *****/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
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

#include "message.h"
#include "envelope.h"
#include "smtp.h"


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
smtp_send_message( SNET *snet, struct message *m, void (*logger)(char *))
{
    char		*line;
    struct recipient	*r;
    struct line		*l;

    /* MAIL FROM: */
    if ( snet_writef( snet, "MAIL FROM: %s\r\n", m->m_env->e_mail ) < 0 ) {
	return( 1 );
    }

#ifdef DEBUG
    printf( "--> MAIL FROM: %s\n", m->m_env->e_mail );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	return( 1 );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	return( 1 );
    }

    /* RCPT TO: */
    for ( r = m->m_env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: <%s>\r\n", r->r_rcpt ) < 0 ) {
	    return( 1 );
	}

#ifdef DEBUG
    printf( "--> RCPT TO: <%s>\n", r->r_rcpt );
#endif /* DEBUG */

	if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	    return( 1 );
	}


	if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	    return( 1 );
	}
    }

    /* DATA */
    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	return( 1 );
    }

#ifdef DEBUG
    printf( "--> DATA\n" );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	return( 1 );
    }

    if ( smtp_eval( SMTP_DATAOK, line ) != 0 ) {
	return( 1 );
    }

    /* send message */
    for ( l = m->m_data->md_first; l != NULL; l = l->line_next ) {
	if ( *l->line_data == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", l->line_data ) < 0 ) {
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "--> .%s\n", l->line_data );
#endif /* DEBUG */

	} else {
	    if ( snet_writef( snet, "%s\r\n", l->line_data ) < 0 ) {
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "--> %s\n", l->line_data );
#endif /* DEBUG */

	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	return( 1 );
    }

#ifdef DEBUG
    printf( "--> .\n" );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	return( 1 );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    /* return pointer on success
     * return NULL on failure
     *
     * syslog errors
     */

    SNET *
smtp_connect( char *hostname, int port )
{
    struct hostent		*hp;
    struct sockaddr_in		sin;
    int				s;
    SNET			*snet;

    if (( hp = gethostbyname( hostname )) == NULL ) {
	syslog( LOG_ERR, "gethostbyname %s: %m", hostname );
	return( NULL );
    }

    memcpy( &(sin.sin_addr.s_addr), hp->h_addr_list[ 0 ],
	    (unsigned int)hp->h_length );

    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
	syslog( LOG_ERR, "socket: %m" );
	return( NULL );
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons( port );

    if ( connect( s, (struct sockaddr*)&sin,
	    sizeof( struct sockaddr_in )) < 0 ) {
	syslog( LOG_ERR, "connect: %m" );
	return( NULL );
    }

    if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	return( NULL );
    }

    return( snet );
}


    /* return 0 on success
     * return -1 on syscall failure
     * return 1 on recoverable error
     *
     * syslog errors
     */

    int
smtp_helo( SNET *snet, void (*logger)(char *))
{
    char			*line;
    char			local_host[ MAXHOSTNAMELEN ];
    char			*remote_host;
    char			*i;

    if ( gethostname( local_host, MAXHOSTNAMELEN ) != 0 ) {
	syslog( LOG_ERR, "gethostname: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    /* read connect banner */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "gethostname: %m" );
	return( SMTP_ERR_SYNTAX );
    }

    if ( logger != NULL ) {
	(*logger)( line );
    }

    if ( smtp_eval( SMTP_CONNECT, line ) != 0 ) {
	return( SMTP_ERR_SYNTAX );
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
	return( SMTP_ERR_SYNTAX );
    }

    i = remote_host;

    while (( *i != ' ' ) && ( *i != '\t' )) {
	i++;
    }

    /* check to see if remote smtp server is actually the local machine */
    if ( strncasecmp( local_host, remote_host, (int)(i - remote_host) ) == 0 ) {
	while ( *(line + 3) == '-' ) {
	    if (( line = snet_getline( snet, NULL )) == NULL ) {
		syslog( LOG_ERR, "snet_getline: %m" );
		return( SMTP_ERR_SYNTAX );
	    }

	    if ( logger != NULL ) {
		(*logger)( line );
	    }
	}

	if ( smtp_quit( snet, logger ) < 0 ) {
	    exit( 1 );
	}

	return( SMTP_ERR_MAIL_LOOP );
    }

    while ( *(line + 3) == '-' ) {
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR, "snet_getline: %m" );
	    return( SMTP_ERR_SYNTAX );
	}

	if ( logger != NULL ) {
	    (*logger)( line );
	}
    }

    /* say HELO */
    if ( snet_writef( snet, "HELO %s\r\n", local_host ) < 0 ) {
	return( SMTP_ERR_SYSCALL );
    }

#ifdef DEBUG
    printf( "--> HELO %s\n", local_host );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	return( SMTP_ERR_SYSCALL );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	return( SMTP_ERR_SYNTAX );
    }

    return( 0 );
}


    int
smtp_rset( SNET *snet, void (*logger)(char *))
{
    char			*line;

    /* say RSET */
    if ( snet_writef( snet, "RSET\r\n" ) < 0 ) {
	syslog( LOG_ERR, "smtp_rset: snet_writef: %m" );
	return( SMTP_ERR_SYSCALL );
    }

#ifdef DEBUG
    printf( "--> RSET\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_ERR, "smtp_rset: snet_getline_multi: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    /* XXX only catching last line of smtp error banner */
    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_rset: bad reply: %s", line );
	return( SMTP_ERR_SYNTAX );
    }

    return( 0 );
}


    /* return 0 on success
     * return 1 on syntax error
     * return -1 on syscall error
     *
     * syslog errors
     */

    int
smtp_quit( SNET *snet, void (*logger)(char *))
{
    char			*line;

    /* say QUIT */
    if ( snet_writef( snet, "QUIT\r\n" ) < 0 ) {
	syslog( LOG_ERR, "smtp_quit snet_writef: %m" );
	return( SMTP_ERR_SYSCALL );
    }

#ifdef DEBUG
    printf( "--> QUIT\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_ERR, "smtp_quit snet_getline_multi: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    /* XXX only preserving last line of banner error message */
    if ( smtp_eval( SMTP_DISCONNECT, line ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_quit bad banner: %s", line );
	return( SMTP_ERR_SYNTAX );
    }

    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_NOTICE, "smtp_quit snet_close: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    return( 0 );
}


    int
smtp_send_single_message( char *hostname, int port, struct message *m,
	void (*logger)(char *))
{
    SNET			*snet;
    int				r;

    if (( snet = smtp_connect( hostname, port )) == NULL ) {
	return( 1 );
    }

    if (( r = smtp_helo( snet, logger )) != 0 ) {
	return( 1 );
    }

    if ( smtp_send_message( snet, m, logger ) != 0 ) {
	return( 1 );
    }

    if ( smtp_quit( snet, logger ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    /* return 0 on success
     * return -1 on syscall failure
     * return 1 on recoverable error
     *
     * syslog errors
     * envelope struct tracks success/failures for each recipient
     */

    int
smtp_send( SNET *snet, struct envelope *env, SNET *message,
	void (*logger)(char *))
{
    char		*line;
    struct recipient	*r;

    /* MAIL FROM: */
    if (( env->e_mail == NULL ) || ( *env->e_mail == '\0' )) {
	if ( snet_writef( snet, "MAIL FROM: <>\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

#ifdef DEBUG
    printf( "--> MAIL FROM: <>\n" );
#endif /* DEBUG */

    } else {
	if ( snet_writef( snet, "MAIL FROM: <%s>\r\n", env->e_mail ) < 0 ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

#ifdef DEBUG
    printf( "--> MAIL FROM: <%s>\n", env->e_mail );
#endif /* DEBUG */
    }

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_ERR, "snet_getline_multi: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded, line );
	return( SMTP_ERR_SYNTAX );
    }

    env->e_failed = 0;
    env->e_tempfail = 0;
    env->e_success = 0;

    /* RCPT TO: */
    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: %s\r\n", r->r_rcpt ) < 0 ) {
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( SMTP_ERR_SYSCALL );
	}

#ifdef DEBUG
    printf( "--> RCPT TO: %s\n", r->r_rcpt );
#endif /* DEBUG */

	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_NOTICE, "host %s: no banner", env->e_expanded );
	    return( SMTP_ERR_SYNTAX );
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
	    return( SMTP_ERR_SYNTAX );
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
	    if (( line = snet_getline( snet, NULL )) == NULL ) {
		syslog( LOG_NOTICE, "host %s: no banner", env->e_expanded );
		return( SMTP_ERR_SYNTAX );
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

    /* DATA */
    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	syslog( LOG_ERR, "snet_writef: %m" );
	return( SMTP_ERR_SYSCALL );
    }

#ifdef DEBUG
    printf( "--> DATA\n" );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_ERR, "snet_getline_multi: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    if ( smtp_eval( SMTP_DATAOK, line ) != 0 ) {
	syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded, line );
	return( SMTP_ERR_SYNTAX );
    }

    /* send message */
    while (( line = snet_getline( message, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", line ) < 0 ) {
		syslog( LOG_ERR, "snet_writef: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

#ifdef DEBUG
	    printf( "--> .%s\n", line );
#endif /* DEBUG */

	} else {
	    if ( snet_writef( snet, "%s\r\n", line ) < 0 ) {
		syslog( LOG_ERR, "snet_writef: %m" );
		return( SMTP_ERR_SYSCALL );
	    }

#ifdef DEBUG
	    printf( "--> %s\n", line );
#endif /* DEBUG */

	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	syslog( LOG_ERR, "snet_writef: %m" );
	return( SMTP_ERR_SYSCALL );
    }

#ifdef DEBUG
    printf( "--> .\n" );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	syslog( LOG_ERR, "snet_getline_multi: %m" );
	return( SMTP_ERR_SYSCALL );
    }

    if ( smtp_eval( SMTP_OK, line ) != 0 ) {
	syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded, line );
	return( SMTP_ERR_SYNTAX );
    }

    return( 0 );
}
