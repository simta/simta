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

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
	return( 1 );
    }

    /* RCPT TO: */
    for ( r = m->m_env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: %s\r\n", r->r_rcpt ) < 0 ) {
	    return( 1 );
	}

#ifdef DEBUG
    printf( "--> RCPT TO: %s\n", r->r_rcpt );
#endif /* DEBUG */

	if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	    return( 1 );
	}

	if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
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

    if ( strncmp( line, SMTP_DATAOK, 3 ) != 0 ) {
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

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
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

    /* ZZZ working here */
    if ( strncmp( line, SMTP_CONNECT, 3 ) != 0 ) {
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
	/* XXX gracefully close the connection? */
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

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
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
	return( 1 );
    }

#ifdef DEBUG
    printf( "--> RSET\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	return( 1 );
    }

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
	return( 1 );
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
	return( SMTP_ERR_SYSCALL );
    }

#ifdef DEBUG
    printf( "--> QUIT\n" );
#endif /* DEBUG */

    /* read reply banner */
    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	return( SMTP_ERR_SYSCALL );
    }

    if ( strncmp( line, SMTP_DISCONNECT, 3 ) != 0 ) {
	return( SMTP_ERR_SYNTAX );
    }

    if ( snet_close( snet ) != 0 ) {
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
     */

    int
smtp_send( SNET *snet, struct envelope *env, SNET *message,
	void (*logger)(char *))
{
    char		*line;
    struct recipient	*r;

    /* MAIL FROM: */
    if ( snet_writef( snet, "MAIL FROM: %s\r\n", env->e_mail ) < 0 ) {
	/* XXX correct error handling? */
	syslog( LOG_ERR, "snet_writef: %m" );
	return( -1 );
    }

#ifdef DEBUG
    printf( "--> MAIL FROM: %s\n", env->e_mail );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	/* XXX correct error handling? */
	syslog( LOG_ERR, "snet_getline_multi: %m" );
	return( -1 );
    }

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
	syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded, line );
	return( 1 );
    }

    /* RCPT TO: */
    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( snet_writef( snet, "RCPT TO: %s\r\n", r->r_rcpt ) < 0 ) {
	    /* XXX correct error handling? */
	    syslog( LOG_ERR, "snet_writef: %m" );
	    return( -1 );
	}

#ifdef DEBUG
    printf( "--> RCPT TO: %s\n", r->r_rcpt );
#endif /* DEBUG */

	if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	    /* XXX correct error handling? */
	    syslog( LOG_ERR, "snet_getline_multi: %m" );
	    return( -1 );
	}

	if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
	    syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded,
		    line );
	    return( 1 );
	}
    }

    /* DATA */
    if ( snet_writef( snet, "DATA\r\n" ) < 0 ) {
	/* XXX correct error handling? */
	syslog( LOG_ERR, "snet_writef: %m" );
	return( -1 );
    }

#ifdef DEBUG
    printf( "--> DATA\n" );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	/* XXX correct error handling? */
	syslog( LOG_ERR, "snet_getline_multi: %m" );
	return( -1 );
    }

    if ( strncmp( line, SMTP_DATAOK, 3 ) != 0 ) {
	syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded, line );
	return( 1 );
    }

    /* send message */
    while (( line = snet_getline( message, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    /* don't send EOF */
	    if ( snet_writef( snet, ".%s\r\n", line ) < 0 ) {
		/* XXX correct error handling? */
		syslog( LOG_ERR, "snet_writef: %m" );
		return( -1 );
	    }

#ifdef DEBUG
	    printf( "--> .%s\n", line );
#endif /* DEBUG */

	} else {
	    if ( snet_writef( snet, "%s\r\n", line ) < 0 ) {
		/* XXX correct error handling? */
		syslog( LOG_ERR, "snet_writef: %m" );
		return( -1 );
	    }

#ifdef DEBUG
	    printf( "--> %s\n", line );
#endif /* DEBUG */

	}
    }

    if ( snet_writef( snet, "%s\r\n", SMTP_EOF ) < 0 ) {
	/* XXX correct error handling? */
	syslog( LOG_ERR, "snet_writef: %m" );
	return( -1 );
    }

#ifdef DEBUG
    printf( "--> .\n" );
#endif /* DEBUG */

    if (( line = snet_getline_multi( snet, logger, NULL )) == NULL ) {
	/* XXX correct error handling? */
	syslog( LOG_ERR, "snet_getline_multi: %m" );
	return( -1 );
    }

    if ( strncmp( line, SMTP_OK, 3 ) != 0 ) {
	syslog( LOG_NOTICE, "host %s bad banner: %s", env->e_expanded, line );
	return( 1 );
    }

    return( 0 );
}
