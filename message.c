/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	message.c	**********/

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "envelope.h"
#include "message.h"
#include "receive.h"


    /* create & return a message structure */

    /*
    struct envelope {
	struct envelope	*e_next;
	struct sockaddr_in	*e_sin;
	char		*e_helo;
	char		*e_mail;
	struct recipient	*e_rcpt;
	int			e_flags;
    };
    */

    struct message *
message_create( void )
{
    struct message	*m;
    struct timeval	tv;
    struct sockaddr_in	sin;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	return( NULL );
    }

    m->m_first_line = NULL;
    m->m_last_line = NULL;

    if (( m->m_env = env_create()) == NULL ) {
	return( NULL );
    }

    if ( gethostname( m->m_env->e_hostname, MAXHOSTNAMELEN ) != 0 ) {
	return( NULL );
    }

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	return( NULL );
    }

    sprintf( m->m_env->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec );

    memset( &sin, 0, sizeof( struct sockaddr_in ));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    m->m_env->e_sin = &sin;

    return( m );
}


    /* add a line to the message */

    struct line *
message_line( struct message *m, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( NULL );
    }

    if (( l->line_data = strdup( line )) == NULL ) {
	return( NULL );
    }

    l->line_next = NULL;

    if ( m->m_first_line == NULL ) {
	m->m_first_line = l;
	m->m_last_line = l;
	l->line_prev = NULL;

    } else {
	l->line_prev = m->m_last_line;
	m->m_last_line->line_next = l;
	m->m_last_line = l;
    }

    return( l );
}


    /* prepend a line to the message */

    struct line *
message_prepend_line( struct message *m, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( NULL );
    }

    if (( l->line_data = strdup( line )) == NULL ) {
	return( NULL );
    }

    l->line_next = m->m_first_line;
    l->line_prev = NULL;

    if ( m->m_first_line == NULL ) {
	m->m_first_line = l;
	m->m_last_line = l;

    } else {
	m->m_first_line = l;
    }

    return( l );
}


    /* print a message to stdout for debugging purposes */

    void
message_stdout( struct message *m )
{
    struct line		*l;
    int			x = 0;

    for ( l = m->m_first_line; l != NULL ; l = l->line_next ) {
	x++;
	printf( "%d:\t%s\n", x, l->line_data );
    }
}


    int
message_store( struct message *m )
{
    int			fd;
    time_t		clock;
    struct tm		*tm;
    struct recipient	*r;
    FILE		*dff, *tff;
    char		df[ 25 ];
    char		tf[ 25 ];
    char		ef[ 25 ];
    char		daytime[ 30 ];
    struct line		*l;

    sprintf( df, "tmp/D%s", m->m_env->e_id );
    sprintf( tf, "tmp/t%s", m->m_env->e_id );
    sprintf( ef, "tmp/E%s", m->m_env->e_id );

    if (( fd = open( df, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	fprintf( stderr, "open %s: ", df );
	perror( NULL );
	return( 1 );
    }

    if (( dff = fdopen( fd, "w" )) == NULL ) {
	perror( "fdopen" );
	close( fd );
	goto cleanup;
    }

    if ( time( &clock ) < 0 ) {
	perror( "time" );
	goto cleanup;
    }

    if (( tm = localtime( &clock )) == NULL ) {
	perror( "localtime" );
	goto cleanup;
    }

    if ( strftime( daytime, sizeof( daytime ), "%e %b %Y %T", tm ) == 0 ) {
	perror( "strftime" );
	goto cleanup;
    }

    /* XXX */
    if ( fprintf( dff, "Received: FROM %s ([%s])\n\tBY %s ID %s ;\n\t%s %s\n",
	    "user@localhost",
	    inet_ntoa( m->m_env->e_sin->sin_addr ), m->m_env->e_hostname,
	    m->m_env->e_id, daytime, tz( tm )) < 0 ) {
	perror( "fprintf" );
	fclose( dff );
	goto cleanup;
    }

    for ( l = m->m_first_line; l != NULL; l = l->line_next ) {
	if ( fprintf( dff, "%s\n", l->line_data ) < 0 ) {
	    perror( "fprintf" );
	    goto cleanup;
	}
    }

    if ( fclose( dff ) != 0 ) {
	perror( "fclose" );
	goto cleanup;
    }

    /* make E (t) file */
    if (( fd = open( tf, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	fprintf( stderr, "open %s: ", tf );
	perror( NULL );
	goto cleanup;
    }

    if (( tff = fdopen( fd, "w" )) == NULL ) {
	perror( "fdopen" );
	close( fd );
	goto cleanup2;
    }

    if ( fprintf( tff, "%s\n", m->m_env->e_mail ) < 0 ) {
	perror( "fprintf" );
	fclose( tff );
	goto cleanup2;
    }

    for ( r = m->m_env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( fprintf( tff, "%s\n", r->r_rcpt ) < 0 ) {
	    perror( "fprintf" );
	    fclose( tff );
	    goto cleanup2;
	}
    }

    if ( fclose( tff ) != 0 ) {
	perror( "2fclose" );
	goto cleanup2;
    }

    if ( rename( tf, ef ) < 0 ) {
	perror( "rename" );
	goto cleanup2;
    }

    return( 0 );

cleanup2:
    if ( unlink( tf ) < 0 ) {
	fprintf( stderr, "unlink %s: ", tf );
	perror( NULL );
    }

cleanup:
    if ( unlink( df ) < 0 ) {
	fprintf( stderr, "unlink %s: ", df );
	perror( NULL );
    }
    return( 1 );
}


    int
message_recipient( struct message *m, char *addr )
{
    struct recipient		*r;

    if (( r = (struct recipient*)malloc( sizeof( struct recipient )))
	    == NULL ) {
	return( -1 );
    }

    r->r_rcpt = addr;
    r->r_next = m->m_env->e_rcpt;
    m->m_env->e_rcpt = r;

    return( 0 );
}
