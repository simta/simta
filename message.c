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

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <snet.h>

#include "envelope.h"
#include "message.h"
#include "receive.h"


    /* Add a line to a message data structure  */

    struct line *
data_add_line( struct data *d, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( NULL );
    }
    memset( l, 0, sizeof( struct line ));

    if (( l->line_data = strdup( line )) == NULL ) {
	return( NULL );
    }

    l->line_next = NULL;

    if ( d->d_first_line == NULL ) {
	d->d_first_line = l;
	d->d_last_line = l;
	l->line_prev = NULL;

    } else {
	l->line_prev = d->d_last_line;
	d->d_last_line->line_next = l;
	d->d_last_line = l;
    }

    return( l );
}


    /* prepend a line to the message data */

    struct line *
data_prepend_line( struct data *d, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( NULL );
    }
    memset( l, 0, sizeof( struct line ));

    if (( l->line_data = strdup( line )) == NULL ) {
	return( NULL );
    }

    l->line_next = d->d_first_line;
    l->line_prev = NULL;

    if ( d->d_first_line == NULL ) {
	d->d_first_line = l;
	d->d_last_line = l;

    } else {
	d->d_first_line = l;
    }

    return( l );
}


    /* read a D file from directory "dir" for message "id" */

    struct data *
data_infile( char *dir, char *id )
{
    char			filename[ MAXPATHLEN ];
    char			*line;
    SNET			*snet;
    struct line			*l;
    struct data			*d;

    if (( d = (struct data*)malloc( sizeof( struct data ))) == NULL ) {
	return( NULL );
    }
    memset( d, 0, sizeof( struct data ));

    /* read data file */
    sprintf( filename, "%s/D%s", dir, id );

    if (( snet = snet_open( filename, O_RDONLY, 0, 1024 * 1024 )) == NULL ) {
	return( NULL );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if (( l = data_add_line( d, line )) == NULL ) {
	    return( NULL );
	}
    }

    if ( snet_close( snet ) < 0 ) {
	return( NULL );
    }

    return( d );
}


    /* print data to stdout for debugging purposes */

    void
data_stdout( struct data *d )
{
    struct line		*l;
    int			x = 0;

    for ( l = d->d_first_line; l != NULL ; l = l->line_next ) {
	x++;
	printf( "%d:\t%s\n", x, l->line_data );
    }
}


    /* build a message from E and D files in directory "dir" for message
     * "id".
     */

    struct message *
message_infiles( char *dir, char *id )
{
    struct message		*m;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	return( NULL );
    }
    memset( m, 0, sizeof( struct message ));

    if (( m->m_env = env_infile( dir, id )) == NULL ) {
	return( NULL );
    }

    if (( m->m_data = data_infile( dir, id )) == NULL ) {
	return( NULL );
    }

    return( m );
}


    void
message_stdout( struct message *m )
{
    printf( "ENVELOPE:\n" );
    env_stdout( m->m_env );

    printf( "\nMESSAGE DATA:\n" );
    data_stdout( m->m_data );
}


    /* store message "m" as E and D files in directory "dir" */

    int
message_outfiles( struct message *m, char *dir )
{
    int			fd;
    time_t		clock;
    struct tm		*tm;
    struct recipient	*r;
    FILE		*dff, *tff;
    char		df[ MAXPATHLEN ];
    char		tf[ MAXPATHLEN ];
    char		ef[ MAXPATHLEN ];
    char		daytime[ 30 ];
    struct line		*l;

    sprintf( df, "%s/D%s", dir, m->m_env->e_id );
    sprintf( tf, "%s/t%s", dir, m->m_env->e_id );
    sprintf( ef, "%s/E%s", dir, m->m_env->e_id );

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

    for ( l = m->m_data->d_first_line; l != NULL; l = l->line_next ) {
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


    /* XXX totally wrong */

    struct message *
message_create( char *id )
{
    struct message		*m;
    struct timeval		tv;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	return( NULL );
    }
    memset( m, 0, sizeof( struct message ));

    if (( m->m_data = (struct data*)malloc( sizeof( struct data ))) == NULL ) {
	return( NULL );
    }
    memset( m->m_data, 0, sizeof( struct data ));
	
    if (( m->m_env = env_create()) == NULL ) {
	return( NULL );
    }

    if ( gethostname( m->m_env->e_hostname, MAXHOSTNAMELEN ) != 0 ) {
	return( NULL );
    }

    if ( id == NULL ) {
	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    return( NULL );
	}

	sprintf( m->m_env->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec );
    } else {
	/* XXX OVERFLOW */
	strcpy( m->m_env->e_id, id );
    }

    if (( m->m_env->e_sin = (struct sockaddr_in*)malloc(
	    sizeof( struct sockaddr_in ))) == NULL ) {
	return( NULL );
    }
    memset( m->m_env->e_sin, 0, sizeof( struct sockaddr_in ));

    m->m_env->e_sin->sin_family = AF_INET;
    m->m_env->e_sin->sin_addr.s_addr = INADDR_ANY;

    return( m );
}
