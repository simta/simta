/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	message.c	**********/

#include <sys/param.h>
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


    /* return a line_file */

    struct line_file *
line_file_create( void )
{
    struct line_file		*lf;

    if (( lf = (struct line_file*)malloc( sizeof( struct line_file )))
	    == NULL ) {
	return( NULL );
    }
    memset( lf, 0, sizeof( struct message_data ));

    return( lf );
}


    /* append a line to a line_file structure  */

    struct line *
line_append( struct line_file *lf, char *line )
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

    if ( lf->l_first == NULL ) {
	lf->l_first = l;
	lf->l_last = l;
	l->line_prev = NULL;

    } else {
	l->line_prev = lf->l_last;
	lf->l_last->line_next = l;
	lf->l_last = l;
    }

    return( l );
}


    /* prepend a line to a line_file structure  */

    struct line *
line_prepend( struct line_file *lf, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( NULL );
    }
    memset( l, 0, sizeof( struct line ));

    if (( l->line_data = strdup( line )) == NULL ) {
	return( NULL );
    }

    l->line_prev = NULL;

    if ( lf->l_first == NULL ) {
	lf->l_first = l;
	lf->l_last = l;
	l->line_next = NULL;

    } else {
	l->line_next = lf->l_first;
	lf->l_first->line_prev = l;
	lf->l_first = l;
    }

    return( l );
}


    /* Add a line to a message data structure  */

    struct line *
data_add_line( struct message_data *d, char *line )
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

    if ( d->md_first == NULL ) {
	d->md_first = l;
	d->md_last = l;
	l->line_prev = NULL;

    } else {
	l->line_prev = d->md_last;
	d->md_last->line_next = l;
	d->md_last = l;
    }

    return( l );
}


    /* prepend a line to the message data */

    struct line *
data_prepend_line( struct message_data *d, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( NULL );
    }
    memset( l, 0, sizeof( struct line ));

    if (( l->line_data = strdup( line )) == NULL ) {
	return( NULL );
    }

    l->line_next = d->md_first;
    l->line_prev = NULL;

    if ( d->md_first == NULL ) {
	d->md_first = l;
	d->md_last = l;

    } else {
	d->md_first = l;
    }

    return( l );
}


    /* read a D file from directory "dir" for message "id" */

    struct message_data *
data_infile( char *dir, char *id )
{
    char			filename[ MAXPATHLEN ];
    char			*line;
    SNET			*snet;
    struct line			*l;
    struct message_data		*d;

    if (( d = (struct message_data*)malloc( sizeof( struct message_data )))
	    == NULL ) {
	return( NULL );
    }
    memset( d, 0, sizeof( struct message_data ));

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
data_stdout( struct message_data *d )
{
    struct line		*l;
    int			x = 0;

    for ( l = d->md_first; l != NULL ; l = l->line_next ) {
	x++;
	printf( "%d:\t%s\n", x, l->line_data );
    }
}


    /* build a message from E and D files in directory "dir" for message
     * "id".
     */

    /* XXX rewrite API */
    struct message *
message_infiles( char *dir, char *id )
{
    struct message		*m;
    int				result;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	return( NULL );
    }
    memset( m, 0, sizeof( struct message ));

    if (( m->m_env = env_create( id )) == NULL ) {
	return( NULL );
    }

    if (( result = env_infile( m->m_env, dir )) < 0 ) {
	/* syserror */
	return( NULL );
    } else if ( result > 0 ) {
	/* syntax error */
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
    if ( m->m_env != NULL ) {
	env_stdout( m->m_env );
    } else {
	printf( "ENVELOPE:\tNULL\n" );
    }

    if (( m->m_data != NULL ) && ( m->m_data->md_first != NULL )) {
	printf( "MESSAGE DATA:\n" );
	data_stdout( m->m_data );
    } else {
	printf( "MESSAGE DATA:\tNULL\n" );
    }
}


    /* store message "m" as E and D files in directory "dir" */

    int
message_outfiles( struct message *m, char *dir )
{
    int			fd;
    time_t		clock;
    struct tm		*tm;
    FILE		*dff;
    char		df[ MAXPATHLEN ];
    char		daytime[ 30 ];
    struct line		*l;

    sprintf( df, "%s/D%s", dir, m->m_env->e_id );

    if (( fd = open( df, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	return( 1 );
    }

    if (( dff = fdopen( fd, "w" )) == NULL ) {
	close( fd );
	goto cleanup;
    }

    if ( time( &clock ) < 0 ) {
	fclose( dff );
	goto cleanup;
    }

    if (( tm = localtime( &clock )) == NULL ) {
	fclose( dff );
	goto cleanup;
    }

    if ( strftime( daytime, sizeof( daytime ), "%e %b %Y %T", tm ) == 0 ) {
	fclose( dff );
	goto cleanup;
    }

    /* XXX */
    if ( fprintf( dff, "Received: FROM %s ([%s])\n\tBY %s ID %s ;\n\t%s %s\n",
	    "user@localhost",
	    inet_ntoa( m->m_env->e_sin->sin_addr ), m->m_env->e_hostname,
	    m->m_env->e_id, daytime, tz( tm )) < 0 ) {
	fclose( dff );
	goto cleanup;
    }

    for ( l = m->m_data->md_first; l != NULL; l = l->line_next ) {
	if ( fprintf( dff, "%s\n", l->line_data ) < 0 ) {
	    fclose( dff );
	    goto cleanup;
	}
    }

    if ( fclose( dff ) != 0 ) {
	goto cleanup;
    }

    if ( env_outfile( m->m_env, dir ) != 0 ) {
	goto cleanup;
    }

    return( 0 );

cleanup:
    unlink( df );

    return( 1 );
}


    /* XXX totally wrong */

    struct message *
message_create( char *id )
{
    struct message		*m;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	return( NULL );
    }
    memset( m, 0, sizeof( struct message ));

    if (( m->m_data = (struct message_data*)malloc(
	    sizeof( struct message_data ))) == NULL ) {
	return( NULL );
    }
    memset( m->m_data, 0, sizeof( struct message_data ));
	
    if (( m->m_env = env_create( id )) == NULL ) {
	return( NULL );
    }

    if ( gethostname( m->m_env->e_hostname, MAXHOSTNAMELEN ) != 0 ) {
	return( NULL );
    }

    if ( id == NULL ) {
	if ( env_gettimeofday_id( m->m_env ) != 0 ) {
	    return( NULL );
	}
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
