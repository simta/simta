/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <snet.h>

#include "envelope.h"

    struct envelope *
env_create()
{
    struct envelope	*env;

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	return( NULL );
    }
    memset( env, 0, sizeof( struct envelope ));

    env->e_next = NULL;
    env->e_sin = NULL;
    *env->e_hostname = '\0';
    env->e_helo = NULL;
    env->e_mail = NULL;
    env->e_rcpt = NULL;
    *env->e_id = '\0';
    env->e_flags = 0;

    return( env );
}

    void
env_reset( struct envelope *env )
{
    struct recipient	*r, *rnext;

    if ( env->e_next != NULL ) {
	syslog( LOG_CRIT, "env_reset: e_next not NULL" );
	abort();
    }

    if ( env->e_mail != NULL ) {
	free( env->e_mail );
	env->e_mail = NULL;
    }

    if ( env->e_rcpt != NULL ) {
	for ( r = env->e_rcpt; r != NULL; r = rnext ) {
	    rnext = r->r_next;
	    free( r->r_rcpt );
	    free( r );
	}
	env->e_rcpt = NULL;
    }

    *env->e_id = '\0';
    env->e_flags = 0;
    return;
}


    void
env_stdout( struct envelope *e )
{
    struct recipient		*r;

    if ( *e->e_id == '\0' ) {
	printf( "Message-Id NULL\n" );
    } else {
	printf( "Message-Id:\t%s\n", e->e_id );
    }

    if ( e->e_mail != NULL ) {
	printf( "mail:\t%s\n", e->e_mail );
    } else {
	printf( "mail NULL\n" );
    }

    for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	printf( "rcpt:\t%s\n", r->r_rcpt );
    }

}


    int
env_recipient( struct envelope *e, char *addr )
{
    struct recipient		*r;

    if (( r = (struct recipient*)malloc( sizeof( struct recipient )))
	    == NULL ) {
	return( -1 );
    }
    memset( r, 0, sizeof( struct recipient ));

    if (( r->r_rcpt = strdup( addr )) == NULL ) {
	return( -1 );
    }

    r->r_next = e->e_rcpt;
    e->e_rcpt = r;

    return( 0 );
}


    struct envelope *
env_infile( char *dir, char *id )
{
    char			filename[ MAXPATHLEN ];
    char			*line;
    SNET			*snet;
    struct envelope		*e;

    if (( e = env_create()) == NULL ) {
	return( NULL );
    }

    sprintf( filename, "%s/E%s", dir, id );

    if (( snet = snet_open( filename, O_RDONLY, 0, 1024 * 1024 )) == NULL ) {
	return( NULL );
    }

    /* get from-address */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	return( NULL );
    }

    if (( e->e_mail = strdup( line )) == NULL ) {
	return( NULL );
    }

    /* get to-addresses */
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( env_recipient( e, line ) != 0 ) {
	    return( NULL );
	}
    }

    if ( snet_close( snet ) < 0 ) {
	return( NULL );
    }

    return( e );
}
