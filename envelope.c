/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <netdb.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "envelope.h"

    struct envelope *
env_create()
{
    struct envelope	*env;

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	return( NULL );
    }

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

    if ( e->e_mail != NULL ) {
	printf( "mail: %s\n", e->e_mail );
    } else {
	printf( "mail NULL\n" );
    }

    for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	printf( "rcpt: %s\n", r->r_rcpt );
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

    if (( r->r_rcpt = strdup( addr )) == NULL ) {
	return( -1 );
    }

    r->r_next = e->e_rcpt;
    e->e_rcpt = r;

    return( 0 );
}
