/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	ll.c	**********/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "ll.h"


    /*****     ll_lookup     *****/
    /* looks through a given symbol table, and returns the entry, if any,
     * that has a key that corresponds to the one given
     */

    void*
ll_lookup( struct stab_entry *st, char *key )
{
    for( ; st != NULL; st = st->st_next ) {
	if ( strcasecmp( st->st_key, key ) == 0 ) {
	    /* match found */
	    return( st->st_data );
	}
    }
    /* no match found */
    return( NULL );
}


    /*****     ll_insert     *****/
    /* This function inserts a given node in to a given stab table */

    int
ll_insert( struct stab_entry **stab, char *key, void *data,
	int (*ll_compare)( struct stab_entry *, struct stab_entry * ))
{
    struct stab_entry	*st;
    struct stab_entry	**i;

    if ( ll_lookup( *stab, key ) != NULL ) {
	/* return fail, as item already exists */
	return( 1 );
    }

    if (( st = (struct stab_entry*)malloc( sizeof( struct stab_entry )))
	    == NULL ) {
	perror( "malloc" );
	exit( 1 );
    }
    memset( st, 0, sizeof( struct stab_entry ));

    st->st_key = key;
    st->st_data = data;

    for ( i = stab; *i != NULL; i = &((*i)->st_next) ) {
	if ( ll_compare( st, *i ) < 0 ) {
	    break;
	}
    }

    st->st_next = *i;
    *i = st;

    return( 0 );
}


    /*****     ll_remove     *****/
    /* This function removes a given node from a stab table */

    void *
ll_remove( struct stab_entry **stab, char *key )
{
    struct stab_entry	*st;
    struct stab_entry	**i;
    void		*data;

    for ( i = stab; *i != NULL; i = &((*i)->st_next) ) {
	if ( strcmp( key, (*i)->st_key ) == 0 ) {
	    break;
	}
    }

    if (( st = *i ) == NULL ) {
	return( NULL );
    }

    data = st->st_data;

    *i = (*i)->st_next;

    free( st );

    return( data );
}


    void
ll_walk( struct stab_entry *st, void (*ll_func)( void * ))
{
    for ( ; st != NULL; st = st->st_next ) {
	ll_func( st->st_data );
    }
}
