#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rcptlist.h"


    struct rcptlist *
r_alloc( rcpt )
    char 	*rcpt;
{

    struct rcptlist	*t;

    if (( t = (struct rcptlist *)malloc(sizeof( struct rcptlist ))) == NULL ) {
	return( NULL );
    }

    if (( t->r_rcpt = strdup( rcpt )) == NULL ) {
	return( NULL );
    }

    return( t );
}


    int
r_append( rcpt, r_head, r_tail )
    char        *rcpt;
    struct rcptlist **r_head;
    struct rcptlist **r_tail;
{
    struct rcptlist *i;

    if ( ( i = r_alloc( rcpt ) ) == NULL ) {
	return( -1 );
    }
    i->r_next = NULL;

    if ( *r_head == NULL ) {
	*r_head = *r_tail = i;
    } else {
	(*r_tail)->r_next = i;
	*r_tail = i;
    }
    return( 1 );
}



    int
r_prepend( r_head, rcpt )
    struct rcptlist	**r_head;
    char		*rcpt;
{

    struct rcptlist	*t;

    if ( ( t = r_alloc( rcpt ) ) == NULL ) {
        return( -1 );
    }

    t->r_next = *r_head;
    *r_head = t;
    return( 0 );
}

    void
r_output( r_head )
    struct rcptlist	*r_head;
{

    struct rcptlist	*i;

    for ( i = r_head; i != NULL; i = i->r_next ) {
        printf( "RCPT TO: %s\n", i->r_rcpt );
    }
}
