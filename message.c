/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	message.c	**********/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "message.h"


    /* create & return a message structure */

    struct message *
message_create( void )
{
    struct message	*m;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	return( NULL );
    }

    m->m_first = NULL;
    m->m_last = NULL;

    return( m );
}


    /* add a line to the message */

    int
message_line( struct message *m, char *line )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	return( 1 );
    }

    if (( l->line_data = strdup( line )) == NULL ) {
	return( 1 );
    }

    l->line_next = NULL;

    if ( m->m_first == NULL ) {
	m->m_first = l;
	m->m_last = l;

    } else {
	m->m_last->line_next = l;
	m->m_last = l;
    }

    return( 0 );
}
