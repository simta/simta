/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	line_file.c	**********/
#include "config.h"

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "line_file.h"


    /* return a line_file */

    struct line_file *
line_file_create( void )
{
    struct line_file		*lf;

    if (( lf = (struct line_file*)malloc( sizeof( struct line_file )))
	    == NULL ) {
	syslog( LOG_ERR, "line_file_create malloc: %m" );
	return( NULL );
    }
    memset( lf, 0, sizeof( struct line_file ));

    return( lf );
}


    void
line_file_free( struct line_file *lf )
{
    struct line		*l;

    if ( lf != NULL ) {
	while (( l = lf->l_first ) != NULL ) {
	    lf->l_first = l->line_next;
	    free( l->line_data );
	    free( l );
	}

	free( lf );
    }
}


    /* append a line to a line_file structure  */

    struct line *
line_append( struct line_file *lf, char *data )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	syslog( LOG_ERR, "line_append malloc: %m" );
	return( NULL );
    }
    memset( l, 0, sizeof( struct line ));

    if (( l->line_data = strdup( data )) == NULL ) {
	syslog( LOG_ERR, "line_append strdup: %m" );
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
line_prepend( struct line_file *lf, char *data )
{
    struct line		*l;

    if (( l = (struct line*)malloc( sizeof( struct line ))) == NULL ) {
	syslog( LOG_ERR, "line_prepend malloc: %m" );
	return( NULL );
    }
    memset( l, 0, sizeof( struct line ));

    if (( l->line_data = strdup( data )) == NULL ) {
	syslog( LOG_ERR, "line_prepend strdup: %m" );
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
