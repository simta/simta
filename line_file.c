/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	line_file.c	**********/

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
	return( NULL );
    }
    memset( lf, 0, sizeof( struct line_file ));

    return( lf );
}


    void
line_free( struct line *line )
{
    if ( line != NULL ) {
	line_free( line->line_next );
	free( line->line_data );
	free( line );
    }
}


    void
line_file_free( struct line_file *lf )
{
    if ( lf != NULL ) {
	line_free( lf->l_first );
	free( lf );
    }
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
