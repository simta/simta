/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*
 * Return parsed argc/argv.
 */

#include "config.h"

#include <stdlib.h>
#include <strings.h>

#include "argcargv.h"

#define ACV_ARGC		10
#define ACV_WHITE		0
#define ACV_WORD		1
#define ACV_BRACKET		2
#define ACV_DQUOTE		3

static ACAV *acavg = NULL;

    ACAV*
acav_alloc( void )
{
    ACAV *acav;

    if (( acav = (ACAV*)malloc( sizeof( ACAV ))) == NULL ) {
	return( NULL );
    }
    if (( acav->acv_argv =
	    (char **)malloc( sizeof(char *) * ( ACV_ARGC ))) == NULL ) {
	return( NULL );
    }
    acav->acv_argc = ACV_ARGC;

    return( acav );
}

/*
 *
 */
    int
acav_parse2821( ACAV *acav, char *line, char **argv[] )
{
    int		ac;
    int		state;

    if ( acav == NULL ) {
	if ( acavg == NULL ) {
	    acavg = acav_alloc();
	}
	acav = acavg;
    }

    ac = 0;
    state = ACV_WHITE;

    for ( ; *line != '\0'; line++ ) {
	switch ( *line ) {
	case ' ' :
	case '\t' :
	case '\n' :
	    if ( state == ACV_WORD ) {
		*line = '\0';
		state = ACV_WHITE;
	    }
	    break;

	case '\\' :
	    if (( state == ACV_DQUOTE ) && (*(line + 1) != '\0' )) {
		line++;
	    }
	    break;

	case '>' :
	    if ( state == ACV_BRACKET ) {
		state = ACV_WORD;
	    }
	    break;

	default :
	    if ( state == ACV_WHITE ) {
		acav->acv_argv[ ac++ ] = line;
		if ( ac >= acav->acv_argc ) {
		    /* realloc */
		    if (( acav->acv_argv = (char **)realloc( acav->acv_argv,
			    sizeof( char * ) * ( acav->acv_argc + ACV_ARGC )))
			    == NULL ) {
			return( -1 );
		    }
		    acav->acv_argc += ACV_ARGC;
		}
		state = ACV_WORD;
	    }
	    if ( *line == '<' && state == ACV_WORD ) {
	    	state = ACV_BRACKET;
	    }
	    if ( *line == '"' ) {
		if ( state == ACV_BRACKET ) {
		    state = ACV_DQUOTE;
		} else if ( state == ACV_DQUOTE ) {
		    state = ACV_BRACKET;
		}
	    }
	    break;
	}
    }

    acav->acv_argv[ ac ] = NULL; 
    *argv = acav->acv_argv;
    return( ac );
}

#ifdef notdef
main( int ac, char *av[] )
{
    char	**nav;
    int		nac, i;

    printf( "av: %s\n", av[ 1 ] );

    nac = acav_parse2821( NULL, av[ 1 ], &nav );

    for ( i = 0; i < nac; i++ ) {
	printf( "nav[ %d ] = %s\n", i, nav[ i ] );
    }
    exit( 0 );
}
#endif // notdef

/*
 * acav->acv_argv = **argv[] if passed an ACAV
 */

    int
acav_parse( ACAV *acav, char *line, char **argv[] )
{
    int		ac;
    int		state;

    if ( acav == NULL ) {
	if ( acavg == NULL ) {
	    acavg = acav_alloc();
	}
	acav = acavg;
    }

    ac = 0;
    state = ACV_WHITE;

    for ( ; *line != '\0'; line++ ) {
	switch ( *line ) {
	case ' ' :
	case '\t' :
	case '\n' :
	    if ( state == ACV_WORD ) {
		*line = '\0';
		state = ACV_WHITE;
	    }
	    break;
	default :
	    if ( state == ACV_WHITE ) {
		acav->acv_argv[ ac++ ] = line;
		if ( ac >= acav->acv_argc ) {
		    /* realloc */
		    if (( acav->acv_argv = (char **)realloc( acav->acv_argv,
			    sizeof( char * ) * ( acav->acv_argc + ACV_ARGC )))
			    == NULL ) {
			return( -1 );
		    }
		    acav->acv_argc += ACV_ARGC;
		}
		state = ACV_WORD;
	    }
	}
    }

    acav->acv_argv[ ac ] = NULL; 
    *argv = acav->acv_argv;
    return( ac );
}

    int
acav_free( ACAV *acav )
{
    free( acav->acv_argv );
    free( acav );

    return( 0 );
}
