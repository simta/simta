/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

/*
 * Return parsed argc/argv.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "argcargv.h"

#define ACV_ARGC                10
#define ACV_WHITE               0
#define ACV_WORD                1
#define ACV_BRACKET             2
#define ACV_DQUOTE              3

static ACAV *acavg = NULL;

    ACAV*
acav_alloc( void )
{
    ACAV *acav;

    acav = malloc( sizeof( ACAV ));
    acav->acv_argv = malloc( sizeof(char *) * ( ACV_ARGC ));
    acav->acv_argc = ACV_ARGC;

    return( acav );
}

/*
 *
 */
    int
acav_parse2821( ACAV *acav, char *line, char **argv[] )
{
    int         ac;
    int         state;

    if ( acav == NULL ) {
        if ( acavg == NULL ) {
            if (( acavg = acav_alloc() ) == NULL ) {
                return ( -1 );
            }
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
                    acav->acv_argv = (char **)realloc( acav->acv_argv,
                            sizeof( char * ) * ( acav->acv_argc + ACV_ARGC ));
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
    char        **nav;
    int         nac, i;

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
    int         ac = 0;
    int         state = ACV_WHITE;

    if ( acav == NULL ) {
        if ( acavg == NULL ) {
            if (( acavg = acav_alloc() ) == NULL ) {
                return ( -1 );
            };
        }
        acav = acavg;
    }

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
                    acav->acv_argv = realloc( acav->acv_argv,
                            sizeof( char * ) * ( acav->acv_argc + ACV_ARGC ));
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
    if ( acav ) {
        free( acav->acv_argv );
        free( acav );
    }

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
