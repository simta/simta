#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <db.h>

#include "../argcargv.h"
#include "../bdb.h"

    int
main( int argc, char **argv )
{
    int		linenum, aac, i, len, ret;
    char	**aargv;
    char	line[ MAXPATHLEN * 2 ];
    DB		*dbp = NULL;
    FILE	*f;

    if (( ret = db_new( &dbp, DB_DUP, argv[ 1 ], NULL, DB_HASH )) != 0 ) {
	fprintf( stderr, "db_new: %s\n", db_strerror( ret ));
	exit( 1 );
    }

    if (( f = fopen( "./aliases", "r" )) == NULL ) {
        perror( "./aliases" );
        exit( 1 );
    }
    while ( fgets( line, MAXPATHLEN, f ) != NULL ) {
	linenum++;

	aac = acav_parse( NULL, line, &aargv );

	if (( aac == 0 ) || ( *aargv[ 0 ] == '#' )) {
	    continue;
	}

        /* Remove trailing ";" */
        len = strlen( aargv[ 0 ] );
        if ( aargv[ 0 ][ len - 1 ] == ':' ) {
            aargv[ 0 ][ len - 1 ] = '\0';
        }

        for ( i = 1; i < aac; i++ ) {
            /* removed tailing "," */
            len = strlen( aargv[ i ] );
            if ( aargv[ i ][ len - 1 ] == ',' ) {
                aargv[ i ][ len - 1 ] = '\0';
            }

	    if (( ret =  db_put( dbp, aargv[ 0 ], aargv[ i ] )) != 0 ) {
		dbp->err( dbp, ret, "%s", argv[ 1 ] );
		exit( 1 );
	    }
        }
    }

    if (( ret = db_close( dbp )) != 0 ) {
	printf( "db_close failed: %s\n", db_strerror( ret ));
	exit( 1 );
    }

    printf( "DB %s create\n", arv[ 1 ] );

    if (( ret = db_open_r( &dbp, argv[ 1 ], NULL )) != 0 ) {
	printf( "db_open_r failed: %s\n", db_strerror( ret ));
	exit( 1 );
    }

    if ( db_walk( dbp ) < 0 ) {
	printf( "walk_db failed\n" );
	exit( 1 );
    }

    if (( ret = db_close( dbp )) != 0 ) {
	printf( "db_close failed: %s\n", db_strerror( ret ));
	exit( 1 );
    }

    exit( 0 );
}
