#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <db.h>

#include "argcargv.h"
#include "bdb.h"

    int
main( int argc, char **argv )
{
    int			c, err = 0, linenum = 0, aac, i, len, ret;
    int			verbose = 0;
    extern int		optind;
    extern char		*optarg;
    char		**aargv, *prog, *input = NULL, *output = NULL;
    char		line[ MAXPATHLEN * 2 ];
    DB			*dbp = NULL;
    FILE		*f;

    if (( prog = strrchr( argv[ 0 ], '/' )) == NULL ) {
        prog = argv[ 0 ];
    } else {
	prog++;      
    }

    while (( c = getopt( argc, argv, "i:o:v" )) != -1 ) {
	switch ( c ) {
	case 'i':
	    input = optarg;
	    break;
	case 'o':
	    output = optarg;
	    break;
	case 'v':
	    verbose++;
	    break;
	default:
	    err++;
	}
    }

    if ( err || input == NULL || output == NULL ) {
	fprintf( stderr, "usage: %s ", prog );
	fprintf( stderr, "-i [input-file] -o [output-file]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    if (( ret = db_new( &dbp, DB_DUP, output, NULL, DB_HASH )) != 0 ) {
	fprintf( stderr, "db_new: %s\n", db_strerror( ret ));
	exit( 1 );
    }

    if (( f = fopen( input, "r" )) == NULL ) {
        perror( input );
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

	    if ( verbose ) printf( "Added %s -> %s\n", aargv[ 0 ], aargv[ i ] );
        }
    }

    if (( ret = db_close( dbp )) != 0 ) {
	printf( "db_close failed: %s\n", db_strerror( ret ));
	exit( 1 );
    }

    if ( verbose ) printf( "%s: created\n", output );

    exit( 0 );
}
