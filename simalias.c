#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <stdio.h>
#include <db.h>
#include <dirent.h>

#include "denser.h"
#include "ll.h"
#include "expand.h"
#include "red.h"
#include "envelope.h"
#include "simta.h"
#include "argcargv.h"
#include "mx.h"
#include "simta_ldap.h"
#include "bdb.h"
#include "queue.h"
#include "ml.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */



int simalias_dump( void );
int simalias_create( void );

int		verbose = 0;
char		*input;
char		*output;
char		*progname;
FILE		*finput;
FILE		*foutput;

    int
main( int argc, char **argv )
{
    int			c, err = 0;
    int			dump = 0;
    extern char		*optarg;

    if (( progname = strrchr( argv[ 0 ], '/' )) == NULL ) {
	progname = argv[ 0 ];
    } else {
	progname++;      
    }

    while (( c = getopt( argc, argv, "di:o:v" )) != -1 ) {
	switch ( c ) {
	case 'd':
	    dump++;
	    break;

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

    if ( err ) {
	fprintf( stderr, "usage: %s ", progname );
	fprintf( stderr, "[ -d ] [ -i input-file ] [ -o output-file ]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	fprintf( stderr, "simta_read_config error: %s\n", SIMTA_FILE_CONFIG );
	exit( 1 );
    }

    if ( dump ) {
	if ( input == NULL ) {
	    input = simta_default_alias_db;
	}
	if ( output == NULL ) {
	    foutput = stdout;
	} else { 
	    if (( foutput = fopen( output, "r" )) == NULL ) {
		perror( output );
		exit( 1 );
	    }
	}
	exit( simalias_dump( ));

    } else {
	/* not dump */
	if ( input == NULL ) {
	    finput = stdin;
	} else {
	    if (( finput = fopen( input, "r" )) == NULL ) {
		perror( input );
		exit( 1 );
	    }
	}
	if ( output == NULL ) {
	    output = simta_default_alias_db;
	}
	exit( simalias_create( ));
    }
}

    int
simalias_dump( void )
{
    DB		*dbp;
    DBC		*dbcp;
    DBT		 key, data;
    int		 ret, close_db = 0, close_dbc = 0;

    if (( ret = db_open_r( &dbp, input, NULL )) != 0 ) {
	fprintf( stderr, "db_open_r: %s: %s\n", input, db_strerror( ret ));
	goto error;
    }
    close_db = 1;

    if (( ret = dbp->cursor( dbp, NULL, &dbcp, 0 )) != 0 ) {
	dbp->err(dbp, ret, "DB->cursor");
	goto error;
    }
    close_dbc = 1;

    memset( &key, 0, sizeof( key ));
    memset( &data, 0, sizeof(data ));

    while (( ret = dbcp->c_get( dbcp, &key, &data, DB_NEXT )) == 0 ) {
	printf("%s:\t\t%s\n", (char *)key.data, (char *)data.data);
    }
    if ( ret != DB_NOTFOUND ) {
	dbp->err(dbp, ret, "DBcursor->get");
	goto error;
    }

    if ( close_dbc && (( ret = dbcp->c_close( dbcp )) != 0 )) {
	    dbp->err(dbp, ret, "DBcursor->close");
	    goto error;
    }
    if ( close_db && (( ret = dbp->close( dbp, 0 )) != 0 )) {
	fprintf(stderr,
	    "%s: DB->close: %s\n", progname, db_strerror(ret));
	goto error;
    }

    return( 0 );

error:
    if ( close_dbc ) {
	dbcp->c_close( dbcp );
    }
    close_dbc = 0;
    if ( close_db ) {
	dbp->close( dbp, 0 );
    }
    close_db = 0;

    return( 1 );
}

    int
simalias_create( void )
{
    int			linenum = 0, aac, i, len, ret;
    char		line[ MAXPATHLEN * 2 ];
    char		**argv;
    DB			*dbp = NULL;

    if (( ret = db_new( &dbp, DB_DUP, output, NULL, DB_HASH )) != 0 ) {
	fprintf( stderr, "db_new: %s: %s\n", output, db_strerror( ret ));
	return( 1 );
    }

    while ( fgets( line, MAXPATHLEN, finput ) != NULL ) {
	linenum++;

	aac = acav_parse( NULL, line, &argv );

	if (( aac == 0 ) || ( *argv[ 0 ] == '#' )) {
	    continue;
	}

	/* Remove trailing ":" */
	len = strlen( argv[ 0 ] );
	if ( argv[ 0 ][ len - 1 ] == ':' ) {
	    argv[ 0 ][ len - 1 ] = '\0';
	}

	for ( i = 1; i < aac; i++ ) {
	    /* removed tailing "," */
	    len = strlen( argv[ i ] );
	    if ( argv[ i ][ len - 1 ] == ',' ) {
		argv[ i ][ len - 1 ] = '\0';
	    }

	    if (( ret =  db_put( dbp, argv[ 0 ], argv[ i ] )) != 0 ) {
		dbp->err( dbp, ret, "%s", argv[ 1 ] );
		return( 1 );
	    }

	    if ( verbose ) printf( "Added %s -> %s\n", argv[ 0 ], argv[ i ] );
	}
    }

    if (( ret = db_close( dbp )) != 0 ) {
	printf( "db_close failed: %s\n", db_strerror( ret ));
	return( 1 );
    }

    if ( verbose ) printf( "%s: created\n", output );

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
