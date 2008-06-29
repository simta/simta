#include <mysql.h>
#include <mysqld_error.h>
#define __USE_XOPEN
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define _PATH_MYSQL_CONFIG	"./my-pb.conf"
char	*config = _PATH_MYSQL_CONFIG;

main( int ac, char *av[] )
{
    MYSQL	mysql;
    MYSQL_RES	*result;
    MYSQL_ROW	row;
    char	query[ 1024 ];
    int		c, err = 0, len, rc;
    int		verbose = 0;
    int		count, affected, total = 0;
    time_t	start, stop;
    extern int	optind;

    while (( c = getopt( ac, av, "vf:" )) != -1 ) {
	switch ( c ) {
	case 'f' :
	    config = optarg;
	    break;

	case 'v' :
	    verbose = 1;
	    break;

	case '?' :
	default :
	    err++;
	    break;
	}
    }

    if ( ac - optind != 1 ) {
	err++;
    }

    if ( err ) {
	fprintf( stderr, "usage: %s [ -f mysql-config ] count\n", av[ 0 ] );
	exit( 0 );
    }

    count = atoi( av[ optind ]);

    if ( mysql_init( &mysql ) == NULL ) {
	perror( "mysql_init" );
	exit( 0 );
    }

    if ( mysql_options( &mysql, MYSQL_READ_DEFAULT_FILE, config ) != 0 ) {
	fprintf( stderr, "mysql_options %s failed\n", config );
	exit( 0 );
    }

    if ( mysql_real_connect( &mysql, NULL, NULL, NULL, NULL, 0, NULL, 0 )
	    == NULL ) {
	fprintf( stderr, "MySQL connection failed: %s\n",
		mysql_error( &mysql ));
	exit( 0 );
    }

    if (( len = snprintf( query, sizeof( query ),
	    "DELETE FROM signatures WHERE"
	    " DATE_SUB( NOW(), INTERVAL 3 DAY ) > time LIMIT %d",
	    count )) >= sizeof( query )) {
	fprintf( stderr, "DELETE too long! %d\n", len );
	exit( 0 );
    }

    start = time( NULL );

    do {

	if (( rc = mysql_real_query( &mysql, query, len )) != 0 ) {
	    fprintf( stderr, "DELETE %s\n", mysql_error( &mysql ));
	    goto done;
	}

	if (( result = mysql_store_result( &mysql )) != NULL ) {
	    fprintf( stderr, "mysql_store_result unexpected result\n" );
	    exit( 0 );
	}

	affected = mysql_affected_rows( &mysql );

	total += affected;

	if ( verbose ) {
	    stop = time( NULL );
	    printf( "%d rows deleted in %d seconds\n", total,
		    (int)difftime( stop, start ));
	}

    } while ( affected == count );

done:
    stop = time( NULL );
    printf( "%d rows deleted in %d seconds\n", total,
	    (int)difftime( stop, start ));

    exit( 0 );
}
