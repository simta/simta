#include <mysql.h>
#include <mysqld_error.h>
#define __USE_XOPEN
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

/*
 * This program will be exec'd by the enclosing shell script, so the exit
 * values must obey those that SiMTA uses for content filters:
 *
 * The content filter return code is a bitfield.  The first line of text
 * returned from the content filter will be logged and displayed to the
 * SMTP client.
 *
 * Results:
 * 0x0000 0000	MESSAGE_ACCEPT
 * 0x0000 0001	MESSAGE_TEMPFAIL
 * 0x0000 0010	MESSAGE_REJECT
 *
 * On most errors, we will "accept" the message.  During initial insertion
 * into the database, we will "tempfail" the message.
 */

#define _PATH_MYSQL_CONFIG	"./my-pb.conf"
char	*config = _PATH_MYSQL_CONFIG;

main( int ac, char *av[] )
{
    MYSQL	mysql;
    MYSQL_RES	*result;
    MYSQL_ROW	row;
    char	*ip, *cksum, *from, *escaped_from, *reason;
    char	query[ 1024 ];
    int		c, err = 0, len, rc;
    struct tm	tm;
    time_t	then, now;
    double	dt;
    extern int	optind;

    while (( c = getopt( ac, av, "f:" )) != -1 ) {
	switch ( c ) {
	case 'f' :
	    config = optarg;
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
	fprintf( stderr, "usage: %s [ -f mysql-config ] reason\n", av[ 0 ] );
	exit( 0 );
    }

    reason = av[ optind ];

    if (( cksum = getenv( "SIMTA_CHECKSUM" )) == NULL ) {
	fprintf( stderr, "SIMTA_CHECKSUM not set\n" );
	exit( 0 );
    }
    if (( ip = getenv( "SIMTA_REMOTE_IP" )) == NULL ) {
	fprintf( stderr, "SIMTA_REMOTE_IP not set\n" );
	exit( 0 );
    }
    if (( from = getenv( "SIMTA_SMTP_MAIL_FROM" )) == NULL ) {
	fprintf( stderr, "SIMTA_SMTP_MAIL_FROM not set\n" );
	exit( 0 );
    }

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

    len = strlen( from );
    if (( escaped_from = malloc( len * 2 + 1 )) == NULL ) {
	perror( "malloc" );
	exit( 0 );
    }
    mysql_real_escape_string( &mysql, escaped_from, from, len );

    if (( len = snprintf( query, sizeof( query ),
	    "INSERT INTO signatures () VALUES"
	    " ('%s', '%s', '%s', DEFAULT, '%s')",
	    cksum, ip, escaped_from, reason )) >= sizeof( query )) {
	fprintf( stderr, "INSERT too long! %d\n", len );
	exit( 0 );
    }
    if (( rc = mysql_real_query( &mysql, query, len )) == 0 ) {
	/*
	 * Should I commit this transaction?  Should I close the connection?
	 */
	printf( "PenaltyBox: Record: [%s] <%s> %s\n", ip, from, reason );
	exit( 1 );
    }

    if ( ER_DUP_ENTRY != mysql_errno( &mysql )) {
	fprintf( stderr, "INSERT %s\n", mysql_error( &mysql ));
	exit( 0 );
    }

    if (( len = snprintf( query, sizeof( query ),
	    "SELECT time, reason FROM signatures WHERE"
	    " checksum = '%s' AND ip_address = '%s' AND from_address = '%s'"
	    " LIMIT 1",
	    cksum, ip, escaped_from )) >= sizeof( query )) {
	fprintf( stderr, "SELECT too long! %d\n", len );
	exit( 0 );
    }
    if ( mysql_real_query( &mysql, query, len ) != 0 ) {
	fprintf( stderr, "SELECT failed: %s\n", mysql_error( &mysql ));
	exit( 0 );
    }

    if (( result = mysql_store_result( &mysql )) == NULL ) {
	fprintf( stderr, "mysql_store_result failed: %s\n",
		mysql_error( &mysql ));
	exit( 0 );
    }

    if (( row = mysql_fetch_row( result )) == NULL ) {
	fprintf( stderr, "mysql_fetch_row failed: %s\n",
		mysql_error( &mysql ));
	exit( 0 );
    }

    /* time is in the format YYYY-MM-DD HH:MM:SS */
    tm.tm_isdst = -1;
    if ( strptime( row[ 0 ], "%Y-%m-%d %H:%M:%S", &tm ) == NULL ) {
	fprintf( stderr, "Could not parse timestamp: %s\n", row[ 0 ] );
	exit( 0 );
    }

    then = mktime( &tm );
    now = time( NULL );

    if (( dt = difftime( now, then )) < 5 * 60 ) {
	printf( "PenaltyBox: Window: %ds [%s] <%s> %s\n",
		(int)dt, ip, from, row[ 1 ] );
	exit( 1 );
    }

    if (( len = snprintf( query, sizeof( query ),
	    "DELETE FROM signatures WHERE"
	    " checksum = '%s' AND ip_address = '%s' AND from_address = '%s'"
	    " LIMIT 1",
	    cksum, ip, escaped_from )) >= sizeof( query )) {
	fprintf( stderr, "DELETE too long! %d\n", len );
	exit( 0 );
    }
    if ( mysql_real_query( &mysql, query, len ) != 0 ) {
	fprintf( stderr, "DELETE failed: %s\n", mysql_error( &mysql ));
	exit( 0 );
    }

    printf( "PenaltyBox: Accept: %ds [%s] <%s> %s\n",
	    (int)dt, ip, from, row[ 1 ] );
    exit( 0 );
}
