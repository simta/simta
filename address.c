#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <pwd.h>

#include <db.h>

#include "address.h"
#include "bdb.h"

#define DATABASE "/Volumes/Local/Users/editor/src/simta/simta-aliases.db"

/*
 * Return values:
 *	< 0	error
 *	  0 	local address
 * 	> 0	non-local address
 */

DB		*dbp = NULL;

    int
address_local( char *address )
{
    int			ret;
    char		*user, *p;	
    struct passwd	*passwd;
    DBT			value;

    if (( user = strdup( address )) == NULL ) {
	return( -1 );
    }
    if (( p = strchr( user, '@' )) == NULL ) {
	free( user );
	return( -1 );
    }
    *p = '\0';

    /* XXX check alias file */
    if ( dbp == NULL ) {
	if (( ret = db_open_r( &dbp, DATABASE, NULL )) != 0 ) {
	    free( user );
	    return( -1 );
	}
    }
    if (( ret = db_get( dbp, user, &value )) == 0 ) {
	free( user );
	return( 0 );
    }
    /* XXX where do we want to do this? */
    /*
    if (( ret = db_close( dbp )) != 0 ) {
	free( user );
	return( -1 );
    }
    */

    /* Check password file */
    if (( passwd = getpwnam( user )) != NULL ) {
	free( user );
	return( 0 );
    }

    /* XXX do we check .forward? */
    free( user );
    return( 1 );
}

/*
 * Return values:
 *	< 0	non-local address
 *	  0 	no expansion
 *	> 0	number of expanded addresses
 */

    int
address_expand( char *address )
{
    int			ret, count = 0;
    char		*user, *p;
    char		path[ MAXPATHLEN + 1];
    struct passwd	*passwd;
    FILE		*f;
    DBC			*dbcp = NULL;
    DBT			key, value;

    if (( user = strdup( address )) == NULL ) {
	return( -1 );
    }
    if (( p = strchr( user, '@' )) == NULL ) {
	free( user );
	return( -1 );
    }
    *p = '\0';

    /* XXX check alias file */
    memset( &key, 0, sizeof( DBT ));
    memset( &value, 0, sizeof( DBT ));

    key.data = user;
    key.size = strlen( user ) + 1;

    if ( dbp == NULL ) {
	if (( ret = db_open_r( &dbp, DATABASE, NULL )) != 0 ) {
	    free( user );
	    return( -1 );
	}
    }

    if (( ret = db_cursor_set( dbp, &dbcp, &key, &value )) != 0 ) {
	if ( ret != DB_NOTFOUND ) {
	    free( user );
	    return( -1 );
	} else {
	    goto passwd;
	}
    }
    memset( &value, 0, sizeof( DBT ));

    while (( ret = db_cursor_next( dbp, &dbcp, &key, &value )) == 0 ) {
	count++;
	memset( &value, 0, sizeof( DBT ));
    }

    if ( ret != DB_NOTFOUND ) {
	free( user );
	return( -1 );
    }
passwd:
    if ( db_cursor_close( dbcp ) != 0 ) {
	free( user );
	return( -1 );
    }

    /* Check password file */
    if (( passwd = getpwnam( user )) == NULL ) {
	free( user );
	return( -1 );
    }

    /* Check .forward */
    sprintf( path, "%s%s", passwd->pw_dir, ".forward" );
    if (( f = fopen( path, "r" )) == NULL ) {
	/* XXX ( how? ) should we return error? */
	free( user );
	return( NULL );
    }

    return( count );
}
