#include "config.h"

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <db.h>

#include "bdb.h"

int db_open( DB *bdp, char *file, char *database, DBTYPE type,
    u_int32_t flags, int mode );

    int
db_open( DB *dbp, char *file, char *database, DBTYPE type,
    u_int32_t flags, int mode )
{
    return( dbp->open( dbp, NULL, file, database, type, flags, mode ));
}

    int
db_open_rw( DB **dbp, char *file, char *database )
{
    int		ret;

    if (( ret = db_create( dbp, NULL, 0 )) != 0 ) {
	return( ret );
    }
    return( db_open( *dbp, file, database, DB_UNKNOWN, DB_RDONLY, 0664 ));
}

    int
db_open_r( DB **dbp, char *file, char *database )
{
    int		ret;

    if (( ret = db_create( dbp, NULL, 0 )) != 0 ) {
	return( ret );
    }
    return( db_open( *dbp, file, database, DB_UNKNOWN, DB_RDONLY, 0664 ));
}

    int 
db_new( DB **dbp, u_int32_t flags, char *file, char *database, DBTYPE type )
{
    int		ret;

    if (( ret = db_create( dbp, NULL, 0 )) != 0 ) {
	goto err;
    }
    if (( ret = (*dbp)->set_flags( *dbp, DB_DUP )) != 0 ) {
	goto err;
    }
    if (( ret = db_open( *dbp, file, database, type,
	    DB_CREATE | DB_TRUNCATE, 0664 )) != 0 ) {
	goto err;
    }

err:
    return( ret );
}

    int
db_put( DB *dbp, char *keydata, char *valuedata )
{
    DBT 	key, value;

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    key.data = keydata;
    key.size = strlen( keydata ) + 1;
    value.data = valuedata;
    value.size = strlen( valuedata ) + 1;

    return( dbp->put(dbp, NULL, &key, &value, 0 ));
}

    int
db_get( DB *dbp, char *keyvalue, DBT *value )
{
    DBT		key;
    DBC		*dbcp;
    int		ret, t_ret;

    /* Acquire a cursor for the database. */
    if (( ret = dbp->cursor( dbp, NULL, &dbcp, 0 )) != 0 ) {
	goto err;
    }

    /* Re-initialize the key/data pair. */
    memset( &key, 0, sizeof( DBT ));
    memset( value, 0, sizeof( DBT ));
    key.data = keyvalue;
    key.size = strlen( keyvalue ) + 1;

    if (( ret = dbcp->c_get( dbcp, &key, value, DB_SET )) != 0 ) {
	goto err;
    }

err:
    /* Close the cursor. */
    if (( t_ret = dbcp->c_close( dbcp )) != 0 && ret == 0 ) {
	ret = t_ret;
    }

    return(ret);
}

    int
db_cursor_set( DB *dbp, DBC **dbcp, DBT *key, DBT *value )
{
    int 	ret;

    /* Acquire a cursor for the database. */
    if ( *dbcp == NULL ) {
	if (( ret = dbp->cursor( dbp, NULL, dbcp, 0 )) != 0 ) {
	    return( ret );
	}
    }

    return( (*dbcp)->c_get( *dbcp, key, value, DB_SET ));
}

    int
db_cursor_next( DB *dbp, DBC **dbcp, DBT *key, DBT *value )
{
    int 	ret;

    /* Acquire a cursor for the database. */
    if ( *dbcp == NULL ) {
	if (( ret = dbp->cursor( dbp, NULL, dbcp, 0 )) != 0 ) {
	    return( ret );
	}
    }

    /* Walk through the database and print out the key/data pairs. */
    return( (*dbcp)->c_get( *dbcp, key, value, DB_NEXT_DUP ));
}

    int
db_cursor_close( DBC *dbcp )
{
    return( dbcp->c_close( dbcp ));
}

    int
db_close( DB *bdp )
{
    return( bdp->close( bdp, 0 ));
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
