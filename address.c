#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <pwd.h>
#include <unistd.h>

#include <db.h>

#include "ll.h"
#include "address.h"
#include "bdb.h"

#define DATABASE "/Users/editor/src/simta/simta-aliases.db"

DB		*dbp = NULL;

    void
expansion_stab_stdout( void *string )
{
    printf( "%s\n", (char *)string );
}

extern struct stab_entry *hosts;

/*
 * Return values:
 *	< 0	error
 *	  0 	local address
 * 	> 0	non-local address
 */

    int
address_local( char *address )
{
    int			ret;
    char		*user= NULL, *domain = NULL, *p = NULL;	
    struct passwd	*passwd = NULL;
    DBT			value;
    struct stab_entry	*lookup = NULL, *i = NULL;

    /* Check for domain in domain table */
    if (( domain = strchr( address, '@' )) == NULL ) {
	return( -1 );
    }
    domain++;
    if (( lookup = ll_lookup( hosts, domain )) == NULL ) {
	return( 1 );
    }

    /* Get user */
    if (( user = strdup( address )) == NULL ) {
	return( -1 );
    }
    if (( p = strchr( user, '@' )) == NULL ) {
	free( user );
	return( -1 );
    }
    *p = '\0';

    /* Search for user using lookup ll */
    for ( i = lookup; i != NULL; i = i->st_next ) {
	if ( strcmp( i->st_key, "alias" ) == 0 ) {


	    /* check alias file */
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

	} else if ( strcmp( i->st_key, "password" ) == 0 ) {


	    /* Check password file */
	    if (( passwd = getpwnam( user )) != NULL ) {
		free( user );
		return( 0 );
	    }
	    /* XXX do we check .forward? */

	} else {
	    //printf( "unknown lookup %s\n", i->st_key );
	    return( 1 );
	}
    }
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
address_expand( char *address, struct stab_entry **expansion, struct stab_entry **seen)
{
    int			ret = 0, count = 0;
    char		*user = NULL, *data = NULL, *domain = NULL;
    char		*address_local;
    char		buf[ MAXPATHLEN * 2 ];
    struct passwd	*passwd = NULL;
    DBC			*dbcp = NULL;
    DBT			key, value;
    struct stab_entry	*lookup = NULL, *i = NULL;

    /* Check to see if we have seen addr already */
    if ( ll_lookup( *seen, address ) != NULL ) {
	//printf( "...seen\n" );
	return( 0 );
    } else {
	/* Add address to seen list */
	//printf( "...new\n" );
	/* XXX - Must free */
	data = strdup( address );
	if ( ll_insert( seen, data, data, NULL ) != 0 ) {
	    return( -1 );
	}
	//printf( "%s insterted into seen list\n", data );
    }

    /* Get user and domain */
    if (( address_local = strdup( address )) == NULL ) {
	return( -1 );
    }
    user = address_local;
    if (( domain = strchr( address_local, '@' )) == NULL ) {
        return( -1 );
    }
    *domain = '\0';
    domain++;

    /* Check for domain in hosts table */
    //printf( "%s in hosts table?", domain );
    if (( lookup = ll_lookup( hosts, domain )) == NULL ) {
        //printf( "...no\n" );
        return( 0 );
    } else {
        //printf( "...yes\n" );
    }

    /* Expand user using lookup table for host */
    for ( i = lookup; i != NULL; i = i->st_next ) {
        if ( strcmp( i->st_key, "alias" ) == 0 ) {

	    //printf( "Using alias file\n" );

            /* check alias file */
	    memset( &key, 0, sizeof( DBT ));
	    memset( &value, 0, sizeof( DBT ));

	    key.data = user;
	    key.size = strlen( user ) + 1;

	    if ( dbp == NULL ) {
		if (( ret = db_open_r( &dbp, DATABASE, NULL )) != 0 ) {
		    return( -1 );
		}
	    }

	    /* Set cursor and get first result */
	    if (( ret = db_cursor_set( dbp, &dbcp, &key, &value )) != 0 ) {
		if ( ret != DB_NOTFOUND ) {
		    return( -1 );
		} else {
		    //printf( "%s not in alias file\n", user );
		    continue;
		}
	    }
	    //printf( "%s in alias file\n", user );

	    /* Create address from user and domain */
	    memset( buf, 0, MAXPATHLEN * 2 );
	    /* Check for e-mail address in alias file */
	    if ( strchr( (char*)value.data, '@' ) != NULL ) {
		sprintf( buf, "%s", (char*)value.data );
	    } else {
		sprintf( buf, "%s@%s", (char*)value.data, domain );
	    }

	    /* Check to see if we have seen this address before to prevent
	     * it from being expanded again 
	     */
	    //printf( "have I seen %s?", buf );
	    if ( ll_lookup( *seen, buf ) == NULL ) {
		/* Add address to expansion */
		//printf( "...no\n" );
		data = strdup( buf );
		//printf( "Adding %s to expansion\n", data );
		if ( ll_insert_tail( expansion, data, data ) != 0 ) {
		    return( -1 );
		}
		count++;
	    } else {
		//printf( "...yes\n" );
		continue;
	    }

	    /* Get all other result */
	    memset( &value, 0, sizeof( DBT ));
	    while (( ret = db_cursor_next( dbp, &dbcp, &key, &value )) == 0 ) {

		/* Create address from user and domain */
		memset( buf, 0, MAXPATHLEN * 2 );
		/* Check for e-mail address in alias file */
		if ( strchr( (char*)value.data, '@' ) != NULL ) {
		    sprintf( buf, "%s", (char*)value.data );
		} else {
		    sprintf( buf, "%s@%s", (char*)value.data, domain );
		}

		/* Check to see if we have seen this address before to prevent
		 * it from being expanded again 
		 */
		//printf( "have I seen %s?", buf );
		if ( ll_lookup( *seen, buf ) == NULL ) {
		    /* Add address to expansion */
		    //printf( "...no\n" );
		    data = strdup( buf );
		    //printf( "Adding %s to expansion\n", data );
		    if ( ll_insert_tail( expansion, data, data ) != 0 ) {
			return( -1 );
		    }
		    count++;
		} else {
		    //printf( "...yes\n" );
		    continue;
		}

		memset( &value, 0, sizeof( DBT ));
	    }

	    if ( ret != DB_NOTFOUND ) {
		return( -1 );
	    }

	    if ( count != 0 ) {
		break;
	    }

        } else if ( strcmp( i->st_key, "password" ) == 0 ) {

	    //printf( "Using password file\n" );

            /* Check password file */
	    if (( passwd = getpwnam( user )) == NULL ) {
		//printf( "%s not in password file\n", user );
		continue;
	    }
	    //printf( "%s found in password file\n", user );

	    /* XXX - Check .forward */
	    /* Only expand if there is a .forward */

	    /* Create address from user and domain */
	    memset( buf, 0, MAXPATHLEN * 2 );
	    sprintf( buf, "%s@%s", user, domain );
        } else {
            //printf( "unknown lookup %s\n", i->st_key );
        }
    }

    if ( db_cursor_close( dbcp ) != 0 ) {
	return( -1 );
    }

    free( address_local );
    return( count );
}
