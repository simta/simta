#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include <db.h>

#include "queue.h"
#include "ll.h"
#include "address.h"
#include "bdb.h"
#include "envelope.h"
#include "header.h"
#include "simta.h"

DB		*dbp = NULL;

    void
expansion_stab_stdout( void *string )
{
    printf( "%s\n", (char *)string );
}

extern int debug;

/*
 * Return values:
 *	< 0	error
 * 	  0	non-local address
 *	  1 	local address
 */

    int
address_local( char *addr )
{
    int			ret = 0;
    int			rc = 0;
    char		*user= NULL, *domain = NULL, *p = NULL;	
    struct passwd	*passwd = NULL;
    DBT			value;
    struct stab_entry	*i = NULL;
    struct host		*host;

    /* Check for domain in domain table */
    if (( domain = strchr( addr, '@' )) == NULL ) {
	syslog( LOG_ERR, "address_local: %s: invalid e-mail address", addr );
	return( -1 );
    }
    domain++;
    if (( host = (struct host*)ll_lookup( simta_hosts, domain )) == NULL ) {
	return( 1 );
    }

    /* Get user */
    if (( user = strdup( addr )) == NULL ) {
	syslog( LOG_ERR, "address_local: strdup: %m" );
	return( -1 );
    }
    if (( p = strchr( user, '@' )) == NULL ) {
	syslog( LOG_ERR, "address_local: %s: invalid e-mail address", user );
	ret = -1;
	goto done;
    }
    *p = '\0';

    /* Search for user using lookup ll */
    for ( i = host->h_expansion; i != NULL; i = i->st_next ) {
	if ( strcmp( i->st_key, "alias" ) == 0 ) {
	    /* check alias file */
	    if ( dbp == NULL ) {
		if (( rc = db_open_r( &dbp, SIMTA_ALIAS_DB, NULL )) != 0 ) {
		    syslog( LOG_ERR, "address_local: db_open_r: %s",
			db_strerror( rc ));
		    ret = -1;
		    goto done;
		}
	    }
	    if ( db_get( dbp, user, &value ) == 0 ) {
		ret = 1;
		goto done;
	    }
	    /* XXX where do we want to do this? */
	    /*
	    if (( rc = db_close( dbp )) != 0 ) {
		syslog( LOG_ERR, "address_local: db_close: %s",
		    db_strerr( rc ));
		ret = -1;
		goto done;
	    }
	    */

	} else if ( strcmp( i->st_key, "password" ) == 0 ) {
	    /* Check password file */
	    if (( passwd = getpwnam( user )) != NULL ) {
		ret = 1;
		goto done;
	    }

	} else {
	    /* unknown lookup */
	    syslog( LOG_ERR, "address_local: %s: unknown expansion",
		i->st_key );
	    ret = -1;
	    goto done;
	}
    }

done:
    free( user );
    return( ret );
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
    int			ret = 0, count = 0, len = 0;
    char		*user = NULL, *data = NULL, *domain = NULL;
    char		*address_local = NULL;
    char		*temp = NULL;
    char		buf[ MAXPATHLEN * 2 ];
    struct passwd	*passwd = NULL;
    DBC			*dbcp = NULL;
    DBT			key, value;
    struct host		*host = NULL;
    struct stab_entry	*i = NULL;
    FILE		*f;

    /* Check to see if we have seen addr already */
    if ( ll_lookup( *seen, address ) != NULL ) {
	/* Already expanded */
	if ( debug ) printf( "address_expand: %s: already expanded\n",
	    address );
	return( 0 );
    } else {
	/* Add address to seen list */
	/* XXX - Must free */
	if (( data = strdup( address )) == NULL ) {
	    syslog( LOG_ERR, "address_expand: strdup: %m" );
	}
	if ( ll_insert( seen, data, data, NULL ) != 0 ) {
	    syslog( LOG_ERR, "address_expand: ll_insert: %m" );
	    return( -1 );
	}
    }

    /* Get user and domain */
    /* XXX - Must free */
    if (( address_local = strdup( address )) == NULL ) {
	syslog( LOG_ERR, "address_expand: strdup: %m" );
	return( -1 );
    }
    user = address_local;
    if (( domain = strchr( address_local, '@' )) == NULL ) {
	syslog( LOG_ERR, "address_expand: strchr: %s: invalid address",
	    address_local );
        return( -1 );
    }
    *domain = '\0';
    domain++;

    /* Check for domain in hosts table */
    if (( host = ll_lookup( simta_hosts, domain )) == NULL ) {
	/* Add address to expansion */
	if (( data = strdup( address )) == NULL ) {
	    syslog( LOG_ERR, "address_expand: strdup: %m" );
	}
	if ( ll_insert( expansion, data, data, NULL ) != 0 ) {
	    syslog( LOG_ERR, "address_expand: ll_insert: %m" );
	    return( -1 );
	}
        return( 1 );
    }

    /* Expand user using lookup table for host */
    for ( i = host->h_expansion; i != NULL; i = i->st_next ) {
        if ( strcmp( i->st_key, "alias" ) == 0 ) {

            /* check alias file */
	    memset( &key, 0, sizeof( DBT ));
	    memset( &value, 0, sizeof( DBT ));

	    key.data = user;
	    key.size = strlen( user ) + 1;

	    if ( dbp == NULL ) {
		/* alias DB is option */
		if (( ret = db_open_r( &dbp, SIMTA_ALIAS_DB, NULL )) != 0 ) {
		    syslog( LOG_ERR, "address_expand: db_open_r: %s",
			db_strerror( ret ));
		    return( -1 );
		}
	    }

	    /* Set cursor and get first result */
	    if (( ret = db_cursor_set( dbp, &dbcp, &key, &value )) != 0 ) {
		if ( ret != DB_NOTFOUND ) {
		    syslog( LOG_ERR, "address_expand: db_cursor_set: %s",
			db_strerror( ret ));
		    return( -1 );
		} else {
		    continue;
		}
	    }

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
	    if ( ll_lookup( *seen, buf ) == NULL ) {
		/* Add address to expansion */
		data = strdup( buf );
		if ( ll_insert_tail( expansion, data, data ) != 0 ) {
		    syslog( LOG_ERR, "address_expand: ll_insert_tail: %m" );
		    return( -1 );
		}
		count++;
	    } else {
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
		if ( ll_lookup( *seen, buf ) == NULL ) {
		    /* Add address to expansion */
		    if (( data = strdup( buf )) == NULL ) {
			syslog( LOG_ERR, "address_expand: strdup: %m" );
			return( -1 );
		    }
		    if ( ll_insert_tail( expansion, data, data ) != 0 ) {
			syslog( LOG_ERR, "address_expand: ll_insert_tail: %m" );
			return( -1 );
		    }
		    count++;
		} else {
		    continue;
		}

		memset( &value, 0, sizeof( DBT ));
	    }

	    if ( ret != DB_NOTFOUND ) {
		syslog( LOG_ERR, "address_expand: db_cursor_next: %s",
		    db_strerror( ret ));
		return( -1 );
	    }

	    if ( count != 0 ) {
		break;
	    }

        } else if ( strcmp( i->st_key, "password" ) == 0 ) {

            /* Check password file */
	    if (( passwd = getpwnam( user )) == NULL ) {
		continue;
	    }

	    /* Check .forward */
	    memset( buf, 0, MAXPATHLEN * 2 );
	    sprintf( buf, "%s/.forward", passwd->pw_dir );

	    if ( access( buf, R_OK ) == 0 ) {
		if (( f =  fopen( buf, "r" )) == NULL ) {
		    syslog( LOG_ERR, "address_expand: fopen: %s: %m", buf );
		    return( -1 );
		}
		while ( fgets( buf, MAXPATHLEN, f ) != NULL ) {

		    len = strlen( buf );
		    if (( buf[ len - 1 ] ) != '\n' ) {
			/* XXX - should this be an error? */
			continue;
		    }
		    buf[ len - 1 ] = '\0';

		    /* Check for valid e-mail address */
		    if (( temp = strdup( buf )) == NULL ) {
			syslog( LOG_ERR, "address_expand: strdup: %m" );
			return( -1 );
		    }
		    if ( is_emailaddr( &temp ) != 1 ) {
			free( temp );
			continue;
		    }

		    /* Check to see if we have seen this address before to
		     * prevent it from being expanded again 
		     */
		    if ( ll_lookup( *seen, temp ) == NULL ) {
			/* Add address to expansion */
			if ( ll_insert_tail( expansion, temp, temp ) != 0 ) {
			    syslog( LOG_ERR,
				"address_expand: ll_insert_tail: %m" );
			    return( -1 );
			}
			count++;
		    } else {
			continue;
		    }
		}
	    }

        }
    }

    if ( dbp != NULL ) {
	if (( ret = db_cursor_close( dbcp )) != 0 ) {
	    syslog( LOG_ERR, "address_expand: db_cursor_close: %s",
		db_strerror( ret ));
	    return( -1 );
	}
    }

    free( address_local );
    return( count );
}
