#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <snet.h>

#include <db.h>

#include "line_file.h"
#include "queue.h"
#include "ll.h"
#include "envelope.h"
#include "expand.h"
#include "address.h"
#include "header.h"
#include "simta.h"
#include "bdb.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */

DB		*dbp = NULL;

    void
expansion_stab_stdout( void *string )
{
    printf( "%s\n", (char *)string );
}


/* Creates an entry in STAB with a key of ADDRESS and a data pointer
 * to an expansion structure:
 *
 *	expn->e_expn = ADDRESS;
 *	expn->e_rcpt_parent = RCPT;
 * 
 * Return values:
 *	-1	system error
 *	 0	success
 */

    int
add_address( struct stab_entry **stab, char *address, struct recipient *rcpt )
{
    char		*data;
    struct expn		*expn;

    if (( data = strdup( address )) == NULL ) {
	syslog( LOG_ERR, "add_address: strdup: %m" );
	return( -1 );
    }

    if (( expn = (struct expn*)malloc( sizeof( struct expn ))) == NULL ) {
	syslog( LOG_ERR, "add_address: malloc: %m" );
	goto error1;
    }

    expn->e_expn = data;
    expn->e_rcpt_parent = rcpt;

    if ( ll_insert_tail( stab, data, expn ) != 0 ) {
	syslog( LOG_ERR, "add_address: ll_insert_tail: %m" );
	goto error2;
    }

    return( 0 );

error2:
    free( expn );

error1:
    free( data );
    return( -1 );
}


    int
address_local( char *addr )
{
    int			rc;
    char		*domain;
    char		*at;
    struct host		*host;
    struct passwd	*passwd;
    struct stab_entry	*i;
    DBT			value;

    /* Check for domain in domain table */
    if (( at = strchr( addr, '@' )) == NULL ) {
	return( ADDRESS_NOT_LOCAL );
    }

    *at = '\0';
    domain = at + 1;

    if (( host = (struct host*)ll_lookup( simta_hosts, domain )) == NULL ) {
	*at = '@';
	return( ADDRESS_NOT_LOCAL );
    }

    /* Search for user using expansion table */
    for ( i = host->h_expansion; i != NULL; i = i->st_next ) {
	if ( strcmp( i->st_key, "alias" ) == 0 ) {
	    /* check alias file */
	    if ( dbp == NULL ) {
		if (( rc = db_open_r( &dbp, SIMTA_ALIAS_DB, NULL )) != 0 ) {
		    syslog( LOG_ERR, "address_local: db_open_r: %s",
			    db_strerror( rc ));
		    *at = '@';
		    return( ADDRESS_SYSERROR );
		}
	    }

	    if ( db_get( dbp, addr, &value ) == 0 ) {
		*at = '@';
		return( ADDRESS_LOCAL );
	    }

	} else if ( strcmp( i->st_key, "password" ) == 0 ) {
	    /* Check password file */
	    if (( passwd = getpwnam( addr )) != NULL ) {
		*at = '@';
		return( ADDRESS_LOCAL );
	    }

#ifdef HAVE_LDAP
	} else if ( strcmp( i->st_key, "ldap" ) == 0 ) {
	    /* Check LDAP */
	    *at = '@';

	    switch ( ldap_address_local( addr ) == ADDRESS_LOCAL ) {
	    default:
		syslog( LOG_ERR,
			"address_local ldap_address_local: bad return value" );
	    case LDAP_SYSERROR:
		return( ADDRESS_SYSERROR );

	    case LDAP_NOT_LOCAL:
		*at = '\0';
		continue;

	    case LDAP_LOCAL:
		return( ADDRESS_LOCAL );
	    }
#endif /* HAVE_LDAP */

	} else {
	    /* unknown lookup */
	    syslog( LOG_ERR, "address_local: %s: unknown expansion",
		    i->st_key );
	    *at = '@';
	    return( ADDRESS_SYSERROR );
	}
    }

    *at = '@';
    return( ADDRESS_NOT_LOCAL );
}


    int
address_expand( char *address, struct recipient *rcpt,
	struct stab_entry **expansion, struct stab_entry **seen )
{
    int			ret;
    int			len;
    char		*user;
    char		*at;
    char		*domain;
    char		*tmp;
    struct passwd	*passwd;
    struct host		*host;
    struct stab_entry	*i;
    FILE		*f;
    DBC			*dbcp = NULL;
    DBT			key;
    DBT			value;
    char		fname[ MAXPATHLEN ];
    /* XXX buf should be large enough to accomodate any valid email address */
    char		buf[ 1024 ];

    syslog( LOG_DEBUG, "address_expand: address %s from rcpt %s\n", address,
	    rcpt->r_rcpt );

    /*
     * Check/correct address for valid syntax
     * Check seen list for address
     * Add address to seen list
     * Check to see if the address has a local domain
     */

    if (( user = strdup( address )) == NULL ) {
	syslog( LOG_ERR, "address_expand: strdup: %m" );
	return( ADDRESS_SYSERROR );
    }

    /* verify and correct user address, check if it's been seen already */
    switch ( is_emailaddr( &user )) {
    case 1:
	/* addr correct, check if we have seen it already */
	if ( ll_lookup( *seen, user ) != NULL ) {
	    free( user );
	    return( ADDRESS_EXCLUDE );

	} else {
	    /* Add user address to seen list */
	    if ( add_address( seen, user, rcpt ) != 0 ) {
		/* add_address syslogs syserrors */
		free( user );
		return( ADDRESS_SYSERROR );
	    }
	}
	break;

    case 0:
	/* address is not syntactically correct, or correctable */
	free( user );
	if ( rcpt_error( rcpt, "bad address format: ", address, NULL ) != 0 ) {
	    /* rcpt_error syslogs syserrors */
	    return( ADDRESS_SYSERROR );
	}
	return( ADDRESS_EXCLUDE );

    default:
	syslog( LOG_ERR, "address_expand is_emailaddr 1: %m" );
	free( user );
	return( ADDRESS_SYSERROR );
    }

    /* Get user and domain, addres should now be valid */
    if (( at = strchr( user, '@' )) == NULL ) {
	syslog( LOG_ERR, "address_expand strchr: @ not found!" );
	free( user );
	return( ADDRESS_SYSERROR );
    }

    *at = '\0';
    domain = at + 1;

    /* Check to see if domain is off the local host */
    if (( host = ll_lookup( simta_hosts, domain )) == NULL ) {
	free( user );
        return( ADDRESS_FINAL );
    }

    /* At this point, we should have a valid address destined for
     * a local domain.  Now we use the expansion table to resolve it.
     */

    /* Expand user using expansion table for domain */
    for ( i = host->h_expansion; i != NULL; i = i->st_next ) {
        if ( strcmp( i->st_key, "alias" ) == 0 ) {
            /* check alias file */
	    memset( &key, 0, sizeof( DBT ));
	    memset( &value, 0, sizeof( DBT ));
	    key.data = user;
	    key.size = strlen( user ) + 1;

	    if ( dbp == NULL ) {
		if (( ret = db_open_r( &dbp, SIMTA_ALIAS_DB, NULL )) != 0 ) {
		    syslog( LOG_ERR, "address_expand: db_open_r: %s",
			    db_strerror( ret ));
		    /* XXX return syserror, or try next expansion? */
		    free( user );
		    return( ADDRESS_SYSERROR );
		}
	    }

	    /* Set cursor and get first result */
	    if (( ret = db_cursor_set( dbp, &dbcp, &key, &value )) != 0 ) {
		if ( ret != DB_NOTFOUND ) {
		    syslog( LOG_ERR, "address_expand: db_cursor_set: %s",
			    db_strerror( ret ));
		    free( user );
		    return( ADDRESS_SYSERROR );
		}

		/* not in alias db, try next expansion */
		continue;
	    }

	    /* until the db says we have no more entries, we:
	     *     - verify that the given address is syntactically correct
	     *     - check to see if the given address is in the seen list
	     *     - add it to the expansion list, if correct and not seen
	     *     - get the next address from the db
	     */

	    for ( ; ; ) {
		if (( tmp = strdup((char*)value.data )) == NULL ) {
		    syslog( LOG_ERR, "address_expand: strdup: %m" );
		    free( user );
		    return( ADDRESS_SYSERROR );
		}

		switch ( is_emailaddr( &tmp )) {
		case 1:
		    /* address correct, check if it's already been seen */
		    if ( ll_lookup( *seen, tmp ) == NULL ) {
			/* Add address from alias file to expansion list */
			if ( add_address( expansion, tmp, rcpt ) != 0 ) {
			    /* add_address syslogs syserrors */
			    free( tmp );
			    free( user );
			    return( ADDRESS_SYSERROR );
			}
		    }
		    free( tmp );
		    break;

		case 0:
		    /* address is not syntactically correct, or correctable */
		    if ( rcpt_error( rcpt, address, " alias db bad address: ",
			    tmp ) != 0 ) {
			/* rcpt_error syslogs syserrors */
			free( tmp );
			free( user );
			return( ADDRESS_SYSERROR );
		    }

		    free( tmp );
		    continue;

		default:
		    syslog( LOG_ERR, "address_expand is_emailaddr 2: %m" );
		    free( tmp );
		    free( user );
		    return( ADDRESS_SYSERROR );
		}

		/* Get next db result, if any */
		memset( &value, 0, sizeof( DBT ));
		if (( ret = db_cursor_next( dbp, &dbcp, &key, &value )) != 0 ) {
		    if ( ret != DB_NOTFOUND ) {
			syslog( LOG_ERR, "address_expand: db_cursor_next: %s",
				db_strerror( ret ));
			free( user );
			return( ADDRESS_SYSERROR );

		    } else {
			/* one or more addresses found in alias db */
			free( user );
			return( ADDRESS_EXCLUDE );
		    }
		}
	    }

        } else if ( strcmp( i->st_key, "password" ) == 0 ) {
            /* Check password file */
	    if (( passwd = getpwnam( user )) == NULL ) {
		/* not in passwd file, try next expansion */
		continue;
	    }

	    /* Check .forward */
	    sprintf( fname, "%s/.forward", passwd->pw_dir );

	    if ( access( fname, R_OK ) == 0 ) {
		/* a .forward file exists */
		if (( f = fopen( fname, "r" )) == NULL ) {
		    syslog( LOG_ERR, "address_expand fopen: %s: %m", fname );
		    free( user );
		    return( ADDRESS_SYSERROR );
		}

		while ( fgets( buf, 1024, f ) != NULL ) {
		    len = strlen( buf );

		    if (( buf[ len - 1 ] ) != '\n' ) {
			/* XXX here we have a .forward line too long */
			free( user );

			if ( fclose( f ) != 0 ) {
			    syslog( LOG_ERR, "address_expand fclose %s: %m",
				    fname );
			    return( ADDRESS_SYSERROR );
			}

			if ( rcpt_error( rcpt, address,
				" .forward: line too long", NULL ) != 0 ) {
			    /* rcpt_error syslogs syserrors */
			    return( ADDRESS_SYSERROR );
			}

			/* tho the .forward is bad, it expanded */
			return( ADDRESS_EXCLUDE );
		    }

		    buf[ len - 1 ] = '\0';

		    if (( tmp = strdup( buf )) == NULL ) {
			syslog( LOG_ERR, "address_expand: strdup: %m" );
			free( user );

			if ( fclose( f ) != 0 ) {
			    syslog( LOG_ERR, "address_expand fclose %s: %m",
				    fname );
			}

			return( ADDRESS_SYSERROR );
		    }

		    switch ( is_emailaddr( &tmp )) {
		    case 1:
			/* address correct, check if it's already been seen */
			if ( ll_lookup( *seen, tmp ) == NULL ) {
			    /* Add .forward address to expansion list */
			    if ( add_address( expansion, tmp, rcpt ) != 0 ) {
				/* add_address syslogs syserrors */
				free( tmp );
				free( user );

				if ( fclose( f ) != 0 ) {
				    syslog( LOG_ERR,
					    "address_expand fclose %s: %m",
					    fname );
				}

				return( ADDRESS_SYSERROR );
			    }
			}
			free( tmp );
			break;

		    case 0:
			/* address is not correct, or correctable */
			free( tmp );

			if ( rcpt_error( rcpt, address,
				" .forward bad address: ", tmp ) != 0 ) {
			    /* rcpt_error syslogs syserrors */
			    free( user );

			    if ( fclose( f ) != 0 ) {
				syslog( LOG_ERR,
					"address_expand fclose %s: %m", fname );
			    }

			    return( ADDRESS_SYSERROR );
			}

			continue;

		    default:
			syslog( LOG_ERR, "address_expand is_emailaddr 3: %m" );
			free( tmp );
			free( user );

			if ( fclose( f ) != 0 ) {
			    syslog( LOG_ERR, "address_expand fclose %s: %m",
				    fname );
			}

			return( ADDRESS_SYSERROR );
		    }
		}

		free( user );

		if ( fclose( f ) != 0 ) {
		    syslog( LOG_ERR, "address_expand fclose %s: %m", fname );
		    return( ADDRESS_SYSERROR );
		}

		return( ADDRESS_EXCLUDE );

	    } else {
		/* No .forward, it's a local address */
		free( user );
		return( ADDRESS_FINAL );
	    }
	}

#ifdef HAVE_LDAP
        else if ( strcmp( i->st_key, "ldap" ) == 0 ) {
	    at = '@';

	    switch ( ldap_expand( user, rcpt, expansion, seen )) {

	    case LDAP_EXCLUDE:
		free( user );
		return( ADDRESS_EXCLUDE );

	    case LDAP_FINAL:
		free( user );
		return( ADDRESS_FINAL );

	    case LDAP_NOT_FOUND:
		at = '\0';
		continue;

	    default:
		syslog( LOG_ERR, "address_expand default ldap switch" );
	    case LDAP_SYSERROR:
		/* XXX make sure a syslog LOG_ERR occurs up the chain */
		free( user );
		return( ADDRESS_SYSERROR );
	    }
	}
#endif /* HAVE_LDAP */

    }

    free( user );

    if ( rcpt_error( rcpt, "address not found: ", address, NULL ) != 0 ) {
	/* rcpt_error syslogs syserrors */
	return( ADDRESS_SYSERROR );
    }

    return( ADDRESS_EXCLUDE );
}
