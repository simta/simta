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

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

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

DB		*dbp = NULL;

int verify_and_correct_address( char **address, struct recipient *rcpt );

    void
expansion_stab_stdout( void *string )
{
    printf( "%s\n", (char *)string );
}

    int
verify_and_correct_address( char **address, struct recipient *rcpt )
{
    int		ret;
    char	err_text[ SIMTA_MAX_LINE_LEN ];

    /* verify and correct address */
    ret = is_emailaddr( address );

    switch( ret ) {
    case 1:
	/* address was correct, or corrected */
	break;

    case 0:
	/* address is not syntactically correct, or correctable */
	if ( rcpt->r_text == NULL ) {
	    if (( rcpt->r_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "verify_and_correct_address:"
		" line_file_create: %m" );
		return( -1 );
	    }
	}
	if ( snprintf( err_text, SIMTA_MAX_LINE_LEN, "%s: Invalid e-mail\n",
		*address ) >= SIMTA_MAX_LINE_LEN ) {
	    syslog( LOG_ERR,
		"verify_and_correct_address: snprintf: attempted buffer"
		" overflow" );
	    return( -1 );
	}
	if ( simta_debug ) printf( "added err_text for %s: %s\n",
	    rcpt->r_rcpt, err_text );
	if ( line_append( rcpt->r_text, err_text ) == NULL ) {
	    syslog( LOG_ERR, "verify_and_correct_address: line_append: %m" );
	    return( -1 );
	}
	rcpt->r_delivered = R_FAILED;
	return( 0 );

    default:
	/* syserror */
	syslog( LOG_ERR, "verify_and_correct_address: is_emailaddr: %m" );
	return( -1 );
    }

    return( 1 );
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
address_expand( char *address, struct recipient *rcpt,
    struct stab_entry **expansion, struct stab_entry **seen, int *ae_error)
{
    int			rc, ret = 0, count = 0, len = 0;
    char		*user = NULL, *domain = NULL;
    char		*address_local = NULL;
    char		*temp = NULL;
    char		buf[ MAXPATHLEN * 2 ];
    char		err_text[ SIMTA_MAX_LINE_LEN ];
    struct passwd	*passwd = NULL;
    DBC			*dbcp = NULL;
    DBT			key, value;
    struct host		*host = NULL;
    struct stab_entry	*i = NULL;
    FILE		*f;

    *ae_error = SIMTA_EXPAND_ERROR_NONE;

    memset( err_text, 0, SIMTA_MAX_LINE_LEN );

    /* Check if we have seen addr already */
    if ( ll_lookup( *seen, address ) != NULL ) {
	/* Already expanded */
	if ( simta_debug ) printf( "%s: already seen\n", address );

	*ae_error = SIMTA_EXPAND_ERROR_SEEN;
	return( 0 );
    } else {
	/* Add address to seen list */
	if ( add_address( seen, address, rcpt ) != 0 ) {
	    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
	    return( -1 );
	}
	if ( simta_debug ) printf( "%s new: added to seen\n", address );
    }

    /* Duplicate address for parsing */
    /* XXX - Must free */
    if (( user = strdup( address )) == NULL ) {
	syslog( LOG_ERR, "address_expand: strdup: %m" );
	*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
	return( -1 );
    }

    /* verify and correct address */
    rc = verify_and_correct_address( &user, rcpt );
    switch( rc ) {
    case 1:
	/* address was correct, or corrected */
	break;
    case 0:
	/* address is not syntactically correct, or correctable */
	*ae_error = SIMTA_EXPAND_ERROR_BAD_FORMAT;
	return( 0 );
    default:
	/* syserror */
	*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
	return( -1 );
    }

    /* Get user and domain */
    if (( domain = strchr( user, '@' )) == NULL ) {
	syslog( LOG_ERR, "address_expand: strchr: %s: invalid address",
	    address_local );
	*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
        return( -1 );
    }
    *domain = '\0';
    domain++;

    /* Check to see if domain is off the local host */
    if (( host = ll_lookup( simta_hosts, domain )) == NULL ) {
	if ( simta_debug ) printf( "%s: no expansion ( off host )\n",
	    address );

	*ae_error = SIMTA_EXPAND_ERROR_OFF_HOST;
        return( 0 );
    }

    /* Expand user using expansion table for domain */
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
		    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
		    return( -1 );
		}
	    }

	    /* Set cursor and get first result */
	    if (( ret = db_cursor_set( dbp, &dbcp, &key, &value )) != 0 ) {
		if ( ret != DB_NOTFOUND ) {
		    syslog( LOG_ERR, "address_expand: db_cursor_set: %s",
			db_strerror( ret ));
		    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
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
		/* Add expansion to expansion */
		if ( add_address( expansion, buf, rcpt ) != 0 ) {
		    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
		    return( -1 );
		}
		if ( simta_debug ) printf( "%s new: added to expansion"
		    " ( from alias db )\n", buf );
		count++;
	    } else {
		/* Already has been seen */
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
		    /* Add expansion to expansion */
		    if ( add_address( expansion, buf, rcpt ) != 0 ) {
			*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
			return( -1 );
		    }
		    if ( simta_debug ) printf( "%s new: added to expansion"
			" ( from alias db )\n", buf );
		    count++;
		} else {
		    /* Already has been seen */
		    continue;
		}

		memset( &value, 0, sizeof( DBT ));
	    }

	    if ( ret != DB_NOTFOUND ) {
		syslog( LOG_ERR, "address_expand: db_cursor_next: %s",
		    db_strerror( ret ));
		*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
		return( -1 );
	    }

	    if ( count != 0 ) {
		break;
	    }

        } else if ( strcmp( i->st_key, "password" ) == 0 ) {
	    if ( simta_debug ) printf( "checking password file for %s...",
		user );

            /* Check password file */
	    if (( passwd = getpwnam( user )) == NULL ) {
		if ( simta_debug ) printf( "not found\n" );
		continue;
	    }
	    if ( simta_debug ) printf( "found\n" );

	    /* Check .forward */
	    memset( buf, 0, MAXPATHLEN * 2 );
	    sprintf( buf, "%s/.forward", passwd->pw_dir );

	    if ( access( buf, R_OK ) == 0 ) {
		if (( f =  fopen( buf, "r" )) == NULL ) {
		    syslog( LOG_ERR, "address_expand: fopen: %s: %m", buf );
		    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
		    return( -1 );
		}
		while ( fgets( buf, MAXPATHLEN, f ) != NULL ) {

		    len = strlen( buf );
		    if (( buf[ len - 1 ] ) != '\n' ) {
			/* XXX - should this be an error? */
			continue;
		    }
		    buf[ len - 1 ] = '\0';

		    if (( temp = strdup( buf )) == NULL ) {
			syslog( LOG_ERR, "address_expand: strdup: %m" );
			*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
			return( -1 );
		    }

		    /* verify and correct address */
		    rc = verify_and_correct_address( &temp, rcpt );
		    switch( rc ) {
		    case 1:
			/* address was correct, or corrected */
			break;
		    case 0:
			/* address is not syntactically correct, or
			 * correctable
			 */
			*ae_error = SIMTA_EXPAND_ERROR_BAD_FORMAT;
			return( 0 );
		    default:
			/* syserror */
			*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
			return( -1 );
		    }

		    /* Check to see if we have seen this address before to
		     * prevent it from being expanded again 
		     */
		    if ( ll_lookup( *seen, temp ) == NULL ) {
			/* Add address to expansion list */
			if ( add_address( expansion, temp, rcpt ) != 0 ) {
			    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
			    return( -1 );
			}
			if ( simta_debug ) printf( "%s new: added to"
			    " expansion ( in .forward )\n", temp);
			count++;
		    } else {
			continue;
		    }
		}
	    } else {
		/* No .forward, so don't do anything */
		if ( simta_debug ) printf( "%s: local\n", address );
		return( 0 );
	    }
        }
    }

    /* If no expansion was found at this point, the domain is local
     * but the user was not found - we need to set an error
     * message in the parent rcpt that includs this failed address.
     */
    if ( count == 0 ) {
	*ae_error = SIMTA_EXPAND_ERROR_NOT_LOCAL;

	if ( rcpt->r_text == NULL ) {
	    if (( rcpt->r_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR, "address_expand: line_file_create: %m" );
		*ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
		return( -1 );
	    }
	}
	if ( snprintf( err_text, SIMTA_MAX_LINE_LEN, "%s: User unknown\n",
		address ) >= SIMTA_MAX_LINE_LEN ) {
	    syslog( LOG_ERR,
		"address_expand: snprintf: attempted buffer overflow" );
	    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
	    return( -1 );
	}
	if ( simta_debug ) printf( "added err_text for %s: %s\n",
	    rcpt->r_rcpt, err_text );
	if ( line_append( rcpt->r_text, err_text )
		== NULL ) {
	    syslog( LOG_ERR, "address_expand: line_append: %m" );
	    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
	    return( -1 );
	}
	rcpt->r_delivered = R_FAILED;
    }

    if ( dbp != NULL ) {
	if (( ret = db_cursor_close( dbcp )) != 0 ) {
	    syslog( LOG_ERR, "address_expand: db_cursor_close: %s",
		db_strerror( ret ));
	    *ae_error = SIMTA_EXPAND_ERROR_SYSTEM;
	    return( -1 );
	}
    }

    free( address_local );
    return( count );
}
