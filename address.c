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
#include "header.h"
#include "simta.h"
#include "bdb.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */

DB		*dbp = NULL;

void expansion_stab_stdout( void * );

    void
expansion_stab_stdout( void *string )
{
    printf( "%s\n", (char *)string );
}


    /*
     * return non-zero if there is a syserror  
     */

    int
add_address( struct expand *exp, char *addr, struct recipient *addr_rcpt,
	int addr_type )
{
    char			*address;
    struct exp_addr		*e;

    if (( address = strdup( addr )) == NULL ) {
	syslog( LOG_ERR, "add_address: strdup: %m" );
	return( 1 );
    }

    /* make sure we understand what type of address this is, and error check
     * it's syntax if applicable.
     */

    switch ( addr_type ) {

    case ADDRESS_TYPE_EMAIL:
	/* verify and correct address syntax */
	switch ( is_emailaddr( &address )) {
	case 1:
	    /* addr correct, check if we have seen it already */
	    break;

	case 0:
	    /* address is not syntactically correct, or correctable */
	    free( address );
	    if ( rcpt_error( addr_rcpt, "bad email address format: ",
		    address, NULL ) != 0 ) {
		/* rcpt_error syslogs syserrors */
		return( 1 );
	    }
	    return( 0 );

	default:
	    syslog( LOG_ERR, "add_address is_emailaddr: %m" );
	    free( address );
	    return( 1 );
	}
	break;

    #ifdef HAVE_LDAP
    case ADDRESS_TYPE_LDAP:
	break;
    #endif /* HAVE_LDAP */

    default:
	syslog( LOG_ERR, "add_address bad type" );
	free( address );
	return( 1 );
    }

    /* check to see if address is in the expansion list already */
    if ( ll_lookup( exp->exp_addr_list, address ) != NULL ) {
	free( address );
	return( 0 );
    }

    if (( e = (struct exp_addr*)malloc( sizeof( struct exp_addr ))) == NULL ) {
	syslog( LOG_ERR, "add_address: malloc: %m" );
	free( address );
	return( 1 );
    }

    e->e_addr = address;
    e->e_addr_rcpt = addr_rcpt;
    e->e_addr_type = addr_type;

    if ( ll_insert_tail( &(exp->exp_addr_list), address, e ) != 0 ) {
	syslog( LOG_ERR, "add_address: ll_insert_tail: %m" );
	free( address );
	free( e );
	return( 1 );
    }

    return( 0 );
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
address_expand( struct expand *exp, struct exp_addr *e_addr )
{
    char		*at;
    char		*domain;
    struct host		*host = NULL;
    struct stab_entry	*i;
    int			ret;
    int			len;
    struct passwd	*passwd;
    FILE		*f;
    DBC			*dbcp = NULL;
    DBT			key;
    DBT			value;
    char		fname[ MAXPATHLEN ];
    /* XXX buf should be large enough to accomodate any valid email address */
    char		buf[ 1024 ];

    syslog( LOG_DEBUG, "address_expand: address %s from rcpt %s\n",
	    e_addr->e_addr, e_addr->e_addr_rcpt->r_rcpt );

    switch ( e_addr->e_addr_type ) {

    case ADDRESS_TYPE_EMAIL:
	/* Get user and domain, addres should now be valid */
	if (( at = strchr( e_addr->e_addr, '@' )) == NULL ) {
	    syslog( LOG_ERR, "address_expand strchr: @ not found!" );
	    return( ADDRESS_SYSERROR );
	}

	domain = at + 1;

	/* Check to see if domain is off the local host */
	if (( host = ll_lookup( simta_hosts, domain )) == NULL ) {
	    return( ADDRESS_FINAL );
	}
	break;

#ifdef HAVE_LDAP
    case ADDRESS_TYPE_LDAP:
	goto ldap_exclusive;
#endif /*  HAVE_LDAP */

    default:
	syslog( LOG_ERR, "address_expand bad address type" );
	return( ADDRESS_SYSERROR );
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
	    *at = '\0';
	    key.data = e_addr->e_addr;
	    key.size = strlen( key.data ) + 1;

	    if ( dbp == NULL ) {
		if (( ret = db_open_r( &dbp, SIMTA_ALIAS_DB, NULL )) != 0 ) {
		    syslog( LOG_ERR, "address_expand: db_open_r: %s",
			    db_strerror( ret ));
		    /* XXX return syserror, or try next expansion? */
		    *at = '@';
		    return( ADDRESS_SYSERROR );
		}
	    }

	    /* Set cursor and get first result */
	    if (( ret = db_cursor_set( dbp, &dbcp, &key, &value )) != 0 ) {
		if ( ret != DB_NOTFOUND ) {
		    syslog( LOG_ERR, "address_expand: db_cursor_set: %s",
			    db_strerror( ret ));
		    *at = '@';
		    return( ADDRESS_SYSERROR );
		}

		/* not in alias db, try next expansion */
		*at = '@';
		continue;
	    }

	    for ( ; ; ) {
		if ( add_address( exp, (char*)value.data,
			e_addr->e_addr_rcpt,  ADDRESS_TYPE_EMAIL ) != 0 ) {
		    /* add_address syslogs errors */
		    *at = '@';
		    return( ADDRESS_SYSERROR );
		}

		/* Get next db result, if any */
		memset( &value, 0, sizeof( DBT ));
		if (( ret = db_cursor_next( dbp, &dbcp, &key, &value )) != 0 ) {
		    if ( ret != DB_NOTFOUND ) {
			syslog( LOG_ERR, "address_expand: db_cursor_next: %s",
				db_strerror( ret ));
			*at = '@';
			return( ADDRESS_SYSERROR );

		    } else {
			/* one or more addresses found in alias db */
			*at = '@';
			return( ADDRESS_EXCLUDE );
		    }
		}
	    }

        } else if ( strcmp( i->st_key, "password" ) == 0 ) {
            /* Check password file */
	    *at = '\0';
	    passwd = getpwnam( e_addr->e_addr );
	    *at = '@';

	    if ( passwd == NULL ) {
		/* not in passwd file, try next expansion */
		continue;
	    }

	    /* Check .forward */
	    sprintf( fname, "%s/.forward", passwd->pw_dir );

	    if ( access( fname, R_OK ) == 0 ) {
		/* a .forward file exists */
		if (( f = fopen( fname, "r" )) == NULL ) {
		    syslog( LOG_ERR, "address_expand fopen: %s: %m", fname );
		    return( ADDRESS_SYSERROR );
		}

		while ( fgets( buf, 1024, f ) != NULL ) {
		    len = strlen( buf );

		    if (( buf[ len - 1 ] ) != '\n' ) {
			/* XXX here we have a .forward line too long */

			if ( fclose( f ) != 0 ) {
			    syslog( LOG_ERR, "address_expand fclose %s: %m",
				    fname );
			    return( ADDRESS_SYSERROR );
			}

			if ( rcpt_error( e_addr->e_addr_rcpt, e_addr->e_addr,
				" .forward: line too long", NULL ) != 0 ) {
			    /* rcpt_error syslogs syserrors */
			    return( ADDRESS_SYSERROR );
			}

			/* tho the .forward is bad, it expanded */
			return( ADDRESS_EXCLUDE );
		    }

		    buf[ len - 1 ] = '\0';

		    if ( add_address( exp, buf,
			    e_addr->e_addr_rcpt, ADDRESS_TYPE_EMAIL ) != 0 ) {
			/* add_address syslogs errors */

			if ( fclose( f ) != 0 ) {
			    syslog( LOG_ERR, "address_expand fclose %s: %m",
				    fname );
			}

			return( ADDRESS_SYSERROR );
		    }
		}

		return( ADDRESS_EXCLUDE );

	    } else {
		/* No .forward, it's a local address */
		return( ADDRESS_FINAL );
	    }
	}

#ifdef HAVE_LDAP
        else if ( strcmp( i->st_key, "ldap" ) == 0 ) {
ldap_exclusive:
	    switch ( ldap_expand( exp, e_addr )) {

	    case LDAP_EXCLUDE:
		return( ADDRESS_EXCLUDE );

	    case LDAP_FINAL:
		/* XXX if its in the db, can it be terminal? */
		return( ADDRESS_FINAL );

	    case LDAP_NOT_FOUND:
		if ( host == NULL ) {
		    /* data is exclusively for ldap */
		    break;
		}
		continue;

	    default:
		syslog( LOG_ERR, "address_expand default ldap switch" );
	    case LDAP_SYSERROR:
		/* XXX make sure a syslog LOG_ERR occurs up the chain */
		return( ADDRESS_SYSERROR );
	    }
	}
#endif /* HAVE_LDAP */

    }

    if ( rcpt_error( e_addr->e_addr_rcpt, "address not found: ",
	    e_addr->e_addr, NULL ) != 0 ) {
	/* rcpt_error syslogs syserrors */
	return( ADDRESS_SYSERROR );
    }

    return( ADDRESS_EXCLUDE );
}
