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

#include "denser.h"
#include "line_file.h"
#include "queue.h"
#include "ll.h"
#include "envelope.h"
#include "expand.h"
#include "header.h"
#include "simta.h"
#include "bdb.h"
#include "bounce.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "simta_ldap.h"
#endif /* HAVE_LDAP */


    void
expand_tree_stdout( struct exp_addr *e, int i )
{
    int				x;

    if ( e != NULL ) {
	for ( x = 0; x < i; x++ ) {
	    printf( " " );
	}
	printf( "%x %s\n", e, e->e_addr );

#ifdef HAVE_LDAP
	expand_tree_stdout( e->e_addr_child, i + 1 );
	expand_tree_stdout( e->e_addr_peer, i );
#endif /* HAVE_LDAP */
    }
}


    struct envelope *
address_bounce_create( struct expand *exp )
{
    struct envelope		*bounce_env;

    if (( bounce_env = env_create( NULL )) == NULL ) {
	return( NULL );
    }

    if ( env_gettimeofday_id( bounce_env ) != 0 ) {
	env_free( bounce_env );
	return( NULL );
    }

    if ( env_sender( bounce_env, NULL ) != 0 ) {
	env_free( bounce_env );
	return( NULL );
    }

    bounce_env->e_dir = simta_dir_fast;
    bounce_env->e_next = exp->exp_errors;
    exp->exp_errors = bounce_env;

    return( bounce_env );
}


    /*
     * return non-zero if there is a syserror  
     */

    int
add_address( struct expand *exp, char *addr, struct envelope *error_env,
	int addr_type )
{
    char			*address;
    struct exp_addr		*e;
#ifdef HAVE_LDAP
    struct exp_addr		*parent;
#endif /* HAVE_LDAP */

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
	    if ( bounce_text( error_env, "bad email address format: ",
		    address, NULL ) != 0 ) {
		free( address );
		return( 1 );
	    }
	    free( address );
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

    if (( e = (struct exp_addr*)ll_lookup( exp->exp_addr_list, address ))
	    == NULL ) {
	if (( e = (struct exp_addr*)malloc( sizeof( struct exp_addr )))
		== NULL ) {
	    syslog( LOG_ERR, "add_address: malloc: %m" );
	    free( address );
	    return( 1 );
	}
	memset( e, 0, sizeof( struct exp_addr ));

	e->e_addr = address;
	e->e_addr_errors = error_env;
	e->e_addr_type = addr_type;

	if ( ll_insert_tail( &(exp->exp_addr_list), address, e ) != 0 ) {
	    syslog( LOG_ERR, "add_address: ll_insert_tail: %m" );
	    free( address );
	    free( e );
	    return( 1 );
	}

#ifdef HAVE_LDAP
	if (( addr_type == ADDRESS_TYPE_EMAIL ) &&
		( exp->exp_env->e_mail != NULL )) {
	    /* compare the address in hand with the sender */
	    if ( simta_mbx_compare( address, exp->exp_env->e_mail ) == 0 ) {
		/* here we have a match */
		e->e_addr_status = ( e->e_addr_status | STATUS_EMAIL_SENDER );
	    }
	}
#endif /* HAVE_LDAP */

#ifdef HAVE_LDAP
	e->e_addr_child = NULL;
	if ( exp->exp_parent == NULL ) {
	    e->e_addr_parent = NULL;
	    e->e_addr_peer = exp->exp_root;
	    exp->exp_root = e;
	} else {
	    e->e_addr_parent = exp->exp_parent;
	    e->e_addr_peer = exp->exp_parent->e_addr_child;
	    exp->exp_parent->e_addr_child = e;
	}
#endif /* HAVE_LDAP */

    } else {
	/* free local address and use the previously allocated one */
	free( address );
    }

#ifdef HAVE_LDAP
    if (( e->e_addr_status & STATUS_EMAIL_SENDER ) != 0 ) {
	for ( parent = exp->exp_parent; parent != NULL;
		parent = parent->e_addr_parent ) {
	    parent->e_addr_status =
		    ( parent->e_addr_status | STATUS_EMAIL_SENDER );
	}
    }
#endif /* HAVE_LDAP */

    return( 0 );
}


    int
address_expand( struct expand *exp, struct exp_addr *e_addr )
{
    struct host		*host = NULL;
    struct stab_entry	*s;

    switch ( e_addr->e_addr_type ) {
    case ADDRESS_TYPE_EMAIL:
	/* Get user and domain, addres should now be valid */
	if (( e_addr->e_addr_at = strchr( e_addr->e_addr, '@' )) == NULL ) {
	    /* XXX case sensitive? */
	    if (( *(e_addr->e_addr) != '\0' ) && ( strcmp( "postmaster",
		    e_addr->e_addr ) != 0 )) {
		syslog( LOG_ERR,
			"address_expand <%s>: ERROR bad address format",
			e_addr->e_addr );
		return( ADDRESS_SYSERROR );
	    }
	} else {

	    if ( strlen( e_addr->e_addr_at + 1 ) > MAXHOSTNAMELEN ) {
		syslog( LOG_ERR, "address_expand <%s>: ERROR domain too long",
			e_addr->e_addr );
		return( ADDRESS_SYSERROR );
	    }

	    /* Check to see if domain is off the local host */
	    if (( host = ll_lookup( simta_hosts, e_addr->e_addr_at + 1 ))
		    == NULL ) {
		syslog( LOG_DEBUG,
			"address_expand <%s> FINAL: domain not local",
			e_addr->e_addr );
		return( ADDRESS_FINAL );
	    }
	}
	break;

#ifdef HAVE_LDAP
    case ADDRESS_TYPE_LDAP:
	syslog( LOG_DEBUG, "address_expand <%s>: ldap data", e_addr->e_addr );
	goto ldap_exclusive;
#endif /*  HAVE_LDAP */

    default:
	panic( "address_expand: address type out of range" );
    }

    /* At this point, we should have a valid address destined for
     * a local domain.  Now we use the expansion table to resolve it.
     */

    /* Expand user using expansion table for domain */
    for ( s = host->h_expansion; s != NULL; s = s->st_next ) {
	switch ( s->st_key ) {
	case EXPANSION_TYPE_ALIAS:
	    switch ( alias_expand( exp, e_addr )) {
	    case ALIAS_EXCLUDE:
		syslog( LOG_DEBUG, "address_expand <%s> EXPANDED: alias",
			e_addr->e_addr );
		return( ADDRESS_EXCLUDE );

	    case ALIAS_NOT_FOUND:
		syslog( LOG_DEBUG, "address_expand <%s>: not in alias file",
			e_addr->e_addr );
		continue;

	    case ALIAS_SYSERROR:
		return( ADDRESS_SYSERROR );

	    default:
		panic( "address_expand default alias switch" );
	    }

	case EXPANSION_TYPE_PASSWORD:
	    switch ( password_expand( exp, e_addr )) {
	    case PASSWORD_EXCLUDE:
		syslog( LOG_DEBUG, "address_expand <%s> EXPANDED: password",
			e_addr->e_addr );
		return( ADDRESS_EXCLUDE );

	    case PASSWORD_FINAL:
		syslog( LOG_DEBUG, "address_expand <%s> FINAL: password",
			e_addr->e_addr );
		return( ADDRESS_FINAL );

	    case PASSWORD_NOT_FOUND:
		syslog( LOG_DEBUG, "address_expand <%s>: not in password file",
			e_addr->e_addr );
		continue;

	    case PASSWORD_SYSERROR:
		return( ADDRESS_SYSERROR );

	    default:
		panic( "address_expand default password switch" );
	    }

#ifdef HAVE_LDAP
        case EXPANSION_TYPE_LDAP:
ldap_exclusive:
	    switch ( simta_ldap_expand( exp, e_addr )) {
	    case LDAP_EXCLUDE:
		syslog( LOG_DEBUG, "address_expand <%s> EXPANDED: ldap",
			e_addr->e_addr );
		return( ADDRESS_EXCLUDE );

	    case LDAP_FINAL:
		syslog( LOG_DEBUG, "address_expand <%s> FINAL: ldap",
			e_addr->e_addr );
		return( ADDRESS_FINAL );

	    case LDAP_NOT_FOUND:
		syslog( LOG_DEBUG, "address_expand <%s>: not in ldap db",
			e_addr->e_addr );
		if ( host == NULL ) {
		    /* data is exclusively for ldap, and it didn't find it */
		    goto not_found;
		}
		continue;

	    case LDAP_SYSERROR:
		return( ADDRESS_SYSERROR );

	    default:
		panic( "address_expand ldap_expand out of range" );
	    }
#endif /* HAVE_LDAP */
	    
	    default:
		panic( "address_expand expansion type out of range" );
	}
    }

#ifdef HAVE_LDAP
not_found:
#endif /* HAVE_LDAP */

    /* If we can't resolve the local postmaster's address, expand it to
     * the dead queue.
     */
    if ( e_addr->e_addr_at == NULL ) {
	e_addr->e_addr_type = ADDRESS_TYPE_DEAD;
	syslog( LOG_ERR, "address_expand <%s> FINAL: can't resolve local "
		"postmaster, expanding to dead queue", e_addr->e_addr );
	return( ADDRESS_FINAL );
    }

    syslog( LOG_DEBUG, "address_expand <%s> FINAL: not found", e_addr->e_addr );

    if ( bounce_text( e_addr->e_addr_errors, "address not found: ",
	    e_addr->e_addr, NULL ) != 0 ) {
	/* bounce_text syslogs errors */
	return( ADDRESS_SYSERROR );
    }

    return( ADDRESS_EXCLUDE );
}


    int
password_expand( struct expand *exp, struct exp_addr *e_addr )
{
    int			ret;
    int			len;
    FILE		*f;
    struct passwd	*passwd;
    char		fname[ MAXPATHLEN ];
    char		buf[ 1024 ];

    /* Check password file */
    if ( e_addr->e_addr_at != NULL ) {
	*(e_addr->e_addr_at) = '\0';
	passwd = getpwnam( e_addr->e_addr );
	*(e_addr->e_addr_at) = '@';
    } else {
	passwd = getpwnam( "postmaster" );
    }

    if ( passwd == NULL ) {
	/* not in passwd file, try next expansion */
	syslog( LOG_DEBUG, "address_expand <%s>: not in passwd file",
		e_addr->e_addr );
	return( PASSWORD_NOT_FOUND );
    }

    /* Check .forward */
    sprintf( fname, "%s/.forward", passwd->pw_dir );

    if ( access( fname, R_OK ) != 0 ) {
	/* No .forward, it's a local address */
	syslog( LOG_DEBUG, "address_expand <%s> FINAL: passwd file",
		e_addr->e_addr );
	return( PASSWORD_FINAL );

    } else {
	/* a .forward file exists */
	if (( f = fopen( fname, "r" )) == NULL ) {
	    syslog( LOG_ERR, "address_expand fopen: %s: %m", fname );
	    return( PASSWORD_NOT_FOUND );
	}

	while ( fgets( buf, 1024, f ) != NULL ) {
	    len = strlen( buf );
	    if (( buf[ len - 1 ] ) != '\n' ) {
		/* here we have a .forward line too long */
		if ( bounce_text( e_addr->e_addr_errors,
			e_addr->e_addr, " .forward: line too long",
			NULL ) != 0 ) {
		    /* bounce_text syslogs errors */
		    return( PASSWORD_SYSERROR );
		}

		syslog( LOG_WARNING,
			"address_expand <%s>: .forward line too long",
			e_addr->e_addr );
		ret = PASSWORD_NOT_FOUND;
		goto cleanup_forward;
	    }

	    buf[ len - 1 ] = '\0';

	    if ( add_address( exp, buf,
		    e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL ) != 0 ) {
		/* add_address syslogs errors */
		ret = PASSWORD_SYSERROR;
		goto cleanup_forward;
	    }

	    syslog( LOG_DEBUG,
		    "address_expand <%s> EXPANDED <%s>: .forward",
		    e_addr->e_addr, buf );
	    ret = PASSWORD_EXCLUDE;
	}

cleanup_forward:
	if ( fclose( f ) != 0 ) {
	    syslog( LOG_ERR, "address_expand fclose %s: %m",
		    fname );
	    return( PASSWORD_SYSERROR );
	}

	return( ret );
    }
}


    int
alias_expand( struct expand *exp, struct exp_addr *e_addr )
{
    int			ret;
    DBC			*dbcp = NULL;
    DBT			key;
    DBT			value;

    if ( simta_dbp == NULL ) {
	if (( ret = db_open_r( &simta_dbp, SIMTA_ALIAS_DB, NULL ))
		!= 0 ) {
	    syslog( LOG_ERR, "address_expand: db_open_r: %s",
		    db_strerror( ret ));
	    return( ALIAS_NOT_FOUND );
	}
    }

    /* Set cursor and get first result */
    memset( &key, 0, sizeof( DBT ));
    memset( &value, 0, sizeof( DBT ));

    if ( e_addr->e_addr_at != NULL ) {
	*(e_addr->e_addr_at) = '\0';
	key.data = e_addr->e_addr;
    } else {
	key.data = "postmaster";
    }

    key.size = strlen( key.data ) + 1;

    if (( ret = db_cursor_set( simta_dbp, &dbcp, &key, &value ))
	    != 0 ) {
	if ( ret != DB_NOTFOUND ) {
	    syslog( LOG_ERR, "address_expand: db_cursor_set: %s",
		    db_strerror( ret ));
	    if ( e_addr->e_addr_at != NULL ) {
		*(e_addr->e_addr_at) = '@';
	    }
	    return( ALIAS_NOT_FOUND );
	}

	/* not in alias db, try next expansion */
	syslog( LOG_DEBUG, "address_expand <%s>: not in alias db",
		e_addr->e_addr );
	if ( e_addr->e_addr_at != NULL ) {
	    *(e_addr->e_addr_at) = '@';
	}
	return( ALIAS_NOT_FOUND );
    }

    for ( ; ; ) {
	if ( add_address( exp, (char*)value.data,
		e_addr->e_addr_errors,  ADDRESS_TYPE_EMAIL ) != 0 ) {
	    /* add_address syslogs errors */
	    if ( e_addr->e_addr_at != NULL ) {
		*(e_addr->e_addr_at) = '@';
	    }
	    return( ALIAS_SYSERROR );
	}

	syslog( LOG_DEBUG, "address_expand <%s> EXPANDED <%s>: alias db",
		e_addr->e_addr, (char*)value.data );

	/* Get next db result, if any */
	memset( &value, 0, sizeof( DBT ));
	if (( ret = db_cursor_next( simta_dbp, &dbcp, &key, &value ))
		!= 0 ) {
	    if ( ret != DB_NOTFOUND ) {
		syslog( LOG_ERR, "address_expand: db_cursor_next: %s",
			db_strerror( ret ));
		if ( e_addr->e_addr_at != NULL ) {
		    *(e_addr->e_addr_at) = '@';
		}
		return( ALIAS_NOT_FOUND );

	    } else {
		/* one or more addresses found in alias db */
		if ( e_addr->e_addr_at != NULL ) {
		    *(e_addr->e_addr_at) = '@';
		}
		return( ALIAS_EXCLUDE );
	    }
	}
    }
}

#ifdef HAVE_LDAP

    int
ok_list_add( struct expand *exp, struct exp_addr *exclusive, char *ok_addr )
{
    return( 0 );
}


    int
exclusive_check( struct expand *exp, struct exp_addr *exclusive )
{
    return( 0 );
}

#endif /* HAVE_LDAP */
