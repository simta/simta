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

#include "mx.h"
#include "denser.h"
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

    if ( env_id( bounce_env ) != 0 ) {
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


    int
address_string_recipients( struct expand *exp, char *line,
	struct exp_addr *e_addr, char *from )
{
    char				*start;
    char				*comma;
    char				*end;
    char				*email_start;
    char				swap;

    if (( start = skip_cws( line )) == NULL ) {
	return( 0 );
    }

    for ( ; ; ) {
	if (( *start != '"' ) && ( *start != '<' )) {
	    if (( end = token_dot_atom( start )) == NULL ) {
		return( 0 );
	    }

	    if ( *(end+1) == '@' ) {
		/* Consume sender@domain [,]*/
		email_start = start;
		start = end + 2;

		if ( *start == '[' ) {
		    if (( end = token_domain_literal( start )) == NULL ) {
			return( 0 );
		    }
		} else {
		    if (( end = token_domain( start )) == NULL ) {
			return( 0 );
		    }
		}

		end++;
		swap = *end;
		*end = '\0';

		if ( add_address( exp, email_start, e_addr->e_addr_errors,
			ADDRESS_TYPE_EMAIL, from ) != 0 ) {
		    *end = swap;
		    return( 1 );
		}

		*end = swap;

		if (( comma = skip_cws( end )) == NULL ) {
		    return( 0 );
		}

		if ( *comma != ',' ) {
		    return( 0 );
		}

		if (( start = skip_cws( comma + 1 )) == NULL ) {
		    return( 0 );
		}

		continue;
	    }

	    if (( start = skip_cws( end + 1 )) == NULL ) {
		return( 0 );
	    }
	}

	while ( *start != '<' ) {
	    if ( *start == '"' ) {
		if (( end = token_quoted_string( start )) == NULL ) {
		    return( 0 );
		}

	    } else {
		if (( end = token_dot_atom( start )) == NULL ) {
		    return( 0 );
		}
	    }

	    if (( start = skip_cws( end + 1 )) == NULL ) {
		return( 0 );
	    }
	}

	email_start = start + 1;
	for ( end = start + 1; *end != '>'; end++ ) {
	    if ( *end == '\0' ) {
		return( 0 );
	    }
	}

	*end = '\0';

	if ( add_address( exp, email_start, e_addr->e_addr_errors,
		ADDRESS_TYPE_EMAIL, from ) != 0 ) {
	    *end = '>';
	    return( 1 );
	}

	*end = '>';

	if (( comma = skip_cws( end + 1 )) == NULL ) {
	    return( 0 );
	}

	if ( *comma != ',' ) {
	    return( 0 );
	}

	if (( start = skip_cws( comma + 1 )) == NULL ) {
	    return( 0 );
	}
    }

    return( 0 );
}


    /*
     * return non-zero if there is a syserror  
     */

    int
add_address( struct expand *exp, char *addr, struct envelope *error_env,
	int addr_type, char *from )
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
	break;

#ifdef HAVE_LDAP
    case ADDRESS_TYPE_LDAP:
	break;
#endif /* HAVE_LDAP */

    default:
	panic( "add_address type out of range" );
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

	if (( e->e_addr_from = strdup( from )) == NULL ) {
	    syslog( LOG_ERR, "strdup: %m" );
	    free( address );
	    free( e );
	    return( 1 );
	}

	if ( ll_insert_tail( &(exp->exp_addr_list), address, e ) != 0 ) {
	    syslog( LOG_ERR, "add_address: ll_insert_tail: %m" );
	    free( address );
	    free( e->e_addr_from );
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
    struct expansion	*expansion_list;

    switch ( e_addr->e_addr_type ) {
    case ADDRESS_TYPE_EMAIL:
	/* Get user and domain, address should now be valid */
	if (( e_addr->e_addr_at = strchr( e_addr->e_addr, '@' )) == NULL ) {
	    if (( *(e_addr->e_addr) != '\0' ) && ( strcasecmp( "postmaster",
		    e_addr->e_addr ) != 0 )) {
		syslog( LOG_ERR,
			"address_expand <%s>: ERROR bad address format",
			e_addr->e_addr );
		return( ADDRESS_SYSERROR );
	    } else {
		host = simta_default_host;
	    }
	} else {
	    if ( strlen( e_addr->e_addr_at + 1 ) > MAXHOSTNAMELEN ) {
		syslog( LOG_ERR, "address_expand <%s>: ERROR domain too long",
			e_addr->e_addr );
		return( ADDRESS_SYSERROR );
	    }

	    /* Check to see if domain is off the local host */
	    if (( host = host_local( e_addr->e_addr_at + 1 )) == NULL ) {
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
    for ( expansion_list = host->h_expansion; expansion_list != NULL;
	    expansion_list = expansion_list->e_next ) {
	switch ( expansion_list->e_type) {
	/* Other types might include files, pipes, etc */
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
	    if ( e_addr->e_addr_at == NULL ) {
		continue;
	    }

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
    if (( e_addr->e_addr_at == NULL ) || ( strncasecmp( e_addr->e_addr,
	    "postmaster", e_addr->e_addr_at - e_addr->e_addr ) == 0 )) {
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
    int			linetoolong = 0;
    FILE		*f;
    struct passwd	*passwd;
    char		fname[ MAXPATHLEN ];
    char		buf[ 1024 ];

    /* Check password file */
    if ( e_addr->e_addr_at != NULL ) {
	*e_addr->e_addr_at = '\0';
	passwd = getpwnam( e_addr->e_addr );
	*e_addr->e_addr_at = '@';
    } else {
	passwd = getpwnam( "postmaster" );
    }

    if ( passwd == NULL ) {
	/* not in passwd file, try next expansion */
	syslog( LOG_DEBUG, "password_expand <%s>: not in passwd file",
		e_addr->e_addr );
	return( PASSWORD_NOT_FOUND );
    }

    ret = PASSWORD_FINAL;

    /* Check .forward */
    if ( snprintf( fname, MAXPATHLEN, "%s/.forward",
	    passwd->pw_dir ) >= MAXPATHLEN ) {
	syslog( LOG_ERR, "password_expand <%s>: .forward path to long",
	    e_addr->e_addr );
	return( PASSWORD_FINAL );
    }

    if (( f = fopen( fname, "r" )) == NULL ) {
	switch( errno ) {
	case EACCES:
	case ENOENT:
	case ENOTDIR:
	case ELOOP:
	    syslog( LOG_DEBUG, "password_expand <%s>: no .forward",
		    e_addr->e_addr );
	    return( PASSWORD_FINAL );

	default:
	    syslog( LOG_ERR, "password_expand fopen: %s: %m", fname );
	    return( PASSWORD_SYSERROR );
	}
    }

    /* XXX - Do we have a defined max e-mail length? */
    while ( fgets( buf, 1024, f ) != NULL ) {
	len = strlen( buf );
	if (( buf[ len - 1 ] ) != '\n' ) {
	    linetoolong = 1;
	    continue;
	}

	if ( linetoolong ) {
	    syslog( LOG_WARNING, "password_expand <%s>: .forward line too long",
		    e_addr->e_addr );
	    linetoolong = 0;
	} else {
	    buf[ len - 1 ] = '\0';

	    if ( add_address( exp, buf, e_addr->e_addr_errors,
		    ADDRESS_TYPE_EMAIL, e_addr->e_addr_from ) != 0 ) {
		/* add_address syslogs errors */
		ret = PASSWORD_SYSERROR;
		goto cleanup_forward;
	    }

	    syslog( LOG_DEBUG, "password_expand <%s> EXPANDED <%s>: .forward",
		    e_addr->e_addr, buf );
	    ret = PASSWORD_EXCLUDE;
	}
    }

cleanup_forward:
    if ( fclose( f ) != 0 ) {
	syslog( LOG_ERR, "password_expand fclose %s: %m", fname );
	return( PASSWORD_SYSERROR );
    }

    return( ret );
}


    int
alias_expand( struct expand *exp, struct exp_addr *e_addr )
{
    int			ret = ALIAS_NOT_FOUND;
    char		address[ SIMTA_MAX_LINE_LEN ];
    DBC			*dbcp = NULL;
    DBT			key;
    DBT			value;

    if ( simta_dbp == NULL ) {
	if (( ret = db_open_r( &simta_dbp, SIMTA_ALIAS_DB, NULL ))
		!= 0 ) {
	    syslog( LOG_ERR, "alias_expand: db_open_r: %s",
		    db_strerror( ret ));
	    goto done;
	}
    }

    /* Set cursor and get first result */
    memset( &key, 0, sizeof( DBT ));
    memset( &value, 0, sizeof( DBT ));

    if ( e_addr->e_addr_at != NULL ) {
	*e_addr->e_addr_at = '\0';
	/* XXX - len check */
	strcpy( address, e_addr->e_addr );
	*e_addr->e_addr_at = '@';
    } else {
	strcpy( address, "postmaster" );
    }

    /* XXX - Is there a limit on key length? */
    key.data = &address;
    key.size = strlen( key.data ) + 1;

    if (( ret = db_cursor_set( simta_dbp, &dbcp, &key, &value ))
	    != 0 ) {
	if ( ret != DB_NOTFOUND ) {
	    syslog( LOG_ERR, "alias_expand: db_cursor_set: %s",
		    db_strerror( ret ));
	    goto done;
	}

	/* not in alias db, try next expansion */
	syslog( LOG_DEBUG, "alias_expand <%s>: not in alias db",
		e_addr->e_addr );
	ret = ALIAS_NOT_FOUND;
	goto done;
    }

    for ( ; ; ) {
	if ( add_address( exp, (char*)value.data,
		e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL,
		e_addr->e_addr_from ) != 0 ) {
	    /* add_address syslogs errors */
	    ret = ALIAS_SYSERROR;
	    goto done;
	}

	syslog( LOG_DEBUG, "alias_expand <%s> EXPANDED <%s>: alias db",
		e_addr->e_addr, (char*)value.data );

	/* Get next db result, if any */
	memset( &value, 0, sizeof( DBT ));
	if (( ret = db_cursor_next( simta_dbp, &dbcp, &key, &value ))
		!= 0 ) {
	    if ( ret != DB_NOTFOUND ) {
		syslog( LOG_ERR, "alias_expand: db_cursor_next: %s",
		    db_strerror( ret ));
		goto done;
	    } else {
		/* one or more addresses found in alias db */
		ret = ALIAS_EXCLUDE;
		goto done;
	    }
	}
    }

done:
    if ( dbcp != NULL ) {
	if ( db_cursor_close( dbcp ) != 0 ) {
	    syslog( LOG_ERR, "alias_expand: db_cursor_close: %s",
		db_strerror( ret ));
	}
    }
    return( ret );
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
