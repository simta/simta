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

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include <db.h>

#include "red.h"
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


    struct envelope *
address_bounce_create( struct expand *exp )
{
    struct envelope		*bounce_env;

    if (( bounce_env = env_create( NULL, exp->exp_env )) == NULL ) {
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

		if ( is_emailaddr( email_start ) != 0 ) {
		    if ( add_address( exp, email_start, e_addr->e_addr_errors,
			    ADDRESS_TYPE_EMAIL, from ) != 0 ) {
			*end = swap;
			return( 1 );
		    }
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

	if ( is_emailaddr( email_start ) != 0 ) {
	    if ( add_address( exp, email_start, e_addr->e_addr_errors,
		    ADDRESS_TYPE_EMAIL, from ) != 0 ) {
		*end = '>';
		return( 1 );
	    }
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
    struct exp_addr		*e;
    int				insert_head = 0;
#ifdef HAVE_LDAP
    struct simta_red		*red;
    struct action		*a;
#endif /* HAVE_LDAP */

    for ( e = exp->exp_addr_head; e != NULL; e = e->e_addr_next ) {
	if ( strcasecmp( addr, e->e_addr ) == 0 ) {
	    break;
	}
    }

    if ( e == NULL ) {
	if (( e = (struct exp_addr*)malloc( sizeof( struct exp_addr )))
		== NULL ) {
	    syslog( LOG_ERR, "add_address: malloc: %m" );
	    return( 1 );
	}
	memset( e, 0, sizeof( struct exp_addr ));

	e->e_addr_errors = error_env;
	e->e_addr_type = addr_type;

	if (( e->e_addr = strdup( addr )) == NULL ) {
	    syslog( LOG_ERR, "strdup: %m" );
	    goto error;
	}

	if (( e->e_addr_from = strdup( from )) == NULL ) {
	    syslog( LOG_ERR, "strdup: %m" );
	    goto error;
	}

	/* do syntax checking and special processing */
	switch ( addr_type ) {
	case ADDRESS_TYPE_EMAIL:
	    if (( e->e_addr_at = strchr( e->e_addr, '@' )) == NULL ) {
		if (( *(e->e_addr) != '\0' ) &&
			( strcasecmp( "postmaster", e->e_addr ) != 0 )) {
		    syslog( LOG_ERR, "add_address <%s>: ERROR bad address",
			    e->e_addr );
		    goto error;
		}

#ifdef HAVE_LDAP
	    } else {
		/* check to see if we might need LDAP for this domain */
		if (( red =
			simta_red_lookup_host( e->e_addr_at + 1 )) != NULL ) {
		    for ( a = red->red_expand; a != NULL; a = a->a_next ) {
			if ( a->a_action == EXPANSION_TYPE_LDAP ) {
			    insert_head = 1;
			    e->e_addr_try_ldap = 1;
			    break;
			}
		    }
		}


		/* check to see if the address is the sender */
		if ( exp->exp_env->e_mail != NULL ) {
		    /* compare the address in hand with the sender */
		    if ( simta_mbx_compare( e->e_addr,
			    exp->exp_env->e_mail ) == 0 ) {
			/* here we have a match */
			e->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
		    }
		}
#endif /* HAVE_LDAP */
	    }
	    break;

#ifdef HAVE_LDAP
	case ADDRESS_TYPE_LDAP:
	    insert_head = 1;
	    e->e_addr_try_ldap = 1;
	    break;
#endif /* HAVE LDAP */

	default:
	    panic( "add_address type out of range" );
	}

	if ( exp->exp_addr_tail == NULL ) {
	    exp->exp_addr_head = e;
	    exp->exp_addr_tail = e;
	} else if ( insert_head == 0 ) {
	    exp->exp_addr_tail->e_addr_next = e;
	    exp->exp_addr_tail = e;
	} else if ( exp->exp_addr_cursor != NULL ) {
	    if (( e->e_addr_next = exp->exp_addr_cursor->e_addr_next )
		    == NULL ) {
		exp->exp_addr_tail = e;
	    }
	    exp->exp_addr_cursor->e_addr_next = e;
	} else {
	    e->e_addr_next = exp->exp_addr_head;
	    exp->exp_addr_head = e;
	}
    }

#ifdef HAVE_LDAP
    /* add links */
    if ( exp_addr_link( &(e->e_addr_parents), exp->exp_addr_cursor ) != 0 ) {
	return( 1 );
    }

    if ( exp->exp_addr_cursor != NULL ) {
	if ( exp_addr_link( &(exp->exp_addr_cursor->e_addr_children), e )
		!= 0 ) {
	    return( 1 );
	}
    }
#endif /* HAVE_LDAP */

    return( 0 );

error:
    free( e->e_addr );
    free( e->e_addr_from );
    free( e );
    return( 1 );
}


    int
address_expand( struct expand *exp )
{
    struct exp_addr		*e_addr;
    struct simta_red		*red = NULL;
    struct action		*action;

    e_addr = exp->exp_addr_cursor;

    switch ( e_addr->e_addr_type ) {
    case ADDRESS_TYPE_EMAIL:
	if ( e_addr->e_addr_at == NULL ) {
	    red = simta_default_host;

	} else {
	    if ( strlen( e_addr->e_addr_at + 1 ) > MAXHOSTNAMELEN ) {
		syslog( LOG_ERR, "address_expand <%s>: ERROR domain too long",
			e_addr->e_addr );
		return( ADDRESS_SYSERROR );
	    }

	    /* Check to see if domain is off the local host */
	    if ((( red = host_local( e_addr->e_addr_at + 1 )) == NULL ) 
		    || ( red->red_host_type == RED_HOST_TYPE_SECONDARY_MX ) ||
		    ( red->red_expand == NULL )) {
		syslog( LOG_DEBUG,
			"address_expand <%s> FINAL: expansion complete",
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
    for ( action = red->red_expand; action != NULL; action = action->a_next ) {
	switch ( action->a_action ) {
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
		if ( red == NULL ) {
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

    while ( fgets( buf, 1024, f ) != NULL ) {
	len = strlen( buf );
	if (( buf[ len - 1 ] ) != '\n' ) {
	    syslog( LOG_WARNING, "password_expand <%s>: .forward line too long",
		    e_addr->e_addr );
	    continue;
	}

	buf[ len - 1 ] = '\0';
	if ( address_string_recipients( exp, buf, e_addr,
		e_addr->e_addr_from ) != 0 ) {
	    /* add_address syslogs errors */
	    ret = PASSWORD_SYSERROR;
	    goto cleanup_forward;
	}

	syslog( LOG_DEBUG, "password_expand <%s> EXPANDED <%s>: .forward",
		e_addr->e_addr, buf );
	ret = PASSWORD_EXCLUDE;
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
    char		address[ 1024 + 1 ];
    char		*alias_addr;
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
	if (( e_addr->e_addr_at - e_addr->e_addr ) > 1024 ) {
	    syslog( LOG_WARNING, "alias_expand: address too long: %s",
		    e_addr->e_addr );
	    goto done;
	}

	*e_addr->e_addr_at = '\0';
	strcpy( address, e_addr->e_addr );
	*e_addr->e_addr_at = '@';

    } else {
	strcpy( address, "postmaster" );
    }

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
	if (( alias_addr = strdup((char*)value.data )) == NULL ) {
	    ret = ALIAS_SYSERROR;
	    goto done;
	}

	switch ( correct_emailaddr( &alias_addr )) {
	case -1:
	    ret = ALIAS_SYSERROR;
	    free( alias_addr );
	    goto done;

	case 0:
	    syslog( LOG_DEBUG, "alias_expand <%s> BAD EXPANSION <%s>: alias db",
		    e_addr->e_addr, alias_addr );
	    free( alias_addr );
	    break;

	case 1:
	    if ( add_address( exp, alias_addr,
		    e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL,
		    e_addr->e_addr_from ) != 0 ) {
		/* add_address syslogs errors */
		ret = ALIAS_SYSERROR;
		goto done;
	    }
	    syslog( LOG_DEBUG, "alias_expand <%s> EXPANDED <%s>: alias db",
		    e_addr->e_addr, alias_addr );
	    free( alias_addr );
	    break;

	default:
	    panic( "alias_expand: correct_emailaddr return out of range" );
	}

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
exp_addr_link( struct exp_link **links, struct exp_addr *add )
{
    struct exp_link		*link;

    for ( link = *links; link != NULL; link = link->el_next ) {
	if ( link->el_exp_addr == add ) {
	    return( 0 );
	}
    }

    if (( link = malloc( sizeof( struct exp_link ))) == NULL ) {
	syslog( LOG_ERR, "exp_addr_link: malloc: %m" );
	return( 1 );
    }
    memset( link, 0, sizeof( struct exp_link ));

    link->el_exp_addr = add;
    link->el_next = *links;
    *links = link;

    return( 0 );
}


    void
exp_addr_link_free( struct exp_link *links )
{
    struct exp_link		*link;

    while (( link = links ) != NULL ) {
	links = links->el_next;
	free( link );
    }

    return;
}
#endif /* HAVE_LDAP */
