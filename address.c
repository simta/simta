/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>
#include <dirent.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "dns.h"
#include "envelope.h"
#include "expand.h"
#include "red.h"
#include "header.h"
#include "simta.h"
#include "queue.h"
#include "srs.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "simta_ldap.h"
#endif /* HAVE_LDAP */

#ifdef HAVE_LMDB
#include "simta_lmdb.h"
#endif /* HAVE_LMDB */

    struct envelope *
address_bounce_create( struct expand *exp )
{
    struct envelope		*bounce_env;

    if (( bounce_env =
	    env_create( simta_dir_fast, NULL, "", exp->exp_env )) == NULL ) {
	return( NULL );
    }

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
    char			*at;
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
	e = calloc( 1, sizeof( struct exp_addr ));

	e->e_addr_errors = error_env;
	e->e_addr_type = addr_type;
	e->e_addr_parent_action = exp->exp_current_action;
	exp->exp_entries++;

	e->e_addr = strdup( addr );
	e->e_addr_from = strdup( from );

	/* do syntax checking and special processing */
	switch ( addr_type ) {
	case ADDRESS_TYPE_EMAIL:
	    if (( *(e->e_addr) != '\0' ) &&
		    ( strcasecmp( STRING_POSTMASTER, e->e_addr ) != 0 )) {
		if ( *(e->e_addr) == '"' ) {
		    if (( at = token_quoted_string( e->e_addr )) == NULL ) {
			syslog( LOG_ERR, "add_address <%s>: bad address: "
				"bad quoted string", e->e_addr );
			goto error;
		    }

		} else {
		    if (( at = token_dot_atom( e->e_addr )) == NULL ) {
			syslog( LOG_ERR, "add_address <%s>: address missing",
				e->e_addr );
			goto error;
		    }
		}

		at++;

		if ( *at != '@' ) {
		    syslog( LOG_ERR, "add_address <%s>: bad address: "
			    "'@' expected", e->e_addr );
		    goto error;
		}

		e->e_addr_at = at;
	    }

#ifdef HAVE_LDAP
	    if ( e->e_addr_at != NULL ) {
		/* check to see if we might need LDAP for this domain */
		if (( red = red_host_lookup( e->e_addr_at + 1 )) != NULL ) {
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
		    if ( simta_mbx_compare( 2, e->e_addr,
			    exp->exp_env->e_mail ) == 0 ) {
			/* here we have a match */
			e->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
		    }
		}
	    }
#endif /* HAVE_LDAP */
	    break;

#ifdef HAVE_LDAP
	case ADDRESS_TYPE_LDAP:
	    insert_head = 1;
	    e->e_addr_try_ldap = 1;
	    break;
#endif /* HAVE LDAP */

	default:
	    panic( "add_address: type out of range" );
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
	e->e_addr_max_level = exp->exp_addr_cursor->e_addr_max_level + 1;
	if ( exp->exp_max_level < e->e_addr_max_level ) {
	    exp->exp_max_level = e->e_addr_max_level;
	}

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
    int				local_postmaster = 0;

    e_addr = exp->exp_addr_cursor;

    switch ( e_addr->e_addr_type ) {
    case ADDRESS_TYPE_EMAIL:
	if ( e_addr->e_addr_at == NULL ) {
	    red = simta_red_host_default;

	} else {
	    if ( strlen( e_addr->e_addr_at + 1 ) > SIMTA_MAX_HOST_NAME_LEN ) {
		syslog( LOG_ERR, "Expand env <%s>: <%s>: domain too long",
			exp->exp_env->e_id, e_addr->e_addr );
		return( ADDRESS_SYSERROR );
	    }

	    /* Check to see if domain is off the local host */
	    if ((( red = red_host_lookup( e_addr->e_addr_at + 1 )) == NULL )
		    || ( red->red_expand == NULL )) {
		simta_debuglog( 1, "Expand env <%s>: <%s>: expansion complete",
			exp->exp_env->e_id, e_addr->e_addr );
		return( ADDRESS_FINAL );
	    }
	}
	break;

#ifdef HAVE_LDAP
    case ADDRESS_TYPE_LDAP:
	exp->exp_current_action = e_addr->e_addr_parent_action;
	simta_debuglog( 2, "Expand env <%s>: <%s>: LDAP data", exp->exp_env->e_id,
		e_addr->e_addr );
	goto ldap_exclusive;
#endif /*  HAVE_LDAP */

    default:
	panic( "address_expand: address type out of range" );
    }

    /* At this point, we should have a valid address destined for
     * a local domain.  Now we use the expansion table to resolve it.
     */

    /* Expand user using expansion table for domain */
    for ( exp->exp_current_action = red->red_expand;
	    exp->exp_current_action != NULL;
	    exp->exp_current_action = exp->exp_current_action->a_next ) {
	switch ( exp->exp_current_action->a_action ) {
	/* Other types might include files, pipes, etc */
#ifdef HAVE_LMDB
	case EXPANSION_TYPE_ALIAS:
	    switch ( alias_expand( exp, e_addr, exp->exp_current_action )) {
	    case ADDRESS_EXCLUDE:
		simta_debuglog( 1, "Expand.alias env <%s>: <%s>: found in DB %s",
			exp->exp_env->e_id, e_addr->e_addr,
				exp->exp_current_action->a_fname );
		return( ADDRESS_EXCLUDE );

	    case ADDRESS_NOT_FOUND:
		simta_debuglog( 1, "Expand.alias env <%s>: <%s>: not in DB %s",
			exp->exp_env->e_id, e_addr->e_addr,
			exp->exp_current_action->a_fname );
		continue;

	    case ADDRESS_SYSERROR:
		return( ADDRESS_SYSERROR );

	    default:
		panic( "address_expand default alias switch" );
	    }
#endif /* HAVE_LMDB */

	case EXPANSION_TYPE_PASSWORD:
	    switch ( password_expand( exp, e_addr, exp->exp_current_action )) {
	    case ADDRESS_EXCLUDE:
		simta_debuglog( 1,
			"Expand.password env <%s>: <%s>: found in file %s",
			exp->exp_env->e_id, e_addr->e_addr,
			exp->exp_current_action->a_fname );
		return( ADDRESS_EXCLUDE );

	    case ADDRESS_FINAL:
		simta_debuglog( 1,
			"Expand.password env <%s>: <%s>: terminal in file %s",
			exp->exp_env->e_id, e_addr->e_addr,
			exp->exp_current_action->a_fname );
		return( ADDRESS_FINAL );

	    case ADDRESS_NOT_FOUND:
		simta_debuglog( 1,
			"Expand.password env <%s>: <%s>: not in file %s",
			exp->exp_env->e_id, e_addr->e_addr,
			exp->exp_current_action->a_fname );
		continue;

	    case ADDRESS_SYSERROR:
		return( ADDRESS_SYSERROR );

	    default:
		panic( "address_expand default password switch" );
	    }

	case EXPANSION_TYPE_SRS:
	    switch( srs_expand( exp, e_addr, exp->exp_current_action )) {
	    case ADDRESS_EXCLUDE:
		simta_debuglog( 1, "Expand.SRS env <%s>: <%s>: valid",
			exp->exp_env->e_id, e_addr->e_addr );
		return( ADDRESS_EXCLUDE );

	    case ADDRESS_NOT_FOUND:
		simta_debuglog( 1, "Expand.SRS env <%s>: <%s>: not valid",
			exp->exp_env->e_id, e_addr->e_addr );
		continue;

	    case ADDRESS_SYSERROR:
		return( ADDRESS_SYSERROR );

	    default:
		panic( "address_expand srs_expand out of range" );
	    }

#ifdef HAVE_LDAP
	case EXPANSION_TYPE_LDAP:
	    if ( e_addr->e_addr_at == NULL ) {
		continue;
	    }
	    exp->exp_current_action = exp->exp_current_action;

ldap_exclusive:
	    switch ( simta_ldap_expand( exp->exp_current_action->a_ldap,
		    exp, e_addr )) {
	    case ADDRESS_EXCLUDE:
		simta_debuglog( 1, "Expand.LDAP env <%s>: <%s>: expanded",
			exp->exp_env->e_id, e_addr->e_addr );
		return( ADDRESS_EXCLUDE );

	    case ADDRESS_FINAL:
		simta_debuglog( 1, "Expand.LDAP env <%s>: <%s>: terminal",
			exp->exp_env->e_id, e_addr->e_addr );
		return( ADDRESS_FINAL );

	    case ADDRESS_NOT_FOUND:
		simta_debuglog( 1, "Expand.LDAP env <%s>: <%s>: not found",
			exp->exp_env->e_id, e_addr->e_addr );
		if ( red == NULL ) {
		    /* data is exclusively for ldap, and it didn't find it */
		    goto not_found;
		}
		continue;

	    case ADDRESS_SYSERROR:
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
	local_postmaster = 1;
    } else {
	*(e_addr->e_addr_at) = '\0';
	if ( strcasecmp( e_addr->e_addr, STRING_POSTMASTER ) == 0 ) {
	    local_postmaster = 1;
	}
	*(e_addr->e_addr_at) = '@';
    }

    if ( local_postmaster ) {
	e_addr->e_addr_type = ADDRESS_TYPE_DEAD;
	syslog( LOG_ERR, "Expand env <%s>: <%s>: can't resolve local "
		"postmaster, expanding to dead queue", exp->exp_env->e_id,
		e_addr->e_addr );
	return( ADDRESS_FINAL );
    }

    syslog( LOG_INFO, "Expand env <%s>: <%s>: not found", exp->exp_env->e_id,
	    e_addr->e_addr );

    if ( bounce_text( e_addr->e_addr_errors, TEXT_ERROR, "address not found: ",
	    e_addr->e_addr, NULL ) != 0 ) {
	/* bounce_text syslogs errors */
	return( ADDRESS_SYSERROR );
    }

    return( ADDRESS_EXCLUDE );
}


    struct passwd *
simta_getpwnam( struct action *a, char *user )
{
    struct passwd		*p;
    FILE			*f;

    if (( f = fopen( a->a_fname, "r" )) == NULL ) {
	return( NULL );
    }

    /* FIXME: fgetpwent() is not portable */
    while (( p = fgetpwent( f )) != NULL ) {
	if ( strcasecmp( user, p->pw_name ) == 0 ) {
	    break;
	}
    }

    if ( fclose( f ) != 0 ) {
	syslog( LOG_ERR, "Syserror: simta_getpwnam fclose %s: %m", a->a_fname );
	return( NULL );
    }

    return( p );
}


    int
password_expand( struct expand *exp, struct exp_addr *e_addr, struct action *a )
{
    int			ret;
    int			len;
    FILE		*f;
    struct passwd	*passwd;
    char		fname[ MAXPATHLEN ];
    char		buf[ 1024 ];

    /* Special handling for /dev/null */
    if ( strncasecmp( e_addr->e_addr, "/dev/null@", 10 ) == 0 ) {
	syslog( LOG_INFO,
		"Expand.password env <%s>: <%s>: expanded to /dev/null",
		exp->exp_env->e_id, e_addr->e_addr );
	return( ADDRESS_FINAL );
    }

    /* Check password file */
    if ( e_addr->e_addr_at != NULL ) {
	*e_addr->e_addr_at = '\0';
	passwd = simta_getpwnam( a, e_addr->e_addr );
	*e_addr->e_addr_at = '@';
    } else {
	passwd = simta_getpwnam( a, STRING_POSTMASTER );
    }

    if ( passwd == NULL ) {
	/* not in passwd file, try next expansion */
	return( ADDRESS_NOT_FOUND );
    }

    ret = ADDRESS_FINAL;

    /* Check .forward */
    if ( snprintf( fname, MAXPATHLEN, "%s/.forward",
	    passwd->pw_dir ) >= MAXPATHLEN ) {
	syslog( LOG_ERR,
		"Expand.password env <%s>: <%s>: .forward path too long",
		exp->exp_env->e_id, e_addr->e_addr );
	return( ADDRESS_FINAL );
    }

    if (( f = fopen( fname, "r" )) == NULL ) {
	switch( errno ) {
	case EACCES:
	case ENOENT:
	case ENOTDIR:
	case ELOOP:
	    simta_debuglog( 2, "Expand.password env <%s>: <%s>: no .forward",
		    exp->exp_env->e_id, e_addr->e_addr );
	    return( ADDRESS_FINAL );

	default:
	    syslog( LOG_ERR, "Syserror: password_expand fopen %s: %m", fname );
	    return( ADDRESS_SYSERROR );
	}
    }

    while ( fgets( buf, 1024, f ) != NULL ) {
	len = strlen( buf );
	if (( buf[ len - 1 ] ) != '\n' ) {
	    syslog( LOG_WARNING,
		    "Expand.password env <%s>: <%s>: .forward line too long",
		    exp->exp_env->e_id, e_addr->e_addr );
	    continue;
	}

	buf[ len - 1 ] = '\0';
	if ( address_string_recipients( exp, buf, e_addr,
		e_addr->e_addr_from ) != 0 ) {
	    /* add_address syslogs errors */
	    ret = ADDRESS_SYSERROR;
	    goto cleanup_forward;
	}

	simta_debuglog( 1,
		"Expand.password env <%s>: <%s>: expanded to <%s>: .forward",
		exp->exp_env->e_id, e_addr->e_addr, buf );
	ret = ADDRESS_EXCLUDE;
    }

cleanup_forward:
    if ( fclose( f ) != 0 ) {
	syslog( LOG_ERR, "Syserror: password_expand fclose %s: %m", fname );
	return( ADDRESS_SYSERROR );
    }

    return( ret );
}


#ifdef HAVE_LMDB
    int
alias_expand( struct expand *exp, struct exp_addr *e_addr, struct action *a )
{
    int			ret = ADDRESS_NOT_FOUND;
    /* FIXME: this should use SIMTA_MAX_HOST_NAME_LEN */
    char		address[ ALIAS_MAX_DOMAIN_LEN ];
    char		domain[ ALIAS_MAX_DOMAIN_LEN ];
    char		owner[ ALIAS_MAX_DOMAIN_LEN * 2 ];
    char		*alias_addr;
    char		*addr_dash;
    struct simta_dbc	*dbcp = NULL, *owner_dbcp = NULL;
    yastr		key = NULL, value = NULL;
    yastr		owner_key = NULL, owner_value = NULL;

    if ( a->a_dbh == NULL ) {
	if (( ret = simta_db_open_r( &(a->a_dbh), a->a_fname )) != 0 ) {
	    syslog( LOG_ERR, "Liberror: alias_expand simta_db_open_r %s: %s",
		    a->a_fname, simta_db_strerror( ret ));
	    a->a_dbh = NULL;
	    ret = ADDRESS_NOT_FOUND;
	    goto done;
	}
    }

    if ( e_addr->e_addr_at != NULL ) {
	if (( e_addr->e_addr_at - e_addr->e_addr ) >= ALIAS_MAX_DOMAIN_LEN ) {
	    syslog( LOG_WARNING,
		    "Expand.alias env <%s>: <%s>: address too long",
		    exp->exp_env->e_id, e_addr->e_addr );
	    goto done;
	}
	if ( strlen( e_addr->e_addr_at + 1 ) >= ALIAS_MAX_DOMAIN_LEN ) {
	    syslog( LOG_WARNING,
		    "Expand.alias env <%s>: <%s>: domain too long: %s",
		    exp->exp_env->e_id, e_addr->e_addr, e_addr->e_addr_at + 1 );
	    goto done;
	}

	strncpy( domain, e_addr->e_addr_at + 1, ALIAS_MAX_DOMAIN_LEN - 1 );

	*e_addr->e_addr_at = '\0';
	if ( strncasecmp( e_addr->e_addr, "owner-", 6 ) == 0 ) {
	    /* Canonicalise sendmail-style owner */
	    strncpy( address, e_addr->e_addr + 6, ALIAS_MAX_DOMAIN_LEN - 8 );
	    strcat( address, "-errors" );
	} else if ((( addr_dash = strrchr( e_addr->e_addr, '-' )) != NULL ) &&
		(( strcasecmp( addr_dash, "-owner" ) == 0 ) ||
		( strcasecmp( addr_dash, "-owners" ) == 0 ) ||
		( strcasecmp( addr_dash, "-error" ) == 0 ) ||
		( strcasecmp( addr_dash, "-request" ) == 0 ) ||
		( strcasecmp( addr_dash, "-requests" ) == 0 ))) {
	    /* simta-style owners are all the same for ALIAS.
	     * errors is canonical */
	    *addr_dash = '\0';
	    strncpy( address, e_addr->e_addr, ALIAS_MAX_DOMAIN_LEN - 8 );
	    *addr_dash = '-';
	    strcat( address, "-errors" );
	} else {
	    strncpy( address, e_addr->e_addr, ALIAS_MAX_DOMAIN_LEN - 1 );
	}
	*e_addr->e_addr_at = '@';

    } else {
	strncpy( address, STRING_POSTMASTER, ALIAS_MAX_DOMAIN_LEN - 1 );
    }

    key = yaslauto( address );

    if (( ret = simta_db_cursor_open( a->a_dbh, &dbcp )) != 0 ) {
	syslog( LOG_ERR, "Liberror: alias_expand simta_db_cursor_open: %s",
		simta_db_strerror( ret ));
	ret = ADDRESS_SYSERROR;
	goto done;
    }

    if (( ret = simta_db_cursor_get( dbcp, &key, &value )) != 0 ) {
	if ( ret == SIMTA_DB_NOTFOUND ) {
	    ret = ADDRESS_NOT_FOUND;
	} else {
	    syslog( LOG_ERR, "Liberror: alias_expand simta_db_cursor_get: %s",
		    simta_db_strerror( ret ));
	    ret = ADDRESS_SYSERROR;
	}
	goto done;
    }

    if ( strcmp( address, STRING_POSTMASTER ) != 0 ) {
	if ( owner_key == NULL ) {
	    if (( owner_key = yaslempty( )) == NULL ) {
		ret = ADDRESS_SYSERROR;
		goto done;
	    }
	}
	if (( owner_key = yaslcpy( owner_key, address )) == NULL ) {
	    ret = ADDRESS_SYSERROR;
	    goto done;
	}
	if (( owner_key = yaslcat( owner_key, "-errors" )) == NULL ) {
	    ret = ADDRESS_SYSERROR;
	    goto done;
	}
	if (( ret = simta_db_cursor_open( a->a_dbh, &owner_dbcp )) != 0 ) {
	    syslog( LOG_ERR, "Liberror: alias_expand simta_db_cursor_open: %s",
		    simta_db_strerror( ret ));
	    ret = ADDRESS_SYSERROR;
	    goto done;
	}
	if (( ret = simta_db_cursor_get( owner_dbcp, &owner_key,
		&owner_value )) != 0 ) {
	    if ( ret != SIMTA_DB_NOTFOUND ) {
		syslog( LOG_ERR,
			"Liberror: alias_expand simta_db_cursor_get: %s",
			simta_db_strerror( ret ));
		ret = ADDRESS_SYSERROR;
		goto done;
	    }
	} else {
	    sprintf( owner, "%s-errors@%s", address, domain );
	    if (( e_addr->e_addr_errors =
		    address_bounce_create( exp )) == NULL ) {
		syslog( LOG_ERR, "Expand.alias env <%s>: <%s>: "
			"failed creating error env: %s",
			exp->exp_env->e_id, e_addr->e_addr, owner );
		ret = ADDRESS_SYSERROR;
		goto done;
	    }
	    if ( env_recipient( e_addr->e_addr_errors, owner ) != 0 ) {
		syslog( LOG_ERR, "Expand.alias env <%s>: <%s>: "
			"failed setting error recip: %s",
			exp->exp_env->e_id, e_addr->e_addr, owner );
		ret = ADDRESS_SYSERROR;
		goto done;
	    }
	    e_addr->e_addr_from = strdup( owner );
	}
    }

    for ( ; ; ) {
	alias_addr = strdup( value );

	switch ( correct_emailaddr( &alias_addr )) {
	case -1:
	    ret = ADDRESS_SYSERROR;
	    free( alias_addr );
	    goto done;

	case 0:
	    syslog( LOG_INFO,
		    "Expand.alias env <%s>: <%s>: bad expansion <%s>",
		    exp->exp_env->e_id, e_addr->e_addr, alias_addr );
	    free( alias_addr );
	    break;

	case 1:
	    if ( add_address( exp, alias_addr,
		    e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL,
		    e_addr->e_addr_from ) != 0 ) {
		/* add_address syslogs errors */
		ret = ADDRESS_SYSERROR;
		goto done;
	    }
	    simta_debuglog( 1, "Expand.alias env <%s>: <%s>: expanded to <%s>",
		    exp->exp_env->e_id, e_addr->e_addr, alias_addr );
	    free( alias_addr );
	    break;

	default:
	    panic( "alias_expand: correct_emailaddr return out of range" );
	}

	/* Get next db result, if any */
	if (( ret = simta_db_cursor_get( dbcp, &key, &value )) != 0 ) {
	    if ( ret != SIMTA_DB_NOTFOUND ) {
		syslog( LOG_ERR, "Liberror: alias_expand db_cursor_get: %s",
		    simta_db_strerror( ret ));
		ret = ADDRESS_SYSERROR;
		goto done;
	    } else {
		/* one or more addresses found in alias db */
		ret = ADDRESS_EXCLUDE;
		goto done;
	    }
	}
    }

done:
    yaslfree( key );
    yaslfree( value );
    yaslfree( owner_key );
    yaslfree( owner_value );
    simta_db_cursor_close( dbcp );
    simta_db_cursor_close( owner_dbcp );
    return( ret );
}
#endif /* HAVE_LMDB */

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

    link = calloc( 1, sizeof( struct exp_link ));

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
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
