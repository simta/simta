
#include "config.h"

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <sys/time.h>		/* struct timeval */
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include "ll.h"
#include "envelope.h"
#include "expand.h"
#include "ldap.h"

#define	SIMTA_LDAP_CONF		"./simta_ldap.conf"

int	ldap_message_stdout ___P(( LDAPMessage *m ));


static char			*attrs[] = { "*", NULL };
struct list			*ldap_searches = NULL;
struct list			*ldap_people = NULL;
struct list			*ldap_groups = NULL;
LDAP				*ld = NULL;


    /* return a statically allocated string if all goes well, NULL if not.
     *
     *     - Build search string where:
     *         + %s -> username
     *         + %h -> hostname
     */

    char *
ldap_string( char *filter, char *user, char *domain )
{
    size_t		len;
    static size_t	buf_len = 0;
    static char		*buf = NULL;
    char		*c;
    char		*d;
    char		*insert;
    int			whiteout;
    size_t		place;

    /* make sure buf is big enough search url */
    if (( len = strlen( filter ) + 1 ) > buf_len ) {
	if (( buf = (char*)realloc( buf, len )) == NULL ) {
	    syslog( LOG_ERR, "realloc: %m" );
	    return( NULL );
	}

	buf_len = len;
    }

    d = buf;
    c = filter;

    while ( *c != '\0' ) {

	if ( *c != '%' ) {
	    /* raw character, copy to data buffer */
	    *d = *c;

	    /* advance cursors */
	    d++;
	    c++;

	} else if ( *( c + 1 ) == '%' ) {
	    /* %% -> copy single % to data buffer */
	    *d = *c;

	    /* advance cursors */
	    c += 2;
	    d++;

	} else {
	    if (( *( c + 1 ) == 's' ) ||  ( *( c + 1 ) == 'h' )) {
		/* we currently support %s -> username, %h -> hostname */
		if ( *( c + 1 ) == 's' ) {
		    insert = user;
		    whiteout = 1;

		} else {
		    insert = domain;
		    whiteout = 0;
		}

		/* if needed, resize buf to handle upcoming insert */
		if (( len += strlen( insert )) > buf_len ) {
		    place = d - buf;

		    if (( buf = (char*)realloc( buf, len )) == NULL ) {
			syslog( LOG_ERR, "realloc: %m" );
			return( NULL );
		    }

		    d = buf + place;
		    buf_len = len;
		}

		/* insert word */
		while ( *insert != '\0' ) {
		    if ((( *insert == '.' ) || ( *insert == '_' ))
			    && ( whiteout != 0 )) {
			*d = ' ';
		    } else {
			*d = *insert;
		    }

		    insert++;
		    d++;
		}

		/* advance read cursor */
		c += 2;

	    } else {
		/* XXX unknown/unsupported sequence, copy & warn for now */
		syslog( LOG_WARNING, "unknown ldap print sequence: %c\n",
			*( c + 1 ));
		*d = *c;
		c++;
	    }
	}
    }

    *d = '\0';

    return( buf );
}


    /* this function should return:
     *     LDAP_SYSERROR if there is an error
     *     LDAP_LOCAL if addr is found in the db
     *     LDAP_NOT_LOCAL if addr is not found in the db
     */

    int
ldap_address_local( char *addr )
{
    char		*at;
    char		*search_string;
    struct list		*l;
    int			count = 0;
    char		*domain;
    LDAPMessage		*res;
    LDAPURLDesc		*lud;
    struct timeval	timeout = {60,0};

    /* addr should be user@some.domain */
    if (( at = strchr( addr, '@' )) == NULL ) {
	return( LDAP_NOT_LOCAL );
    }

    domain = at + 1;

    if ( ld == NULL ) {
	/* XXX static hostname for now */
	if (( ld = ldap_init( "da.dir.itd.umich.edu", 4343 )) == NULL ) {
	    syslog( LOG_ERR, "ldap_init: %m" );
	    return( LDAP_SYSERROR );
	}
    }

    /* for each base string in ldap_searches:
     *     - Build search string
     *     - query the LDAP db with the search string
     */
    for ( l = ldap_searches; l != NULL; l = l->l_next ) {
	/* break the address to user and domain chunks for ldap_sting */
	*at = '\0';
	if (( search_string = ldap_string( l->l_string, addr, domain ))
		== NULL ) {
	    return( LDAP_SYSERROR );
	}
	*at = '@';

	if ( ldap_url_parse( search_string, &lud ) != 0 ) {
	    syslog( LOG_ERR, "ldap_url_parse %s: %m", search_string );
	    return( LDAP_SYSERROR );
	}

	if ( ldap_search_st( ld, lud->lud_dn, lud->lud_scope,
		lud->lud_filter, attrs, 0, &timeout, &res ) != LDAP_SUCCESS ) {
	    syslog( LOG_ERR, "ldap_search_st: %s",
		    ldap_err2string( ldap_result2error( ld, res, 1 )));
	    return( LDAP_SYSERROR );
	}

	if (( count = ldap_count_entries( ld, res )) < 0 ) {
	    syslog( LOG_ERR, "ldap_count_entries: %s",
		    ldap_err2string( ldap_result2error( ld, res, 1 )));
	    return( LDAP_SYSERROR );
	}

	/* XXX ldap_msgfree here? */

	if ( count > 0 ) {
	    ldap_msgfree( res );
	    return( LDAP_LOCAL );
	}
    }

    ldap_msgfree( res );
    return( LDAP_NOT_FOUND );
}


    /* given a config filename, this function sets up the search strings,
     * etc, that ldap needs later on.  This function is called *before*
     * simta becomes a daemon, so errors on stderr are ok.  Note that
     * we should still syslog all errors.
     *
     * XXX note that the ldap host is hardcoded at the moment, we will
     * want to be able to set that here.
     */

    int
ldap_config( char *fname )
{
    int			lineno = 0;
    int			fd;
    char		*line;
    SNET		*snet;
    char		*c;
    char		*d;
    size_t		len;
    struct list		**l;
    struct list		*l_new;
    struct list		**add;

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	if ( errno == ENOENT ) {
	    errno = 0;
	    /* XXX file not found, error? */
	    return( 0 );

	} else {
	    fprintf( stderr, "conf_read open %s: ", fname );
	    perror( NULL );
	    return( -1 );
	}
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	perror( "conf_read snet_attach" );
	return( -1 );
    }

    for ( l = &ldap_searches; *l != NULL; l = &((*l)->l_next))
    	    ;

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	lineno++;

	for ( c = line; ( *c != '\0' ) && ( *c != '#' ); c++ ) {
	    if (( *c != ' ' ) && ( *c != '\t' ) && ( *c != '\n' )) {
		if (( strncasecmp( c, "uri", 3 ) == 0 ) ||
			( strncasecmp( c, "url", 3 ) == 0 )) {

		    c += 3;

		    if ( isspace( *c ) == 0 ) {
			fprintf( stderr, "error 1: %s\n", line );
			break;
		    }

		    for ( c++; isspace( *c ) != 0; c++ );

		    if ( ldap_is_ldap_url( c ) != 0 ) {

			if (( *l = (struct list*)malloc( sizeof( struct list )))
				== NULL ) {
			    perror( "malloc" );
			    return( -1 );
			}

			if (((*l)->l_string = strdup( c )) == NULL ) {
			    perror( "strdup" );
			    return( -1 );
			}

			(*l)->l_next = NULL;

			l = &((*l)->l_next);

		    } else {
			fprintf( stderr, "error 2: %s\n", line );
		    }

		} else if (( strncasecmp( c, "oc", 2 ) == 0 ) ||
			( strncasecmp( c, "objectclass", 11 ) == 0 )) {

		    if ( strncasecmp( c, "oc", 2 ) == 0 ) {
			c += 2;
		    } else {
			c += 11;
		    }

		    if ( isspace( *c ) == 0 ) {
			fprintf( stderr, "error 3: %s\n", line );
			break;
		    }

		    for ( c++; isspace( *c ) != 0; c++ );

		    add = NULL;

		    if ( strncasecmp( c, "person", 6 ) == 0 ) {
			c += 6;
			add = &ldap_people;

		    } else if ( strncasecmp( c, "group", 5 ) == 0 ) {
			c += 5;
			add = &ldap_groups;
		    }

		    if ( add != NULL ) {
			if ( isspace( *c ) == 0 ) {
			    fprintf( stderr, "error 4: %s\n", line );
			    break;
			}

			for ( c++; isspace( *c ) != 0; c++ );

			if ( *c == '\0' ) {
			    fprintf( stderr, "error 5: %s\n", line );

			} else {
			    for ( d = c; *d != '\0'; d++ ) {
				if ( isspace( *d ) != 0 ) {
				    break;
				}
			    }

			    len = d - c + 1;

			    while ( *d != '\0' ) {
				if ( isspace( *d ) == 0 ) {
				    break;
				}

				d++;
			    }

			    if ( *d != '\0' ) {
				fprintf( stderr, "error 8: %s\n", line );

			    } else {
				if (( l_new = (struct list*)malloc(
					sizeof( struct list ))) == NULL ) {
				    perror( "malloc" );
				    return( -1 );
				}
				memset( l_new, 0, sizeof( struct list ));

				if (( l_new->l_string = (char*)malloc( len ))
					== NULL ) {
				    perror( "malloc" );
				    return( -1 );
				}
				memset( l_new->l_string, 0, len );

				strncpy( l_new->l_string, c, len );

				l_new->l_next = *add;
				*add = l_new;
			    }
			}

		    } else {
			fprintf( stderr, "error 6: %s\n", line );
		    }

		} else {
		    fprintf( stderr, "error 7: %s\n", line );
		}
		break;
	    }
	}
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "nlist snet_close" );
	return( -1 );
    }

    /* XXX check to see that ldap is configured correctly */

    if ( ldap_people == NULL ) {
	fprintf( stderr, "%s: No ldap people\n", fname );
	return( 1 );
    }

    if ( ldap_searches == NULL ) {
	fprintf( stderr, "%s: No ldap searches\n", fname );
	return( 1 );
    }

    return( 0 );
}


    int
ldap_value( LDAPMessage *e, char *attr, struct list *master )
{
    int				x;
    char			**values;
    struct list			*l;

    if (( values = ldap_get_values( ld, e, attr )) == NULL ) {
	/* XXX proper ldap error message needed here */
	return( -1 );
    }

    for ( x = 0; values[ x ] != NULL; x++ ) {
	for ( l = master ; l != NULL; l = l->l_next ) {
	    if ( strcasecmp( values[ x ], l->l_string ) == 0 ) {
		ldap_value_free( values );
		return( 1 );
	    }
	}
    }

    ldap_value_free( values );

    return( 0 );
}


    /* this function should return:
     *     LDAP_NOT_FOUND if addr is not found in the database
     *     LDAP_FINAL if addr is a terminal expansion
     *     LDAP_EXCLUDE if addr is an error, and/or expands to other addrs.
     *     LDAP_SYSERROR if there is a system error
     *
     * XXX is LDAP_FINAL useless?  if its in the db, it can never be terminal?
     *
     * struct expand *exp->exp_env->e_mail
     *     - is the sender of the message
     *
     * expansion (not system) errors should be reported back to the sender
     * using rcpt_error(...);
     *
     * rcpt_error( e_addr->e_addr_rcpt, char*, char*, char* );
     *     - used to create a bounce for an address
     *
     * add_address( exp, char *new_addr, e_addr->e_addr_rcpt, TYPE );
     *     - used to add new_addr to the expansion list
     *     - TYPE can be either ADDRESS_TYPE_EMAIL or ADDRESS_TYPE_LDAP
     */

    int
ldap_expand( struct expand *exp, struct exp_addr *e_addr )
{
    int			x;
    int			result;
    int			count = 0;
    char		*at;
    char		*domain;
    char		*search_string;
    char		**values;
    LDAPMessage		*res;
    LDAPMessage		*message;
    LDAPMessage		*entry;
    LDAPURLDesc		*lud;
    struct list		*l;
    struct timeval	timeout = {60,0};

    if ( e_addr->e_addr_type == ADDRESS_TYPE_LDAP ) {
	/* XXX not implemented yet */
	return( LDAP_SYSERROR );
    }

    /* addr should be user@some.domain */
    if (( at = strchr( e_addr->e_addr, '@' )) == NULL ) {
	if ( rcpt_error( e_addr->e_addr_rcpt, "bad address format: ",
		e_addr->e_addr, NULL ) != 0 ) {
	    /* rcpt_error syslogs syserrors */
	}
	return( LDAP_SYSERROR );
    }

    domain = at + 1;

    if ( ld == NULL ) {
	/* XXX static hostname for now */
	if (( ld = ldap_init( "da.dir.itd.umich.edu", 4343 )) == NULL ) {
	    syslog( LOG_ERR, "ldap_init: %m" );
	    return( LDAP_SYSERROR );
	}
    }

    /* for each base string in ldap_searches:
     *     - Build search string
     *     - query the LDAP db with the search string
     */
    for ( l = ldap_searches; l != NULL; l = l->l_next ) {
	/* break the address to user and domain chunks for ldap_sting */
	*at = '\0';
	if (( search_string = ldap_string( l->l_string, e_addr->e_addr,
		domain )) == NULL ) {
	    return( LDAP_SYSERROR );
	}
	*at = '@';

	if ( ldap_url_parse( search_string, &lud ) != 0 ) {
	    /* XXX correct error reporting? */
	    syslog( LOG_ERR, "ldap_url_parse %s: %m", search_string );
	    return( LDAP_SYSERROR );
	}

	if ( ldap_search_st( ld, lud->lud_dn, lud->lud_scope,
		lud->lud_filter, attrs, 0, &timeout, &res ) != LDAP_SUCCESS ) {
	    syslog( LOG_ERR, "ldap_search_st: %s",
		    ldap_err2string( ldap_result2error( ld, res, 1 )));
	    return( LDAP_SYSERROR );
	}

	if (( count = ldap_count_entries( ld, res )) < 0 ) {
	    syslog( LOG_ERR, "ldap_count_entries: %s",
		    ldap_err2string( ldap_result2error( ld, res, 1 )));
	    return( LDAP_SYSERROR );
	}

	if ( count > 0 ) {
	    break;
	}
    }

#ifdef DEBUG
    printf( "%d matches found\n", count );
#endif /* DEBUG */

    if ( count == 0 ) {
	/* no entries found */
	return( LDAP_NOT_FOUND );
    }

    if (( entry = ldap_first_entry( ld, res )) == NULL ) {
	syslog( LOG_ERR, "ldap_first_entry: %s",
		ldap_err2string( ldap_result2error( ld, res, 1 )));
	return( LDAP_SYSERROR );
    }

#ifdef DEBUG
    printf( "%d entrie(s)\n", count );
#endif /* DEBUG */

    if (( message = ldap_first_message( ld, res )) == NULL ) {
	syslog( LOG_ERR, "ldap_first_message: %s",
		ldap_err2string( ldap_result2error( ld, res, 1 )));
	return( LDAP_SYSERROR );
    }

    result = 0;

    if ( ldap_groups != NULL ) {
	if (( result = ldap_value( entry, "objectClass", ldap_groups )) < 0 ) {

	} else if ( result > 0 ) {

#ifdef DEBUG
	    printf( "%s IS A GROUP!\n", e_addr->e_addr );
#endif /* DEBUG */

	}
    }

    if ( result == 0 ) {
	if (( result = ldap_value( entry, "objectClass", ldap_people )) < 0 ) {
	    /* XXX daemon error handling/reporting */
	    ldap_perror( ld, "ldap_get_values 2" );
	    goto error;

	} else if ( result > 0 ) {

#ifdef DEBUG
	    printf( "%s IS A PERSON!\n", e_addr->e_addr );

	    /*
	    if ( ldap_message_stdout( entry ) != 0 ) {
		return( LDAP_SYSERROR );
	    }
	    */
#endif /* DEBUG */

	    /* get individual's email address(es) */
	    if (( values = ldap_get_values( ld, entry,
		    "mailForwardingAddress" )) == NULL ) {
		/* XXX daemon error handling/reporting */
		ldap_perror( ld, "ldap_get_values 2" );
		goto error;
	    }

	    for ( x = 0; values[ x ] != NULL; x++ ) {
		if ( add_address( exp, values[ x ],
			e_addr->e_addr_rcpt, ADDRESS_TYPE_EMAIL ) != 0 ) {
		    perror( "add_address" );
		    return( LDAP_SYSERROR );
		}

		count++;
	    }

	    ldap_value_free( values );

	} else {
	    /* not a group, or a person */

#ifdef DEBUG
	    printf( "%s IS NOT A PERSON OR A GROUP!\n", e_addr->e_addr );
#endif /* DEBUG */

	    /* XXX daemon error handling/reporting */
	    return( LDAP_SYSERROR );
	}
    }

    /* XXX need to do more than just return */
    ldap_msgfree( res );
    if ( count > 0 ) {
	return( LDAP_EXCLUDE );
    } else {
	return( LDAP_NOT_FOUND );
    }

error:
    /* XXX daemon error handling/reporting */
    ldap_msgfree( res );
    return( LDAP_SYSERROR );
}



    int
ldap_message_stdout( LDAPMessage *m )
{
    LDAPMessage		*entry;
    LDAPMessage		*message;
    char		*dn;
    char		*attribute;
    BerElement		*ber;
    char		**values;
    int			i;

    if (( entry = ldap_first_entry( ld, m )) == NULL ) {
	ldap_perror( ld, "ldap_first_entry" );
	return( -1 );
    }

    if (( message = ldap_first_message( ld, m )) == NULL ) {
	ldap_perror( ld, "ldap_first_message" );
	return( -1 );
    }

    if (( dn = ldap_get_dn( ld, message )) == NULL ) {
	ldap_perror( ld, "ldap_get_dn" );
	return( -1 );
    }

    printf( "dn: %s\n", dn );

    /* Print attriubtes and values */
    if (( attribute = ldap_first_attribute( ld, message, &ber )) == NULL ) {
	ldap_perror( ld, "ldap_first_attribute" );
	return( -1 );
    }

    printf( "%s:\n", attribute );

    if (( values = ldap_get_values( ld, entry, attribute )) == NULL ) {
	ldap_perror( ld, "ldap_get_values" );
	return( -1 );
    }

    for ( i = 0; values[ i ] != NULL; i++ ) {
	printf( "	%s\n", values[ i ] );
    }

    ldap_value_free( values );

    while (( attribute = ldap_next_attribute( ld, message, ber )) != NULL ) {
	printf( "%s:\n", attribute );

	if (( values = ldap_get_values( ld, entry, attribute )) == NULL ) {
	    ldap_perror( ld, "ldap_get_values" );
	    return( -1 );
	}

	for ( i = 0; values[ i ] != NULL; i++ ) {
	    printf( "	%s\n", values[ i ] );
	}

	ldap_value_free( values );
    }

    ber_free( ber, 0 );

    return( 0 );
}
