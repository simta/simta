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
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <netdb.h>

#include "ldap.h"

#define	SIMTA_LDAP_CONF		"./simta_ldap.conf"


static char			*attrs[] = { "*", NULL };
struct list			*ldap_searches = NULL;
struct list			*ldap_people = NULL;
struct list			*ldap_groups = NULL;
LDAP				*ld;



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
			    exit( 1 );
			}

			if (((*l)->l_string = strdup( c )) == NULL ) {
			    perror( "strdup" );
			    exit( 1 );
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
				    exit( 1 );
				}
				memset( l_new, 0, sizeof( struct list ));

				if (( l_new->l_string = (char*)malloc( len ))
					== NULL ) {
				    perror( "malloc" );
				    exit( 1 );
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

    return( 0 );
}


    int
ldap_value( LDAPMessage *e, char *attr, struct list *master )
{
    int				x;
    char			**values;
    struct list			*l;

    if (( values = ldap_get_values( ld, e, attr )) == NULL ) {
	/* XXX ldaperror? */
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


    int
ldap_expand( char *addr )
{
    int			result;
    int			count;
    int			i;
    struct timeval	timeout = {60,0};
    LDAPMessage		*res;
    LDAPMessage		*message;
    LDAPMessage		*entry;
    BerElement		*ber;
    char		*dn;
    char		*attribute;
    char		**values;
    char		*buf = NULL;
    size_t		buf_len = 0;
    size_t		len;
    char		*c;
    char		*d;
    char		*insert;
    size_t		place;
    char		*domain = "umich.edu";
    LDAPURLDesc		*lud;
    struct list		*l;

    if ( ldap_config() != 0 ) {
	exit( 1 );
    }

    if (( ld = ldap_init( "ldap.itd.umich.edu", 389 )) == NULL ) {
	perror( "ldap_init" );
	exit( 1 );
    }

    if ( ldap_groups == NULL ) {
	printf( "No ldap groups\n" );
	return( 0 );
    }

    if ( ldap_people == NULL ) {
	printf( "No ldap people\n" );
	return( 0 );
    }

    if ( ldap_searches == NULL ) {
	printf( "No ldap searches\n" );
	return( 0 );
    }

    for ( l = ldap_searches; l != NULL; l = l->l_next ) {
	/* make sure buf is big enough search url */
	if (( len = strlen( l->l_string) + 1 ) > buf_len ) {
	    if (( buf = (char*)realloc( buf, len )) == NULL ) {
		perror( "malloc" );
		exit( 1 );
	    }

	    buf_len = len;
	}

	d = buf;
	c = l->l_string;

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
			for ( insert = addr; *insert != '\0'; insert++ ) {
			    if (( *insert == '_' ) || ( *insert == '.' )) {
				*insert = ' ';
			    }
			}

			insert = addr;

		    } else {
			insert = domain;
		    }

		    /* if needed, resize buf to handle upcoming insert */
		    if (( len += strlen( insert )) > buf_len ) {
			place = d - buf;

			if (( buf = (char*)realloc( buf, len )) == NULL ) {
			    perror( "malloc" );
			    exit( 1 );
			}

			d = buf + place;
			buf_len = len;
		    }

		    /* insert word */
		    while ( *insert != '\0' ) {
			*d = *insert;
			insert++;
			d++;
		    }

		    /* advance read cursor */
		    c += 2;

		} else {
		    /* XXX unknown/unsupported sequence, copy & warn for now */
		    fprintf( stderr, "unknown sequence: %c\n", *( c + 1 ));
		    *d = *c;
		    c++;
		}
	    }
	}

	*d = '\0';

	if ( ldap_url_parse( buf, &lud ) != 0 ) {
	    fprintf( stderr, "ldap_url_parse %s:", buf );
	    perror( NULL );
	    exit( 1 );
	}

printf( "search base %s, filter %s\n", lud->lud_dn, lud->lud_filter );

	if ( ldap_search_st( ld, lud->lud_dn, lud->lud_scope,
		lud->lud_filter, attrs, 0, &timeout, &res ) != LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_search_st" );
	    exit( 1 );
	}

	if (( count = ldap_count_entries( ld, res )) < 0 ) {
	    ldap_perror( ld, "ldap_count_entries" );
	    goto error;
	}

	if ( count > 0 ) {
	    break;
	}
    }

    printf( "%d matches found\n", count );

    if ( count == 0 ) {
	return( 0 );
    }

    if (( entry = ldap_first_entry( ld, res )) == NULL ) {
	ldap_perror( ld, "ldap_first_entry" );
	goto error;
    }
    printf( "%d entrie(s)\n", count );

    if (( message = ldap_first_message( ld, res )) == NULL ) {
	ldap_perror( ld, "ldap_first_message" );
	goto error;
    }

    if (( result = ldap_value( entry, "objectClass", ldap_groups )) < 0 ) {
	ldap_perror( ld, "ldap_get_values 1" );
	goto error;

    } else if ( result > 0 ) {
	printf( "ITS A GROUP!\n" );

    } else {

	if (( result = ldap_value( entry, "objectClass", ldap_people )) < 0 ) {
	    ldap_perror( ld, "ldap_get_values 2" );
	    goto error;

	} else if ( result > 0 ) {
	    printf( "ITS A PERSON!\n" );

	} else {
	    /* not a group, or a person */
	    fprintf( stderr, "Not a person or a group!\n" );
	    exit( 1 );
	}


	/* get individual's email address(es) */
	/*
	if (( addrs = ldap_get_values( ld, entry, "mailForwardingAddress" ))
		== NULL ) {
	    ldap_perror( ld, "ldap_get_values 2" );
	    goto error;
	} else {
	    printf( "here\n" );
	}
	*/
    }

    if (( dn = ldap_get_dn( ld, message )) == NULL ) {
	ldap_perror( ld, "ldap_get_dn" );
	goto error;
    }
    printf( "dn: %s\n", dn );


    /* Print attriubtes and values */
    if (( attribute = ldap_first_attribute( ld, message, &ber )) == NULL ) {
	ldap_perror( ld, "ldap_first_attribute" );
	goto error;
    }
    printf( "%s:\n", attribute );
    if (( values = ldap_get_values( ld, entry, attribute )) == NULL ) {
	ldap_perror( ld, "ldap_get_values" );
	goto error;
    }
    for ( i = 0; values[ i ] != NULL; i++ ) {
	printf( "	%s\n", values[ i ] );
    }
    ldap_value_free( values );

    while (( attribute = ldap_next_attribute( ld, message, ber )) != NULL ) {
	printf( "%s:\n", attribute );
	if (( values = ldap_get_values( ld, entry, attribute )) == NULL ) {
	    ldap_perror( ld, "ldap_get_values" );
	    goto error;
	}
	for ( i = 0; values[ i ] != NULL; i++ ) {
	    printf( "	%s\n", values[ i ] );
	}
	ldap_value_free( values );
    }

    ber_free( ber, 0 );

    /* Check for ldap_first_attribute error? */

    exit( 0 );

error:
    ldap_msgfree( res );
    exit( 1 );
}
