#include <sys/time.h>		/* struct timeval */
#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

static char	*attrs[] = { "*", NULL };

    int
main( int argc, char **argv )
{
    int			count, i;
    struct timeval	timeout = {60,0};
    LDAP		*ld;
    LDAPMessage		*res;
    LDAPMessage		*message;
    LDAPMessage		*entry;
    BerElement		*ber;
    char		*base = "ou=People, dc=umich, dc=edu";
    int 		scope = LDAP_SCOPE_SUBTREE;
    char 		*filter = "uid=mcneal";
    char		*dn;
    char		*attribute;
    char		**values;

    if (( ld = ldap_init( "ldap.itd.umich.edu", 389 )) == NULL ) {
	perror( "ldap_init" );
	exit( 1 );
    }

    if ( ldap_search_st( ld, base, scope, filter, attrs, 0, &timeout,
	    &res ) != LDAP_SUCCESS ) {
	ldap_perror( ld, "ldap_search_st" );
	exit( 1 );
    }

    if (( count = ldap_count_entries( ld, res )) < 0 ) {
	ldap_perror( ld, "ldap_count_entries" );
	goto error;
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
