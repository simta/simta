/* dn.c - routines for dealing with distinguished names */

#include <stdio.h>
#include <ctype.h>

#define B4TYPE		0
#define INTYPE		1
#define B4EQUAL		2
#define B4VALUE		3
#define INVALUE		4
#define INQUOTEDVALUE	5
#define B4SEPARATOR	6

#define DNSEPARATOR(c)  ((c) == ',' || (c) == ';')
#define SEPARATOR(c)    ((c) == ',' || (c) == ';' || (c) == '+')
#define SPACE(c)        ((c) == ' ' || (c) == '\n')
#define NEEDSESCAPE(c)  ((c) == '\\' || (c) == '"')

# define TOUPPER(c)        (islower(c) ? toupper(c) : (c))
# define TOLOWER(c)        (isupper(c) ? tolower(c) : (c))

/*
 * dn_normalize - put dn into a canonical format.  the dn is
 * normalized in place, as well as returned.
 */

char *
dn_normalize( char *dn )
{
	char	*d, *s;
	int	state, gotesc;

	/* Debug( LDAP_DEBUG_TRACE, "=> dn_normalize \"%s\"\n", dn, 0, 0 ); */

	gotesc = 0;
	state = B4TYPE;
	for ( d = s = dn; *s; s++ ) {
		switch ( state ) {
		case B4TYPE:
			if ( ! SPACE( *s ) ) {
				state = INTYPE;
				*d++ = *s;
			}
			break;
		case INTYPE:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				*d++ = *s;
			}
			break;
		case B4EQUAL:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*d++ = *s;
			}
			break;
		case B4VALUE:
			if ( *s == '"' ) {
				state = INQUOTEDVALUE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) { 
				state = INVALUE;
				*d++ = *s;
			}
			break;
		case INVALUE:
			if ( !gotesc && SEPARATOR( *s ) ) {
				while ( SPACE( *(d - 1) ) )
					d--;
				state = B4TYPE;
				if ( *s == '+' ) {
					*d++ = *s;
				} else {
					*d++ = ',';
				}
			} else if ( gotesc && !NEEDSESCAPE( *s ) &&
			    !SEPARATOR( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case INQUOTEDVALUE:
			if ( !gotesc && *s == '"' ) {
				state = B4SEPARATOR;
				*d++ = *s;
			} else if ( gotesc && !NEEDSESCAPE( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case B4SEPARATOR:
			if ( SEPARATOR( *s ) ) {
				state = B4TYPE;
				*d++ = *s;
			}
			break;
		default:
			fprintf (stderr,
			    "dn_normalize - unknown state %d dn:%s \n", 
				state, dn );
			break;
		}
		if ( *s == '\\' ) {
			gotesc = 1;
		} else {
			gotesc = 0;
		}
	}
	*d = '\0';

	/* Debug( LDAP_DEBUG_TRACE, "<= dn_normalize \"%s\"\n", dn, 0, 0 ); */
	return( dn );
}

/*
 * dn_normalize_case - put dn into a canonical form suitable for storing
 * in a hash database.  this involves normalizing the case as well as
 * the format.  the dn is normalized in place as well as returned.
 */

char *
dn_normalize_case( char *dn )
{
	char	*s;

	/* normalize format */
	dn_normalize( dn );

	/* normalize case */
	for ( s = dn; *s; s++ ) {
		*s = TOLOWER( (unsigned char) *s );
	}

	return( dn );
}
