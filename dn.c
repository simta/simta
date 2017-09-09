/* Copyright (c) 1992-1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

/* dn.c - routines for dealing with distinguished names
 *
 * Copied from UM-LDAP
 */

#include <ctype.h>
#include <stdio.h>

#include "dn.h"

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

/*
 * dn_normalize - put dn into a canonical format.  the dn is
 * normalized in place, as well as returned.
 */

char *
dn_normalize( char *dn )
{
    char	*d, *s;
    int	state, gotesc;

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
	    } else if ( gotesc && !NEEDSESCAPE( *s ) && !SEPARATOR( *s ) ) {
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
	    fprintf (stderr, "dn_normalize - unknown state %d dn:%s \n",
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
	*s = tolower((unsigned char) *s );
    }

    return( dn );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
