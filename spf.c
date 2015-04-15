/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <denser.h>
#include <yasl.h>

#include "spf.h"
#include "dns.h"
#include "simta.h"

struct spf_state {
    yastr			s_local;
    yastr			s_domain;
    yastr			s_ehlo;
    const struct sockaddr	*s_addr;
};

int spf_check_host( const struct spf_state *, const yastr );
static int spf_check_a( const struct spf_state *, const yastr, long int, const char * );
static yastr spf_macro_expand( const struct spf_state *, const yastr, const yastr );
static yastr spf_parse_domainspec_cidr( const struct spf_state *, const yastr, yastr, long int *, long int * );
static int simta_cidr_compare( int, long int, const struct sockaddr *, const struct sockaddr *, const char * );

    int
spf_lookup( const char *ehlo, const char *email, const struct sockaddr *addr )
{
    int			    ret = SPF_RESULT_NONE;
    char		    *p;
    struct spf_state	    s;

    s.s_addr = addr;
    s.s_ehlo = yaslauto( ehlo );

    if (( p = strrchr( email, '@' )) != NULL ) {
	s.s_domain = yaslauto( p + 1 );
	s.s_local = yaslnew( email, p - email );
    } else {
	s.s_domain = yaslauto( email );
	s.s_local = yaslauto( "postmaster" );
    }

    if ( simta_spf_verbose ) {
	syslog( LOG_DEBUG, "SPF %s: localpart %s", s.s_domain, s.s_local );
    }

    ret = spf_check_host( &s, s.s_domain );

    yaslfree( s.s_domain );
    yaslfree( s.s_local );
    yaslfree( s.s_ehlo );

    return( ret );
}

    int
spf_check_host( const struct spf_state *s, const yastr domain )
{
    int			    i, j, rc, qualifier, ret = SPF_RESULT_NONE;
    struct dnsr_result	    *dnsr_res, *dnsr_res_mech = NULL;
    struct dnsr_string      *txt;
    yastr		    record = NULL, redirect = NULL, domain_spec, tmp;
    size_t		    tok_count;
    yastr		    *split = NULL;
    char		    *p;
    long int		    cidr, cidr6;

    /* RFC 7208 3.1 DNS Resource Records
     * SPF records MUST be published as a DNS TXT (type 16) Resource Record
     * (RR) [RFC1035] only.
     */
    if (( dnsr_res = get_txt( domain )) == NULL ) {
	syslog( LOG_WARNING, "SPF %s [%s]: TXT lookup %s failed",
		s->s_domain, domain, domain );
	return( SPF_RESULT_TEMPERROR );
    }

    for ( i = 0 ; i < dnsr_res->r_ancount ; i++ ) {
	if ( dnsr_res->r_answer[ i ].rr_type == DNSR_TYPE_TXT ) {
	    txt = dnsr_res->r_answer[ i ].rr_txt.txt_data;
	    /* RFC 7208 4.5 Selecting Records
	     * Starting with the set of records that were returned by the
	     * lookup, discard records that do not begin with a version section
	     * of exactly "v=spf1".  Note that the version section is
	     * terminated by either an SP character or the end of the record.
	     */
	    if (( strncasecmp( txt->s_string, "v=spf1", 6 ) == 0 ) &&
		    (( txt->s_string[ 6 ] == ' ' ) ||
		    ( txt->s_string[ 6 ] == '\0' ))) {
		if ( record != NULL ) {
		    /* RFC 7208 3.2 Multiple DNS Records
		     * A domain name MUST NOT have multiple records that would
		     * cause an authorization check to select more than one
		     * record.
		     */
		    syslog( LOG_ERR,
			    "SPF %s [%s]: multiple v=spf1 records found",
			    s->s_domain, domain );
		    ret = SPF_RESULT_PERMERROR;
		    goto cleanup;
		}
		record = yaslempty( );
		/* RFC 7208 3.3 Multiple Strings in a Single DNS Record
		 * If a published record contains multiple character-strings,
		 * then the record MUST be treated as if those strings are
		 * concatenated together without adding spaces.
		 */
		for ( ; txt != NULL ; txt = txt->s_next ) {
		    record = yaslcat( record, txt->s_string );
		}
	    }
	}
    }

    if ( record == NULL ) {
	syslog( LOG_DEBUG, "SPF %s [%s]: no SPF record found",
		s->s_domain, domain );
	goto cleanup;
    }

    if ( simta_spf_verbose ) {
	syslog( LOG_DEBUG, "SPF %s [%s]: record: %s",
		s->s_domain, domain, record );
    }

    split = yaslsplitlen( record, yasllen( record ), " ", 1, &tok_count );

    /* Start at 1, 0 is v=spf1 */
    for ( i = 1 ; i < tok_count ; i++ ) {
	/* multiple spaces in a record will result in empty elements */
	if ( yasllen( split[ i ] ) == 0 ) {
	    continue;
	}

	/* RFC 7208 4.6.2 Mechanisms
	 * The possible qualifiers, and the results they cause check_host() to
	 * return, are as follows:
	 *
	 * "+" pass
	 * "-" fail
	 * "~" softfail
	 * "?" neutral
	 *
	 * The qualifier is optional and defaults to "+".
	 */
	switch ( *split[ i ] ) {
	case '+':
	    qualifier = SPF_RESULT_PASS;
	    yaslrange( split[ i ], 1, -1 );
	    break;
	case '-':
	    qualifier = SPF_RESULT_FAIL;
	    yaslrange( split[ i ], 1, -1 );
	    break;
	case '~':
	    qualifier = SPF_RESULT_SOFTFAIL;
	    yaslrange( split[ i ], 1, -1 );
	    break;
	case '?':
	    qualifier = SPF_RESULT_NEUTRAL;
	    yaslrange( split[ i ], 1, -1 );
	    break;
	default:
	    qualifier = SPF_RESULT_PASS;
	    break;
	}

	if ( strncasecmp( split[ i ], "redirect=", 9 ) == 0 ) {
	    redirect = split[ i ];
	    yaslrange( redirect, 9, -1 );
	    if ( simta_spf_verbose ) {
		syslog( LOG_DEBUG, "SPF %s [%s]: redirect to %s",
			s->s_domain, domain, redirect );
	    }

	/* RFC 7208 5.1 "all"
	 * The "all" mechanism is a test that always matches.
	 */
	} else if ( strcasecmp( split[ i ], "all" ) == 0 ) {
	    if ( simta_spf_verbose ) {
		syslog( LOG_DEBUG, "SPF %s [%s]: matched all: %s",
			s->s_domain, domain, spf_result_str( qualifier ));
	    }
	    ret = qualifier;
	    goto cleanup;

	/* RFC 7208 5.2 "include"
	 * The "include" mechanism triggers a recursive evaluation of
	 * check_host().
	 */
	} else if ( strncasecmp( split[ i ], "include:", 8 ) == 0 ) {
	    yaslrange( split[ i ], 8, -1 );
	    if ( simta_spf_verbose ) {
		syslog( LOG_DEBUG, "SPF %s [%s]: include %s",
			s->s_domain, domain, split[ i ] );
	    }
	    rc = spf_check_host( s, split[ i ] );
	    switch ( rc ) {
	    case SPF_RESULT_NONE:
		ret = SPF_RESULT_PERMERROR;
		goto cleanup;
	    case SPF_RESULT_PASS:
		ret = qualifier;
		goto cleanup;
	    case SPF_RESULT_TEMPERROR:
	    case SPF_RESULT_PERMERROR:
		ret = rc;
		goto cleanup;
	    }

	/* RFC 7208 5.3 "a" */
	} else if (( strcasecmp( split[ i ], "a" ) == 0 ) ||
		( strncasecmp( split[ i ], "a:", 2 ) == 0 ) ||
		( strncasecmp( split[ i ], "a/", 2 ) == 0 )) {
	    yaslrange( split[ i ], 1, -1 );

	    if (( domain_spec = spf_parse_domainspec_cidr( s, domain,
		    split[ i ], &cidr, &cidr6 )) == NULL ) {
		/* Macro expansion failed, probably a syntax problem. */
		ret = SPF_RESULT_PERMERROR;
		goto cleanup;
	    }

	    rc = spf_check_a( s, domain, cidr, domain_spec );

	    switch( rc ) {
	    case SPF_RESULT_PASS:
		if ( simta_spf_verbose ) {
		    syslog( LOG_DEBUG, "SPF %s [%s]: matched a %s/%ld: %s",
			    s->s_domain, domain, domain_spec, cidr,
			spf_result_str( qualifier ));
		}
		yaslfree( domain_spec );
		ret = qualifier;
		goto cleanup;
	    case SPF_RESULT_TEMPERROR:
		yaslfree( domain_spec );
		ret = rc;
		goto cleanup;
	    default:
		break;
	    }

	    yaslfree( domain_spec );

	/* RFC 7208 5.4 "mx" */
	} else if (( strcasecmp( split[ i ], "mx" ) == 0 ) ||
		( strncasecmp( split[ i ], "mx:", 3 ) == 0 ) ||
		( strncasecmp( split[ i ], "mx/", 3 ) == 0 )) {
	    yaslrange( split[ i ], 2, -1 );

	    if (( domain_spec = spf_parse_domainspec_cidr( s, domain,
		    split[ i ], &cidr, &cidr6 )) == NULL ) {
		/* Macro expansion failed, probably a syntax problem. */
		ret = SPF_RESULT_PERMERROR;
		goto cleanup;
	    }

	    if (( dnsr_res_mech = get_mx( domain_spec )) == NULL ) {
		syslog( LOG_WARNING, "SPF %s [%s]: MX lookup %s failed",
			s->s_domain, domain, domain_spec );
		yaslfree( domain_spec );
		ret = SPF_RESULT_TEMPERROR;
		goto cleanup;
	    }

	    for ( j = 0 ; j < dnsr_res_mech->r_ancount ; j++ ) {
		if ( dnsr_res_mech->r_answer[ j ].rr_type == DNSR_TYPE_MX ) {
		    rc = spf_check_a( s, domain, cidr,
			    dnsr_res_mech->r_answer[ j ].rr_mx.mx_exchange );
		    switch( rc ) {
		    case SPF_RESULT_PASS:
			if ( simta_spf_verbose ) {
			    syslog( LOG_DEBUG,
				    "SPF %s [%s]: matched mx %s/%ld: %s",
				    s->s_domain, domain, domain_spec, cidr,
				    spf_result_str( qualifier ));
			}
			ret = qualifier;
			dnsr_free_result( dnsr_res_mech );
			yaslfree( domain_spec );
			goto cleanup;
		    case SPF_RESULT_PERMERROR:
		    case SPF_RESULT_TEMPERROR:
			ret = rc;
			dnsr_free_result( dnsr_res_mech );
			yaslfree( domain_spec );
			goto cleanup;
		    default:
			break;
		    }
		}
	    }

	    dnsr_free_result( dnsr_res_mech );
	    yaslfree( domain_spec );

	/* RFC 7208 5.5 "ptr" (do not use) */
	} else if (( strcasecmp( split[ i ], "ptr" ) == 0 ) ||
		( strncasecmp( split[ i ], "ptr:", 4 ) == 0 )) {
	    if (( dnsr_res_mech = get_ptr( s->s_addr )) == NULL ) {
		/* RFC 7208 5.5 "ptr" (do not use )
		 * If a DNS error occurs while doing the PTR RR lookup,
		 * then this mechanism fails to match.
		 */
		continue;
	    }

	    if ( dnsr_res_mech->r_ancount == 0 ) {
		dnsr_free_result( dnsr_res_mech );
		continue;
	    }

	    if ( split[ i ][ 3 ] == ':' ) {
		domain_spec = yaslnew(( split[ i ] + 4 ),
			( yasllen( split[ i ] ) - 4 ));
	    } else {
		domain_spec = yasldup( domain );
	    }

	    for ( j = 0 ; j < dnsr_res_mech->r_ancount ; j++ ) {
		if ( dnsr_res_mech->r_answer[ j ].rr_type != DNSR_TYPE_PTR ) {
		    continue;
		}
		/* We only care if it's a pass; like the initial PTR query,
		 * DNS errors are treated as a non-match rather than an error.
		 */
		/* FIXME:
		 * RFC 7208 4.6.4 DNS Lookup Limits
		 * the evaluation of each "PTR" record MUST NOT result in
		 * querying more than 10 address records -- either "A" or
		 * "AAAA" resource records.  If this limit is exceeded, all
		 * records  other than the first 10 MUST be ignored.
		 */
		if ( spf_check_a( s, domain, 32,
			dnsr_res_mech->r_answer[ j ].rr_dn.dn_name ) ==
			SPF_RESULT_PASS ) {
		    tmp = yaslauto(
			    dnsr_res_mech->r_answer[ j ].rr_dn.dn_name );
		    while (( yasllen( tmp ) > yasllen( domain_spec )) &&
			    ( p = strchr( tmp, '.' ))) {
			yaslrange( tmp, ( p - tmp + 1 ), -1 );
		    }
		    rc = strcasecmp( tmp, domain_spec );
		    yaslfree( tmp );
		    if ( rc == 0 ) {
			if ( simta_spf_verbose ) {
			    syslog( LOG_DEBUG,
				    "SPF %s [%s]: matched ptr %s (%s): %s",
				    s->s_domain, domain, domain_spec,
				    dnsr_res_mech->r_answer[ j ].rr_dn.dn_name,
				    spf_result_str( qualifier ));
			}
			ret = qualifier;
			yaslfree( domain_spec );
			dnsr_free_result( dnsr_res_mech );
			goto cleanup;
		    }
		}
	    }

	    yaslfree( domain_spec );
	    dnsr_free_result( dnsr_res_mech );

	/* RFC 7208 5.6 "ip4" and "ip6"
	 * These mechanisms test whether <ip> is contained within a given
	 * IP network.
	 */
	} else if ( strncasecmp( split[ i ], "ip4:", 4 ) == 0 ) {
	    if ( s->s_addr->sa_family != AF_INET ) {
		continue;
	    }

	    yaslrange( split[ i ], 4, -1 );
	    if (( p = strchr( split[ i ], '/' )) != NULL ) {
		cidr = strtol( p + 1, NULL, 10 );
		if (( cidr < 0 ) || ( cidr > 32 )) {
		    syslog( LOG_WARNING, "SPF %s [%s]: invalid CIDR mask: %ld",
			    s->s_domain, domain, cidr );
		    ret = SPF_RESULT_PERMERROR;
		    goto cleanup;
		}
		yaslrange( split[ i ], 0, p - split[ i ] - 1 );
	    } else {
		cidr = 32;
	    }

	    if (( rc = simta_cidr_compare( AF_INET, cidr,
		    s->s_addr, NULL, split[ i ] )) < 0 ) {
		syslog( LOG_WARNING,
			"SPF %s [%s]: simta_cidr_compare failed for %s",
			s->s_domain, domain, split[ i ] );
		ret = SPF_RESULT_PERMERROR;
		goto cleanup;
	    } else if ( rc == 0 ) {
		if ( simta_spf_verbose ) {
		    syslog( LOG_DEBUG, "SPF %s [%s]: matched ip4 %s/%ld: %s",
			    s->s_domain, domain, split[ i ], cidr,
			    spf_result_str( qualifier ));
		}
		ret = qualifier;
		goto cleanup;
	    }

	} else if ( strncasecmp( split[ i ], "ip6:", 4 ) == 0 ) {
	    if ( s->s_addr->sa_family != AF_INET6 ) {
		continue;
	    }
	    /* This is just a stub for now; simta doesn't support IPv6 yet. */
	    if ( simta_spf_verbose ) {
		syslog( LOG_DEBUG, "SPF %s [%s]: burning desire to check ip6",
			s->s_domain, domain );
	    }

	/* RFC 7208 5.7 "exists" */
	} else if ( strncasecmp( split[ i ], "exists:", 7 ) == 0 ) {
	    yaslrange( split[ i ], 7, -1 );
	    if (( domain_spec =
		    spf_macro_expand( s, domain, split[ i ] )) == NULL ) {
		/* Macro expansion failed, probably a syntax problem. */
		ret = SPF_RESULT_PERMERROR;
		goto cleanup;
	    }

	    if (( dnsr_res_mech = get_a( domain_spec )) == NULL ) {
		syslog( LOG_WARNING, "SPF %s [%s]: A lookup %s failed",
			s->s_domain, domain, domain_spec );
		yaslfree( domain_spec );
		ret = SPF_RESULT_TEMPERROR;
		goto cleanup;
	    }

	    if ( dnsr_res_mech->r_ancount > 0 ) {
		if ( simta_spf_verbose ) {
		    syslog( LOG_DEBUG, "SPF %s [%s]: matched exists %s: %s",
			    s->s_domain, domain, domain_spec,
			    spf_result_str( qualifier ));
		}
		dnsr_free_result( dnsr_res_mech );
		yaslfree( domain_spec );
		ret = qualifier;
		goto cleanup;
	    }

	    yaslfree( domain_spec );
	    dnsr_free_result( dnsr_res_mech );

	} else {
	    for ( p = split[ i ] ; isalnum( *p ) ; p++ );

	    if ( *p == '=' ) {
		/* RFC 7208 6 Modifier Definitions
		 * Unrecognized modifiers MUST be ignored
		 */
		syslog( LOG_DEBUG, "SPF %s [%s]: %s unknown modifier %s",
			s->s_domain, domain, spf_result_str( qualifier ),
			split[ i ] );
	    } else {
		syslog( LOG_WARNING, "SPF %s [%s]: %s unknown mechanism %s",
			s->s_domain, domain, spf_result_str( qualifier ),
			split[ i ] );
		ret = SPF_RESULT_PERMERROR;
		goto cleanup;
	    }
	}
    }

    if ( redirect != NULL ) {
	if (( domain_spec = spf_macro_expand( s, domain, redirect )) == NULL ) {
	    /* Macro expansion failed, probably a syntax problem. */
	    ret = SPF_RESULT_PERMERROR;
	} else {
	    ret = spf_check_host( s, domain_spec );
	    yaslfree( domain_spec );
	}
	if ( ret == SPF_RESULT_NONE ) {
	    ret = SPF_RESULT_PERMERROR;
	}

    } else {
	/* RFC 7208 4.7 Default Result
	 * If none of the mechanisms match and there is no "redirect" modifier,
	 * then the check_host() returns a result of "neutral", just as if
	 * "?all" were specified as the last directive.
	 */
	ret = SPF_RESULT_NEUTRAL;
	if ( simta_spf_verbose ) {
	    syslog( LOG_DEBUG, "SPF %s [%s]: default result: %s",
		    s->s_domain, domain, spf_result_str( ret ));
	}
    }

cleanup:
    if ( split != NULL ) {
	yaslfreesplitres( split, tok_count );
    }
    yaslfree( record );
    dnsr_free_result( dnsr_res );
    return( ret );
}

    static int
spf_check_a( const struct spf_state *s, const yastr domain, long int cidr, const char *a )
{
    int			    i;
    struct sockaddr_in	    sai;
    struct dnsr_result	    *dnsr_res;

    if (( dnsr_res = get_a( a )) == NULL ) {
	syslog( LOG_WARNING, "SPF %s [%s]: A lookup %s failed",
	    s->s_domain, domain, a );
	return( SPF_RESULT_TEMPERROR );
    }

    for ( i = 0 ; i < dnsr_res->r_ancount ; i++ ) {
	if ( dnsr_res->r_answer[ i ].rr_type == DNSR_TYPE_A ) {
	    sai.sin_family = AF_INET;
	    memcpy( &(sai.sin_addr), &(dnsr_res->r_answer[ i ].rr_a.a_address),
		    sizeof( struct in_addr ));
	    if ( simta_cidr_compare( AF_INET, cidr, s->s_addr,
		    (struct sockaddr *)&sai, NULL ) == 0 ) {
		dnsr_free_result( dnsr_res );
		return( SPF_RESULT_PASS );
	    }
	}
    }

    dnsr_free_result( dnsr_res );
    return( SPF_RESULT_FAIL );
}

    static yastr
spf_macro_expand( const struct spf_state *s,
	const yastr domain, const yastr macro )
{
    int	    urlescape, dtransform, rtransform, i, j;
    char    *p, *pp;
    char    delim;
    yastr   expanded, tmp, escaped;
    yastr   *split;
    size_t  tok_count;

    expanded = yaslempty( );
    escaped = yaslempty( );
    tmp = yaslempty( );

    for ( p = macro ; *p != '\0' ; p++ ) {
	if ( *p != '%' ) {
	    expanded = yaslcatlen( expanded, p, 1 );
	    continue;
	}
	p++;
	switch( *p ) {
	case '%':
	    expanded = yaslcat( expanded, "%" );
	    break;
	case '_':
	    expanded = yaslcat( expanded, "_" );
	    break;
	case '-':
	    expanded = yaslcat( expanded, "%20" );
	    break;
	case '{':
	    p++;
	    /* RFC 7208 7.3 Macro Processing Details
	     * Uppercase macros expand exactly as their lowercase equivalents,
	     * and are then URL escaped.
	     */
	    urlescape = isupper( *p );
	    switch( *p ) {
		case 'S':
		case 's':
		    yaslclear( tmp );
		    tmp = yaslcatprintf( tmp, "%s@%s", s->s_local,
			    s->s_domain );
		    break;
		case 'L':
		case 'l':
		    tmp = yaslcpy( tmp, s->s_local );
		    break;
		case 'O':
		case 'o':
		    tmp = yaslcpy( tmp, s->s_domain );
		    break;
		case 'D':
		case 'd':
		    tmp = yaslcpy( tmp, domain );
		    break;
		case 'I':
		case 'i':
		    if ( s->s_addr->sa_family == AF_INET ) {
			tmp = yaslgrowzero( tmp, INET_ADDRSTRLEN );
			if ( inet_ntop( s->s_addr->sa_family,
				&((struct sockaddr_in *)s->s_addr)->sin_addr,
				tmp, yasllen( tmp )) == NULL ) {
			    goto error;
			}
			yaslupdatelen( tmp );
		    }
		    break;
		case 'P':
		case 'p':
		    /* This is overly complex and should not be used,
		     * so we're not going to implement it. */
		    tmp = yaslcpy( tmp, "unknown" );
		    break;
		case 'V':
		case 'v':
		    tmp = yaslcpy( tmp, ( s->s_addr->sa_family == AF_INET6 ) ?
			    "ip6" : "in-addr" );
		    break;
		case 'H':
		case 'h':
		    tmp = yaslcpy( tmp, s->s_ehlo );
		    break;
		default:
		    syslog( LOG_WARNING,
			    "SPF %s [%s]: invalid macro-letter: %c",
			    s->s_domain, domain, *p );
		    goto error;
	    }

	    if ( urlescape ) {
		/* RFC 7208 7.3 Macro Processing Details
		 * Uppercase macros expand exactly as their lowercase
		 * equivalents, and are then URL escaped. URL escaping MUST be
		 * performed for characters not in the "unreserved" set, which
		 * is defined in [RFC3986].
		 */
		yaslclear( escaped );
		for ( pp = tmp ; *pp != '\0' ; pp++ ) {
		    /* RFC 3986 2.3 Unreserved Characters
		     * Characters that are allowed in a URI but do not have a
		     * reserved purpose are called unreserved.  These include
		     * uppercase and lowercase letters, decimal digits, hyphen,
		     * period, underscore, and tilde.
		     */
		    if ( isalnum( *pp ) || *pp == '-' || *pp == '.' ||
			    *pp == '_' || *pp == '~' ) {
			escaped = yaslcatlen( escaped, pp, 1 );
		    } else {
			/* Reserved */
			escaped = yaslcatprintf( escaped, "%%%X", *pp );
		    }
		}
		tmp = yaslcpylen( tmp, escaped, yasllen( escaped ));
	    }
	    p++;

	    /* Check for transformers */
	    dtransform = 0;
	    rtransform = 0;
	    if ( isdigit( *p )) {
		dtransform = strtol( p, &pp, 10 );
		p = pp;
	    }

	    if ( *p == 'r' ) {
		rtransform = 1;
		p++;
	    }

	    delim = '\0';
	    for ( pp = p ; *pp != '\0' ; pp++ ) {
		if ( *pp == '}' ) {
		    break;
		}
		switch( *pp ) {
		/* RFC 7208 7.1 Formal Specification
		 * delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
		 */
		case '.':
		case '-':
		case '+':
		case ',':
		case '/':
		case '_':
		case '=':
			if ( delim != '\0' ) {
			    tmp = yaslmapchars( tmp, pp, &delim, 1 );
			} else {
			    delim = *pp;
			}
		    break;
		default:
		    syslog( LOG_WARNING, "SPF %s [%s]: invalid delimiter: %c",
			    s->s_domain, domain, *pp );
		    goto error;
		}
	    }

	    if (( rtransform == 1 ) || ( dtransform > 0 ) ||
		    ( delim != '\0' )) {
		if ( delim == '\0' ) {
		    delim = '.';
		}
		split = yaslsplitlen( tmp, yasllen( tmp ), &delim, 1,
		    &tok_count );
		yaslclear( tmp );
		if ( rtransform == 1 ) {
		    if (( dtransform > 0 ) && ( tok_count > dtransform )) {
			j = tok_count - dtransform;
		    } else {
			j = 0;
		    }
		    for ( i = tok_count - 1 ; i >= j ; i-- ) {
			if ( yasllen( tmp ) > 0 ) {
			    tmp = yaslcat( tmp, "." );
			}
			tmp = yaslcatyasl( tmp, split [ i ] );
		    }
		} else {
		    if (( dtransform > 0 ) && (tok_count > dtransform )) {
			j = dtransform;
		    } else {
			j = tok_count;
		    }
		    for ( i = 0 ; i < j ; i++ ) {
			if ( yasllen( tmp ) > 0 ) {
			    tmp = yaslcat( tmp, "." );
			}
			tmp = yaslcatyasl( tmp, split[ i ] );
		    }
		}
		yaslfreesplitres( split, tok_count );
	    }
	    expanded = yaslcatyasl( expanded, tmp );
	    break;
	default:
	    syslog( LOG_WARNING, "SPF %s [%s]: invalid macro-expand: %s",
		    s->s_domain, domain, p );
	    goto error;
	}
    }

    if ( yaslcmp( macro, expanded ) && simta_spf_verbose ) {
	syslog( LOG_DEBUG, "SPF %s [%s]: expanded %s to %s",
		s->s_domain, domain, macro, expanded );
    }

    yaslfree( tmp );
    yaslfree( escaped );
    return( expanded );

error:
    yaslfree( tmp );
    yaslfree( escaped );
    yaslfree( expanded );
    return( NULL );
}

    const char *
spf_result_str( const int res )
{
    switch( res ) {
    case SPF_RESULT_PASS:
	return( "pass" );
    case SPF_RESULT_FAIL:
	return( "fail" );
    case SPF_RESULT_SOFTFAIL:
	return( "softfail" );
    case SPF_RESULT_NEUTRAL:
	return( "neutral" );
    case SPF_RESULT_NONE:
	return( "none" );
    case SPF_RESULT_TEMPERROR:
	return( "temperror" );
    case SPF_RESULT_PERMERROR:
	return( "permerror" );
    }
    return( "INVALID" );
}

    static yastr
spf_parse_domainspec_cidr( const struct spf_state *s, yastr domain, yastr dsc, long int *cidr, long int *cidr6 )
{
    char    *p;
    yastr   tmp, domain_spec;

    if ( dsc[ 0 ] == ':' ) {
	yaslrange( dsc, 1, -1 );
	tmp = yasldup( dsc );
	if (( p = strchr( tmp, '/' )) != NULL ) {
	    yaslrange( tmp, 0, ( p - tmp - 1 ));
	    yaslrange( dsc, ( p - tmp ), -1 );
	} else {
	    yaslclear( dsc );
	}
	domain_spec = spf_macro_expand( s, domain, tmp );
	yaslfree( tmp );
	if ( domain_spec == NULL ) {
	    /* Macro expansion failed, probably a syntax problem. */
	    return( NULL );
	}
    } else {
	domain_spec = yasldup( domain );
    }

    *cidr = 32;
    *cidr6 = 128;

    if ( dsc[ 0 ] == '/' ) {
	*cidr = strtol( dsc + 1, &p, 10 );
	if ( *p == '/' ) {
	    *cidr6 = strtol( p + 1, NULL, 10 );
	}
    }

    return( domain_spec );
}

    static int
simta_cidr_compare( int af, long int netmask, const struct sockaddr *addr,
	const struct sockaddr *addr2, const char *ip )
{
    int			rc, ret = 1;
    struct addrinfo	*ip_ai = NULL;
    struct addrinfo	hints;

    if ( af != addr->sa_family ) {
	return( 1 );
    }

    if ( netmask == 0 ) {
	return( 0 );
    }

    if ( addr2 == NULL ) {
	memset( &hints, 0, sizeof( struct addrinfo ));
	hints.ai_family = af;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	if (( rc = getaddrinfo( ip, NULL, &hints, &ip_ai )) != 0 ) {
	    syslog( LOG_DEBUG, "Syserror: simta_cidr_compare getaddrinfo: %s",
		    gai_strerror( rc ));
	    return( -1 );
	}

	addr2 = ip_ai->ai_addr;
    }

    if ( af == AF_INET ) {
	if ( ! ((((struct sockaddr_in *)addr)->sin_addr.s_addr ^
		((struct sockaddr_in *)addr2)->sin_addr.s_addr ) &
		htonl(( 0xFFFFFFFF << ( 32 - netmask ))))) {
	    ret = 0;
	}
    }

    /* AF_INET6 is a bit trickier, so we won't worry about that right now. */

    if ( ip_ai != NULL ) {
	freeaddrinfo( ip_ai );
    }

    return( ret );
}

/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
