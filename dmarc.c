/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <denser.h>
#include <yasl.h>

#include "dmarc.h"
#include "dns.h"
#include "ll.h"
#include "simta.h"

static int dmarc_alignment( char *, char *, int );
static struct dnsr_result *dmarc_lookup_record( const char * );
static yastr dmarc_orgdomain( const char * );
static int dmarc_parse_record( struct dmarc *, yastr );
static int dmarc_parse_result( struct dmarc *, struct dnsr_result * );

    int
dmarc_init( struct dmarc **d )
{
    *d = calloc( 1, sizeof( struct dmarc ));
    dmarc_reset( *d );
    return( 0 );
}

    void
dmarc_reset( struct dmarc *d )
{
    if ( d != NULL ) {
	if ( d->domain ) {
	    yaslfree( d->domain );
	    d->domain = NULL;
	}
	if ( d->spf_domain ) {
	    yaslfree( d->spf_domain );
	    d->spf_domain = NULL;
	}
	if ( d->dkim_domain_list ) {
	    dll_free( d->dkim_domain_list );
	    d->dkim_domain_list = NULL;
	}
	d->policy = DMARC_RESULT_NORECORD;
	d->subpolicy = DMARC_RESULT_NORECORD;
	d->result = DMARC_RESULT_NONE;
	d->dkim_alignment = DMARC_ALIGNMENT_RELAXED;
	d->spf_alignment = DMARC_ALIGNMENT_RELAXED;
	d->pct = 100;
    }
}

    void
dmarc_free( struct dmarc *d )
{
    if ( d == NULL ) {
	return;
    }

    if ( d->domain ) {
	yaslfree( d->domain );
    }
    if ( d->spf_domain ) {
	yaslfree( d->spf_domain );
    }
    if ( d->dkim_domain_list ) {
	dll_free( d->dkim_domain_list );
    }

    free( d );
}

    int
dmarc_lookup( struct dmarc *d, const char *domain )
{
    int				rc;
    struct dnsr_result		*dnsr_result;
    yastr			orgdomain;

    simta_debuglog( 2, "DMARC %s: looking up policy", domain );

    if ( d->domain != NULL ) {
	syslog( LOG_ERR, "DMARC %s: domain already defined", domain );
	yaslfree( d->domain );
    }

    d->domain = yaslauto( domain );

    /* RFC 7489 6.6.3 Policy Discovery
     * Mail Receivers MUST query the DNS for a DMARC TXT record at the DNS
     * domain matching the one found in the RFC5322.From domain in the message.
     * A possibly empty set of records is returned.
     */
    if (( dnsr_result = dmarc_lookup_record( d->domain )) == NULL ) {
	syslog( LOG_WARNING, "DMARC %s: dmarc_lookup_record returned NULL",
		d->domain );
    } else {
	rc = dmarc_parse_result( d, dnsr_result );
	dnsr_free_result( dnsr_result );
	if ( rc == 0 ) {
	    return( 0 );
	}
    }

    /* RFC 7489 6.6.3 Policy Discovery
     * If the set is now empty, the Mail Receiver MUST query the DNS for
     * a DMARC TXT record at the DNS domain matching the Organizational
     * Domain in place of the RFC5322.From domain in the message (if
     * different).  This record can contain policy to be asserted for
     * subdomains of the Organizational Domain.  A possibly empty set of
     * records is returned.
     */
    d->result = DMARC_RESULT_ORGDOMAIN;
    orgdomain = dmarc_orgdomain( d->domain );
    if ( yaslcmp( orgdomain, d->domain ) == 0 ) {
	yaslfree( orgdomain );
	return( 1 );
    }

    simta_debuglog( 1, "DMARC %s: Checking Organizational Domain %s",
	    d->domain, orgdomain );

    dnsr_result = dmarc_lookup_record( orgdomain );
    yaslfree( orgdomain );

    if ( dnsr_result == NULL ) {
	simta_debuglog( 1,
		"DMARC %s: dmarc_lookup_record returned NULL for orgdomain",
		d->domain );
	return( 1 );
    }

    rc = dmarc_parse_result( d, dnsr_result );
    dnsr_free_result( dnsr_result );

    if ( rc == 0 ) {
	return( 0 );
    }

    return( 1 );
}

    int
dmarc_result( struct dmarc *d )
{
    struct dll_entry	*dkim_domain;

    if ( d->domain == NULL ) {
	syslog( LOG_ERR, "DMARC: no DMARC domain set" );
	return( DMARC_RESULT_NORECORD );
    }

    if ( d->spf_domain != NULL ) {
	if ( dmarc_alignment( d->domain, d->spf_domain,
		d->spf_alignment ) == 0 ) {
	    d->result = DMARC_RESULT_PASS;
	    goto done;
	}
    }

    for ( dkim_domain = d->dkim_domain_list ; dkim_domain != NULL ;
	    dkim_domain = dkim_domain->dll_next ) {
	if ( dmarc_alignment( d->domain, dkim_domain->dll_key,
		d->dkim_alignment ) == 0 ) {
	    d->result = DMARC_RESULT_PASS;
	    goto done;
	}
    }

done:
    return( d->result );
}

    int
dmarc_dkim_result( struct dmarc *d, char *domain )
{
    struct dll_entry	*dkim_domain;

    dkim_domain = dll_lookup_or_create( &d->dkim_domain_list, domain, 1 );
    return( 0 );
}

    const char *
dmarc_result_str( const int policy ) {
    switch( policy ) {
    case DMARC_RESULT_NORECORD:
    case DMARC_RESULT_ORGDOMAIN:
	return( "absent" );
    case DMARC_RESULT_NONE:
	return( "none" );
    case DMARC_RESULT_REJECT:
	return( "reject" );
    case DMARC_RESULT_QUARANTINE:
	return( "quarantine" );
    case DMARC_RESULT_PASS:
	return( "pass" );
    case DMARC_RESULT_SYSERROR:
	return( "syserror" );
    }
    return( "INVALID" );
}

    const char *
dmarc_authresult_str( const int policy ) {
    /* https://www.iana.org/assignments/email-auth/email-auth.xhtml */
    switch( policy ) {
    case DMARC_RESULT_NORECORD:
    case DMARC_RESULT_ORGDOMAIN:
	return( "none" );
    case DMARC_RESULT_PASS:
	return( "pass" );
    case DMARC_RESULT_NONE:
    case DMARC_RESULT_QUARANTINE:
    case DMARC_RESULT_REJECT:
	return( "fail" );
    }
    return( "temperror" );
}

    int
dmarc_spf_result( struct dmarc *d, char *domain )
{
    if ( d->spf_domain != NULL ) {
	syslog( LOG_WARNING, "DMARC: already had an SPF result" );
	return( 1 );
    }

    d->spf_domain = yaslauto( domain );
    return( 0 );
}

    static int
dmarc_alignment( char *domain1, char *domain2, int apolicy )
{
    yastr   orgdomain1, orgdomain2;
    int	    a;

    if ( strcasecmp( domain1, domain2 ) == 0 ) {
	return( 0 );
    }

    if ( apolicy == DMARC_ALIGNMENT_STRICT ) {
	return( 1 );
    }

    orgdomain1 = dmarc_orgdomain( domain1 );
    orgdomain2 = dmarc_orgdomain( domain2 );
    a = yaslcmp( orgdomain1, orgdomain2 );
    yaslfree( orgdomain1 );
    yaslfree( orgdomain2 );

    if ( a == 0 ) {
	return( 0 );
    }

    return( 1 );
}

    static struct dnsr_result *
dmarc_lookup_record( const char *domain )
{
    yastr		lookup_domain;
    struct dnsr_result	*res;

    /* RFC 7489 6.1 DMARC Policy Record
     * Domain Owner DMARC preferences are stored as DNS TXT records in
     * subdomains named "_dmarc".  For example, the Domain Owner of
     * "example.com" would post DMARC preferences in a TXT record at
     * "_dmarc.example.com".
     */
    lookup_domain = yaslauto( "_dmarc." );
    lookup_domain = yaslcat( lookup_domain, domain );
    res = get_txt( lookup_domain );
    yaslfree( lookup_domain );
    return( res );
}

    static yastr
dmarc_orgdomain( const char *domain ) {
    size_t		i;
    struct dll_entry	*dentry, *leaf;
    size_t		tok_count;
    yastr		*split, buf, orgdomain = NULL;

    /* RFC 7489 3.2 Organizational Domain
     * The Organizational Domain is determined using the following
     * algorithm:
     *
     *   1.  Acquire a "public suffix" list, i.e., a list of DNS domain names
     *       reserved for registrations.  Some country Top-Level Domains
     *       (TLDs) make specific registration requirements, e.g., the United
     *       Kingdom places company registrations under ".co.uk"; other TLDs
     *       such as ".com" appear in the IANA registry of top-level DNS
     *       domains.  A public suffix list is the union of all of these.
     *       Appendix A.6.1 contains some discussion about obtaining a public
     *       suffix list.
     *
     *   2.  Break the subject DNS domain name into a set of "n" ordered
     *       labels.  Number these labels from right to left; e.g., for
     *       "example.com", "com" would be label 1 and "example" would be
     *       label 2.
     *
     *   3.  Search the public suffix list for the name that matches the
     *       largest number of labels found in the subject DNS domain.  Let
     *       that number be "x".
     *
     *   4.  Construct a new DNS domain name using the name that matched from
     *       the public suffix list and prefixing to it the "x+1"th label from
     *       the subject domain.  This new name is the Organizational Domain.
     *
     *   Thus, since "com" is an IANA-registered TLD, a subject domain of
     *   "a.b.c.d.example.com" would have an Organizational Domain of
     *   "example.com".
     */

    if ( simta_publicsuffix_list == NULL ) {
	/* We can't reliably guess the organizational domain. Return the
	 * original domain.
	 */
	return( yaslauto( domain ));
    }

    split = yaslsplitlen( domain, strlen( domain ), ".", 1, &tok_count );

    dentry = simta_publicsuffix_list;
    buf = yaslempty( );
    for ( i = tok_count ; i > 0 ; i-- ) {
	yasltolower( split[ i - 1 ] );
	if (( leaf = dll_lookup( dentry, split[ i - 1 ] )) != NULL ) {
	    dentry = leaf->dll_data;
	    continue;
	}

	yaslclear( buf );
	buf = yaslcatprintf( buf, "!%s", split[ i - 1 ] );
	if (( leaf = dll_lookup( dentry, buf )) == NULL ) {
	    if (( leaf = dll_lookup( dentry, "*" )) != NULL ) {
		dentry = leaf->dll_data;
		continue;
	    }
	}

	break;
    }

    if ( i > 0 ) {
	i--;
    }

    orgdomain = yasljoinyasl( split + i, tok_count - i, ".", 1 );

    yaslfreesplitres( split, tok_count );
    yaslfree( buf );
    return( orgdomain );
}

    int
dmarc_parse_record( struct dmarc *d, yastr r )
{
    int                         i, ret = 1;
    size_t                      tok_count;
    char                        *p;
    yastr			k = NULL, v = NULL, *split;

    simta_debuglog( 2, "DMARC %s: record: %s", d->domain, r );

    /* RFC 7489 6.3 General Record Format
     * DMARC records follow the extensible "tag-value" syntax for DNS-based
     * key records defined in DKIM.
     *
     *
     * RFC 6376 3.2 Tag=Value Lists
     * tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
     * tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
     * tag-name  =  ALPHA *ALNUMPUNC
     * tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
     *		    ; Prohibits WSP and FWS at beginning and end
     * tval      =  1*VALCHAR
     * VALCHAR   =  %x21-3A / %x3C-7E
     *		    ; EXCLAMATION to TILDE except SEMICOLON
     * ALNUMPUNC =  ALPHA / DIGIT / "_"
     *
     * Note that WSP is allowed anywhere around tags. In particular, any
     * WSP after the "=" and any WSP before the terminating ";" is not part
     * of the value; however, WSP inside the value is significant.
     *
     * Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
     * processed as case sensitive unless the specific tag description of
     * semantics specifies case insensitivity.
     *
     * Tags with duplicate names MUST NOT occur within a single tag-list; if
     * a tag name does occur more than once, the entire tag-list is invalid.
     */

    split = yaslsplitlen( r, yasllen( r ), ";", 1, &tok_count );

    if ( tok_count < 1 ) {
	goto cleanup;
    }

    k = yaslempty( );
    v = yaslempty( );

    for ( i = 0 ; i < tok_count ; i++ ) {
	if ( yasllen( split[ i ] ) == 0 ) {
	    /* If we're not at the end this is an error */
	    if (( i + 1 ) != tok_count ) {
		simta_debuglog( 1, "DMARC %s: empty tag-value list member %d",
			d->domain, i );
	    }
	    continue;
	}

	if (( p = strchr( split[ i ], '=' )) == NULL ) {
	    simta_debuglog( 1, "DMARC %s: invalid tag-value list member %d: %s",
		    d->domain, i, split[ i ] );
	    continue;
	}

	k = yaslcpylen( k, split[ i ], (size_t)( p - split[ i ] ));
	v = yaslcpy( v, p + 1 );
	yasltrim( k, " \t" );
	yasltrim( v, " \t" );

	/* RFC 7489 6.3 General Record Format
	 * v: Version (plain-text; REQUIRED). Identifies the record retrieved
	 * as a DMARC record. It MUST have the value of "DMARC1". The value
	 * of this tag MUST match precisely; if it does not or it is absent,
	 * the entire retrieved record MUST be ignored. It MUST be the first
	 * tag in the list.
	 */
	if ( i == 0 ) {
	    if ( strcmp( k, "v" ) != 0 ) {
		simta_debuglog( 1, "DMARC %s: tag 0: v expected, %s found",
			d->domain, k );
		goto cleanup;
	    }
	    if ( strcmp( v, "DMARC1" ) != 0 ) {
		simta_debuglog( 1, "DMARC %s: tag 0: invalid version: %s",
			d->domain, v );
		goto cleanup;
	    }

	} else if ( strcmp( k, "v" ) == 0 ) {
	    simta_debuglog( 1, "DMARC %s: tag %d: invalid duplicate v tag: %s",
		    d->domain, i, v );

	/* RFC 7489 6.3 General Record Format
	 * adkim: (plain-text; OPTIONAL; default is "r".) Indicates whether
	 * strict or relaxed DKIM Identifier Alignment mode is required by the
	 * Domain Owner. See Section 3.1.1 for details. Valid values are as
	 * follows:
	 *	r: relaxed mode
	 *	s: strict mode
	 */
	} else if ( strcmp( k, "adkim" ) == 0 ) {
	    if ( strcmp( v, "r" ) == 0 ) {
		d->dkim_alignment = DMARC_ALIGNMENT_RELAXED;
	    } else if ( strcmp( v, "s" ) == 0 ) {
		d->dkim_alignment = DMARC_ALIGNMENT_STRICT;
	    } else {
		simta_debuglog( 1, "DMARC %s: tag %d: unknown adkim value: %s",
			d->domain, i, v );
	    }

	/* RFC 7489 6.3 General Record Format
	 * aspf: (plain-text; OPTIONAL; default is "r".) Indicates whether
	 * strict or relaxed SPF Identifier Alignment mode is required by the
	 * Domain Owner. See Section 3.1.2 for details. Valid values are as
	 * follows:
	 *	r: relaxed mode
	 *	s: strict mode
	 */
	} else if ( strcmp( k, "aspf" ) == 0 ) {
	    if ( strcmp( v, "r" ) == 0 ) {
		d->spf_alignment = DMARC_ALIGNMENT_RELAXED;
	    } else if ( strcmp( v, "s" ) == 0 ) {
		d->spf_alignment = DMARC_ALIGNMENT_STRICT;
	    } else {
		simta_debuglog( 1, "DMARC %s: tag %d: unknown aspf value: %s",
			d->domain, i, v );
	    }

	/* RFC 7489 6.3 General Record Format
	 * fo: Failure reporting options (plain-text; OPTIONAL; default is "0")
	 * Provides requested options for generation of failure reports.
	 * Report generators MAY choose to adhere to the requested options.
	 */
	} else if ( strcmp( k, "fo" ) == 0 ) {
	    /* We choose not to adhere to the requested options. */

	/* RFC 7489 6.3 General Record Format
	 * p: Requested Mail Receiver policy (plain-text; REQUIRED for policy
	 * records).  Indicates the policy to be enacted by the Receiver at
	 * the request of the Domain Owner.  Policy applies to the domain
	 * queried and to subdomains, unless subdomain policy is explicitly
	 * described using the "sp" tag.  This tag is mandatory for policy
	 * records only, but not for third-party reporting records (see
	 * Section 7.1).  Possible values are as follows:
	 *	none: The Domain Owner requests no specific action be taken
	 *	      regarding delivery of messages.
	 *	quarantine: The Domain Owner wishes to have email that fails
	 *		    the DMARC mechanism check be treated by Mail
	 *		    Receivers as suspicious.  Depending on the
	 *		    capabilities of the Mail Receiver, this can mean
	 *		    "place into spam folder", "scrutinize with
	 *		    additional intensity", and/or "flag as suspicious".
	 *	reject: The Domain Owner wishes for Mail Receivers to reject
	 *		email that fails the DMARC mechanism check. Rejection
	 *		SHOULD occur during the SMTP transaction.
	 */
	} else if ( strcmp( k, "p" ) == 0 ) {
	    if ( strcmp( v, "none" ) == 0 ) {
		d->policy = DMARC_RESULT_NONE;
	    } else if ( strcmp( v, "quarantine" ) == 0 ) {
		d->policy = DMARC_RESULT_QUARANTINE;
	    } else if ( strcmp( v, "reject" ) == 0 ) {
		d->policy = DMARC_RESULT_REJECT;
	    } else {
		simta_debuglog( 1, "DMARC %s: tag %d: unknown p value: %s",
			d->domain, i, v );
	    }

	/* RFC 7489 6.3 General Record Format
	 * pct:  (plain-text integer between 0 and 100, inclusive; OPTIONAL;
	 * default is 100).  Percentage of messages from the Domain Owner's
	 * mail stream to which the DMARC policy is to be applied.
	 */
	} else if ( strcmp( k, "pct" ) == 0 ) {
	    errno = 0;
	    d->pct = strtol( v, &p, 10 );
	    if (( p == v ) || ( d->pct < 0 ) || (d->pct > 100) ||
		    ( errno == ERANGE ) || ( errno == EINVAL )) {
		simta_debuglog( 1, "DMARC %s: tag %d: invalid pct value: %s",
			d->domain, i, v );
		d->pct = 100;
	    }

	/* RFC 7489 6.3 General Record Format
	 * rf: Format to be used for message-specific failure reports (colon-
	 * separated plain-text list of values; OPTIONAL; default is "afrf").
	 */
	} else if ( strcmp( k, "rf" ) == 0 ) {
	    /* We don't care about reports yet. */

	/* RFC 7489 6.3 General Record Format
	 * ri: Interval requested between aggregate reports (plain-text 32-bit
	 * unsigned integer; OPTIONAL; default is 86400).
	 */
	} else if ( strcmp( k, "ri" ) == 0 ) {
	    /* We don't care about reports yet. */

	/* RFC 7489 6.3 General Record Format
	 * rua: Addresses to which aggregate feedback is to be sent (comma-
	 * separated plain-text list of DMARC URIs; OPTIONAL).
	 */
	} else if ( strcmp( k, "rua" ) == 0 ) {
	    /* We don't care about reports yet. */

	/* RFC 7489 6.3 General Record Format
	 * ruf: Addresses to which message-specific failure information is to
	 * be reported (comma-separated plain-text list of DMARC URIs;
	 * OPTIONAL).
	 */
	} else if ( strcmp( k, "ruf" ) == 0 ) {
	    /* We don't care about reports yet. */

	/* RFC 7489 6.3 General Record Format
	 * sp: Requested Mail Receiver policy for all subdomains (plain-text;
	 * OPTIONAL). Indicates the policy to be enacted by the Receiver at
	 * the request of the Domain Owner. It applies only to subdomains of
	 * the domain queried and not to the domain itself. Its syntax is
	 * identical to that of the "p" tag defined above.  If absent, the
	 * policy specified by the "p" tag MUST be applied for subdomains.
	 */
	} else if ( strcmp( k, "sp" ) == 0 ) {
	    if ( strcmp( v, "none" ) == 0 ) {
		d->subpolicy = DMARC_RESULT_NONE;
	    } else if ( strcmp( v, "quarantine" ) == 0 ) {
		d->subpolicy = DMARC_RESULT_QUARANTINE;
	    } else if ( strcmp( v, "reject" ) == 0 ) {
		d->subpolicy = DMARC_RESULT_REJECT;
	    } else {
		simta_debuglog( 1, "DMARC %s: tag %d: unknown sp value: %s",
			d->domain, i, v );
	    }

	/* RFC 7489 6.3 General Record Format
	 * Unknown tags MUST be ignored.
	 */
	} else {
	    simta_debuglog( 1, "DMARC %s: tag %d: unknown tag %s: %s",
		    d->domain, i, k, v );
	}
    }

    if (( d->result == DMARC_RESULT_ORGDOMAIN ) &&
	    ( d->subpolicy != DMARC_RESULT_NORECORD )) {
	d->policy = d->subpolicy;
    }

    if ( d->policy == DMARC_RESULT_NORECORD ) {
	d->policy = DMARC_RESULT_NONE;
    }

    d->result = d->policy;

    /* RFC 7489 6.6.4 Message Sampling
     * Mail Receivers implement "pct" via statistical mechanisms that achieve
     * a close approximation to the requested percentage and provide a
     * representative sample across a reporting period.
     */
    if (( d->pct < 100 ) &&
	    (( d->pct == 0 ) || (( random( ) % 100 ) >= d->pct ))) {
	switch( d->result ) {
	case DMARC_RESULT_QUARANTINE:
	    /* RFC 7489 6.6.4 Message Sampling
	     * If the email is not subject to the "quarantine" policy (due to
	     * the "pct" tag), the Mail Receiver SHOULD apply local message
	     * classification as normal.
	     */
	    d->result = DMARC_RESULT_NONE;
	    break;
	case DMARC_RESULT_REJECT:
	    /* RFC 7489 6.6.4 Message Sampling
	     * If the email is not subject to the "reject" policy (due to the
	     * "pct" tag), the Mail Receiver SHOULD treat the email as though
	     * the "quarantine" policy applies.
	     */
	    d->result = DMARC_RESULT_QUARANTINE;
	    break;
	}
    }

    ret = 0;

cleanup:
    yaslfreesplitres( split, tok_count );
    yaslfree( k );
    yaslfree( v );
    return( ret );
}

    static int
dmarc_parse_result( struct dmarc *d, struct dnsr_result *dns )
{
    int				i, valid_records = 0;
    struct dnsr_string		*txt;
    yastr			r;

    if (( r = yaslempty( )) == NULL ) {
	return( 1 );
    }

    for ( i = 0 ; i < dns->r_ancount ; i++ ) {
	if ( dns->r_answer[ i ].rr_type == DNSR_TYPE_TXT ) {
	    yaslclear( r );
	    for ( txt = dns->r_answer[ i ].rr_txt.txt_data ;
		    txt != NULL ; txt = txt->s_next ) {
		r = yaslcat( r, txt->s_string );
	    }
	    /* RFC 7489 6.6.3 Policy Discovery
	     * Records that do not start with a "v=" tag that identifies the
	     * current version of DMARC are discarded.
	     */
	    if ( dmarc_parse_record( d, r ) == 0 ) {
		valid_records++;
	    }
	}
    }

    if ( valid_records == 1 ) {
	return( 0 );
    }

    /* RFC 7489 6.6.3 Policy Discovery
     * If the remaining set contains multiple records or no records,
     * policy discovery terminates and DMARC processing is not applied
     * to this message.
     */
    if ( valid_records > 1 ) {
	dmarc_reset( d );
	return( 0 );
    }

    return( 1 );
}

/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
