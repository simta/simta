/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>

#include <denser.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "envelope.h"
#include "expand.h"
#include "red.h"
#include "dns.h"
#include "simta.h"
#include "queue.h"

static struct dnsr_result *get_address( const char *, int );


    static struct dnsr_result *
get_address( const char *hostname, int qtype )
{
    struct dnsr_result	*result;

    if ( simta_dnsr == NULL ) {
	if (( simta_dnsr = dnsr_new( )) == NULL ) {
	    syslog( LOG_ERR, "Liberror: get_address dnsr_new: %m" );
	    return( NULL );
	}
    }

    if (( dnsr_query( simta_dnsr, qtype, DNSR_CLASS_IN, hostname )) < 0 ) {
	syslog( LOG_ERR, "Liberror: get_address dnsr_query: %d %s: %s",
		qtype, hostname, dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }

    if (( result = dnsr_result( simta_dnsr, NULL )) == NULL ) {
	syslog( LOG_ERR, "Liberror: get_address dnsr_result: %d %s: %s",
		qtype, hostname, dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }

    return( result );
}

    struct dnsr_result *
get_a( const char *hostname )
{
    return get_address( hostname, DNSR_TYPE_A );
}

    struct dnsr_result *
get_aaaa( const char *hostname )
{
    return get_address( hostname, DNSR_TYPE_AAAA );
}

/* RFC 5321 2.3.5 Domain Names
 * Only resolvable, fully-qualified, domain names (FQDNs) are permitted when
 * domain names are used in SMTP.  In other words, names that can be resolved
 * to MX RRs or address (i.e. A or AAAA) RRs (as discussed in section 5) are
 * permitted, as are CNAME RRs whose targets can be resolved, in turn, to MX
 * or address RRs.  Local nicknames or unqualified names MUST NOT be used.
 */

    struct dnsr_result *
get_mx( const char *hostname )
{
    int                 i;
    struct dnsr_result	*result = NULL;
    struct simta_red	*red;

    result = get_address( hostname, DNSR_TYPE_MX );

    if ( simta_dns_auto_config == 0 ) {
	return( result );
    }

    if ( result->r_ancount == 0 ) {
	return( result );
    }

    /* Check to see if hostname is mx'ed to us
     * Only do dynamic configuration when exchange matches our
     * actual host name and is highest preference MX.  Others must be
     * configured by hand.
     */
    /* XXX is this broken?  no check for preference as comments suggest */
    for ( i = 0; i < result->r_ancount; i++ ) {
	switch( result->r_answer[ i ].rr_type ) {
	case DNSR_TYPE_CNAME:
	    if ( strcasecmp( simta_hostname,
		    result->r_answer[ i ].rr_cname.cn_name ) == 0 ) {
		if (( red = red_host_lookup(
			result->r_answer[ i ].rr_cname.cn_name )) == NULL ) {
		    if (( red = red_host_add(
			    result->r_answer[ i ].rr_name)) == NULL ) {
			dnsr_free_result( result );
			return( NULL );
		    }
		    if ( red_action_default( red ) != 0 ) {
			return( NULL );
		    }
		}
	    }
	    break;

	case DNSR_TYPE_MX:
	    if (( strcasecmp( simta_hostname,
		    result->r_answer[ i ].rr_mx.mx_exchange ) == 0 )
		    && ( result->r_answer[ i ].rr_mx.mx_preference <=
		    result->r_answer[ 0 ].rr_mx.mx_preference )) {
		if (( red = red_host_lookup(
			result->r_answer[ i ].rr_name )) == NULL ) {
		    if (( red = red_host_add(
			    result->r_answer[ i ].rr_name)) == NULL ) {
			dnsr_free_result( result );
			return( NULL );
		    }
		    if ( red_action_default( red ) != 0 ) {
			return( NULL );
		    }
		}
	    }
	    break;

	default:
	    syslog( LOG_DEBUG, "get_mx: %s: uninteresting dnsr type: %d",
		result->r_answer[ i ].rr_name,
		result->r_answer[ i ].rr_type );
	    break;
	}
    }

    return( result );
}

    struct dnsr_result *
get_ptr( const struct sockaddr *sa )
{
    struct dnsr_result  *result = NULL;
    char		*hostname;

    if ( simta_dnsr == NULL ) {
        if (( simta_dnsr = dnsr_new( )) == NULL ) {
            syslog( LOG_ERR, "Liberror: get_ptr dnsr_new: %m" );
            return( NULL );
        }
    }

    if (( hostname = dnsr_ntoptr( simta_dnsr, sa->sa_family,
	    (( sa->sa_family == AF_INET )
	    ? (void *)&(((struct sockaddr_in *)sa)->sin_addr)
	    : (void *)&(((struct sockaddr_in6 *)sa)->sin6_addr)),
	    NULL )) == NULL ) {
        syslog( LOG_ERR, "Liberror: get_ptr dnsr_ntoptr: %s",
		dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }

    result = get_address( hostname, DNSR_TYPE_PTR );
    free( hostname );
    return( result );
}


    struct dnsr_result *
get_txt( const char *hostname )
{
    return( get_address( hostname, DNSR_TYPE_TXT ));
}

    struct simta_red *
host_local( char *hostname )
{
    struct simta_red	*red;
    struct dnsr_result	*result;

    /* Check for hostname in host table */
    if (( red = red_host_lookup( hostname )) != NULL ) {
	return( red );
    }

    if ( simta_dns_auto_config == 0 ) {
	return( NULL );
    }

    if (( result = get_mx( hostname )) == NULL ) {
	return( NULL );
    }

    /* Check for an answer */
    if ( result->r_ancount == 0 ) {
	dnsr_free_result( result );
	return( NULL );
    }

    /* Check to see if host has been added to host table */
    if (( red = red_host_lookup( hostname )) != NULL ) {
	dnsr_free_result( result );
	return( red );
    }

    dnsr_free_result( result );

    return( NULL );
}

    int
check_reverse( char *dn, const struct sockaddr *sa )
{
    int				i, j;
    int				ret = REVERSE_UNKNOWN;
    struct dnsr_result		*result_ptr = NULL, *result_a = NULL;

    if (( result_ptr = get_ptr( sa )) == NULL ) {
	return( REVERSE_ERROR );
    }

    for ( i = 0; i < result_ptr->r_ancount; i++ ) {
	if ( result_ptr->r_answer[ i ].rr_type == DNSR_TYPE_PTR ) {
	    /* Get A record on PTR result */
	    if ( sa->sa_family == AF_INET6 ) {
		result_a = get_aaaa( result_ptr->r_answer[ i ].rr_dn.dn_name );
	    } else {
		result_a = get_a( result_ptr->r_answer[ i ].rr_dn.dn_name );
	    }

	    if ( result_a == NULL ) {
		ret = REVERSE_ERROR;
		goto error;
	    }

	    ret = REVERSE_MISMATCH;

	    /* Verify A record matches IP */
	    for ( j = 0; j < result_a->r_ancount; j++ ) {
		if (( sa->sa_family == AF_INET6 ) &&
			( result_a->r_answer[ j ].rr_type == DNSR_TYPE_AAAA )) {
		    if ( memcmp(
			    &(result_a->r_answer[ j ].rr_aaaa.aaaa_address),
			    &(((struct sockaddr_in6 *)sa)->sin6_addr),
			    sizeof( struct in6_addr )) == 0 ) {
			ret = REVERSE_MATCH;
		    }
		} else if (( sa->sa_family == AF_INET ) &&
			( result_a->r_answer[ j ].rr_type == DNSR_TYPE_A )) {
		    if ( memcmp( &(result_a->r_answer[ j ].rr_a.a_address),
			    &(((struct sockaddr_in *)sa)->sin_addr),
			    sizeof( struct in_addr )) == 0 ) {
			ret = REVERSE_MATCH;
		    }

		} else {
		    syslog( LOG_DEBUG,
			"DNS: check_reverse %s: uninteresting dnsr type: %d",
			result_a->r_answer[ j ].rr_name,
			result_a->r_answer[ j ].rr_type );
		}

		if ( ret == REVERSE_MATCH ) {
		    if ( dn ) {
			strncpy( dn, result_ptr->r_answer[ i ].rr_dn.dn_name,
				DNSR_MAX_NAME );
		    }
		    dnsr_free_result( result_a );
		    dnsr_free_result( result_ptr );
		    return( ret );
		}
	    }
	    dnsr_free_result( result_a );

	} else {
	    syslog( LOG_DEBUG,
		    "DNS: check_reverse %s: uninteresting dnsr type: %d",
		    result_ptr->r_answer[ i ].rr_name,
		    result_ptr->r_answer[ i ].rr_type );
	}
    }

error:
    dnsr_free_result( result_ptr );
    return( ret );
}

    int
check_hostname( const char *hostname )
{
    struct dnsr_result		*result;

    if (( result = get_mx( hostname )) == NULL ) {
	return( -1 );
    }
    if ( result->r_ancount > 0 ) {
	dnsr_free_result( result );
	return( 0 );
    }
    dnsr_free_result( result );

    if (( result = get_a( hostname )) == NULL ) {
	return( -1 );
    }
    if ( result->r_ancount > 0 ) {
	dnsr_free_result( result );
	return( 0 );
    }
    dnsr_free_result( result );

    return( 1 );
}


/* The simplest way to get started using the ORDB to protect your mail relay
 * against theft of service by spammers, is to arrange for it to make a DNS
 * query agains relays.ordb.org whenever you receive an incoming mail message
 * from a host whose relaying status you do not know.
 *
 * The theory of operation is simple. Given a host address in its
 * dotted-quad form, reverse the octets and check for the existence of an ``A
 * RR'' at that node under the relays.ordb.org node. So if you get an SMTP
 * session from [192.89.123.5] you would check for the existence of:
 * 5.123.89.192.relays.ordb.org. IN A 127.0.0.2
 *
 * We chose to use an ``A RR'' because that's what most MTA's can use to
 * filter incoming connections. The choice of [127.0.0.2] as the target
 * address was arbitary but will not change. As it happens, we supply a bogus
 * ORDB entry for [127.0.0.2] so that mail transport developers have
 * something to test against.
 *
 * If an ``A RR'' is found by this mechanism, then there will also be a
 * ``TXT RR'' at the same DNS node. The text of this record will be suitable
 * for use as a reason text for a bounced mail notification. (Modified from
 * http://www.mail-abuse.org/rbl/usage.html)
 *
 * Please note: Someone, completely unrelated to ORDB.org, has created a
 * zone called relays.ordb.com, in which everything resolves. That is,
 * anything from hamster.relays.ordb.com to 1.0.0.127.relays.ordb.com
 * resolves. If you have accidently set up your system to use relays.ordb.com
 * instead of relays.ordb.org, your system will instantly reject any incoming
 * SMTP-connection, as it will assume that all mailservers are open relays.
 * If you are experiencing a problem like the one described, please check
 * your configuration.
 */

    int
rbl_check( struct rbl *rbls, const struct sockaddr *sa, char *text, char *host,
	struct rbl **found, char **msg )
{
    struct rbl				*rbl;
    char				*reverse_ip;
    char				*ip;
    char				sa_ip[ INET6_ADDRSTRLEN ];
    struct dnsr_result			*result;
    struct sockaddr_in			sin;

    if ( sa ) {
	if ( getnameinfo( (struct sockaddr *)sa,
		(( sa->sa_family == AF_INET6 )
		? sizeof( struct sockaddr_in6 )
		: sizeof( struct sockaddr_in )),
		sa_ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: rbl_check getnameinfo: %m" );
	    strcpy( sa_ip, "INVALID" );
	}
    }

    for ( rbl = rbls; rbl != NULL; rbl = rbl->rbl_next ) {
	if (( simta_rbl_verbose_logging == 0 ) &&
		( rbl->rbl_type == RBL_LOG_ONLY )) {
	    continue;
	}

	if ( found != NULL ) {
	    *found = rbl;
	}

	if ( sa ) {
	    if (( reverse_ip =
		    dnsr_ntoptr( simta_dnsr, sa->sa_family,
		    (( sa->sa_family == AF_INET )
		    ? (void *)&(((struct sockaddr_in *)sa)->sin_addr)
		    : (void *)&(((struct sockaddr_in6 *)sa)->sin6_addr)),
		    rbl->rbl_domain )) == NULL ) {
		syslog( LOG_ERR, "RBL %s: dnsr_ntoptr failed: %s",
			sa_ip, rbl->rbl_domain );
		continue;
	    }
	} else {
	    reverse_ip = malloc(
		    strlen( rbl->rbl_domain ) + strlen( text ) + 2 );
	    sprintf( reverse_ip, "%s.%s", text, rbl->rbl_domain );
	}

	if (( result = get_a( reverse_ip )) == NULL ) {
	    syslog( LOG_DEBUG, "RBL %s: Timeout: %s", reverse_ip,
		    rbl->rbl_domain );
	    free( reverse_ip );
	    continue;
	}

	if ( result->r_ancount > 0 ) {
	    memset( &sin, 0, sizeof( struct sockaddr_in ));
	    memcpy( &(sin.sin_addr.s_addr),
		    &(result->r_answer[0].rr_a),
		    sizeof( struct in_addr ));

	    ip = strdup( inet_ntoa( sin.sin_addr ));

	    if ( simta_rbl_verbose_logging ) {
		syslog( LOG_DEBUG, "RBL [%s] %s: Found in %s list %s: %s",
			sa ? sa_ip : text, host ? host : "Unknown",
			rbl->rbl_type_text, rbl->rbl_domain, ip );
	    }

	    free( reverse_ip );
	    dnsr_free_result( result );

	    if ( rbl->rbl_type == RBL_LOG_ONLY ) {
		free( ip );
		continue;
	    }

	    if ( msg != NULL ) {
		*msg = ip;
	    } else {
		free( ip );
	    }

	    return( rbl->rbl_type );
	}

	if ( simta_rbl_verbose_logging ) {
	    syslog( LOG_DEBUG, "RBL [%s] %s: Unlisted in %s list %s",
		    sa ? sa_ip : text, host ? host : "Unknown",
		    rbl->rbl_type_text, rbl->rbl_domain );
	}

	free( reverse_ip );
	dnsr_free_result( result );
    }

    if ( simta_rbl_verbose_logging ) {
	syslog( LOG_DEBUG, "RBL [%s] %s: RBL list exhausted, no matches",
		sa ? sa_ip : text, host ? host : "Unknown" );
    }

    if ( found != NULL ) {
	*found = NULL;
    }

    return( RBL_NOT_FOUND );
}


    int
rbl_add( struct rbl **list, int type, char *domain, char *url )
{
    struct rbl			**i;
    struct rbl			*rbl;
    char			*text;

    switch ( type ) {
    default:
	syslog( LOG_ERR, "rbl_add type out of range: %d", type );
	return( 1 );

    case RBL_TRUST:
	text = S_TRUST;
	break;

    case RBL_ACCEPT:
	text = S_ACCEPT;
	break;

    case RBL_LOG_ONLY:
	text = S_LOG_ONLY;
	break;

    case RBL_BLOCK:
	text = S_BLOCK;
	break;
    }

    rbl = calloc( 1, sizeof( struct rbl ));

    rbl->rbl_type = type;
    rbl->rbl_type_text = text;

    rbl->rbl_domain = strdup( domain );
    rbl->rbl_url = strdup( url );

    /* add new struct to end of list */
    for ( i = list; *i != NULL; i = &((*i)->rbl_next) )
	    ;

    *i = rbl;

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
