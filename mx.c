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

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

extern SSL_CTX  *ctx;
#endif /* HAVE_LIBSSL */

#include <snet.h>

#include "ll.h"
#include "denser.h"
#include "queue.h"
#include "envelope.h"
#include "expand.h"
#include "mx.h"
#include "simta.h"

    struct dnsr_result *
get_a( char *hostname )
{
    struct dnsr_result	*result;

    if ( simta_dnsr == NULL ) {
        if (( simta_dnsr = dnsr_new( )) == NULL ) {
            syslog( LOG_ERR, "get_a: dnsr_new: %m" );
	    return( NULL );
	}
    }

    /* Check for A */
    if (( dnsr_query( simta_dnsr, DNSR_TYPE_A, DNSR_CLASS_IN,
	    hostname )) < 0 ) {
	syslog( LOG_ERR, "get_a: dnsr_query: %s: %s", hostname,
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }
    if (( result = dnsr_result( simta_dnsr, NULL )) == NULL ) {
	syslog( LOG_ERR, "get_a: dnsr_result: %s: %s", hostname, 
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }

    return( result );
}

    struct dnsr_result *
get_txt( char *hostname )
{
    struct dnsr_result	*result;

    if ( simta_dnsr == NULL ) {
        if (( simta_dnsr = dnsr_new( )) == NULL ) {
            syslog( LOG_ERR, "get_a: dnsr_new: %m" );
	    return( NULL );
	}
    }

    /* Check for TXT */
    if (( dnsr_query( simta_dnsr, DNSR_TYPE_TXT, DNSR_CLASS_IN,
	    hostname )) < 0 ) {
	syslog( LOG_ERR, "get_txt: dnsr_query: %s: %s", hostname,
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }
    if (( result = dnsr_result( simta_dnsr, NULL )) == NULL ) {
	syslog( LOG_ERR, "get_txt: dnsr_result: %s: %s", hostname, 
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }

    return( result );
}

/* rfc 2821 3.6
 * Only resolvable, fully-qualified, domain names (FQDNs) are permitted
 * when domain names are used in SMTP.  In other words, names that can
 * be resolved to MX RRs or A RRs (as discussed in section 5) are
 * permitted, as are CNAME RRs whose targets can be resolved, in turn,
 * to MX or A RRs.  Local nicknames or unqualified names MUST NOT be
 * used.
 */

    struct dnsr_result *
get_mx( char *hostname )
{
    int                 i;
    struct dnsr_result	*result = NULL;

    if ( simta_dnsr == NULL ) {
        if (( simta_dnsr = dnsr_new( )) == NULL ) {
            syslog( LOG_ERR, "get_mx: dnsr_new: %m" );
	    return( NULL );
	}
    }

    /* Check for MX */
    if (( dnsr_query( simta_dnsr, DNSR_TYPE_MX, DNSR_CLASS_IN,
	    hostname )) != 0 ) {
	syslog( LOG_ERR, "get_mx: dnsr_query: %s: %s", hostname,
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }
    if (( result = dnsr_result( simta_dnsr, NULL )) == NULL ) {
	syslog( LOG_ERR, "get_mx: dnsr_result: %s: %s", hostname,
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( NULL );
    }

    if ( simta_dns_config && result->r_ancount > 0 ) {
	/* Check to see if hostname is mx'ed to us
	 * Only do dynamic configuration when exchange matches our
	 * actual host name and is highest preference MX.  Others must be
	 * configured by hand.
	 */
	for ( i = 0; i < result->r_ancount; i++ ) {
	    switch( result->r_answer[ i ].rr_type ) {
	    case DNSR_TYPE_CNAME:
		if ( strcasecmp( simta_hostname,
			result->r_answer[ i ].rr_cname.cn_name ) == 0 ) {
		    if ( add_host( result->r_answer[ i ].rr_name,
			    HOST_LOCAL ) != 0 ) {
			dnsr_free_result( result );
			return( NULL );
		    }
		}
		break;

	    case DNSR_TYPE_MX:
		if (( strcasecmp( simta_hostname,
			result->r_answer[ i ].rr_mx.mx_exchange ) == 0 ) 
			&& ( result->r_answer[ i ].rr_mx.mx_preference <=
			result->r_answer[ 0 ].rr_mx.mx_preference )) {
		    if ( add_host( result->r_answer[ i ].rr_mx.mx_exchange,
			    HOST_LOCAL ) != 0 ) {
			dnsr_free_result( result );
			return( NULL );
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
    }

    return( result );
}

    struct host *
host_local( char *hostname )
{
    int			i;
    struct host		*host;
    struct dnsr_result	*result;

    /* Check for hostname in host table */
    if (( host = ll_lookup( simta_hosts, hostname )) != NULL ) {
	return( host );
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
    if (( host = ll_lookup( simta_hosts, hostname )) != NULL ) {
	dnsr_free_result( result );
	return( host );
    }

    /* Check for low_pref_mx */
    if ( simta_low_pref_mx_domain != NULL ) {
	for ( i = 0; i < result->r_ancount; i++ ) {
	    switch( result->r_answer[ i ].rr_type ) {
	    case DNSR_TYPE_CNAME:
		break;

	    case DNSR_TYPE_MX:
		if (( strcasecmp( simta_low_pref_mx_domain->h_name,
			result->r_answer[ i ].rr_mx.mx_exchange ) == 0 ) 
			&& ( result->r_answer[ i ].rr_mx.mx_preference >
			result->r_answer[ 0 ].rr_mx.mx_preference )) {
		    dnsr_free_result( result );
		    return( simta_low_pref_mx_domain );
		}
		break;

	    default:
		syslog( LOG_DEBUG,
		    "host_local: %s: uninteresting dnsr type: %d",
		    result->r_answer[ i ].rr_name, 
		    result->r_answer[ i ].rr_type );
		break;
	    }
	}
    }

    dnsr_free_result( result );
    return( NULL );
}

    int
check_reverse( char *dn, struct in_addr *in )
{
    int				i, j;
    char			*temp;
    struct dnsr_result		*result_ptr = NULL, *result_a = NULL;

    if ( simta_dnsr == NULL ) {
        if (( simta_dnsr = dnsr_new( )) == NULL ) {
            syslog( LOG_ERR, "check_reverse: dnsr_new: %m" );
	    return( -1 );
	}
    }

    if (( temp = dnsr_ntoptr( simta_dnsr, in, NULL )) == NULL ) {
        syslog( LOG_ERR, "check_reverse: dnsr_ntoptr: %s",
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( -1 );
    }

    /* Get PTR for connection */
    if ( dnsr_query( simta_dnsr, DNSR_TYPE_PTR, DNSR_CLASS_IN, temp ) < 0 ) {
        syslog( LOG_ERR, "check_reverse: dnsr_query: %s",
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	free( temp );
	return( -1 );
    }

    free( temp );

    if (( result_ptr = dnsr_result( simta_dnsr, NULL )) == NULL ) {
        syslog( LOG_ERR, "check_reverse: dnsr_result: %s",
	    dnsr_err2string( dnsr_errno( simta_dnsr )));
	return( -1 );
    }

    for ( i = 0; i < result_ptr->r_ancount; i++ ) {
	if ( result_ptr->r_answer[ i ].rr_type == DNSR_TYPE_PTR ) {
	    /* Get A record on PTR result */
	    if (( dnsr_query( simta_dnsr, DNSR_TYPE_A, DNSR_CLASS_IN,
		    result_ptr->r_answer[ i ].rr_dn.dn_name )) < 0 ) {
		syslog( LOG_ERR, "check_reverse: dnsr_result: %s",
		    dnsr_err2string( dnsr_errno( simta_dnsr )));
		goto error;
	    }
	    if (( result_a = dnsr_result( simta_dnsr, NULL )) == NULL ) {
		syslog( LOG_ERR, "check_reverse: dnsr_result: %s",
		    dnsr_err2string( dnsr_errno( simta_dnsr )));
		goto error;
	    }

	    /* Verify A record matches IP */
	    for ( j = 0; j < result_a->r_ancount; j++ ) {
		if ( result_a->r_answer[ j ].rr_type == DNSR_TYPE_A ) {
		    if ( memcmp( &(in->s_addr),
			    &(result_a->r_answer[ j ].rr_a),
			    sizeof( int )) == 0 ) {
			if ( dn != NULL ) {
			    strcpy( dn,
				result_ptr->r_answer[ i ].rr_dn.dn_name );
			}
			dnsr_free_result( result_a );
			dnsr_free_result( result_ptr );
			return( 0 );
		    }

		} else {
		    syslog( LOG_DEBUG,
			"check_reverse: %s: uninteresting dnsr type: %d",
			result_a->r_answer[ j ].rr_name, 
			result_a->r_answer[ j ].rr_type );
		}
	    }
	    dnsr_free_result( result_a );

	} else {
	    syslog( LOG_DEBUG, "check_result: %s: uninteresting dnsr type: %d",
		result_ptr->r_answer[ i ].rr_name, 
		result_ptr->r_answer[ i ].rr_type );
	}
    }
    dnsr_free_result( result_ptr );
    return( 1 );

error:
    dnsr_free_result( result_ptr );
    return( -1 );
}

    int
check_hostname( char *hostname )
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

    struct host *
add_host( char *hostname, int type )
{
    struct host		*host;

    /* Look for hostname in host table */
    if (( host = ll_lookup( simta_hosts, hostname )) != NULL ) {
	syslog( LOG_DEBUG, "add_host: %s already added", hostname );
	return( host );
    }

    if ( strlen( hostname ) > DNSR_MAX_HOSTNAME ) {
	syslog( LOG_DEBUG, "add_host: %s: hostname too long", hostname );
	return( NULL );
    }

    if (( host = malloc( sizeof( struct host ))) == NULL ) {
	syslog( LOG_ERR, "add_host: malloc: %m" );
	return( NULL );
    }
    memset( host, 0, sizeof( struct host ));

    host->h_type = type;
    strcpy( host->h_name, hostname );

    /* Add host to host list */
    if ( ll_insert( &simta_hosts, hostname, host, NULL ) != 0 ) {
	syslog( LOG_ERR, "add_host: ll_insert failed" );
	goto error;
    }

    syslog( LOG_DEBUG, "add_host: added %s", host->h_name );
    return( host );

error:
    free( host );
    return( NULL );
}

    int
add_expansion( struct host *host, int type )
{
    struct expansion	*expansion;
    struct expansion	*p;

    if (( expansion = malloc( sizeof( struct expansion ))) == NULL ) {
	syslog( LOG_ERR, "add_expansion: malloc: %m" );
	return( -1 );
    }
    memset( expansion, 0, sizeof( struct expansion ));

    expansion->e_type = type;

    if ( host->h_expansion == NULL ) {
	host->h_expansion = expansion;
    } else {
	for ( p = host->h_expansion; p->e_next != NULL; p = p->e_next );
	p->e_next = expansion;
    }

    syslog( LOG_DEBUG, "add_expansion: %s: added %d", host->h_name, type );
    return( 0 );
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
check_rbl( struct in_addr *in, char *domain, char **txt )
{
    int			i;
    char		*reverse_ip;
    struct dnsr_result	*result;

    if (( reverse_ip = dnsr_ntoptr( simta_dnsr, in, domain )) == NULL ) {
	syslog( LOG_ERR, "check_rbl: dnsr_ntoptr failed" );
	return( -1 );
    }
    if ( simta_debug ) fprintf( stderr, "check_rbl for %s...", reverse_ip );

    if (( result = get_a( reverse_ip )) == NULL ) {
	free( reverse_ip );
	return( -1 );
    }

    if ( result->r_ancount <= 0 ) {
	dnsr_free_result( result );
	if ( simta_debug ) printf( "okay\n" );
	free( reverse_ip );
	return( 1 );
    }
    dnsr_free_result( result );

    if ( txt == NULL ) {
	return( 0 );
    }

    if (( result = get_txt( reverse_ip )) == NULL ) {
	free( reverse_ip );
	return( -1 );
    }
    free( reverse_ip );

    if ( result->r_ancount <= 0 ) {
	*txt = NULL;
    } else {
	for ( i = 0; i < result->r_ancount; i++ ) {
	    switch( result->r_answer[ i ].rr_type ) {
	    case DNSR_TYPE_TXT:
		if (( *txt = strdup( result->r_answer[ i ].rr_txt.t_txt ))
			== NULL ) {
		    syslog( LOG_ERR, "check_rbl: strdup: %m" );
		    goto error;
		}
		goto done;

	    default:
		syslog( LOG_DEBUG, "check_rbl: %s: uninteresting dnsr type: %d",
		    result->r_answer[ i ].rr_name, 
		    result->r_answer[ i ].rr_type );
		break;
	    }
	}
	*txt = NULL;
    }
done:
    if ( simta_debug ) printf( "blocked: %s\n", *txt );
    dnsr_free_result( result );

    return( 0 );

error:
    dnsr_free_result( result );
    return( -1 );
}
