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

    if ( simta_debug ) fprintf( stderr, "get_a: %s...", hostname );

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
    if ( result->r_ancount > 0 ) {
	if ( simta_debug ) fprintf( stderr, "ok\n" );
	return( result );
    }

    if ( simta_debug ) fprintf( stderr, "failed\n" );
    return( NULL );
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
    if ( result->r_ancount > 0 ) {
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
			result->r_answer[ 1 ].rr_mx.mx_preference )) {
		    if ( add_host( result->r_answer[ i ].rr_mx.mx_exchange,
			    HOST_LOCAL ) != 0 ) {
			dnsr_free_result( result );
			return( NULL );
		    }
		}
		break;

	    default:
		syslog( LOG_ERR, "get_mx: %s: unknown type: %d", hostname,
		    result->r_answer[ i ].rr_type );
		break;
	    }
	}
	return( result );
    }
    dnsr_free_result( result );

    return( NULL );
}

    struct host *
host_local( char *hostname )
{
    struct host		*host;
    struct dnsr_result	*result;

    syslog( LOG_ERR, "host_local: %s", hostname );

    /* Look for hostname in host table */
    if (( host = ll_lookup( simta_hosts, hostname )) != NULL ) {
	syslog( LOG_ERR, "host_local: %s found in simta_hosts", hostname );
	return( host );
    }

    syslog( LOG_ERR, "host_local: %s getting DNS", hostname );
    /* Check DNS */
    if (( result = get_mx( hostname )) == NULL ) {
	syslog( LOG_ERR, "host_local: %s no DNS", hostname );
	return( NULL );
    }
    dnsr_free_result( result );

    if (( host = ll_lookup( simta_hosts, hostname )) != NULL ) {
	syslog( LOG_ERR, "host_local: %s found in DNS", hostname );
	return( host );
    }
    syslog( LOG_ERR, "host_local: %s NOT FOUND!", hostname );

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

    if (( temp = dnsr_ntoptr( simta_dnsr, in )) == NULL ) {
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
	    if ( memcmp( &(in->s_addr), &(result_a->r_answer[ j ].rr_a),
		    sizeof( int )) == 0 ) {
		if ( dn != NULL ) {
		    strcpy( dn, result_ptr->r_answer[ i ].rr_dn.dn_name );
		}
		dnsr_free_result( result_a );
		dnsr_free_result( result_ptr );
		return( 0 );
	    }
	}
	dnsr_free_result( result_a );
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

    if (( result = get_mx( hostname )) != NULL ) {
	dnsr_free_result( result );
	return( 0 );
    }

    if (( result = get_a( hostname )) != NULL ) {
	dnsr_free_result( result );
	return( 0 );
    }
    return( 1 );
}

    struct dnsr_result *
get_dnsr_result( char *hostname )
{
    struct dnsr_result		*result;

    if (( result = get_mx( hostname )) != NULL ) {
	return( result );
    }

    if (( result = get_a( hostname )) != NULL ) {
	return( result );
    }
    return( NULL );
}

    int
add_host( char *hostname, int type )
{
    struct host		*host;

    /* Look for hostname in host table */
    if (( host = ll_lookup( simta_hosts, hostname )) != NULL ) {
	return( 0 );
    }

    if (( host = malloc( sizeof( struct host ))) == NULL ) {
	syslog( LOG_ERR, "add_host: malloc: %m" );
	return( -1 );
    }
    memset( host, 0, sizeof( struct host ));

    host->h_type = type;
    /* XXX - Must cleanup */
    host->h_name = strdup( hostname );

    /* Add list of expansions */
    if ( ll_insert_tail( &(host->h_expansion), EXPANSION_TYPE_ALIAS,
	    EXPANSION_TYPE_ALIAS ) != 0 ) {
	syslog( LOG_ERR, "add_host: ll_insert_tail failed" );
	goto error;
    }
    if ( ll_insert_tail( &(host->h_expansion), EXPANSION_TYPE_PASSWORD,
	    EXPANSION_TYPE_PASSWORD ) != 0 ) {
	syslog( LOG_ERR, "add_host: ll_insert_tail failed" );
	goto error;
    }

    /* Add host to host list */
    if ( ll_insert( &simta_hosts, hostname, host, NULL ) != 0 ) {
	syslog( LOG_ERR, "add_host: ll_insert failed" );
	goto error;
    }

    syslog( LOG_ERR, "add_host: added %s", host->h_name );
    return( 0 );

error:
    free( host );
    return( -1 );
}
