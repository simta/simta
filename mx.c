#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

extern SSL_CTX  *ctx;
#endif /* TLS */

#include <snet.h>

#include "ll.h"
#include "denser.h"
#include "queue.h"
#include "envelope.h"
#include "mx.h"
#include "simta.h"

    struct dnsr_result *
get_mx( DNSR *dnsr, char *host )
{
    int                 i;
    struct dnsr_result	*result = NULL;

    /* Check for MX of address */
    if (( dnsr_query( dnsr, DNSR_TYPE_MX, DNSR_CLASS_IN, host ))
	    != 0 ) {
	syslog( LOG_ERR, "dnsr_query %s failed", host );
	goto error;
    }

    /* Check for vaild result */
    if (( result = dnsr_result( dnsr, NULL )) == NULL ) {
	if (( dnsr_errno( dnsr ) == DNSR_ERROR_NAME )
		|| ( dnsr_errno( dnsr ) == DNSR_ERROR_NO_ANSWER )) {

	    /* No MX - Check for A of address */
	    if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN, host )) < 0 ) {
		syslog( LOG_ERR, "dnsr_query %s failed", host );
		goto error;
	    }
	    if (( result = dnsr_result( dnsr, NULL )) == NULL ) {
		if (( dnsr_errno( dnsr ) == DNSR_ERROR_NAME )
			|| ( dnsr_errno( dnsr ) == DNSR_ERROR_NO_ANSWER )) {
		    goto error;
		} else {
		    syslog( LOG_ERR, "dnsr_query %s failed", host );
		    goto error;
		}
	    }
	} else {
	    syslog( LOG_ERR, "dnsr_query %s failed", host );
	    goto error;
	}

    } else {
	if ( simta_debug ) fprintf( stderr, "found MX\n" );

        /* Check for valid A record in MX */
        /* XXX - Should we search for A if no A returned in MX? */
        for ( i = 0; i < result->r_ancount; i++ ) {
            if ( result->r_answer[ i ].rr_ip != NULL ) {
                break;
            }
        }
        if ( i > result->r_ancount ) {

	    /* No valid MX - Check for A of address */
	    if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN, host )) < 0 ) {
		syslog( LOG_ERR, "dnsr_query %s failed", host );
		goto error;
	    }
	    if (( result = dnsr_result( dnsr, NULL )) == NULL ) {
		if (( dnsr_errno( dnsr ) == DNSR_ERROR_NAME )
			|| ( dnsr_errno( dnsr ) == DNSR_ERROR_NO_ANSWER )) {
		    goto error;
		} else {
		    syslog( LOG_ERR, "dnsr_query %s failed", host );
		    goto error;
		}
	    }
        }
    }

    return( 0 );

error:
    free( result );
    return( NULL );
}

/*
 * < 0  error
 *   0  not MX'ed to local host
 *   1  highest level preference MX
 *   2  lower level preference MX
 */
    int
mx_local( struct envelope *env, struct dnsr_result *result, char *domain )
{
    int         	i;
    struct host 	*host;

    /* Look for domain in host table */
    if (( host = ll_lookup( simta_hosts, domain )) != NULL ) {
        if ( host->h_type == HOST_LOCAL ) {
            return( 1 );
        } else if ( host->h_type == HOST_MX ) {
            return( 2 );
        } else {
            syslog( LOG_ERR, "mx_local: unknown host type" );
            return( -1 );
        }
    }
    /* Look for local host in MX's */
    for ( i = 0; i < result->r_ancount; i++ ) {
        if ( strcasecmp( env->e_hostname,
                result->r_answer[ i ].rr_mx.exchange ) == 0 ) {
            if (( host = malloc( sizeof( struct host ))) == NULL ) {
                syslog( LOG_ERR, "mx_local: malloc: %m" );
                return( -1 );
            }
            /* Check preference */
            if ( result->r_answer[ i ].rr_mx.preference ==
                    result->r_answer[ 0 ].rr_mx.preference ) {
                host->h_type = HOST_LOCAL;
            } else {
                host->h_type = HOST_MX;
            }
            host->h_expansion = NULL;

            /* Add list of expansions */
            if ( ll_insert_tail( &(host->h_expansion), "alias",
                    "alias" ) != 0 ) {
                syslog( LOG_ERR, "mx_local: ll_insert_tail failed" );
                free( host );
                return( -1 );
            }
            if ( ll_insert_tail( &(host->h_expansion), "password",
                    "password" ) != 0 ) {
                syslog( LOG_ERR, "mx_local: ll_insert_tail failed" );
                free( host );
                return( -1 );
            }

            /* Add host to host list */
            if ( ll_insert( &simta_hosts,
		    result->r_answer[ i ].rr_mx.exchange,
                    host, NULL ) != 0 ) {
                syslog( LOG_ERR, "mx_local: ll_insert failed" );
                free( host );
                return( -1 );
            }
            if ( host->h_type == HOST_LOCAL ) {
                return( 1 );
            } else if ( host->h_type == HOST_MX ) {
                return( 2 );
            } else {
                syslog( LOG_ERR, "mx_local: unknown host type" );
                return( -1 );
            }
        }
    }

    return( 0 );
}
