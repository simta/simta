#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <netinet/in.h>

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

extern int	debug;

    int
get_mx( DNSR *dnsr, char *host )
{
    int                 i;

    /* Check for MX of address */
    if (( dnsr_query( dnsr, DNSR_TYPE_MX, DNSR_CLASS_IN, host )) < 0 ) {
        syslog( LOG_ERR, "dnsr_query %s failed", host );
        return( -1 );
    }

    /* Check for vaild result */
    if ( dnsr_result( dnsr, NULL ) != 0 ) {

        /* No - Check for A of address */
        if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN, host )) < 0 ) {
            syslog( LOG_ERR, "dnsr_query %s failed", host );
            return( -1 );
        }
        if ( dnsr_result( dnsr, NULL ) != 0 ) {
            syslog( LOG_ERR, "dnsr_query %s failed", host );
            return( -1 );
        }

    } else {

        /* Check for valid A record in MX */
        /* XXX - Should we search for A if no A returned in MX? */
        for ( i = 0; i < dnsr->d_result->ancount; i++ ) {
            if ( dnsr->d_result->answer[ i ].r_ip != NULL ) {
                break;
            }
        }
        if ( i > dnsr->d_result->ancount ) {
            syslog( LOG_ERR, "%s: no valid A record for MX", host );
            return( -1 );
        }
    }

    return( 0 );
}

/*
 * < 0  error
 *   0  not MX'ed to local host
 *   1  highest level preference MX
 *   2  lower level preference MX
 */
    int
mx_local( struct envelope *env, DNSR *dnsr, char *domain )
{
    int         i;
    struct host *host;

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
    for ( i = 0; i < dnsr->d_result->ancount; i++ ) {
        if ( strcasecmp( env->e_hostname,
                dnsr->d_result->answer[ i ].r_mx.exchange ) == 0 ) {
            if (( host = malloc( sizeof( struct host ))) == NULL ) {
                syslog( LOG_ERR, "mx_local: malloc: %m" );
                return( -1 );
            }
            /* Check preference */
            if ( dnsr->d_result->answer[ i ].r_mx.preference ==
                    dnsr->d_result->answer[ 0 ].r_mx.preference ) {
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
		    dnsr->d_result->answer[ i ].r_mx.exchange,
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
