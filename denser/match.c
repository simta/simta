#include <sys/time.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


#include "denser.h"
#include "internal.h"

    int
_dnsr_match_additional( DNSR *dnsr, struct dnsr_result *result )
{
    int		i, j;

    for ( i = 0; i < result->r_arcount; i++ ) { 
	for ( j = 0; j < result->r_ancount; j++ ) {
	    if ( _dnsr_match_ip( dnsr, &result->r_additional[ i ],
		    &result->r_answer[ j ] ) < 0 ) {
		return( 0 );
	    }
	}
	for ( j = 0; j < result->r_nscount; j++ ) {
	    if ( _dnsr_match_ip( dnsr, &result->r_additional[ i ],
		    &result->r_ns[ j ] ) < 0 ) {
		return( 0 );
	    }
	}
    }
    return( 0 );
}

    int
_dnsr_match_ip( DNSR *dnsr, struct dnsr_rr *ar_rr, struct dnsr_rr *rr )
{
    struct ip_info	*ip_info, *prev_ip_info;

    switch( rr->rr_type ) {

    case DNSR_TYPE_A:
	return( 0 );

    case DNSR_TYPE_CNAME:
    case DNSR_TYPE_MB:
    case DNSR_TYPE_MD:
    case DNSR_TYPE_MF:
    case DNSR_TYPE_MG:
    case DNSR_TYPE_MR:
    case DNSR_TYPE_NS:
    case DNSR_TYPE_PTR:
	if ( strcmp( ar_rr->rr_name, rr->rr_dn.dn_name ) != 0 ) {
	    return( 0 );
	}
	break;
	
    case DNSR_TYPE_MX:
	if ( strcmp( ar_rr->rr_name, rr->rr_mx.mx_exchange ) != 0 ) {
	    return( 0 );
	}
	break;

    case DNSR_TYPE_SOA:
	if ( strcmp( ar_rr->rr_name, rr->rr_soa.soa_mname) != 0 ) {
	    return( 0 );
	}
	break;

    case DNSR_TYPE_SRV:
	if ( strcmp( ar_rr->rr_name, rr->rr_srv.srv_target ) != 0 ) {
	    return( 0 );
	}
	break;

    default:
	DEBUG( fprintf( stderr, "create_result: unknown type: %d\n",
	    rr->rr_type ));
	dnsr->d_errno = DNSR_ERROR_TYPE;
	return( -1 );
    }

    if (( ip_info = malloc( sizeof( struct ip_info ))) == NULL ) {
	DEBUG( perror( "malloc" ));
	dnsr->d_errno = DNSR_ERROR_SYSTEM;
	return( -1 );
    }
    memset( ip_info, 0, sizeof( struct ip_info ));

    ip_info->ip_ip.s_addr = ar_rr->rr_a.a_address;
    if ( rr->rr_ip == NULL ) {
	rr->rr_ip = ip_info;
    } else {
	prev_ip_info = rr->rr_ip;
	while (  prev_ip_info->ip_next != NULL ) {
	    prev_ip_info = prev_ip_info->ip_next;
	}
	prev_ip_info->ip_next = ip_info;
    }

    return( 1 );
}
