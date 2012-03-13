#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "denser.h"
#include "internal.h"
#include "argcargv.h"
#include "bprint.h"

struct rr {
    char        *r_name;
    uint16_t    r_type;
    uint16_t    r_class;
    uint32_t    r_ttl;
    uint16_t    r_rdlength;
    char        *r_rdata;
};

/*
 * Return Values:
 *  <0	fatal error
 *   0	okay
 *  >0  non-fatal error
 */

    int
_dnsr_validate_resp( DNSR *dnsr, char *resp, struct sockaddr_in *reply_from )
{
    int			i;
    socklen_t           socklen;
    struct dnsr_header	*h;
    uint16_t		flags;
    char		word[ DNSR_MAX_NAME ];

    DEBUG( fprintf( stderr, "verifying result\n" ));

    /* Determine which server responded */
    for ( i = 0; i < dnsr->d_nscount; i++ ) {

	/* Skip servers we've not asked */
	if ( ! dnsr->d_nsinfo[ i ].ns_asked ) {
	    DEBUG( fprintf( stderr, "ns %d not asked\n", i ));
	    continue;
	}

	socklen = sizeof( struct sockaddr_in );

	/* Do not check sin_len since it might not be defined */
	/* This check is not required by an RFC */
	if ( socklen == sizeof( struct sockaddr_in ) 
		&& memcmp( &dnsr->d_nsinfo[ i ].ns_sa.sin_addr, 
		    &reply_from->sin_addr, sizeof( reply_from->sin_addr )) == 0
		&& memcmp( &dnsr->d_nsinfo[ i ].ns_sa.sin_family, 
		    &reply_from->sin_family,
		    sizeof( reply_from->sin_family )) == 0
		&& memcmp( &dnsr->d_nsinfo[ i ].ns_sa.sin_port, 
		    &reply_from->sin_port,
		    sizeof( reply_from->sin_port )) == 0 ) {
	    dnsr->d_nsresp = i;
	    DEBUG( fprintf( stderr, "ns %d responded\n", i ));
	    break;
	}
    }
    if ( i < 0 || i >= dnsr->d_nscount ) {
	DEBUG( fprintf( stderr, "%d: invalid NS response\n", i ));
	return( DNSR_ERROR_NS_INVALID );
    }

    /* Check ID */
    if ( dnsr->d_id != ( dnsr->d_nsinfo[ i ].ns_id ^
	    ntohs( ((struct dnsr_header*)(resp))->h_id ))) {
	DEBUG( fprintf( stderr, "ID does not match\n" ));
	return( DNSR_ERROR_NS_INVALID );
    }

    memset( word, 0, DNSR_MAX_NAME );

    h = (struct dnsr_header *)resp;
    DEBUG( _dnsr_display_header( h ));

    /* RFC section 4.1.1 Header section format
     * OPCODE, RD, and QD should match question, therefor we can't check
     *
     * Z must be zero in all responses.
     */

    flags = ntohs( h->h_flags );

    /* Check QR */
    if ( !( flags & DNSR_RESPONSE )) {
	DEBUG( fprintf( stderr, "Not a response!\n" ));
	return( DNSR_ERROR_NOT_RESPONSE );
    }
    /* Check RA */
    if ( !( flags & DNSR_RECURSION_AVAILBLE )) {
	DEBUG( fprintf( stderr, "Recursion not available\n" ));
	return( DNSR_ERROR_NO_RECURSION );
    }
    /* Check TC */
    if ( flags & DNSR_TRUNCATION ) {
	DEBUG( fprintf( stderr, "Message truncated\n" ));
	return( DNSR_ERROR_TRUNCATION );
    }
    /* Check Z */
    /*
    if ( flags & DNSR_Z ) {
	DEBUG( fprintf( stderr, "Z not zero\n" ));
	return( DNSR_ERROR_Z );
    }
    */

    /* Check RCODE */
    switch( flags & DNSR_RCODE ) {
    case DNSR_RC_OK:
	break;

    case DNSR_RC_FORMATERR:
	DEBUG( fprintf( stderr, "Format error: The name server was unable "
	    "to interpret the query\n" ));
	return( DNSR_ERROR_FORMAT );

    case DNSR_RC_SVRERR:
	DEBUG( fprintf( stderr, "Server error\n" ));
	return( DNSR_ERROR_SERVER );

    case DNSR_RC_NAMEERR:
	/* RFC 1035 4.1:
	 * Name Error - Meaningful only for
	 * responses from an authoritative name
	 * server, this code signifies that the
	 * domain name referenced in the query does
	 * not exist.
	 *
	 * If authortative, we want to pass back to caller, otherwise
	 * we throw away response.
	 */

	if ( flags & DNSR_AUTHORITATIVE_ANSWER ) {
	    break;
	}
	return( DNSR_ERROR_NAME );

    case DNSR_RC_NOTIMP:
	/* Server Error */
	DEBUG( fprintf( stderr, "Not implemented\n" ));
	return( DNSR_ERROR_NOT_IMPLEMENTED );

    case DNSR_RC_REFUSED:
	/* Server Error */
	DEBUG( fprintf( stderr, "Refused\n" ));
	return( DNSR_ERROR_REFUSED );

    default:
	/* Unknown response code */
	DEBUG( fprintf( stderr, "Unknown response code\n" ));
	return( DNSR_ERROR_RCODE );
    }

    /* Check that the answer was for our question */
    if ( memcmp( (void *)(dnsr->d_query + sizeof( struct dnsr_header )),
		(void *)(resp + sizeof( struct dnsr_header )),
		dnsr->d_querylen - sizeof( struct dnsr_header ) ) != 0 ) {
	DEBUG( fprintf( stderr, "Response question does not match query\n" ));
	return( DNSR_ERROR_QUESTION_WRONG );
    }

    return( 0 );
}

    struct dnsr_result *
_dnsr_create_result( DNSR *dnsr, char *resp, int resplen )
{
    char		*resp_cur;
    struct dnsr_header	*h;
    int			i, j;
    struct dnsr_result	*result;
    struct dnsr_rr	temp;
    
    if (( result = malloc( sizeof( struct dnsr_result ))) == NULL ) {
	DEBUG( perror( "malloc" ));
	dnsr->d_errno = DNSR_ERROR_SYSTEM;
	return( NULL );
    }
    memset( result, 0, sizeof( struct dnsr_result ));

    h = (struct dnsr_header *)resp;
    result->r_ancount = ntohs( h->h_ancount );
    result->r_nscount = ntohs( h->h_nscount );
    result->r_arcount = ntohs( h->h_arcount );
    resp_cur = resp + dnsr->d_querylen;

    if ( result->r_ancount > 0 ) {
	if (( result->r_answer =  malloc( sizeof( struct dnsr_rr ) *
		result->r_ancount )) == NULL ) {
	    DEBUG( perror( "malloc" ));
	    free( result );
	    dnsr->d_errno = DNSR_ERROR_SYSTEM;
	    return( NULL );
	}
	memset( result->r_answer, 0,
	    sizeof( struct dnsr_rr ) * result->r_ancount );
    }
    if ( result->r_nscount > 0 ) {
	if (( result->r_ns = malloc( sizeof( struct dnsr_rr ) *
		result->r_nscount )) == NULL ) {
	    DEBUG( perror( "malloc" ));
	    free( result->r_answer );
	    free( result );
	    dnsr->d_errno = DNSR_ERROR_SYSTEM;
	    return( NULL );
	}
	memset( result->r_ns, 0, sizeof( struct dnsr_rr ) * result->r_nscount );
    }
    if ( result->r_arcount > 0 ) {
	if (( result->r_additional =  malloc( sizeof( struct dnsr_rr )
		* result->r_arcount )) == NULL ) {
	    DEBUG( perror( "malloc" ));
	    free( result->r_answer );
	    free( result->r_ns );
	    free( result );
	    dnsr->d_errno = DNSR_ERROR_SYSTEM;
	    return( NULL );
	}
	memset( result->r_additional, 0,
	    sizeof( struct dnsr_rr ) * result->r_arcount );
    }

    DEBUG( fprintf( stderr, "Answer section\n" ));
    for ( i = 0; i < result->r_ancount; i++ ) {
	if ( _dnsr_parse_rr( dnsr, &result->r_answer[ i ], resp, &resp_cur,
		resplen ) != 0 ) {
	    DEBUG( fprintf( stderr, "parse_rr failed\n" ));
	    goto error;
	}
    }

    if ( result->r_ancount > 0 ) {
	/* XXX - move into _dnsr_sort_result( ) */
	for ( i = 0; i < ( result->r_ancount - 1 ); i++ ) {
	    if ( result->r_answer[ i ].rr_type != DNSR_TYPE_MX ) {
		continue;
	    }
	    for ( j = i + 1; j < result->r_ancount; j++ ) {
		if ( result->r_answer[ j ].rr_type != DNSR_TYPE_MX ) {
		    continue;
		}
		if ( strcmp( result->r_answer[ i ].rr_name,
			result->r_answer[ j ].rr_name ) != 0 ) {
		    continue;
		}
		if ( result->r_answer[ i ].rr_mx.mx_preference >
			result->r_answer[ j ].rr_mx.mx_preference ) {
		    memcpy( &temp, &result->r_answer[ j ],
			sizeof( struct dnsr_rr ));
		    memcpy( &result->r_answer[ j ], &result->r_answer[ i ],
			sizeof( struct dnsr_rr ));
		    memcpy( &result->r_answer[ i ], &temp,
			sizeof( struct dnsr_rr ));
		}
	    }
	}
    }

    DEBUG( fprintf( stderr, "\nNS Authority\n"));
    for ( i = 0; i < result->r_nscount; i++ ) {
	if ( _dnsr_parse_rr( dnsr, &result->r_ns[ i ], resp, &resp_cur,
		resplen ) != 0 ) {
	    DEBUG( fprintf( stderr, "parse_rr failed\n" ));
	    goto error;
	}
    }

    for ( i = 0; i < result->r_arcount; i++ ) {
	if ( _dnsr_parse_rr( dnsr, &result->r_additional[ i ], resp,
		&resp_cur, resplen ) != 0 ) {
	    DEBUG( fprintf( stderr, "parse_rr failed\n" ));
	    goto error;
	}
    }

    return( result );

error:
    dnsr_free_result( result );
    return( NULL );
}

    int
_dnsr_parse_rr( DNSR *dnsr, struct dnsr_rr *rr, char *resp_begin,
    char **resp_cur, int resplen )

{
    char		*dn_cur;
    char		*resp_end;

    resp_end = resp_begin + resplen;

    /* Parse common RR info */

    /* Name */
    dn_cur = rr->rr_name;
    if ( _dnsr_labels_to_name( dnsr, resp_begin, resp_cur, resplen,
	    rr->rr_name, &dn_cur, rr->rr_name + DNSR_MAX_NAME ) < 0 ) {
	return( -1 );
    }
    DEBUG( fprintf( stderr, "%s\n", rr->rr_name ));

    /* Check for size of header */
    if ( *resp_cur + sizeof( uint16_t ) + sizeof( uint16_t ) +
	    sizeof( uint32_t ) + sizeof( uint16_t ) > resp_end ) {
	DEBUG( fprintf( stderr, "parse_rr: no room for header\n" ));
	dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
	return( -1 );
    }
    /* Type */
    memcpy( &rr->rr_type, *resp_cur, sizeof( uint16_t ));
    rr->rr_type = htons( rr->rr_type);
    *resp_cur += sizeof( uint16_t );
    /* Class */
    memcpy( &rr->rr_class, *resp_cur, sizeof( uint16_t ));
    rr->rr_class = htons( rr->rr_class );
    *resp_cur += sizeof( uint16_t );
    /* TTL */
    memcpy( &rr->rr_ttl, *resp_cur, sizeof( uint32_t ));
    rr->rr_ttl = htonl( rr->rr_ttl );
    *resp_cur += sizeof( uint32_t );
    /* RD Length */
    memcpy( &rr->rr_rdlength, *resp_cur, sizeof( uint16_t ));
    rr->rr_rdlength = htons( rr->rr_rdlength );
    *resp_cur += sizeof( uint16_t );
    /* RFC 1035 3.3 
     * The following RR definitions are expected to occur, at least
     * potentially, in all classes.  In particular, NS, SOA, CNAME and PTR
     * will be used in all classes, and have the same format in all classes.
     * 
     * Therefor, we do no check class.
     */

    /* Parse Type specific info */
    switch( rr->rr_type ) {

    /* These all have a single <domain-name> */
    case DNSR_TYPE_CNAME:
    case DNSR_TYPE_MB:
    case DNSR_TYPE_MD:
    case DNSR_TYPE_MF:
    case DNSR_TYPE_MG:
    case DNSR_TYPE_MR:
    case DNSR_TYPE_NS:
    case DNSR_TYPE_PTR:

	dn_cur = rr->rr_dn.dn_name;
	if ( _dnsr_labels_to_name( dnsr, resp_begin, resp_cur, resplen,
		rr->rr_dn.dn_name, &dn_cur, 
		rr->rr_dn.dn_name + DNSR_MAX_NAME ) < 0 ) {
	    return( -1 );
	}
	DEBUG( fprintf( stderr, "%-21s", rr->rr_dn.dn_name ));
	break;

    case DNSR_TYPE_HINFO:
	dn_cur = rr->rr_hinfo.hi_cpu;
	if ( _dnsr_labels_to_string( dnsr, resp_cur, resp_begin + resplen,
		rr->rr_hinfo.hi_cpu ) < 0 ) {
	    return( -1 );
	}
	DEBUG( fprintf( stderr, "%s ", rr->rr_hinfo.hi_cpu ));
	dn_cur = rr->rr_hinfo.hi_os;
	if ( _dnsr_labels_to_string( dnsr, resp_cur, resp_begin + resplen,
		rr->rr_hinfo.hi_os ) < 0 ) {
	    return( -1 );
	}

	DEBUG( fprintf( stderr, "%s\n", rr->rr_hinfo.hi_os ));
	break;

    case DNSR_TYPE_MX:
	/* Check for size of prefernce */
	if ( *resp_cur + sizeof( uint16_t ) > resp_end ) {
	    DEBUG( fprintf( stderr, "parse_rr: no room for header\n" ));
	    dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
	    return( -1 );
	}
	memcpy( &rr->rr_mx.mx_preference, *resp_cur, sizeof( uint16_t ));
	rr->rr_mx.mx_preference = ntohs( rr->rr_mx.mx_preference );
	*resp_cur += sizeof( uint16_t );
	dn_cur = rr->rr_mx.mx_exchange;
	if ( _dnsr_labels_to_name( dnsr, resp_begin, resp_cur, resplen,
		rr->rr_mx.mx_exchange, &dn_cur, 
		rr->rr_mx.mx_exchange + DNSR_MAX_NAME ) < 0 ) {
	    return( -1 );
	}
	DEBUG( fprintf( stderr, "%s\tpreference: %d\n", rr->rr_mx.mx_exchange,
	    rr->rr_mx.mx_preference ));
	break;

    case DNSR_TYPE_SOA:
	dn_cur = rr->rr_soa.soa_mname;
	if ( _dnsr_labels_to_name( dnsr, resp_begin, resp_cur, resplen,
		rr->rr_soa.soa_mname, &dn_cur, 
		rr->rr_soa.soa_mname + DNSR_MAX_NAME ) < 0 ) {
	    return( -1 );
	}
	dn_cur = rr->rr_soa.soa_rname;
	if ( _dnsr_labels_to_name( dnsr, resp_begin, resp_cur, resplen,
		rr->rr_soa.soa_rname, &dn_cur, 
		rr->rr_soa.soa_rname + DNSR_MAX_NAME ) < 0 ) {
	    return( -1 );
	}
	/* Check for size of prefernce */
	if ( *resp_cur + ( 5 * sizeof( uint32_t )) > resp_end ) {
	    DEBUG( fprintf( stderr, "parse_rr: no room for header\n" ));
	    dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
	    return( -1 );
	}
	memcpy( &rr->rr_soa.soa_serial, *resp_cur, sizeof( uint32_t ));
	rr->rr_soa.soa_serial = ntohl( rr->rr_soa.soa_serial );
	*resp_cur += sizeof( uint32_t );
	memcpy( &rr->rr_soa.soa_refresh, *resp_cur, sizeof( uint32_t ));
	rr->rr_soa.soa_refresh = ntohl( rr->rr_soa.soa_refresh );
	*resp_cur += sizeof( uint32_t );
	memcpy( &rr->rr_soa.soa_retry, *resp_cur, sizeof( uint32_t ));
	rr->rr_soa.soa_retry = ntohl( rr->rr_soa.soa_retry );
	*resp_cur += sizeof( uint32_t );
	memcpy( &rr->rr_soa.soa_expire, *resp_cur, sizeof( uint32_t ));
	rr->rr_soa.soa_expire = ntohl( rr->rr_soa.soa_expire );
	*resp_cur += sizeof( uint32_t );
	memcpy( &rr->rr_soa.soa_minimum, *resp_cur, sizeof( uint32_t ));
	rr->rr_soa.soa_minimum = ntohl( rr->rr_soa.soa_minimum );
	*resp_cur += sizeof( uint32_t );
	DEBUG( fprintf( stderr,
	    "mname: %s\trname: %s\n\tserial: %u\n\trefresh: %u\n", 
	    rr->rr_soa.soa_mname, rr->rr_soa.soa_rname, 
	    rr->rr_soa.soa_serial, rr->rr_soa.soa_refresh ));
	DEBUG( fprintf( stderr, "\tretry: %u\n\texpire: %u\n\tminimum: %u\n",
	    rr->rr_soa.soa_retry, rr->rr_soa.soa_expire,
	    rr->rr_soa.soa_minimum ));
	break;

    case DNSR_TYPE_TXT:
	dn_cur = rr->rr_txt.t_txt;
	if ( _dnsr_labels_to_string( dnsr, resp_cur, resp_begin + resplen,
		rr->rr_txt.t_txt ) < 0 ) {
	    return( -1 );
	}
	DEBUG( fprintf( stderr, "%s\n", rr->rr_txt.t_txt));
	break;

    /* XXX - this case needs review */
    case DNSR_TYPE_A:
	{
	    struct in_addr	addr;

	    if ( rr->rr_class == DNSR_CLASS_IN ) {
		memcpy( &addr.s_addr, *resp_cur, sizeof( int32_t ));
		*resp_cur += sizeof( int32_t );
		DEBUG( fprintf( stderr, "%s\n", inet_ntoa( addr )));
		rr->rr_a.a_address = addr.s_addr;
	    } else {
		DEBUG( fprintf( stderr, "%d: unknown class\n", rr->rr_class ));
		dnsr->d_errno = DNSR_ERROR_CLASS;
		return( -1 );
	    }
	    break;
	}

    case DNSR_TYPE_SRV:
	if ( *resp_cur + ( 3 * sizeof( int16_t )) > resp_end ) {
	    DEBUG( fprintf( stderr, "parse_rr: no room for header\n" ));
	    dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
	    return( -1 );
	}
	memcpy( &rr->rr_srv.srv_priority, *resp_cur, sizeof( uint16_t ));
	rr->rr_srv.srv_priority = ntohs( rr->rr_srv.srv_priority );
	*resp_cur += sizeof( uint16_t );

	memcpy( &rr->rr_srv.srv_weight, *resp_cur, sizeof( uint16_t ));
	rr->rr_srv.srv_weight = ntohs( rr->rr_srv.srv_weight );
	*resp_cur += sizeof( uint16_t );

	memcpy( &rr->rr_srv.srv_port, *resp_cur, sizeof( uint16_t ));
	rr->rr_srv.srv_port = ntohs( rr->rr_srv.srv_port );
	*resp_cur += sizeof( uint16_t );

	dn_cur = rr->rr_srv.srv_target;
	if ( _dnsr_labels_to_name( dnsr, resp_begin, resp_cur, resplen,
		rr->rr_srv.srv_target, &dn_cur, 
		rr->rr_srv.srv_target + DNSR_MAX_NAME ) < 0 ) {
	    return( -1 );
	}
	DEBUG( fprintf( stderr, "%s\tpriority: %d\tweight: %d\tport: %d\n",
	    rr->rr_srv.srv_target, rr->rr_srv.srv_priority,
	    rr->rr_srv.srv_weight, rr->rr_srv.srv_port ));
	break;

    /* Also catches TYPE_NULL */
    default:
	DEBUG( fprintf( stderr, "parse_rr: %d: unknown type\n", rr->rr_type ));
	DEBUG( fprintf( stderr, "parse_rr: skipping %d bytes\n",
	    rr->rr_rdlength ));
	*resp_cur += rr->rr_rdlength;
    }

    DEBUG( fprintf( stderr, "type: %d\t", rr->rr_type ));
    DEBUG( fprintf( stderr, "class: %d\t", rr->rr_class ));
    DEBUG( fprintf( stderr, "ttl: " ));
    DEBUG( fprintf( stderr, "%dd %02dh %02dm %02ds\n",
	rr->rr_ttl / 86400,
	( rr->rr_ttl % 86400 ) / 3600,
	( rr->rr_ttl % 3600 ) / 60,
	rr->rr_ttl % 60 ));
    DEBUG( fprintf( stderr, "rdlength: %d\n", rr->rr_rdlength ));

    return( 0 );
}

    int
_dnsr_display_header( struct dnsr_header *h)
{
    uint16_t	flags;

    flags = ntohs( h->h_flags );
    /* XXX - make sure that it's the correct ID XOR with ns */
    printf( "ID:     %d\n", ntohs( h->h_id ));
    printf( "qr:     " );
    if ( flags & DNSR_RESPONSE ) {
	printf( "( Response )\n" );
    } else {
	printf( "( Question )\n" );
    }
    printf( "opcode: %d ", ( flags & DNSR_OPCODE ) >> 11 );
    switch(( flags & DNSR_OPCODE ) >> 11 ) {
    case DNSR_OP_QUERY:
	printf( "( Standard query )\n" );
	break;
    case DNSR_OP_IQUERY:
	printf( "( inverse query )\n" );
	break;
    case DNSR_OP_STATUS:
	printf( "( server status request )\n" );
	break;
    default:
	printf( "( UNKNOWN )\n" );
	break;
    }
    printf( "AA:	" );
    if ( flags & DNSR_AUTHORITATIVE_ANSWER ) {
	printf( "( Authoritative Answer )\n" );
    } else {
	printf( "( Non-authoritative answer )\n" );
    }
    printf( "TC:     " );
    if ( flags & DNSR_TRUNCATION ) {
	printf( "( Message truncated )\n" );
    } else {
	printf( "( Message not truncated )\n" );
    }
    printf( "RD:     " );
    if ( flags & DNSR_RECURSION_DESIRED ) {
	printf( "( Recursion desired )\n" );
    } else {
	printf( "( Recursion not desired )\n" );
    }
    printf( "RA:     " );
    if ( flags & DNSR_RECURSION_AVAILBLE ) {
	printf( "( Recursion available )\n" );
    } else {
	printf( "( Recursion not available )\n" );
    }
    printf( "Z:      " );
    if ( flags & DNSR_Z ) {
	printf( "( INVALID YOU FOOL )\n" );
    } else {
	printf( "( Valid )\n" );
    }
    printf( "rcode:  %d ", flags & DNSR_RCODE );
    switch( flags & DNSR_RCODE ) {
    case DNSR_RC_OK: 
	printf( "( No error condition )\n" );
	break;
    case DNSR_RC_FORMATERR:
	printf( "( Format error )\n" );
	break;
    case DNSR_RC_SVRERR:
	printf( "( Server failure )\n" );
	break;
    case DNSR_RC_NAMEERR:
	printf( "( Name error )\n" );
	break;
    case DNSR_RC_NOTIMP:
	printf( "( Not implemented )\n" );
	break;
    case DNSR_RC_REFUSED:
	printf( "( Refused )\n" );
	break;
    default:
	printf( "( Unknown )\n" );
	break;
    }
    printf( "QDCOUNT: %d\t", ntohs( h->h_qdcount ));
    printf( "ANCOUNT: %d\t", ntohs( h->h_ancount ));
    printf( "NSCOUNT: %d\t", ntohs( h->h_nscount ));
    printf( "ARCOUNT: %d\n", ntohs( h->h_arcount ));
    return( 0 );
}

/* rfc 1035 3.3
 * <character-string> is a single
 * length octet followed by that number of characters.  <character-string>
 * is treated as binary information, and can be up to 256 characters in
 * length (including the length octet).
 */

    int
_dnsr_labels_to_string( DNSR *dnsr, char **resp_cur, char *resp_end,
    char *string_begin )
{
    uint		len, i;

    if ( *resp_cur >= resp_end ) {
	DEBUG( fprintf( stderr, "labels_to_string: no resp\n" ));
	dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
	return( -1 );
    }
    len = **resp_cur;
    (*resp_cur)++;

    if ( len < 0 || *resp_cur + len > resp_end || len > DNSR_MAX_STRING ) {
	DEBUG( fprintf( stderr, "labels_to_string: invalid length\n" ));
	dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
	return( -1 );
    }

    /* Convert label */
    for ( i = 0; i < len; i++ ) {
	string_begin[ i ] = **resp_cur;
	(*resp_cur)++;
    }
    return( 0 );
}

/* rfc 1035 3.1 Name space definitions
 * Domain names in messages are expressed in terms of a sequence of labels.
 * Each label is represented as a one octet length field followed by that
 * number of octets.  Since every domain name ends with the null label of
 * the root, a domain name is terminated by a length byte of zero.  The
 * high order two bits of every length octet must be zero, and the
 * remaining six bits of the length field limit the label to 63 octets or
 * less.
 * 
 * To simplify implementations, the total length of a domain name (i.e.,
 * label octets and label length octets) is restricted to 255 octets or
 * less.
 */

    int
_dnsr_labels_to_name( DNSR *dnsr, char *resp_begin, char **resp_cur,
    uint resplen, char *dn_begin, char **dn_cur, char *dn_end )
{
    uint8_t		len = 0;		// Length of label;
    uint16_t		offset = 0;		// Compression offset
    uint		i = 0;			// Offset into a single label
    char		*offset_cur;

    for ( ; ; ) {
	memcpy( &offset, *resp_cur, sizeof( offset ));
	offset = ntohs( offset );

	/* if first two bits are 11, then the remaining 6 bits are offset */
	if ( offset & DNSR_OFFSET ) {
	    /* Compression */
	    offset &= ~DNSR_OFFSET;

	    if ( offset > resplen ) {
		DEBUG( fprintf( stderr, "labels_to_name: invalid offset\n" ));
		dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
		return( -1 );
	    }

	    offset_cur = resp_begin + offset;
	    if ( _dnsr_labels_to_name( dnsr, resp_begin, &offset_cur,
		    resplen, dn_begin, dn_cur, dn_end ) < 0 ) {
		return( -1 );
	    }
	    /* Advance past compression */
	    (*resp_cur) += 2;
	    return( 0 );

	} else {

	    if ( *resp_cur >= resp_begin + resplen ) {
		DEBUG( fprintf( stderr, "labels_to_string: no resp\n" ));
		dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
		return( -1 );
	    }
	    /* XXX - Do we need to convert from network byte order? */
	    len = **resp_cur;
	    (*resp_cur)++;

	    if ( len > DNSR_MAX_LABEL || *resp_cur + len > resp_begin + resplen
		    || *dn_cur + len > dn_end ) {
		DEBUG( fprintf( stderr, "labels_to_name: invalid length\n" ));
		dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
		return( -1 );
	    }

	    if ( len == 0 ) {
		/* root - add trailing NULL */
		**dn_cur = '\0';
		(*dn_cur)++;
		return( 0 );
	    }

	    /* Add '.' between labels */
	    if ( dn_begin != *dn_cur ) {
		if ( *dn_cur < dn_end ) {
		    **dn_cur = '.';
		    (*dn_cur)++;
		} else {
		    DEBUG( fprintf( stderr,
			"labels_to_name: dn overflow\n" ));
		    dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
		    return( -1 );
		}
	    }

	    /* Convert label */
	    for ( i = 0; i < len; i++ ) {
		**dn_cur = **resp_cur;
		(*dn_cur)++;
		(*resp_cur)++;
	    }
	}
    }
}
