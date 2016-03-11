/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <ctype.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>

#include <yasl.h>

#include "envelope.h"
#include "expand.h"
#include "spf.h"
#include "srs.h"
#include "simta.h"

#ifdef HAVE_LIBSSL
#include <openssl/hmac.h>
#endif /* HAVE_LIBSSL */


static const char *b32_chars = "abcdefghijklmnopqrstuvwxyz234567";

static yastr	srs_hash( const char *, const char *, size_t );
static yastr	srs_reforward( const char * );
static yastr	srs_timestamp( void );
static int	srs_timestamp_validate( const char * );

    int
srs_forward( struct envelope *env ) {
    yastr		newaddr = NULL;
    yastr		localpart = NULL;
    yastr		hash = NULL;
    char		*addr;
    char		*p;
    int			rc = SRS_SYSERROR;
    struct ifaddrs	*ifaddrs;
    struct ifaddrs	*ifa;
    int			spf_result;

    if ( strlen( env->e_mail ) == 0 ) {
	/* Null return-path, don't need to do anything */
	return( SRS_OK );
    }

    if (( p = strrchr( env->e_mail, '@' )) == NULL ) {
	syslog( LOG_ERR, "srs_forward: strchr blivet: %s", env->e_mail );
	return( SRS_BADSYNTAX );
    }

    if (( simta_srs != SRS_POLICY_ALWAYS ) &&
	    ( strcasecmp( p + 1, simta_srs_domain ) == 0 )) {
	/* Already from the correct domain, don't need to do anything */
	return( SRS_OK );
    }

    if ( simta_srs == SRS_POLICY_SMART ) {
	spf_result = SPF_RESULT_TEMPERROR;
	if ( getifaddrs( &ifaddrs ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: srs_forward getifaddrs: %m" );
	    return( SRS_SYSERROR );
	}
	for ( ifa = ifaddrs; (( ifa != NULL ) &&
			( spf_result != SPF_RESULT_FAIL ) &&
			( spf_result != SPF_RESULT_SOFTFAIL ));
		ifa = ifa->ifa_next ) {
	    if (( ifa->ifa_addr == NULL ) ||
		    ( ifa->ifa_flags & IFF_LOOPBACK )) {
		continue;
	    }
	    if (( simta_ipv4 && ( ifa->ifa_addr->sa_family == AF_INET )) ||
		    ( simta_ipv6 && ( ifa->ifa_addr->sa_family == AF_INET6 ))) {
		spf_result = spf_lookup( simta_hostname, env->e_mail,
			ifa->ifa_addr );
	    }
	}
	freeifaddrs( ifaddrs );
	if (( spf_result == SPF_RESULT_NONE ) ||
		( spf_result == SPF_RESULT_NEUTRAL ) ||
		( spf_result == SPF_RESULT_PASS )) {
	    /* SPF won't fail, don't need to do anything */
	    return( SRS_OK );
	}
    }

    addr = env->e_mail;
    if ( *addr == '"' ) {
	newaddr = yaslnew( "\"", 1 );
	addr++;
    } else {
	newaddr = yaslempty( );
    }

    if (( strncasecmp( addr, "SRS", 3 ) == 0 ) && ( strlen( addr ) > 13 ) &&
	    (( addr[ 3 ] == '0' ) || ( addr[ 3 ] == '1' )) &&
	    (( addr[ 4 ] == '=' ) || ( addr[ 4 ] == '-' ) ||
	    ( addr[ 4 ] == '+' ))) {
	localpart = srs_reforward( addr );
    }

    if ( localpart == NULL ) {
	/* Address is not valid SRS that can be reforwarded,
	 * do a plain forward */
	p = strrchr( addr, '@' );
	localpart = yaslcatprintf( srs_timestamp( ), "=%s=", ( p + 1 ));
	localpart = yaslcatlen( localpart, addr, ( p - addr ));
	newaddr = yaslcat( newaddr, "SRS0=" );
    } else {
	newaddr = yaslcat( newaddr, "SRS1=" );
    }

    if (( hash = srs_hash( localpart, simta_srs_secret, 5 )) == NULL ) {
	syslog( LOG_NOTICE, "SRS %s: srs_hash failed", env->e_mail );
	goto error;
    }

    newaddr = yaslcatprintf( newaddr, "%s=%s@%s", hash, localpart,
	    simta_srs_domain );

    rc = SRS_OK;

    env->e_mail_orig = env->e_mail;
    env->e_mail = strdup( newaddr );

error:
    yaslfree( localpart );
    yaslfree( hash );
    yaslfree( newaddr );
    return( rc );
}

    int
srs_reverse( const char *addr, char **newaddr, const char *secret ) {
    int		rc = SRS_BADSYNTAX;
    int		reforwarded = 0;
    int		ret;
    yastr	a;
    yastr	addrhash = NULL;
    yastr	hash = NULL;
    yastr	n;
    char	*p;

    a = yaslauto( addr );

    if ( *a == '"' ) {
	n = yaslauto( "\"" );
	yaslrange( a, 1, -1 );
    } else {
	n = yaslempty( );
    }

    if (( p = strrchr( a, '@' )) == NULL ) {
	goto error;
    }

    yaslrange( a, 0, ( p - a - 1 ));

    if ( strncasecmp( a, "SRS1=", 5 ) == 0 ) {
	/* SRS1=<hash>=<domain>=<SRS0 address> */
	n = yaslcat( n, "SRS0" );
	reforwarded = 1;

    } else if ( strncasecmp( addr, "SRS0=", 5 ) == 0 ) {
	/* SRS0=<hash>=<timestamp>=<domain>=<localpart> */

    } else {
	goto error;
    }

    /* Check the hash */
    yaslrange( a, 5, -1 );
    if (( p = strchr( a, '=' )) == NULL ) {
	simta_debuglog( 1, "SRS %s: can't find hash end", addr );
	goto error;
    }
    addrhash = yaslnew( a, ( p - a ));
    /* Truncate the hash so lowering the hash length doesn't invalidate old
     * addresses. This isn't configurable at the moment, but might be in the
     * future.
     */
    yaslrange( addrhash, 0, 4 );
    yasltolower( addrhash );
    hash = srs_hash( p + 1, secret, 5 );
    if ( yaslcmp( addrhash, hash ) != 0 ) {
	syslog( LOG_INFO, "SRS %s: invalid hash %s should have been %s",
		addr, addrhash, hash );
	rc = SRS_INVALID;
	goto error;
    }
    yaslrange( a, ( p - a + 1 ), -1 );

    if ( !reforwarded ) {
	/* Check the timestamp */
	if (( p = strchr( a, '=' )) == NULL ) {
	    simta_debuglog( 1, "SRS %s: can't find timestamp end", addr );
	    goto error;
	}
	*p = '\0';
	if (( ret = srs_timestamp_validate( a )) != SRS_OK ) {
	    syslog( LOG_INFO, "SRS %s: bad timestamp %s", addr, a );
	    rc = ret;
	    goto error;
	}
	yaslrange( a, ( p - a + 1 ), -1 );
    }

    if (( p = strchr( a, '=' )) == NULL ) {
	simta_debuglog( 1, "SRS %s: can't find domain end", addr );
	goto error;
    }

    n = yaslcat( n, ( p + 1 ));
    n = yaslcat( n, "@" );
    n = yaslcatlen( n, a, ( p - a ));

    *newaddr = strdup( n );
    rc = SRS_OK;

error:
    yaslfree( a );
    yaslfree( addrhash );
    yaslfree( hash );
    yaslfree( n );
    return( rc );
}

    int
srs_expand( struct expand *exp, struct exp_addr *e_addr, struct action *a )
{
    char	*newaddr;
    int		rc;

    if (( rc = srs_reverse( e_addr->e_addr, &newaddr,
	    a->a_fname )) == SRS_OK ) {
	if ( add_address( exp, newaddr, e_addr->e_addr_errors,
		ADDRESS_TYPE_EMAIL, e_addr->e_addr_from ) != 0 ) {
	    free( newaddr );
	    return( ADDRESS_SYSERROR );
	}
	simta_debuglog( 1, "Expand.SRS env <%s>: <%s>: expanded to <%s>",
		exp->exp_env->e_id, e_addr->e_addr, newaddr );
	free( newaddr );
	return( ADDRESS_EXCLUDE );
    }

    if ( rc == SRS_SYSERROR ) {
	return( ADDRESS_SYSERROR );
    }

    return( ADDRESS_NOT_FOUND );
}

    int
srs_valid( const char *addr, const char *secret )
{
    char	*newaddr;
    int		rc;

    if (( rc = srs_reverse( addr, &newaddr, secret )) == SRS_OK ) {
	free( newaddr );
	return( ADDRESS_FINAL );
    }

    if ( rc == SRS_SYSERROR ) {
	return( ADDRESS_SYSERROR );
    }

    return( ADDRESS_NOT_FOUND );
}

    static yastr
srs_hash( const char *str, const char *secret, size_t len )
{
#ifndef HAVE_LIBSSL
    return( NULL );
#else /* HAVE_LIBSSL */
    unsigned char	mac[ EVP_MAX_MD_SIZE ];
    unsigned int	maclen;
    BIO			*bmem;
    BIO			*b64;
    yastr		lc;
    yastr		hash = NULL;

    if ( secret == NULL ) {
	syslog( LOG_NOTICE, "SRS: tried to create hash with no secret" );
	return( NULL );
    }

    lc = yaslauto( str );
    yasltolower( lc );

    if ( HMAC( EVP_sha256( ), secret, strlen( secret ),
	    (unsigned char *)lc, yasllen( lc ), mac, &maclen ) == NULL ) {
	syslog( LOG_ERR, "Liberror: srs_hash HMAC: failed" );
	goto error;
    }

    bmem = BIO_new( BIO_s_mem( ));
    b64 = BIO_push( BIO_new( BIO_f_base64( )), bmem );
    BIO_write( b64, mac, maclen );
    (void)BIO_flush( b64 );

    /* This is slightly wasteful of memory */
    hash = yaslgrowzero( yaslempty( ), maclen * 2 );
    BIO_read( bmem, hash, maclen * 2 );
    yaslupdatelen( hash );
    simta_debuglog( 2, "SRS: hash: %s", hash );
    yaslrange( hash, 0, len - 1 );
    yasltolower( hash );
    simta_debuglog( 3, "SRS: squashed hash: %s", hash );

    BIO_free_all( b64 );

error:
    yaslfree( lc );
    return( hash );
#endif /* HAVE_LIBSSL */
}

    static yastr
srs_reforward( const char *addr )
{
    yastr		local = NULL;
    char		*p;
    const char		*opaque;

    if ( addr[ 3 ] == '1' ) {
	/* SRS1=<useless hash>=<domain>==<opaque>@<useless domain> */
	/* skip the hash of the previous forwarder */
	if (( p = strchr( addr + 5, '=' )) == NULL ) {
	    return( NULL );
	}
	if (( opaque = strchr( p + 1, '=' )) == NULL ) {
	    return( NULL );
	}

	/* copy the domain of the first forwarder */
	local = yaslnew( p + 1, opaque - p - 1 );
	opaque++;
    } else {
	/* SRS0=<opaque>@<domain> */
	opaque = addr + 4;
	if (( p = strrchr( addr, '@' )) == NULL ) {
	    return( NULL );
	}
	/* copy the domain of the previous forwarder */
	local = yaslauto( p + 1 );
    }

    if (( p = strrchr( opaque, '@' )) == NULL ) {
	yaslfree( local );
	return( NULL );
    }
    local = yaslcat( local, "=" );
    local = yaslcatlen( local, opaque, ( p - opaque ));

    return( local );
}

    static yastr
srs_timestamp( void )
{
    char	buf[ 2 ];
    time_t	now;

    now = time( NULL ) / 86400;
    buf[ 0 ] = b32_chars[ ( now >> 5 ) & (( 1 << 5 ) - 1 ) ];
    buf[ 1 ] = b32_chars[ now & (( 1 << 5 ) - 1 ) ];
    return( yaslnew( buf, 2 ));
}

    static int
srs_timestamp_validate( const char *timestamp )
{
    time_t	now;
    time_t	then = 0;
    const char	*p, *pp;

    if ( strlen( timestamp ) != 2 ) {
	return( SRS_BADSYNTAX );
    }

    for ( p = timestamp ; *p ; p++ ) {
	if (( pp = strchr( b32_chars, tolower( *p ))) == NULL ) {
	    return( SRS_BADSYNTAX );
	}
	then = ( then << 5 ) | ( pp - b32_chars );
    }

    now = time( NULL ) / 86400;

    /* Handle wraparound */
    for ( now %= 1024; now < then; now += 1024 );

    if ( now > ( then + simta_srs_maxage )) {
	return( SRS_EXPIRED );
    }

    return( SRS_OK );
}

/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
