/*
 * Copyright (c) 2000 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/time.h>
#include <netdb.h>
#include <strings.h>
#include <syslog.h>
#include <stdlib.h>

#include <krb.h>
#include <des.h>

#include <snet.h>

#include "envelope.h"
#include "receive.h"
#include "auth.h"
#include "base64.h"

/*
 * SASL Authenticate command.  This code can't be copied wholesale unless
 * the protocol's SASL authentication mechanism exactly matches the
 * encoding used here.  This encoding is for SMTP.
 */

static int	f_auth_anon ___P(( struct sasl *, SNET *, struct envelope *,
			int, char *[] ));
static int	f_auth_krb4 ___P(( struct sasl *, SNET *, struct envelope *,
			int, char *[] ));

char		*authas = NULL;

/*
 * See rfc2245 Anonymous SASL Mechanism.
 */
    static int
f_auth_anon( s, snet, env, ac, av )
    struct sasl	*s;
    SNET		*snet;
    struct envelope	*env;
    int			ac;
    char		*av[];
{
    switch ( ac ) {
    case 2 :
	syslog( LOG_INFO, "auth anonymous" );
	snet_writef( snet, "%d AUTH ANONYMOUS succeeds\r\n", 210 );
	return( 0 );

    case 3 :
	syslog( LOG_INFO, "auth anonymous %s", av[ 2 ] );
	snet_writef( snet, "%d AUTH ANONYMOUS as %s succeeds\r\n", 210,
		av[ 2 ] );
	return( 0 );

    default :
	snet_writef( snet, "%d AUTH ANONYMOUS syntax error\r\n", 511 );
	return( 1 );
    }
}

/*
 * See rfc2222 SASL 7.1 and rfc2554 SMTP Authentication.
 */
    static int
f_auth_krb4( s, snet, env, ac, av )
    struct sasl	*s;
    SNET		*snet;
    struct envelope	*env;
    int			ac;
    char		*av[];
{
    struct timeval	tv;
    uint32_t		r, netr;
    int			len, rc;
    char		*line;
    char		*dbuf;
    KTEXT_ST		tkt;
    AUTH_DAT		ad;
    des_key_schedule	ks;
    char		inst[ INST_SZ ];
    unsigned char	data[ 8 ];
    char		buf[ SZ_BASE64_E( sizeof( data )) ]; /* > sizeof( r ) */

    if ( ac != 2 ) {
	snet_writef( snet, "%d AUTH syntax error\r\n", 535 );
	return( 1 );
    }

    r = random();			/* Should use a better PRNG. */
    netr = htonl( r );

    base64_e( (unsigned char *)&netr, sizeof( netr ), buf );
    snet_writef( snet, "%d %s\r\n", 334, buf );

    tv.tv_sec = 60 * 10;
    tv.tv_usec = 0;
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_INFO, "%s: connection dropped", env->e_id /* XXX */ );
	return( -1 );
    }

    /*
     * We could check here for a client cancel, i.e. "*", but there's no
     * point since the error is the same.
     */
    len = strlen( line );
    /* XXX what if ( len % 4 != 0 ) ? */
    if ( SZ_BASE64_D( len ) > MAX_KTXT_LEN ) {
	snet_writef( snet, "%d AUTH ticket too long (%d < %d)\r\n", 501,
		SZ_BASE64_D( len ), MAX_KTXT_LEN );
	return( 1 );
    }

    tkt.length = SZ_BASE64_D( len );
    base64_d( line, (int)len, tkt.dat );
    tkt.mbz = 0;

    /* XXX Should allow the srvtab filename to be set. */
    strcpy( inst, "*" );
    if (( rc = krb_rd_req( &tkt, "smtp", inst, 0L, &ad, "" )) != RD_AP_OK ) {
	snet_writef( snet, "%d AUTH %s\r\n", 535, krb_err_txt[ rc ] );
	syslog( LOG_INFO, "%s: %s", env->e_id, krb_err_txt[ rc ] );
	return( 1 );
    }

    if ( r != ad.checksum ) {
	snet_writef( snet, "%d AUTH wrong checksum\r\n", 535 );
	syslog( LOG_INFO, "%s: wrong checksum", env->e_id );
	return( 1 );
    }

    key_sched( ad.session, ks );

    memset( data, 0, sizeof( netr ));
    netr = htonl( r + 1 );
    memcpy( data, &netr, sizeof( netr ));
    data[ 4 ] = 1;
    data[ 5 ] = 0;
    data[ 6 ] = 0;
    data[ 7 ] = 0;

    des_ecb_encrypt( (des_cblock *)data, (des_cblock *)data, ks, ENCRYPT );

    base64_e( data, sizeof( data ), buf );
    snet_writef( snet, "%d %s\r\n", 334, buf );

    tv.tv_sec = 60 * 10;
    tv.tv_usec = 0;
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_INFO, "%s: connection dropped", env->e_id );
	return( -1 );
    }

    len = strlen( line );
    if ( SZ_BASE64_D( len ) / 8 < 2 ) {
	snet_writef( snet, "%d AUTH data too short\r\n", 501 );
	return( 1 );
    }
    if (( dbuf = malloc( (unsigned)SZ_BASE64_D( len ))) == NULL ) {
	syslog( LOG_ERR, "f_auth_krb4: malloc: %m" );
	snet_writef( snet,
		"%d %s Service not available, closing transmission channel\r\n",
		421, env->e_hostname );
	return( -1 );
    }
    base64_d( line, (int)len, dbuf );
    des_pcbc_encrypt( (des_cblock *)dbuf, (des_cblock *)dbuf,
	    SZ_BASE64_D( len ) - ( SZ_BASE64_D( len ) % 8 ),
	    ks, ad.session, DECRYPT );

    memcpy( &netr, dbuf, sizeof( netr ));
    if ( r != ntohl( netr )) {
	snet_writef( snet, "%d AUTH wrong checksum\r\n", 535 );
	syslog( LOG_INFO, "%s: wrong checksum (%d != %d)", env->e_id, 
		r, ntohl( netr ));
	return( 1 );
    }

    if (( dbuf[ 4 ] != 1 ) || ( dbuf[ 5 ] != 0 ) || ( dbuf[ 6 ] != 0 ) ||
	    ( dbuf[ 7 ] != 0 )) {
	snet_writef( snet, "%d AUTH wrong other stuff\r\n", 535 );
	syslog( LOG_INFO, "%s: wrong other stuff", env->e_id );
	return( 1 );
    }

    syslog( LOG_INFO, "%s: auth as %.*s", env->e_id,
	    SZ_BASE64_D( len ) - 8 - ( SZ_BASE64_D( len ) % 8 ),
	    &dbuf[ 8 ] );

    free( dbuf );

    snet_writef( snet, "%d AUTH successful\r\n", 235 );
    return( 0 );
}

struct sasl	auth_sasl[] = {
    { "KERBEROS_V4",	f_auth_krb4 },
    { "ANONYMOUS",	f_auth_anon },
    { NULL, },
};
struct sasl	*sasl = auth_sasl;

    int
f_auth( snet, env, ac, av )
    SNET		*snet;
    struct envelope	*env;
    int			ac;
    char		*av[];
{
    struct sasl	*s;

    if ( ac < 2 || ac > 3 ) {
	snet_writef( snet, "%d AUTH syntax error\r\n", 510 /*XXX*/ );
	return( 1 );
    }

    /*
     * rfc2554 After an AUTH command has successfully completed, no more AUTH
     * commands may be issued in the same session.
     */
    if ( authas != NULL ) {
	snet_writef( snet, "%d only one AUTH allowed\r\n", 503 );
	return( 1 );
    }

    /*
     * rfc2554 The AUTH command is not permitted during a mail transation.
     */
    if ( env->e_mail != NULL ) {
	snet_writef( snet, "%d AUTH not allowed after MAIL FROM\r\n", 501 );
	return( 1 );
    }

    for ( s = sasl; s->s_name != NULL; s++ ) {
	if ( strcasecmp( s->s_name, av[ 1 ] ) == 0 ) {
	    break;
	}
    }
    if ( s->s_name == NULL ) {
	snet_writef( snet, "%d AUTH type %s not supported\r\n", 504, av[ 1 ] );
	return( 1 );
    }

    return( (*s->s_func)( s, snet, env, ac, av ));
}
