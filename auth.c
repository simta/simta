/*
 * Copyright (c) 2000 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/time.h>
#include <netdb.h>
#include <strings.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>

#include <krb.h>
#include <des.h>

#include <snet.h>

#include "envelope.h"
#include "receive.h"
#include "auth.h"
#include "base64.h"

extern char *krb_err_txt[];

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

struct krb4_crypto {
    des_key_schedule	k4c_sched;
    C_Block		k4c_key;
    struct sockaddr_in	*k4c_sender;
    struct sockaddr_in	*k4c_receiver;
};

    int
auth_krb4_encrypt( void *crypto, char *buf, int len )
{
    abort();
}

    int
auth_krb4_decrypt( void *crypto, char *buf, int len )
{
    MSG_DAT		md;
    struct krb4_crypto	*k4c = crypto;

    abort();

    if ( krb_rd_priv( buf, len, k4c->k4c_sched, k4c->k4c_key,
	    k4c->k4c_sender, k4c->k4c_receiver, &md ) != 0 ) {
	return( -1 );
    }

}

/*
 * See rfc2222 SASL 7.1 and rfc2554 SMTP Authentication.
 */
    static int
f_auth_krb4( s, snet, env, ac, av )
    struct sasl		*s;
    SNET		*snet;
    struct envelope	*env;
    int			ac;
    char		*av[];
{
    struct timeval	tv;
    uint32_t		r, netr, dsize;
    int			len, rc;
    char		*line;
    char		*dbuf;
    KTEXT_ST		tkt;
    AUTH_DAT		ad;
    des_key_schedule	ks;
    struct krb4_crypto	*k4c;
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
	syslog( LOG_INFO, "%connection dropped" );
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
    base64_d( line, len, tkt.dat );
    tkt.mbz = 0;

    /* XXX Should allow the srvtab filename to be set. */
    strcpy( inst, "*" );
    if (( rc = krb_rd_req( &tkt, "rcmd", inst, 0L, &ad, "" )) != RD_AP_OK ) {
	snet_writef( snet, "%d AUTH %s\r\n", 535, krb_err_txt[ rc ] );
	syslog( LOG_INFO, "%s: %s", krb_err_txt[ rc ] );
	return( 1 );
    }

    /* XXX should save ad.pname somewhere */

    if ( r != ad.checksum ) {
	snet_writef( snet, "%d AUTH wrong checksum\r\n", 535 );
	syslog( LOG_INFO, "%s: wrong checksum %X != %X", r, ad.checksum );
	return( 1 );
    }

    key_sched( ad.session, ks );

    netr = htonl( r + 1 );
    memcpy( data, &netr, sizeof( netr ));
    data[ 4 ] = 4;		/* 4 = mk_priv, 2 = mk_safe, 1 = none */
    data[ 5 ] = 8;		/* max buffer = 0x800, 2K */
    data[ 6 ] = 0;
    data[ 7 ] = 0;

    des_ecb_encrypt( (des_cblock *)data, (des_cblock *)data, ks, ENCRYPT );

    base64_e( data, sizeof( data ), buf );
    snet_writef( snet, "%d %s\r\n", 334, buf );

    tv.tv_sec = 60 * 10;
    tv.tv_usec = 0;
    if (( line = snet_getline( snet, &tv )) == NULL ) {
	syslog( LOG_INFO, "%s: connection dropped" );
	return( -1 );
    }

    len = strlen( line );
    if ( SZ_BASE64_D( len ) < 16 ) {
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
	free( dbuf );
	snet_writef( snet, "%d AUTH checksum wrong\r\n", 535 );
	syslog( LOG_INFO, "%s: wrong checksum (%d != %d)", r, ntohl( netr ));
	return( 1 );
    }

    /* XXX should save username somewhere */
    syslog( LOG_INFO, "auth as %.*s",
	    SZ_BASE64_D( len ) - 8 - ( SZ_BASE64_D( len ) % 8 ),
	    &dbuf[ 8 ] );

    /* select security layer */
    switch ( dbuf[ 4 ] ) {
    case 1 :							/* none */
	snet_writef( snet, "%d AUTH successful\r\n", 235 );
	break;

    case 4 :							/* mk_priv */
	dbuf[ 4 ] = 0;
	memcpy( &dsize, &dbuf[ 4 ], sizeof( dsize ));
	dsize = ntohl( dsize );

	if (( k4c = malloc( sizeof( struct krb4_crypto ))) == NULL ) {
	    syslog( LOG_ERR, "f_auth_krb4: malloc: %m" );
	    snet_writef( snet,
    "%d %s Service not available, closing transmission channel\r\n",
		    421, env->e_hostname );
	    return( -1 );
	}
	memcpy( k4c->k4c_sched, ks, sizeof( des_key_sched ));
	memcpy( k4c->k4c_key, ad.session, sizeof( C_Block ));
	k4c->k4c_sender = NULL;
	k4c->k4c_receiver = NULL;

	if ( snet_sasl( snet, k4c, auth_krb4_encrypt, auth_krb4_decrypt,
		    (unsigned)0x800, (unsigned)dsize ) < 0 ) {
	    syslog( LOG_ERR, "f_auth_krb4: snet_sasl: %m" );
	    snet_writef( snet,
    "%d %s Service not available, closing transmission channel\r\n",
		    421, env->e_hostname );
	    return( -1 );
	}
	snet_writef( snet, "%d AUTH successful, begin encryption\r\n", 235 );
	break;

    default :
	free( dbuf );
	snet_writef( snet, "%d AUTH unsupported security layer\r\n", 535 );
	syslog( LOG_INFO, "unsupported security layer %d", dbuf[ 4 ] );
	return( 1 );
    }

    free( dbuf );
    return( 0 );
}

    void
auth_krb4( SNET *snet, int verbose )
{
    unsigned char	data[ 8 ];
    			/* > sizeof( chal ) */
    char		buf[ SZ_BASE64_E( sizeof( data )) ];
    char		*p0, *p1, *line;
    int			rc;
    unsigned int	len;
    uint32_t		chal, chal1, dsize;
    struct krb4_crypto	*k4c;
    KTEXT_ST		tkt;
    CREDENTIALS		cred;
    des_key_schedule	ks;

    /*
     * For now, since I don't want to write a bunch of SMTP parsing code
     * so that I can test SASL, we'll just assume that the server supports k4.
     */

    if ( snet_writef( snet, "AUTH KERBEROS_V4\r\n" ) < 0 ) {
	perror( "snet_writef" );
	exit( EX_IOERR );
    }
    if ( verbose )  printf( ">>> AUTH KERBEROS_V4\n" );
    if (( line = snet_getline( snet, NULL)) == NULL ) {
	perror( "snet_getline" );
	exit( EX_IOERR );
    }
    if ( verbose )  printf( "<<< %s\n", line );
    if (( *line != '3' ) ||
	    ( strlen( line ) + 1 != ( 4 + SZ_BASE64_E( sizeof( chal ))))) {
	fprintf( stderr, "%s\n", line );
	snet_close( snet );
	exit( 1 );
    }

    /* base64 decode challenge */
    base64_d( line + 4, SZ_BASE64_E( sizeof( chal )), buf );
    memcpy( &chal, buf, sizeof( chal ));
    chal = ntohl( chal );

    /*
     * what's a good way to know the instance?  how about the realm?
     * maybe this is corrected in K5.  probably not...
     */
    if (( rc = krb_mk_req( &tkt, "rcmd", "terminator", "UMICH.EDU", chal )) !=
	    KSUCCESS ) {
	fprintf( stderr, "%s.%s: %s\n", "rcmd", "terminator",
		krb_err_txt[ rc ] );
	exit( 1 );
    }

    /*
     * Get the credential immediately, so a long network delay won't
     * allow something to expire in the meantime.
     */
    if (( rc = krb_get_cred( "rcmd", "terminator", "UMICH.EDU", &cred )) !=
	    GC_OK ) {
	fprintf( stderr, "%s.%s: %s\n", "rcmd", "terminator",
		krb_err_txt[ rc ] );
	exit( 1 );
    }
    /* These need to be saved in the crypto structure */
    key_sched( cred.session, ks );

    if (( p0 = malloc( (size_t)SZ_BASE64_E( tkt.length ))) == NULL ) {
	perror( "malloc" );
	exit( 1 );
    }
    base64_e( tkt.dat, tkt.length, p0 );
    snet_writef( snet, "%s\r\n", p0 );
    if ( verbose )  printf( ">>> %s\n", p0 );
    free( p0 );

    if (( line = snet_getline( snet, NULL)) == NULL ) {
	perror( "snet_getline" );
	exit( EX_IOERR );
    }
    if ( verbose )  printf( "<<< %s\n", line );
    if (( *line != '3' ) ||
	    ( strlen( line ) + 1 != ( 4 + SZ_BASE64_E( sizeof( data ))))) {
	fprintf( stderr, "%s\n", line );
	snet_close( snet );
	exit( 1 );
    }
    base64_d( line + 4, SZ_BASE64_E( sizeof( data )), buf );
    memcpy( data, buf, sizeof( data ));

    des_ecb_encrypt( (des_cblock *)data, (des_cblock *)data, ks, DECRYPT );

    memcpy( &chal1, data, sizeof( chal1 ));
    chal1 = ntohl( chal1 );
    if ( chal1 != chal + 1 ) {
	fprintf( stderr, "Checksum incorrect! %d != %d\n", chal1, chal + 1 );
	exit( 1 );
    }

    switch ( data[ 4 ] ) {
    case 1 :
	data[ 4 ] = 1;
	data[ 5 ] = 0;
	data[ 6 ] = 0;
	data[ 7 ] = 0;
	break;

    case 4 :							/* mk_priv */
	data[ 4 ] = 0;
	memcpy( &dsize, &data[ 4 ], sizeof( dsize ));
	dsize = ntohl( dsize );

	data[ 4 ] = 4;
	data[ 5 ] = 8;
	data[ 6 ] = 0;
	data[ 7 ] = 0;
	break;

    default :
	fprintf( stderr, "Unknown security layer! %d\n", data[ 4 ] );
	exit( 1 );
    }

    len = strlen( cred.pname );
    len = (( len / 8 ) + (( len % 8 ) != 0 )) * 8;
    if (( p0 = malloc( sizeof( data ) + len )) == NULL ) {
	perror( "malloc" );
	exit( 1 );
    }
    if (( p1 = malloc( SZ_BASE64_E( sizeof( data ) + len ))) == NULL ) {
	perror( "malloc" );
	free( p0 );
	exit( 1 );
    }

    chal = htonl( chal );
    memcpy( p0, data, sizeof( data ));
    memcpy( p0, &chal, sizeof( chal ));
    memset( p0 + sizeof( data ), 0, len );
    memcpy( p0 + sizeof( data ), cred.pname, strlen( cred.pname ));
    des_pcbc_encrypt( (des_cblock *)p0, (des_cblock *)p0,
	    sizeof( data ) + len, ks, cred.session, ENCRYPT );
    base64_e( p0, sizeof( data ) + len, p1 );
    free( p0 );
    snet_writef( snet, "%s\r\n", p1 );
    free( p1 );

    if (( line = snet_getline( snet, NULL)) == NULL ) {
	perror( "snet_getline" );
	exit( EX_IOERR );
    }
    if ( verbose )  printf( "<<< %s\n", line );
    if ( *line != '2' ) {
	fprintf( stderr, "%s\n", line );
	snet_close( snet );
	exit( 1 );
    }

    if ( data[ 4 ] == 4 ) {
printf( "!!! Encryption !!!\n" );
	if (( k4c = malloc( sizeof( struct krb4_crypto ))) == NULL ) {
	    perror( "malloc" );
	    exit( 1 );
	}
	memcpy( k4c->k4c_sched, ks, sizeof( des_key_sched ));
	memcpy( k4c->k4c_key, cred.session, sizeof( C_Block ));
	k4c->k4c_sender = NULL;
	k4c->k4c_receiver = NULL;

	if ( snet_sasl( snet, k4c, auth_krb4_encrypt, auth_krb4_decrypt,
		    (unsigned)0x800, (unsigned)dsize ) < 0 ) {
	    perror( "snet_sasl" );
	    exit( 1 );
	}
    }

    return;
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
