/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "tls.h"
    
int _randfile( void );

extern void            (*logger)( char * );
extern int		verbose;
extern struct timeval	timeout;


    int
_randfile( void )
{
    char        randfile[ MAXPATHLEN ];

    /* generates a default path for the random seed file */
    if ( RAND_file_name( randfile, sizeof( randfile )) == NULL ) {
	syslog( LOG_ERR, "_randfile: RAND_file_name: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }

    /* reads the complete randfile and adds them to the PRNG */
    if ( RAND_load_file( randfile, -1 ) <= 0 ) {
	syslog( LOG_ERR, "_randfile: RAND_load_file: %s: %s", randfile,
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }

    /* writes a number of random bytes (currently 1024) to randfile */
    if ( RAND_write_file( randfile ) < 0 ) {
	syslog( LOG_ERR, "_randfile: RAND_write_file: %s: %s", randfile,
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }
    return( 0 );
}

    SSL_CTX *
tls_server_setup( int use_randfile, int authlevel, char *caFile, char *caDir,
	char *cert, char *privatekey )
{
    SSL_CTX		*ssl_ctx;
#ifndef OPENSSL_NO_ECDH
    EC_KEY              *ecdh;
#endif
    int                 ssl_mode = 0;

    SSL_load_error_strings();
    SSL_library_init();    

    if ( use_randfile ) {
	if ( _randfile( ) != 0 ) {
	    return( NULL );
	}
    }

    if (( ssl_ctx = SSL_CTX_new( SSLv23_server_method())) == NULL ) {
	syslog( LOG_ERR, "tls_server_setup: "
		"SSL_CTX_new: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	return( NULL );
    }

    /* Disable SSLv2 and SSLv3 */ 
    SSL_CTX_set_options( ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 );

    if ( SSL_CTX_use_PrivateKey_file( ssl_ctx, privatekey,
	    SSL_FILETYPE_PEM ) != 1 ) {
	syslog( LOG_ERR, "tls_server_setup: "
		"SSL_CTX_use_PrivateKey_file: %s: %s",
		privatekey, ERR_error_string( ERR_get_error(), NULL ));
	goto error;
    }
    if ( SSL_CTX_use_certificate_chain_file( ssl_ctx, cert ) != 1 ) {
	syslog( LOG_ERR,
		"tls_server_setup: SSL_CTX_use_certificate_chain_file: %s: %s",
		cert, ERR_error_string( ERR_get_error(), NULL ));
	goto error;
    }
    /* Verify that private key matches cert */
    if ( SSL_CTX_check_private_key( ssl_ctx ) != 1 ) {
	syslog( LOG_ERR, "tls_server_setup: "
		"SSL_CTX_check_private_key: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	goto error;
    }

    /* Load CA */
    if ( caFile != NULL ) {
	if ( SSL_CTX_load_verify_locations( ssl_ctx, caFile, NULL ) != 1 ) {
	    syslog( LOG_ERR, "tls_server_setup: "
		    "SSL_CTX_load_verify_locations: %s: %s",
		    caFile, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
    }
    if ( caDir != NULL ) {
	if ( SSL_CTX_load_verify_locations( ssl_ctx, NULL, caDir ) != 1 ) {
	    syslog( LOG_ERR, "tls_server_setup: "
		    "SSL_CTX_load_verify_locations: %s: %s",
		    caDir, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
    }

    /* Set level of security expecations */
    if ( authlevel <= 1 ) {
	ssl_mode = SSL_VERIFY_NONE; 
    } else {
	/* authlevel == 2 */
	ssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify( ssl_ctx, ssl_mode, NULL );

#ifndef OPENSSL_NO_ECDH
    /* Do not reuse the same ECDH key pair */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    /* OpenSSL >= 1.0.2 automatically handles parameter selection */
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

#elif OPENSSL_VERSION_NUMBER >= 0x10000000L
    /* Manually select the curve. This selection is compliant with RFC 6460
     * when AES-256 cipher suites are in use, but noncompliant when AES-128
     * cipher suites are used. Oh, well. */
    if (( ecdh = EC_KEY_new_by_curve_name( NID_secp384r1 )) != NULL ) {
	SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
	EC_KEY_free(ecdh);
    } else {
	syslog( LOG_ERR, "tls_server_setup: EC_KEY_new failed: %s",
		ERR_error_string( ERR_get_error(), NULL ));
    }
#endif /* openssl 1.0 - 1.0.1 */
#endif /* OPENSSL_NO_ECDH */

    return( ssl_ctx );

    error:
    SSL_CTX_free( ssl_ctx );
    return( NULL );
}


    SSL_CTX *
tls_client_setup( int use_randfile, int authlevel, char *caFile, char *caDir,
	char *cert, char *privatekey, char *ciphers )
{
    SSL_CTX		*ssl_ctx;
    int                 ssl_mode = 0;

    SSL_load_error_strings();
    SSL_library_init();

    if ( use_randfile ) {
	if ( _randfile( ) != 0 ) {
	    return( NULL );
	}
    }

    if (( ssl_ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	syslog( LOG_ERR, "tls_client_setup: "
		"SSL_CTX_new: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	return( NULL );
    }

    /* Disable SSLv2 and SSLv3 */ 
    SSL_CTX_set_options( ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 );

    if ( ciphers != NULL ) {
        SSL_CTX_set_cipher_list( ssl_ctx, ciphers );
    }

    if ( authlevel == 2 ) {
	if ( SSL_CTX_use_PrivateKey_file( ssl_ctx, privatekey,
		SSL_FILETYPE_PEM ) != 1 ) {
	    syslog( LOG_ERR, "tls_client_setup: "
		    "SSL_CTX_use_PrivateKey_file: %s: %s",
		   privatekey, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
	if ( SSL_CTX_use_certificate_chain_file( ssl_ctx, cert ) != 1 ) {
	    syslog( LOG_ERR, "tls_client_setup: "
		    "SSL_CTX_use_certificate_chain_file: %s: %s",
		    cert, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
	/* Verify that private key matches cert */
	if ( SSL_CTX_check_private_key( ssl_ctx ) != 1 ) {
	    syslog( LOG_ERR, "tls_client_setup: "
		    "SSL_CTX_check_private_key: %s",
		    ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
    }

    /* Load CA */
    if ( caFile != NULL ) {
	if ( SSL_CTX_load_verify_locations( ssl_ctx, caFile, NULL ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
		    caFile, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
    }
    if ( caDir != NULL ) {
	if ( SSL_CTX_load_verify_locations( ssl_ctx, NULL, caDir ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
		    caDir, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
    }

    /* Set level of security expecations */
    ssl_mode = SSL_VERIFY_NONE;
    SSL_CTX_set_verify( ssl_ctx, ssl_mode, NULL );
    return( ssl_ctx );

    error:
    SSL_CTX_free( ssl_ctx );
    return( NULL );
}

    int
tls_client_cert( char *hostname, const SSL *ssl )
{
    int                         i, san_names_num;
    char                        buf[ 1024 ];
    X509                        *peer;
    STACK_OF(GENERAL_NAME)      *san_names = NULL;
    GENERAL_NAME                *current_name;

    if ( ssl == NULL ) {
	syslog( LOG_ERR, "tls_client_cert: ssl is NULL" );
	return( 1 );
    }

    if (( peer = SSL_get_peer_certificate( ssl )) == NULL ) {
	syslog( LOG_ERR, "tls_client_cert %s: SSL_X509: %s",
		hostname, ERR_error_string( ERR_get_error(), NULL ));
	return( 1 );
    }

    syslog( LOG_DEBUG, "tls_client_cert %s: cert subject: %s",
	    hostname,
	    X509_NAME_oneline(
		X509_get_subject_name( peer ), buf, sizeof( buf )));

    san_names = X509_get_ext_d2i( peer, NID_subject_alt_name, NULL, NULL );
    san_names_num = sk_GENERAL_NAME_num( san_names );
    for ( i = 0 ; i < san_names_num ; i++ ) {
	current_name = sk_GENERAL_NAME_value( san_names, i );
	if ( current_name->type == GEN_DNS ) {
	    syslog( LOG_DEBUG, "tls_client_cert %s: cert subject alt name: %s",
		    hostname, ASN1_STRING_data( current_name->d.dNSName ));
	}
    }

    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    X509_free( peer );

    if ( SSL_get_verify_result( ssl ) != X509_V_OK ) {
	syslog( LOG_ERR, "tls_client_cert %s: SSL_get_verify_result: %s",
		hostname, ERR_error_string( ERR_get_error(), NULL ));
	return( 1 );
    }

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
