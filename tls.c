/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

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
	fprintf( stderr, "RAND_file_name: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }

    /* reads the complete randfile and adds them to the PRNG */
    if ( RAND_load_file( randfile, -1 ) <= 0 ) {
	fprintf( stderr, "RAND_load_file: %s: %s\n", randfile,
		ERR_error_string( ERR_get_error(), NULL ));
	return( -1 );
    }

    /* writes a number of random bytes (currently 1024) to randfile */
    if ( RAND_write_file( randfile ) < 0 ) {
	fprintf( stderr, "RAND_write_file: %s: %s\n", randfile,
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
    int                 ssl_mode = 0;

    SSL_load_error_strings();
    SSL_library_init();    

    if ( use_randfile ) {
	if ( _randfile( ) != 0 ) {
	    return( NULL );
	}
    }

    if (( ssl_ctx = SSL_CTX_new( SSLv23_server_method())) == NULL ) {
	fprintf( stderr, "SSL_CTX_new: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	return( NULL );
    }

    if ( SSL_CTX_use_PrivateKey_file( ssl_ctx, privatekey,
	    SSL_FILETYPE_PEM ) != 1 ) {
	fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		privatekey, ERR_error_string( ERR_get_error(), NULL ));
	goto error;
    }
    if ( SSL_CTX_use_certificate_chain_file( ssl_ctx, cert ) != 1 ) {
	fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cert, ERR_error_string( ERR_get_error(), NULL ));
	goto error;
    }
    /* Verify that private key matches cert */
    if ( SSL_CTX_check_private_key( ssl_ctx ) != 1 ) {
	fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	goto error;
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
    if ( authlevel <= 1 ) {
	ssl_mode = SSL_VERIFY_NONE; 
    } else {
	/* authlevel == 2 */
	ssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify( ssl_ctx, ssl_mode, NULL );

    return( ssl_ctx );

    error:
    SSL_CTX_free( ssl_ctx );
    return( NULL );
}


    SSL_CTX *
tls_client_setup( int use_randfile, int authlevel, char *caFile, char *caDir,
	char *cert, char *privatekey )
{
    SSL_CTX		*ssl_ctx;
    int                 ssl_mode = 0;
    X509		*ssl_X509;

    SSL_load_error_strings();
    SSL_library_init();

    if ( use_randfile ) {
	if ( _randfile( ) != 0 ) {
	    return( NULL );
	}
    }

    if (( ssl_ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	fprintf( stderr, "SSL_CTX_new: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	return( NULL );
    }

    if ( authlevel == 2 ) {
	if ( SSL_CTX_use_PrivateKey_file( ssl_ctx, privatekey,
		SSL_FILETYPE_PEM ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		   privatekey, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
	if ( SSL_CTX_use_certificate_chain_file( ssl_ctx, cert ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		    cert, ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
	/* Verify that private key matches cert */
	if ( SSL_CTX_check_private_key( ssl_ctx ) != 1 ) {
	    fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		    ERR_error_string( ERR_get_error(), NULL ));
	    goto error;
	}
    }

    /* Load CA */
    if ( authlevel == 2 ) {
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
    }

    /* Set level of security expecations */
    ssl_mode = SSL_VERIFY_NONE;

    SSL_CTX_set_verify( ssl_ctx, ssl_mode, NULL );

    if (( ssl_X509 = SSL_get_peer_certificate( ssl_ctx )) == NULL ) {
	/* ZZZ no certificate */
    }

    X509_free( ssl_X509 );

    if ( SSL_get_verify_result( ssl_ctx ) != X509_V_OK ) {
	/* ZZZ bad result */
    }

    return( ssl_ctx );

    error:
    SSL_CTX_free( ssl_ctx );
    return( NULL );
}
