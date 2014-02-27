/* Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#include "base64.h"



    int
main( int argc, char *argv[])
{
    int				i;
    EVP_MD_CTX			mdctx;
    int				md_len;
    SNET			*snet;
    char			*line;
    u_int			line_len;
    unsigned char		md_value[ EVP_MAX_MD_SIZE ];
    char			md_b64[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 ];
    const EVP_MD		*simta_checksum_md;

    if ( argc != 2 ) {
	fprintf( stderr, "Usage: %s checksum_algorithm\n", argv[ 0 ]);
	return( 1 );
    }

    OpenSSL_add_all_digests();
    simta_checksum_md = EVP_get_digestbyname((const char*)(argv[ 1 ]));

    if ( simta_checksum_md == NULL ) {
	fprintf( stderr, "%s: unknown checksum algorithm\n", argv[ 1 ]);
	return( 1 );
    }

    EVP_MD_CTX_init( &mdctx );
    EVP_DigestInit_ex( &mdctx, simta_checksum_md, NULL);

    if (( snet = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	line_len = strlen( line );
	EVP_DigestUpdate( &mdctx, line, line_len );
    }

    EVP_DigestFinal_ex( &mdctx, md_value, &md_len );
    EVP_MD_CTX_cleanup( &mdctx );

    memset( md_b64, 0, SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 );
    base64_e( md_value, md_len, md_b64 );

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	return( 1 );
    }

    printf( "\nChecksum: %s\n", md_b64 );

    printf( "Digest: " );
    for ( i = 0; i < md_len; i++ ) {
	printf( "%02x", md_value[i] );
    }
    printf( "\n" );

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
