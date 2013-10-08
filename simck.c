/* Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

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
#include "md.h"

extern const EVP_MD *simta_checksum_md;
const EVP_MD        *simta_checksum_md = NULL;

    int
main( int argc, char *argv[])
{
    int				i;
    SNET			*snet;
    char			*line;
    u_int			line_len;
    struct message_digest       md;

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

    md_init( &md );
    md_reset( &md );

    if (( snet = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	line_len = strlen( line );
        md_update( &md, line, line_len );
    }

    md_finalize( &md );
    md_cleanup( &md );

    if ( snet_close( snet ) != 0 ) {
	perror( "snet_close" );
	return( 1 );
    }

    printf( "\nChecksum: %s\n", md.md_b64 );

    printf( "Digest: " );
    for ( i = 0; i < md.md_len; i++ ) {
	printf( "%02x", md.md_value[i] );
    }
    printf( "\n" );

    return( 0 );
}
