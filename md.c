/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include "md.h"
#include "simta.h"

    void
md_init( struct message_digest *md )
{
    md->md_ctx_status = MDCTX_UNINITIALIZED;
}

    void
md_reset( struct message_digest *md )
{
    if ( md->md_ctx_status != MDCTX_READY ) {
	if ( md->md_ctx_status == MDCTX_UNINITIALIZED ) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	    md->md_ctx = EVP_MD_CTX_new( );
#else
	    md->md_ctx = EVP_MD_CTX_create( );
#endif /* OpenSSL 1.1.0 */
	} else if ( md->md_ctx_status == MDCTX_IN_USE ) {
	    EVP_DigestFinal_ex( md->md_ctx, md->md_value, &md->md_len );
	}

	EVP_DigestInit_ex( md->md_ctx, simta_checksum_md, NULL );
	md->md_ctx_status = MDCTX_READY;
	md->md_ctx_bytes = 0;
    }
}

    void
md_update( struct message_digest *md, const void *d, size_t cnt )
{
    EVP_DigestUpdate( md->md_ctx, d, cnt);
    md->md_ctx_bytes += cnt;
    md->md_ctx_status = MDCTX_IN_USE;
}

    void
md_finalize( struct message_digest *md )
{
    int		i;
    EVP_DigestFinal_ex( md->md_ctx, md->md_value, &md->md_len );
    memset( md->md_b16, 0, ( EVP_MAX_MD_SIZE * 2 ) + 1 );
    for ( i = 0 ; i < md->md_len ; i++ ) {
	sprintf( &md->md_b16[ i * 2 ], "%02x", md->md_value[ i ] );
    }
    snprintf( md->md_bytes, MD_BYTE_LEN, "%d", md->md_ctx_bytes );
    md->md_ctx_status = MDCTX_FINAL;
}

    void
md_cleanup( struct message_digest *md )
{
    if ( md->md_ctx_status != MDCTX_UNINITIALIZED ) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	EVP_MD_CTX_free( md->md_ctx );
#else
	EVP_MD_CTX_destroy( md->md_ctx );
#endif /* OpenSSL 1.1.0 */
	md->md_ctx = NULL;
	md->md_ctx_status = MDCTX_UNINITIALIZED;
    }
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
