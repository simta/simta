#define MDCTX_UNINITIALIZED     0
#define MDCTX_READY             1
#define MDCTX_IN_USE            2
#define MDCTX_FINAL             3

#define MD_BYTE_LEN             10

#ifdef HAVE_LIBSSL
struct message_digest {
    unsigned char   md_value[ EVP_MAX_MD_SIZE ];
    char            md_b64[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 ];
    EVP_MD_CTX      md_ctx;
    int             md_ctx_status;
    unsigned int    md_ctx_bytes;
    unsigned int    md_len;
    char            md_bytes[ MD_BYTE_LEN + 1 ];
};
#endif /* HAVE_LIBSSL */

void md_init( struct message_digest * );
void md_reset( struct message_digest * );
void md_update( struct message_digest *, const void *, size_t );
void md_finalize( struct message_digest * );
void md_cleanup( struct message_digest * );
