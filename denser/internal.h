#ifdef __APPLE__
#define socklen_t int
#endif

/* Message opcode ( rfc 1035 4.1.1 ) */
#define DNSR_OP_QUERY	0	/* Standard query */
#define DNSR_OP_IQUERY	1	/* Inverse query */
#define DNSR_OP_STATUS	2	/* Server status request */

/* Responce code ( rfc 1035 4.1.1 ) */
#define DNSR_RC_OK		0	/* No error condition */
#define DNSR_RC_FORMATERR	1	/* Format error */
#define DNSR_RC_SVRERR		2	/* Server failure */
#define DNSR_RC_NAMEERR		3	/* Name error */
#define DNSR_RC_NOTIMP		4	/* Not implemented */
#define DNSR_RC_REFUSED		5	/* Operation refused */

#define DNSR_DEFAULT_PORT	53

/* DNSR bit masks */
#define DNSR_RESPONSE			0x8000
#define DNSR_RECURSION_DESIRED		0x0100
#define DNSR_TRUNCATION			0x0200
#define DNSR_RECURSION_AVAILBLE		0x0080
#define DNSR_RCODE			0x000f
#define DNSR_AUTHORITATIVE_ANSWER	0x0400
#define DNSR_OPCODE			0x7800
#define DNSR_Z				0x0070
#define DNSR_OFFSET			0xc000

#ifdef sun
#define MIN(a,b)        ((a)<(b)?(a):(b))
#define MAX(a,b)        ((a)>(b)?(a):(b))
#endif /* sun */

#ifdef EBUG
#define DEBUG( x )      x
#else
#define DEBUG( x )
#endif

struct dnsr_header {  
    uint16_t   h_id;  
    uint16_t   h_flags;
    uint16_t   h_qdcount;
    uint16_t   h_ancount;
    uint16_t   h_nscount;
    uint16_t   h_arcount;
};

int _dnsr_display_header( struct dnsr_header *h );
char * _dnsr_send_query_tcp( DNSR *dnsr, int *resplen );
int _dnsr_validate_resp( DNSR *dnsr, char *resp, struct sockaddr_in *reply_from );
struct dnsr_result * _dnsr_create_result( DNSR *dnsr, char *resp, int resplen );
int _dnsr_labels_to_name( DNSR *dnsr, char *resp_begin, char **resp_cur, unsigned int resplen, char *dn_begin, char **dn_cur, char *dn_end );
int _dnsr_labels_to_string( DNSR *dnsr, char **resp_cur, char *resp_end, char *string_begin );
int _dnsr_parse_rr( DNSR *dnsr, struct dnsr_rr *rr, char *resp_begin,
    char **resp_cur, int resplen );
int _dnsr_match_additional( DNSR *dnsr, struct dnsr_result *result );
int _dnsr_match_ip( DNSR *dnsr, struct dnsr_rr *ar_rr, struct dnsr_rr *rr );
