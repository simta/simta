/* Size limits ( rfc 1035 2.3.4 ) */
#define DNSR_MAX_FIELD	2        /* Field width in bytes */
#define DNSR_MAX_LABEL	63  
#define DNSR_MAX_LINE	1024
#define DNSR_MAX_HOSTNAME 253	/* Max conventional ASCII representation */
#define DNSR_MAX_NAME	255  
#define DNSR_MAX_STRING	256     /* rfc 1034 3.3 */
#define DNSR_MAX_UDP	512    
#define DNSR_MAX_NS	4	/* Max number of name servers */
#define DNSR_MAX_RDATA	(uint16_t)65535
#define DNSR_MAX_ERRNO	31	/* Highest valid error number */
#define DNSR_MAX_TYPE	255	/* Highest valid type */
#define DNSR_MAX_CLASS	4	/* Highest valid class */

/* RR types ( rfc 1035 3.2.2 ) */
#define DNSR_TYPE_A	1	/* Host address */
#define DNSR_TYPE_NS 	2	/* Authoritative name server */
#define DNSR_TYPE_MD 	3	/* Mail destination */
#define DNSR_TYPE_MF 	4	/* Mail forwarder */
#define DNSR_TYPE_CNAME	5	/* Canonical name for an alias */
#define DNSR_TYPE_SOA	6	/* Start of a zone of authority */
#define DNSR_TYPE_MB	7	/* Mailbox domain */
#define DNSR_TYPE_MG	8	/* Mail group member */
#define DNSR_TYPE_MR	9	/* Mail rename domain name */
#define DNSR_TYPE_NULL	10	/* Null RR */
#define DNSR_TYPE_WKS	11	/* Well known service description */
#define DNSR_TYPE_PTR	12	/* Domain name pointer */
#define DNSR_TYPE_HINFO	13	/* Host information */
#define DNSR_TYPE_MINFO	14	/* Mailbox or mail list information */
#define DNSR_TYPE_MX	15	/* Mail exchange */
#define DNSR_TYPE_TXT	16	/* Text string */
#define DNSR_TYPE_AAAA	28	/* IPv6 AAAA type */
#define DNSR_TYPE_SRV	33	/* Service Record RFC 2728 */
#define DNSR_TYPE_ALL	255	/* All records */

/* RR query types ( rfc 1035 3.2.3 ) */
#define DNSR_TYPE_AXFR 252	/* Request transfer of an entire zone */
//#define DNSR_TYPE_MAILB 253	/* Request mail-box related records */
//#define DNSR_TYPE_MAILA 254	/* Request for mail agent records */
//#define DNSR_TYPE_ALL 255	/* Request all records */

/* RR class values ( rfc 1035 3.2.4 ) */
#define DNSR_CLASS_IN 	1		/* Internet */
#define DNSR_CLASS_CS 	2		/* CSNET */
#define DNSR_CLASS_CH 	3		/* CHAOS */
#define DNSR_CLASS_HS 	4		/* HESIOD */

/* RR qclass values ( rfc 1035 3.2.5 ) */
#define DNSR_CLASS_ALL 255	/* Any class */

/* DNSR flags */
#define DNSR_FLAG_ON			0	/* Turn flag on */
#define DNSR_FLAG_OFF			1	/* Turn flag off */
#define DNSR_FLAG_RECURSION		2	/* Recursion */

/* DNSR error codes */
#define DNSR_ERROR_NONE			0	/* No error condition */
#define DNSR_ERROR_FORMAT		1	/* Format error */
#define DNSR_ERROR_SERVER		2	/* Server failure */
#define DNSR_ERROR_NAME			3	/* Name error - Meaningful only
						 * for responses from an
						 * authoritative name server,
						 * name does not exist */
#define DNSR_ERROR_NOT_IMPLEMENTED	4	/* Not implemented */
#define DNSR_ERROR_REFUSED		5	/* Operation refused */
						/* 6 and 7 reserverd for future
					 	 * RC values */

#define DNSR_ERROR_CONFIG		8	/* Config file error */
#define DNSR_ERROR_NO_QUERY		9	/* dnsr_rr called without
						 * query being sent */
#define DNSR_ERROR_TIMEOUT		10	/* Timeout */
#define DNSR_ERROR_ID_WRONG		11	/* rr ID does not match
						 * query ID */
#define DNSR_ERROR_NOT_RESPONSE		12	/* NS did not return a resp */
#define DNSR_ERROR_NO_RECURSION		13	/* NS does not offer
						 * recursion */
#define DNSR_ERROR_QUESTION_WRONG	14	/* rr question does not
						 * match query question */
#define DNSR_ERROR_NO_ANSWER		15	/* No answer in rr */
#define DNSR_ERROR_TRUNCATION		16	/* Response truncated */
#define DNSR_ERROR_SYSTEM		17	/* System error. See errono. */
#define DNSR_ERROR_SIZELIMIT_EXCEEDED	18	/* Size limit exceeded */
#define DNSR_ERROR_NS_INVALID		19	/* Invalid NS */
#define DNSR_ERROR_NS_DEAD		20	/* NS dead */
#define DNSR_ERROR_TV			21	/* Time Vale negative */
#define DNSR_ERROR_FD_SET		22	/* Wrong FD selected */
#define DNSR_ERROR_PARSE		23	/* Parse error */
#define DNSR_ERROR_STATE		24	/* Unknown state */
#define DNSR_ERROR_TYPE			25	/* Unknown type */
#define DNSR_ERROR_RCODE		26	/* Unknown rcode */
#define DNSR_ERROR_TOGGLE		27	/* Unknown toggle */
#define DNSR_ERROR_FLAG			28	/* Unknown flag */
#define DNSR_ERROR_CLASS		29	/* Unknown class */
#define DNSR_ERROR_Z			30	/* Z code not zero */
#define DNSR_ERROR_CONNECTION_CLOSED	31	/* Z code not zero */
#define DNSR_ERROR_UNKNOWN		32	/* Unknown error */

struct dnsr_result {
    unsigned int 		r_ancount;
    struct dnsr_rr 		*r_answer;
    unsigned int		r_nscount;
    struct dnsr_rr		*r_ns;
    unsigned int		r_arcount;
    struct dnsr_rr 		*r_additional;
};

struct nsinfo {
    uint16_t		ns_id;
    int                 ns_asked;
    struct sockaddr_in	ns_sa;
};

typedef struct {
    uint16_t		d_id;
    uint16_t		d_flags;
    char		d_dn[ DNSR_MAX_NAME + 1 ];
    char		d_query[ DNSR_MAX_UDP ];
    int			d_querylen;
    int			d_querysent;
    int			d_state;
    int			d_errno;
    struct nsinfo	d_nsinfo[ DNSR_MAX_NS ];
    int			d_nscount;
    int			d_nsresp;
    int			d_fd;
    struct timeval 	d_querytime;
} DNSR;

/* 
 * 3.3. Standard RRs
 * 
 * The following RR definitions are expected to occur, at least
 * potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
 * will be used in all classes, and have the same format in all classes.
 * Because their RDATA format is known, all domain names in the RDATA
 * section of these RRs may be compressed.
 * 
 * <domain-name> is a domain name represented as a series of labels, and
 * terminated by a label with zero length.  <character-string> is a single
 * length octet followed by that number of characters.  <character-string>
 * is treated as binary information, and can be up to 256 characters in
 * length (including the length octet).
 */ 

/* Generic RR Domain */
struct rr_dn {
    char	dn_name[ DNSR_MAX_NAME + 1];
};

/* 3.3.1. CNAME RDATA format */
struct rr_cname {
    char	cn_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.2. HINFO RDATA format */
struct rr_hinfo {
    char	hi_cpu[ DNSR_MAX_STRING + 1 ];
    char	hi_os[ DNSR_MAX_STRING + 1 ];
};

/* 3.3.3. MB RDATA format */
struct rr_mb {
    char	mb_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.4. MD RDATA format */
struct rr_md {
    char	md_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.5. MF RDATA format */
struct rr_mf {
    char	mf_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.6. MG RDATA format */
struct rr_mg {
    char	mg_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.7. MINFO RDATA format */
struct rr_minfo {
    char	mi_rmailbx[ DNSR_MAX_NAME + 1 ];
    char	mi_emailbx[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.8. MR RDATA format */
struct rr_mr {
    char	mr_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.9. MX RDATA format */
struct rr_mx {
    uint16_t	mx_preference;
    char	mx_exchange[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.10. NULL RDATA format */
struct rr_null {
    char	null_name[ DNSR_MAX_RDATA ];
};

/* 3.3.11. NS RDATA format */
struct rr_ns {
    char	ns_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.12. PTR RDATA format */
struct rr_ptr {
    char	ptr_name[ DNSR_MAX_NAME + 1 ];
};

/* 3.3.13 SOA RDATA format */
struct rr_soa {
    char	soa_mname[ DNSR_MAX_NAME + 1 ];
    char	soa_rname[ DNSR_MAX_NAME + 1 ];
    int		soa_serial;
    int32_t	soa_refresh;
    int32_t	soa_retry;
    int32_t	soa_expire;
    int32_t	soa_minimum;
};

/* 3.3.14. TXT RDATA format */
struct rr_txt {
    char	t_txt[ DNSR_MAX_STRING + 1 ];
};

/* 
 * 3.4. Internet specific RRs
 */

/* 3.4.1. A RDATA format */
struct rr_a {
    int		a_address;
};

/* RFC 2782 SRV record */
struct rr_srv {
    uint16_t	srv_priority;
    uint16_t	srv_weight;
    uint16_t	srv_port;
    char	srv_target[ DNSR_MAX_NAME + 1 ];
};

struct ip_info {
    struct in_addr	ip_ip;
    struct ip_info	*ip_next;
};

struct dnsr_rr {
    char			rr_name[ DNSR_MAX_NAME + 1 ];  /* domain name */
    struct ip_info		*rr_ip;		/* related IP */
    uint16_t			rr_type;	/* RR type */
    uint16_t			rr_class;	/* RR class */
    uint32_t			rr_ttl;		/* RR ttl */
    uint16_t			rr_rdlength;	/* length of RDATA field */
    union {
	struct rr_dn	rd_dn;
#define rr_dn rr_u.rd_dn
	struct rr_cname	rd_cname;
#define rr_cname rr_u.rd_cname
	struct rr_hinfo	rd_hinfo;
#define rr_hinfo rr_u.rd_hinfo
	struct rr_mb	rd_mb;
#define rr_mb rr_u.rd_mb
	struct rr_md	rd_md;
#define rr_md rr_u.rd_md
	struct rr_mf	rd_mf;
#define rr_mf rr_u.rd_mf
	struct rr_mg	rd_mg;
#define rr_mg rr_u.rd_mg
	struct rr_minfo	rd_minfo;
#define rr_minfo rr_u.rd_minfo
	struct rr_mr	rd_mr;
#define rr_mr rr_u.rd_mr
	struct rr_mx	rd_mx;
#define rr_mx rr_u.rd_mx
	struct rr_null	rd_null;
#define rr_null rr_u.rd_null
	struct rr_ns	rd_ns;
#define rr_ns rr_u.rd_ns
	struct rr_ptr	rd_ptr;
#define rr_ptr rr_u.rd_ptr
	struct rr_soa	rd_soa;
#define rr_soa rr_u.rd_soa
	struct rr_txt	rd_txt;
#define rr_txt rr_u.rd_txt
	struct rr_a	rd_a;
#define rr_a rr_u.rd_a
	struct rr_srv	rd_srv;
#define rr_srv rr_u.rd_srv
    } rr_u; 
};

DNSR * dnsr_new( void );
int dnsr_nameserver( DNSR *dnsr, char *server );
int dnsr_config( DNSR *dnsr, int flag, int toggle );
int dnsr_query( DNSR *dnsr, uint16_t qtype, uint16_t qclass, char *dn );
struct dnsr_result* dnsr_result( DNSR *dnsr, struct timeval *timeout );
int dnsr_result_expired( DNSR *dnsr, struct dnsr_result *result );

char * dnsr_ntoptr( DNSR *, const void *src, char * );
char * dnsr_reverse_ip( DNSR *, char *, char * );

int dnsr_errno( DNSR *dnser );
void dnsr_errclear( DNSR *dnser );
char * dnsr_err2string( int dnsr_errno );
void dnsr_perror( DNSR *dnsr, const char *s );

int dnsr_free( DNSR *dnsr );
void dnsr_free_result( struct dnsr_result *result );

int _dnsr_send_query( DNSR *dnsr, int ns );
