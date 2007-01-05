#define	RBL_ERROR		0
#define	RBL_BLOCK		1
#define	RBL_ACCEPT		2

struct rbl {
    struct rbl			*rbl_next;
    int				rbl_type;
    char			*rbl_domain;
    char			*rbl_url;
};

struct dnsr_result * get_a( char * );
struct dnsr_result * get_mx( char * );
int check_reverse( char *, struct in_addr * );
int check_hostname( char * );
struct simta_red *host_local( char * );
int rbl_add( struct rbl**, int, char *, char * );
int rbl_check( struct rbl *, struct in_addr *, struct rbl** );
