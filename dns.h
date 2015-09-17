#ifndef SIMTA_DNS_H
#define SIMTA_DNS_H

#include <netinet/in.h>

#define	RBL_UNKNOWN		0
#define	RBL_ERROR		1
#define	RBL_NOT_FOUND		2
#define	RBL_BLOCK		3
#define	RBL_ACCEPT		4
#define	RBL_LOG_ONLY		5
#define	RBL_TRUST		6

#define	S_MISMATCH	"Mismatch"
#define	S_ACCEPT	"Accept"
#define	S_BLOCK		"Block"
#define	S_LOG_ONLY	"Log_Only"
#define	S_TRUST		"Trust"

#define	REVERSE_MATCH		0
#define REVERSE_ERROR		1
#define REVERSE_UNKNOWN		2
#define REVERSE_MISMATCH	3
#define REVERSE_UNRESOLVED	4


struct rbl {
    struct rbl			*rbl_next;
    int				rbl_type;
    char			*rbl_type_text;
    char			*rbl_domain;
    char			*rbl_url;
};

struct dnsr_result *get_a( const char * );
struct dnsr_result *get_aaaa( const char * );
struct dnsr_result *get_mx( const char * );
struct dnsr_result *get_ptr( const struct sockaddr * );
struct dnsr_result *get_txt( const char * );
int check_reverse( char *, const struct sockaddr * );
int check_hostname( const char * );
struct simta_red *host_local( char * );
int rbl_add( struct rbl**, int, char *, char * );
int rbl_check( struct rbl *, const struct sockaddr *, char *, char *,
	struct rbl**, char ** );

#endif /* SIMTA_DNS_H */
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
