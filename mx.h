struct dnsr_result * get_a( DNSR *dnsr, char *host );
struct dnsr_result * get_mx( DNSR *dnsr, char *host );
int check_reverse( DNSR **dnsr, char *dn, struct in_addr *in );
int check_hostname( DNSR **dnsr, char *hostname );
int add_host( char *hostname, int type );
