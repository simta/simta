struct dnsr_result * get_a( char *hostname );
struct dnsr_result * get_mx( char *hostname );
int check_reverse( char *dn, struct in_addr *in );
int check_hostname( char *hostname );
struct dnsr_result * get_dnsr_result( char *hostname );
int add_host( char *hostname, int type );
