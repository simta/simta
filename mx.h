struct dnsr_result * get_a( char * );
struct dnsr_result * get_mx( char * );
int check_reverse( char *, struct in_addr * );
int check_hostname( char * );
struct simta_red *host_local( char * );
int check_rbl( struct in_addr *, char *domain );
