struct dnsr_result * get_a( char * );
struct dnsr_result * get_mx( char * );
int check_reverse( char *, struct in_addr * );
int check_hostname( char * );
struct host * add_host( char *, int );
int add_expansion( struct host *, int );
struct host * host_local( char * );
int check_rbl( struct in_addr *, char *domain );
