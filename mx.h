struct dnsr_result * get_a( char * );
struct dnsr_result * get_mx( char * );
int check_reverse( char *, struct in_addr * );
int check_hostname( char * );
struct dnsr_result * get_dnsr_result( char * );
struct host * add_host( char *, int );
struct host * host_local( char * );
