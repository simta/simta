SSL_CTX *tls_server_setup( int, int, char *, char *, char *, char *, char * );
SSL_CTX *tls_client_setup( int, int, char *, char *, char *, char *, char * );
int tls_client_cert( char *, const SSL * );
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
