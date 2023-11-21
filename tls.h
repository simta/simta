#ifndef SIMTA_TLS_H
#define SIMTA_TLS_H

#include <openssl/ssl.h>

SSL_CTX *tls_server_setup(void);
SSL_CTX *tls_client_setup(const char *);
int      tls_client_cert(const char *, const SSL *);

#endif /* SIMTA_TLS_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
