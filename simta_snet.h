/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#ifndef SIMTA_SIMTA_SNET_H
#define SIMTA_SIMTA_SNET_H

#include <sys/time.h>
#include <sys/types.h>

#include <yasl.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

typedef struct {
#ifdef HAVE_LIBSSL
    void *sn_ssl;
#endif /* HAVE_LIBSSL */
    char          *sn_rbuf;
    char          *sn_rcur;
    yastr          sn_wbuf;
    size_t         sn_buflen;
    size_t         sn_maxlen;
    struct timeval sn_read_timeout;
    struct timeval sn_write_timeout;
    struct timeval sn_ssl_connect_timeout;
    struct timeval sn_ssl_accept_timeout;
    int            sn_fd;
    int            sn_rstate;
    int            sn_flag;
} SNET;

#define SNET_EOF (1 << 0)
#define SNET_TLS (1 << 1)
#define SNET_WRITE_TIMEOUT (1 << 2)
#define SNET_READ_TIMEOUT (1 << 3)
#define SNET_SSL_CONNECT_TIMEOUT (1 << 4)
#define SNET_SSL_ACCEPT_TIMEOUT (1 << 5)

#define snet_fd(sn) ((sn)->sn_fd)
#define snet_flags(sn) ((sn)->sn_flag)

int     snet_eof(SNET *);
SNET   *snet_attach(int);
SNET   *snet_open(const char *, int, int);
int     snet_close(SNET *);
ssize_t snet_writef(SNET *, const char *, ...);
char   *snet_getline(SNET *, struct timeval *);
yastr   snet_getline_safe(SNET *, struct timeval *);
void    snet_timeout(SNET *, int, struct timeval *);
bool    snet_hasdata(SNET *);
void    snet_flush(SNET *);
ssize_t snet_read(SNET *, char *, size_t, struct timeval *);
ssize_t snet_write(SNET *, char *, size_t);
int     snet_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#ifdef HAVE_LIBSSL
int snet_starttls(SNET *, SSL_CTX *, int);
int snet_starttls_tv(SNET *, SSL_CTX *, int, struct timeval *);
#endif /* HAVE_LIBSSL */

#endif /* SIMTA_SIMTA_SNET_H */
