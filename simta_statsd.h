#ifndef SIMTA_STATSD_H
#define SIMTA_STATSD_H

#include <netinet/in.h>
#include <stddef.h>

#include "simta.h"


struct simta_statsd {
    struct sockaddr_in server;
    int                fd;
};

extern struct simta_statsd *simta_statsd_handle;

simta_result simta_statsd_init(struct simta_statsd **);
void         simta_statsd_free(struct simta_statsd *);
simta_result simta_statsd_send(const char *, const char *, const char *, yastr);
simta_result statsd_counter(const char *, const char *, size_t);
simta_result statsd_timer(const char *, const char *, size_t);
simta_result statsd_gauge(const char *, const char *, size_t);
simta_result statsd_setitem(const char *, const char *, const char *);

#endif /* SIMTA_STATSD_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
