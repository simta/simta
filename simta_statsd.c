/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <yasl.h>

#include "simta.h"

#include "simta_statsd.h"


simta_result
simta_statsd_init(struct simta_statsd **s) {
    const char *     host;
    const char *     port;
    struct addrinfo  hints;
    struct addrinfo *ai = NULL;
    int              rc;
    int              fd;
    bool             retval = false;

    host = simta_config_str("core.statsd.server");
    port = simta_config_str("core.statsd.port");

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;
    if ((rc = getaddrinfo(host, port, &hints, &ai)) != 0) {
        syslog(LOG_ERR, "Syserror: simta_statsd_init getaddrinfo: %s",
                gai_strerror(rc));
        return (false);
    }

    if ((fd = socket(ai->ai_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) ==
            -1) {
        syslog(LOG_ERR, "Syserror: simta_statsd_init socket: %s",
                strerror(errno));
        goto error;
    }

    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        syslog(LOG_ERR, "Syserror: simta_statsd_init connect: %s",
                strerror(errno));
        goto error;
    }

    *s = calloc(1, sizeof(struct simta_statsd));
    (*s)->fd = fd;
    retval = true;

error:
    freeaddrinfo(ai);
    return (retval);
}

void
simta_statsd_free(struct simta_statsd *s) {
    if (s) {
        close(s->fd);
        free(s);
    }
}

simta_result
simta_statsd_send(
        const char *ns, const char *name, const char *type, yastr value) {
    yastr        buf = NULL;
    int          rc;
    simta_result retval = SIMTA_ERR;

    if (!simta_config_bool("core.statsd.enabled")) {
        goto error;
    }

    if (simta_statsd_handle == NULL) {
        if (!simta_statsd_init(&simta_statsd_handle)) {
            goto error;
        }
    }

    /* Format as statname:value|type */
    buf = yaslauto(simta_config_str("core.statsd.prefix"));
    buf = yaslcatlen(buf, ".", 1);
    buf = yaslcat(buf, ns);
    buf = yaslcatlen(buf, ".", 1);
    buf = yaslcat(buf, name);
    buf = yaslcatlen(buf, ":", 1);
    buf = yaslcatyasl(buf, value);
    buf = yaslcatlen(buf, "|", 1);
    buf = yaslcat(buf, type);

    rc = send(simta_statsd_handle->fd, buf, yasllen(buf), 0);
    yaslfree(buf);
    if (rc == -1) {
        syslog(LOG_ERR, "Syserror simta_statsd_send send: %s", strerror(errno));
    } else {
        retval = SIMTA_OK;
    }

error:
    yaslfree(buf);
    yaslfree(value);
    return (retval);
}

/* Counters accumulate until they are flushed */
simta_result
statsd_counter(const char *ns, const char *name, size_t value) {
    return (simta_statsd_send(ns, name, "c", yaslfromlonglong(value)));
}

/* Timers measure how long something took */
simta_result
statsd_timer(const char *ns, const char *name, size_t value) {
    return (simta_statsd_send(ns, name, "ms", yaslfromlonglong(value)));
}

/* Gauges are a single persistent value */
simta_result
statsd_gauge(const char *ns, const char *name, size_t value) {
    return (simta_statsd_send(ns, name, "g", yaslfromlonglong(value)));
}

/* Sets keep track of the number of unique values seen */
simta_result
statsd_setitem(const char *ns, const char *name, const char *value) {
    return (simta_statsd_send(ns, name, "s", yaslauto(value)));
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
