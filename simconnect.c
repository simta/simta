/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "envelope.h"
#include "queue.h"
#include "red.h"
#include "smtp.h"

const char *simta_progname = "simconnect";

int next_dnsr_host_lookup(struct deliver *, struct host_q *);

int
main(int ac, char *av[]) {
    int            s, r;
    char *         hostname;
    struct host_q *hq;
    struct deliver d;

    if (ac != 2) {
        fprintf(stderr, "Usage:\t\t%s hostname\n", av[ 0 ]);
        exit(1);
    }

    if (simta_read_config(SIMTA_FILE_CONFIG) < 0) {
        exit(1);
    }

    simta_openlog(0, LOG_PERROR);

    hostname = av[ 1 ];

    hq = host_q_create_or_lookup(hostname);
    memset(&d, 0, sizeof(struct deliver));

    /* Dummy up some values so we don't crash */
    hq->hq_status = HOST_DOWN;
    d.d_env = env_create(NULL, hostname, "simta@umich.edu", NULL);

    for (;;) {
        if (next_dnsr_host_lookup(&d, hq) != 0) {
            exit(0);
        }

    retry:
        if ((s = socket(d.d_sa.ss_family, SOCK_STREAM, 0)) < 0) {
            syslog(LOG_ERR, "[%s] %s: socket: %m", d.d_ip, hq->hq_hostname);
        }

        if (connect(s, (struct sockaddr *)&(d.d_sa),
                    ((d.d_sa.ss_family == AF_INET6)
                                    ? sizeof(struct sockaddr_in6)
                                    : sizeof(struct sockaddr_in))) < 0) {
            syslog(LOG_ERR, "[%s] %s: connect: %m", d.d_ip, hq->hq_hostname);
            close(s);
            continue;
        }

        syslog(LOG_INFO, "[%s] %s: connect: Success", d.d_ip, hq->hq_hostname);

        if ((d.d_snet_smtp = snet_attach(s, 1024 * 1024)) == NULL) {
            syslog(LOG_ERR, "[%s] %s: snet_attach: %m", d.d_ip,
                    hq->hq_hostname);
            close(s);
            continue;
        }

        r = smtp_connect(hq, &d);
        if (r == SMTP_BAD_TLS) {
            snet_close(d.d_snet_smtp);
            syslog(LOG_INFO, "[%s] %s: disabling TLS", d.d_ip, hq->hq_hostname);
            simta_ucl_toggle(hq->hq_red, "deliver.tls", "enabled", false);
            goto retry;
        }

        if (r == SMTP_OK || r == SMTP_ERROR) {
            smtp_quit(hq, &d);
        }

        snet_close(d.d_snet_smtp);
    }
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
