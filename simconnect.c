/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdbool.h>
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

int
main(int argc, char *argv[]) {
    int            s, r;
    int            c;
    const char    *conf_file = NULL;
    const char    *extra_conf = NULL;
    char          *hostname;
    struct host_q *hq;
    struct deliver d;
    bool           test_connect = true;
    bool           error = false;

    while ((c = getopt(argc, argv, "f:lU:")) != EOF) {
        switch (c) {
        case 'f':
            conf_file = optarg;
            break;
        case 'l':
            test_connect = false;
            break;
        case 'U':
            extra_conf = optarg;
            break;
        default:
            error = true;
            break;
        }
    }

    if (error || (optind == argc)) {
        fprintf(stderr,
                "Usage:\t\t%s [ -f conf_file ] [ -U extra_conf ] "
                "[ -l ] hostname\n",
                argv[ 0 ]);
        exit(1);
    }

    if (simta_read_config(conf_file, extra_conf) != SIMTA_OK) {
        exit(1);
    }

    simta_openlog(false, LOG_PERROR);

    hostname = argv[ optind ];

    hq = host_q_create_or_lookup(hostname);
    memset(&d, 0, sizeof(struct deliver));

    /* Dummy up some values so we don't crash */
    hq->hq_status = SIMTA_HOST_DOWN;
    d.d_env = env_create(NULL, hostname, "simta@umich.edu", NULL);

    for (;;) {
        if (next_dnsr_host_lookup(&d, hq) != SIMTA_OK) {
            exit(0);
        }

        if (!test_connect) {
            continue;
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
