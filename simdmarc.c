/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#include "dmarc.h"
#include "simta.h"

const char *simta_progname = "simdmarc";

int
main(int argc, char *argv[]) {
    int           c;
    yastr         test_str;
    struct dmarc *d;
    const char   *conf_file = NULL;
    const char   *extra_conf = NULL;
    bool          verbose = false;
    int           error = 0;

    while ((c = getopt(argc, argv, "f:U:v")) != EOF) {
        switch (c) {
        case 'f':
            conf_file = optarg;
            break;

        case 'U':
            extra_conf = optarg;
            break;

        case 'v':
            verbose = true;
            break;

        default:
            error++;
            break;
        }
    }
    if (error || (optind == argc)) {
        fprintf(stderr,
                "Usage: %s [ -v ] [ -f conf_file ] [ -U extra_conf ] "
                "RFC5322.From domain [ SPF domain ] [ DKIM domain ]\n",
                argv[ 0 ]);
        exit(1);
    }

    simta_openlog(false, LOG_PERROR);

    if (simta_read_config(conf_file, extra_conf) != SIMTA_OK) {
        exit(1);
    }

    simta_openlog(false, verbose ? LOG_PERROR : 0);

    dmarc_init(&d);

    dmarc_lookup(d, argv[ optind++ ]);

    printf("DMARC lookup result: policy %s, percent %d, result %s\n",
            dmarc_result_str(d->policy), d->pct, dmarc_result_str(d->result));

    test_str = yaslauto(d->domain);

    if (optind < argc) {
        dmarc_spf_result(d, argv[ optind ]);
        test_str = yaslcat(test_str, "/");
        test_str = yaslcat(test_str, argv[ optind++ ]);
    }
    if (optind < argc) {
        dmarc_dkim_result(d, argv[ optind ]);
        test_str = yaslcat(test_str, "/");
        test_str = yaslcat(test_str, argv[ optind++ ]);
    }

    printf("DMARC policy result for %s: %s\n", test_str,
            dmarc_result_str(dmarc_result(d)));

    exit(0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
