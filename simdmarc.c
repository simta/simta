/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <syslog.h>

#include "dmarc.h"
#include "simta.h"

const char *simta_progname = "simdmarc";

int
main(int ac, char *av[]) {
    yastr         test_str;
    struct dmarc *d;

    if ((ac < 2) || (ac > 4)) {
        fprintf(stderr,
                "Usage:\t\t%s 5322.From domain [ SPF domain ] [ DKIM domain "
                "]\n",
                av[ 0 ]);
        exit(1);
    }

    if (simta_read_config(SIMTA_FILE_CONFIG) < 0) {
        exit(1);
    }

    simta_openlog(0, LOG_PERROR);

    dmarc_init(&d);

    dmarc_lookup(d, av[ 1 ]);

    printf("DMARC lookup result: policy %s, percent %d, result %s\n",
            dmarc_result_str(d->policy), d->pct, dmarc_result_str(d->result));

    test_str = yaslauto(d->domain);

    if (ac > 2) {
        dmarc_spf_result(d, av[ 2 ]);
        test_str = yaslcat(test_str, "/");
        test_str = yaslcat(test_str, av[ 2 ]);
    }
    if (ac > 3) {
        dmarc_dkim_result(d, av[ 3 ]);
        test_str = yaslcat(test_str, "/");
        test_str = yaslcat(test_str, av[ 3 ]);
    }

    printf("DMARC policy result for %s: %s\n", test_str,
            dmarc_result_str(dmarc_result(d)));

    exit(0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
