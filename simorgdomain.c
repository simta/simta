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

const char *simta_progname = "simorgdomain";

int
main(int argc, char *argv[]) {
    int           c;
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
    if (error || (optind + 1 != argc)) {
        fprintf(stderr,
                "Usage: %s [ -v ] [ -f conf_file ] [ -U extra_conf ] "
                "domain\n",
                argv[ 0 ]);
        exit(1);
    }

    simta_openlog(false, LOG_PERROR);

    if (simta_read_config(conf_file, extra_conf) != SIMTA_OK) {
        exit(1);
    }

    simta_openlog(false, verbose ? LOG_PERROR : 0);

    printf("%s\n", dmarc_orgdomain(argv[ optind ]));

    exit(0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
