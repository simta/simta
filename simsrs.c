/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include "simta.h"
#include "srs.h"

const char *simta_progname = "simsrs";

int
main(int argc, char *argv[]) {
    struct envelope *env;
    char *           p;
    int              c;
    const char *     conf_file = NULL;
    const char *     extra_conf = NULL;
    bool             verbose = false;

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
        }
    }

    if (argc - optind != 1) {
        fprintf(stderr,
                "Usage: %s [ -f conf_file ] [ -U extra_conf ] [ -v ] address\n",
                argv[ 0 ]);
        exit(1);
    }

    simta_openlog(0, LOG_PERROR);

    if (simta_read_config(conf_file, extra_conf) < 0) {
        exit(1);
    }

    simta_openlog(0, verbose ? LOG_PERROR : 0);

    if ((p = strrchr(argv[ optind ], '@')) == NULL) {
        fprintf(stderr, "Bad address\n");
        exit(1);
    }

    if (strcasecmp((p + 1), simta_config_str("receive.srs.domain")) == 0) {
        if (srs_reverse(argv[ optind ], &p,
                    simta_config_str("receive.srs.secret")) == SRS_OK) {
            printf("%s\n", p);
        } else {
            printf("srs_reverse failed\n");
        }
    } else {
        env = env_create(NULL, "srs", argv[ optind ], NULL);
        srs_forward(env);
        printf("%s\n", env->e_mail);
    }

    exit(0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
