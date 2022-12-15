/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "simta.h"
#include "spf.h"

const char *simta_progname = "simspf";

int
main(int argc, char *argv[]) {
    int              c;
    struct addrinfo *addrinfo;
    struct addrinfo  hints;
    const char      *email;
    const char      *addrlookup;
    const char      *ehlo;
    struct spf      *spf;
    const char      *conf_file = NULL;
    const char      *extra_conf = NULL;
    int              error = 0;

    while ((c = getopt(argc, argv, "f:U:")) != EOF) {
        switch (c) {
        case 'f':
            conf_file = optarg;
            break;

        case 'U':
            extra_conf = optarg;
            break;

        default:
            error++;
            break;
        }
    }

    if (error || (optind == argc)) {
        fprintf(stderr,
                "Usage:\t\t%s [ -f conf_file ] [ -U extra_conf ] "
                "<email> [ip] [ehlo host]\n",
                argv[ 0 ]);
        exit(1);
    }

    simta_openlog(false, LOG_PERROR);

    if (simta_read_config(conf_file, extra_conf) != SIMTA_OK) {
        exit(1);
    }

    simta_debug = 8;

    /* Handle positional parameters */
    email = argv[ optind++ ];
    if (optind < argc) {
        addrlookup = argv[ optind++ ];
    } else {
        addrlookup = "203.0.113.1";
    }

    if (optind < argc) {
        ehlo = argv[ optind++ ];
    } else {
        ehlo = "hostname.example.com";
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICSERV;
    getaddrinfo(addrlookup, NULL, &hints, &addrinfo);

    spf = spf_lookup(ehlo, email, addrinfo->ai_addr);
    printf("SPF result: %s\n", spf_result_str(spf->spf_result));

    exit(0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
