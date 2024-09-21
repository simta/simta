/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "simta.h"

const char *simta_progname = "snetcat";

int
main(int argc, char *argv[]) {
    int    fd;
    int    c;
    size_t buflen = 0;
    size_t maxlen = 0;
    bool   error = false;
    SNET  *snet;
    SNET  *snet_out;
    char  *line;
    bool   safe = false;

    while ((c = getopt(argc, argv, "b:m:s")) != EOF) {
        switch (c) {
        case 'b':
            if ((buflen = atoi(optarg)) == 0) {
                error = true;
            }
            break;
        case 'm':
            if ((maxlen = atoi(optarg)) == 0) {
                error = true;
            }
            break;
        case 's':
            safe = true;
            break;
        default:
            error = true;
            break;
        }
    }

    if (error || (optind == argc)) {
        fprintf(stderr,
                "Usage: %s [-b buffer_size] [-m max_buffer_size] <file>\n",
                argv[ 0 ]);
        exit(1);
    }

    if (strcmp(argv[ optind ], "-") == 0) {
        fd = fileno(stdin);
    } else {
        if ((fd = open(argv[ optind ], O_RDONLY, 0)) < 0) {
            perror("open");
            exit(1);
        }
    }

    if ((snet = snet_attach(fd)) == NULL) {
        perror("snet_attach");
        exit(1);
    }

    if ((snet_out = snet_attach(fileno(stdout))) == NULL) {
        perror("snet_attach stdout");
        exit(1);
    }

    if (buflen > 0) {
        snet->sn_buflen = buflen;
        snet_out->sn_buflen = buflen;
    }
    if (maxlen > 0) {
        snet->sn_maxlen = maxlen;
        snet_out->sn_maxlen = maxlen;
    }

    do {
        if (safe) {
            line = snet_getline_safe(snet, NULL);
        } else {
            line = snet_getline(snet, NULL);
        }
        if (line) {
            snet_writef(snet_out, "%s\r\n", line);
        }
    } while (line);

    if (!snet_eof(snet)) {
        perror("snet_eof");
        exit(1);
    }

    if (snet_close(snet) != 0) {
        perror("snet_close");
        exit(1);
    }

    if (snet_close(snet_out) != 0) {
        perror("snet_close stdout");
        exit(1);
    }

    return 0;
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
