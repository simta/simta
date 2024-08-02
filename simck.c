/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md.h"
#include "simta.h"

const char *simta_progname = "simck";

int
main(int argc, char *argv[]) {
    int                   fd;
    SNET                 *snet;
    char                 *line;
    u_int                 line_len;
    const EVP_MD         *testdigest;
    struct message_digest md;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <checksum_algorithm> <file>\n", argv[ 0 ]);
        return 1;
    }

    testdigest = EVP_get_digestbyname((const char *)(argv[ 1 ]));

    if (testdigest == NULL) {
        fprintf(stderr, "%s: unknown checksum algorithm\n", argv[ 1 ]);
        return 1;
    }

    md_init(&md);
    md_reset(&md, argv[ 1 ]);

    if ((fd = open(argv[ 2 ], O_RDONLY, 0)) < 0) {
        perror("open");
        exit(1);
    }

    if ((snet = snet_attach(fd, 1024 * 1024)) == NULL) {
        perror("snet_attach");
        exit(1);
    }

    while ((line = snet_getline(snet, NULL)) != NULL) {
        line_len = strlen(line);
        md_update(&md, line, line_len);
    }

    md_finalize(&md);
    md_cleanup(&md);

    if (snet_close(snet) != 0) {
        perror("snet_close");
        return 1;
    }

    printf("\nChecksum: %s\n", md.md_b16);

    return 0;
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
