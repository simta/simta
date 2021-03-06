/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <utime.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "envelope.h"
#include "expand.h"
#include "ml.h"
#include "queue.h"
#include "simta.h"
#include "smtp.h"

const char *simta_progname = "q_runner";

int
main(int argc, char *argv[]) {
    char *conf_file = NULL;
    char *op;

    simta_debug = 1;

    if ((argc != 4) && (argc != 3)) {
        fprintf(stderr, "Usage: %s conf_file [ base_dir ] ( LOCAL | SLOW )\n",
                argv[ 0 ]);
        exit(EX_USAGE);
    }

    if (argc == 4) {
        conf_file = argv[ 2 ];
        op = argv[ 3 ];
    } else {
        op = argv[ 2 ];
    }

    if (simta_read_config(conf_file) < 0) {
        fprintf(stderr, "simta_read_config error\n");
        exit(EX_DATAERR);
    }

    simta_base_dir = argv[ 1 ];
    /* init simta config / defaults */
    if (simta_config() != 0) {
        fprintf(stderr, "simta_config error\n");
        exit(EX_DATAERR);
    }

    simta_openlog(0, 0);

    if (strcasecmp(op, "LOCAL") == 0) {
        exit(q_runner_dir(simta_dir_local));

    } else if (strcasecmp(op, "SLOW") == 0) {
        exit(q_runner_dir(simta_dir_slow));

    } else {
        fprintf(stderr,
                "Usage: %s conf_file [ base_dir ] ( LOCAL | SLOW | CLEAN )\n",
                argv[ 0 ]);
        exit(EX_USAGE);
    }
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
