/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
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
#include "expand.h"
#include "simta.h"

const char *simta_progname = "simexpander";

int
main(int argc, char *argv[]) {
    struct envelope *env;

    const char *sender = "sender@expansion.test";
    int         c;
    int         nextargc = 1;
    int         exp_level = 0;
    int         error = 0;

    extern int   optind;
    extern char *optarg;

    simta_debug = 1;
    simta_expand_debug = 1;

    while ((c = getopt(argc, argv, "f:x:")) != EOF) {
        switch (c) {
        case 'x':
            if ((exp_level = atoi(optarg)) < 0) {
                error++;
            }
            nextargc = nextargc + 2;
            break;

        case 'f':
            sender = strdup(optarg);
            nextargc = nextargc + 2;
            break;

        default:
            error++;
            nextargc++;
            break;
        }
    }
    if ((argc < 3) | (error)) {
        fprintf(stderr,
                "Usage: %s [ -x level ] [-f sendermail] conf_file "
                "address\n",
                argv[ 0 ]);
        exit(EX_USAGE);
    }

    if (simta_read_config(argv[ nextargc ]) < 0) {
        fprintf(stderr, "simta_read_config error: %s\n", argv[ nextargc ]);
        exit(EX_DATAERR);
    }

    /* init simta config / defaults */
    if (simta_config() != 0) {
        fprintf(stderr, "simta_config error\n");
        exit(EX_DATAERR);
    }

    simta_openlog(0, 0);

    env = env_create(NULL, "DEAD60FF", sender, NULL);

    env->e_n_exp_level = exp_level;

    do {
        nextargc++;

        printf("Original Recipient: %s\n", argv[ nextargc ]);
        env_recipient(env, argv[ nextargc ]);

    } while (nextargc < argc - 1);

    if (expand(env) != 0) {
        return (1);
    }
    env_free(env);

    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
