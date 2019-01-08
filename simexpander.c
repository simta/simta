/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
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
#include "expand.h"
#include "simta.h"

const char *simta_progname = "simexpander";

int
main(int argc, char *argv[]) {
    struct envelope *env;
    const char *     conf_file = NULL;
    const char *     extra_conf = NULL;
    const char *     sender = "sender@expansion.test";
    int              c;
    int              exp_level = 0;
    int              error = 0;
    bool             verbose = false;

    simta_debug = 1;
    simta_expand_debug = 1;

    while ((c = getopt(argc, argv, "f:F:U:vx:")) != EOF) {
        switch (c) {
        case 'f':
            conf_file = optarg;
            break;

        case 'F':
            sender = strdup(optarg);
            break;

        case 'U':
            extra_conf = optarg;
            break;

        case 'v':
            verbose = true;
            break;

        case 'x':
            if ((exp_level = atoi(optarg)) < 0) {
                error++;
            }
            break;

        default:
            error++;
            break;
        }
    }
    if (error || (optind == argc)) {
        fprintf(stderr,
                "Usage: %s [ -f conf_file ] [ -U extra_conf ] "
                "[ -x level ] [ -F sender ] "
                "address\n",
                argv[ 0 ]);
        exit(EX_USAGE);
    }

    simta_openlog(0, LOG_PERROR);

    if (simta_read_config(conf_file, extra_conf) < 0) {
        exit(EX_DATAERR);
    }

    simta_openlog(0, verbose ? LOG_PERROR : 0);

    env = env_create(NULL, "DEAD60FF", sender, NULL);

    env->e_n_exp_level = exp_level;

    for (int i = optind; i < argc; i++) {
        printf("Original Recipient: %s\n", argv[ i ]);
        env_recipient(env, argv[ i ]);
    }

    if (expand(env) != 0) {
        return (1);
    }
    env_free(env);

    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
