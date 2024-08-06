/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <ucl.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "dns.h"
#include "simta.h"
#include "simta_acl.h"

#define SIMRBL_EXIT_NOT_BLOCKED 0
#define SIMRBL_EXIT_BLOCKED 1
#define SIMRBL_EXIT_ERROR 2

const char *simta_progname = "simrbl";

int
main(int argc, char *argv[]) {
    int                c;
    const char        *server = NULL;
    const char        *port = "53";
    int                rc;
    int                err = 0;
    bool               quiet = false;
    bool               log = true;
    int                exclusive = 0;
    int                check_text = 0;
    ucl_object_t      *config;
    ucl_object_t      *list_config;
    struct addrinfo    hints;
    struct addrinfo   *ai;
    struct acl_result *list = NULL;
    struct timeval     tv_now;

    /* Skip normal config parsing, we're just knocking up a list. */
    simta_config = ucl_object_typed_new(UCL_OBJECT);
    config = ucl_object_typed_new(UCL_ARRAY);
    ucl_object_insert_key(simta_config, config, simta_progname, 0, false);

    while ((c = getopt(argc, argv, "dif:l:np:s:tq")) != -1) {
        switch (c) {
        case 'd':
            simta_debug++;
            break;

        case 'f':
            list_config = ucl_object_typed_new(UCL_OBJECT);
            ucl_object_insert_key(list_config,
                    simta_ucl_object_fromstring(optarg), "list", 0, false);
            ucl_object_insert_key(list_config,
                    simta_ucl_object_fromstring("report"), "action", 0, false);
            ucl_object_insert_key(list_config,
                    simta_ucl_object_fromstring("file"), "type", 0, false);

            ucl_array_append(config, list_config);
            break;

        case 'i':
            if (exclusive != 0) {
                err++;
                break;
            }
            exclusive++;
            break;

        case 'l':
            list_config = ucl_object_typed_new(UCL_OBJECT);
            ucl_object_insert_key(list_config,
                    simta_ucl_object_fromstring(optarg), "list", 0, false);
            ucl_object_insert_key(list_config,
                    simta_ucl_object_fromstring("report"), "action", 0, false);
            ucl_object_insert_key(list_config,
                    simta_ucl_object_fromstring("dns"), "type", 0, false);

            ucl_array_append(config, list_config);
            break;

        case 'n':
            log = false;
            break;

        case 'p':
            port = optarg;
            break;

        case 'q':
            quiet = true;
            break;

        case 's':
            server = optarg;
            break;

        case 't':
            if (exclusive != 0) {
                err++;
                break;
            }
            exclusive++;
            check_text = 1;
            break;

        default:
            err++;
            break;
        }
    }

    if ((argc - optind) < 1) {
        err++;
    }

    if (err) {
        fprintf(stderr, "Usage: %s ", argv[ 0 ]);
        fprintf(stderr, "[ -dq ] ");
        fprintf(stderr, "[ -l dnsl-domain ] ");
        fprintf(stderr, "[ -s server ] [ -p port ] ");
        fprintf(stderr, "([ -i ] address | -t text ) [...]\n");
        exit(EX_USAGE);
    }

    if (server != NULL) {
        if ((simta_dnsr = dnsr_new()) == NULL) {
            perror("dnsr_new");
            exit(SIMRBL_EXIT_ERROR);
        }
        if ((rc = dnsr_nameserver_port(simta_dnsr, server, port)) != 0) {
            dnsr_perror(simta_dnsr, "dnsr_nameserver");
            exit(SIMRBL_EXIT_ERROR);
        }
        if (simta_debug > 1) {
            fprintf(stderr, "using nameserver: %s:%s\n", server, port);
        }
    }

    if (log) {
        /* call simta_gettimeofday() to initialize simta_tv_now */
        simta_gettimeofday(&tv_now);
        simta_openlog(false, 0);
    }

    if (ucl_array_size(config) == 0) {
        list_config = ucl_object_typed_new(UCL_OBJECT);
        ucl_object_insert_key(list_config,
                simta_ucl_object_fromstring("mx-deny.dnsbl"), "list", 0, false);
        ucl_object_insert_key(list_config,
                simta_ucl_object_fromstring("report"), "action", 0, false);
        ucl_object_insert_key(list_config, simta_ucl_object_fromstring("dns"),
                "type", 0, false);
        ucl_array_append(config, list_config);
    }

    while ((optind < argc) && (list == NULL)) {
        if (check_text == 0) {
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_NUMERICHOST;

            if ((rc = getaddrinfo(argv[ optind ], NULL, &hints, &ai)) != 0) {
                fprintf(stderr, "Syserror: getaddrinfo: %s\n",
                        gai_strerror(rc));
                exit(SIMRBL_EXIT_ERROR);
            }

            list = acl_check(simta_progname, ai->ai_addr, NULL);
        } else {
            list = acl_check(simta_progname, NULL, argv[ optind ]);
        }
        if (list == NULL) {
            optind++;
        }
    }

    if (list == NULL) {
        if (!quiet)
            printf("not found\n");
        exit(SIMRBL_EXIT_NOT_BLOCKED);
    } else {
        if (!quiet)
            printf("%s found in %s: %s (%s)\n", argv[ optind ], list->acl_list,
                    list->acl_result, list->acl_reason);
        exit(SIMRBL_EXIT_BLOCKED);
    }
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
