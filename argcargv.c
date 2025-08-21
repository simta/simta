/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

/*
 * Return parsed argc/argv.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "argcargv.h"
#include "simta_malloc.h"

#define ACV_ARGC 10
#define ACV_WHITE 0
#define ACV_WORD 1
#define ACV_BRACKET 2
#define ACV_DQUOTE 3

static ACAV *acavg = NULL;

ACAV *
acav_alloc(void) {
    ACAV *acav;

    acav = simta_malloc(sizeof(ACAV));
    acav->acv_argv = simta_malloc(sizeof(char *) * (ACV_ARGC));
    acav->acv_argc = ACV_ARGC;

    return acav;
}

/*
 * acav->acv_argv = **argv[] if passed an ACAV
 */

int
acav_parse(ACAV *acav, char *line, char **argv[]) {
    int ac = 0;
    int state = ACV_WHITE;

    if (acav == NULL) {
        if (acavg == NULL) {
            if ((acavg = acav_alloc()) == NULL) {
                return (-1);
            };
        }
        acav = acavg;
    }

    for (; *line != '\0'; line++) {
        switch (*line) {
        case ' ':
        case '\t':
        case '\n':
            if (state == ACV_WORD) {
                *line = '\0';
                state = ACV_WHITE;
            }
            break;
        default:
            if (state == ACV_WHITE) {
                acav->acv_argv[ ac++ ] = line;
                if (ac >= acav->acv_argc) {
                    /* simta_realloc */
                    acav->acv_argv = simta_realloc(acav->acv_argv,
                            sizeof(char *) * (acav->acv_argc + ACV_ARGC));
                    acav->acv_argc += ACV_ARGC;
                }
                state = ACV_WORD;
            }
        }
    }

    acav->acv_argv[ ac ] = NULL;
    *argv = acav->acv_argv;
    return (ac);
}

int
acav_free(ACAV *acav) {
    if (acav) {
        simta_free(acav->acv_argv);
        simta_free(acav);
    }

    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
