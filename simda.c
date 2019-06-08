/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

/* #include "config.h" */

#ifndef SIMTA_PROCMAIL
#define SIMTA_PROCMAIL "/usr/bin/procmail"
#endif
#ifndef SIMTA_MAIL_LOCAL
#define SIMTA_MAIL_LOCAL ""
#endif

int
main(int argc, char **argv) {
    struct passwd *simta_pw;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <user> <program> [args]\n", argv[ 0 ]);
        return (EX_TEMPFAIL);
    }

    if ((simta_pw = getpwnam(argv[ 1 ])) == NULL) {
        fprintf(stderr, "%s: user not found\n", argv[ 1 ]);
        return (1);
    }

    if ((strcmp(argv[ 2 ], SIMTA_PROCMAIL) == 0) ||
            (strcmp(argv[ 2 ], SIMTA_MAIL_LOCAL) == 0)) {
        /* The program is allowed, drop root privileges. */
        if (initgroups(simta_pw->pw_name, 0) != 0) {
            perror("initgroups");
            return (EX_TEMPFAIL);
        }
        if (setgid(simta_pw->pw_gid) != 0) {
            perror("setgid");
            return (EX_TEMPFAIL);
        }
        if (setuid(simta_pw->pw_uid) != 0) {
            perror("setuid");
            return (EX_TEMPFAIL);
        }

        /* Execute the program as the requested user. */
        argc -= 2;
        argv += 2;
        execv(argv[ 0 ], argv);
        perror("execv");
    } else {
        fprintf(stderr, "%s is not an allowed MDA\n", argv[ 2 ]);
    }

    /* Either execv failed or someone tried to call an unauthorized program */
    return (EX_TEMPFAIL);
}
