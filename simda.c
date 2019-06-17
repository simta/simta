/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

/* #include "config.h" */

int
main(int argc, char **argv) {
    struct passwd *simta_pw;
    char *         p;
    ssize_t        path_len;
    bool           ok = false;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <user> <program> [args]\n", argv[ 0 ]);
        return (EX_TEMPFAIL);
    }

    if ((simta_pw = getpwnam(argv[ 1 ])) == NULL) {
        fprintf(stderr, "%s: user not found\n", argv[ 1 ]);
        return (1);
    }

    if ((p = strrchr(argv[ 2 ], '/')) != NULL) {
        path_len = p - argv[ 2 ];
        if ((strncmp(argv[ 2 ], "/bin", path_len) == 0) ||
                (strncmp(argv[ 2 ], "/sbin", path_len) == 0) ||
                (strncmp(argv[ 2 ], "/usr/bin", path_len) == 0) ||
                (strncmp(argv[ 2 ], "/usr/sbin", path_len) == 0) ||
                (strncmp(argv[ 2 ], "/usr/local/bin", path_len) == 0) ||
                (strncmp(argv[ 2 ], "/usr/local/sbin", path_len) == 0)) {
            if (strcmp(p + 1, "procmail") == 0) {
                ok = true;
            }
        }
    }

    if (ok) {
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
        argv += 2;
        execv(argv[ 0 ], argv);
        perror("execv");
    } else {
        fprintf(stderr, "%s is not an allowed MDA\n", argv[ 2 ]);
    }

    /* Either execv failed or someone tried to call an unauthorized program */
    return (EX_TEMPFAIL);
}
