/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#ifdef HAVE_LDAP
#include <ldap.h>
#endif /* HAVE_LDAP */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "queue.h"
#include "red.h"

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#endif /* HAVE_LDAP */

struct simta_red *red_host_lookup_(char *, struct simta_red **);


void
red_hosts_stdout(void) {
    struct simta_red *red;
    struct action *   a;

    for (red = simta_red_hosts; red != NULL; red = red->red_next) {
        printf("RED %s:\n", red->red_host_name);

        if ((a = red->red_receive) == NULL) {
            printf("\tNo Receive Methods\n");
        } else {
            do {
                printf("\tR %d %d\n", a->a_action, a->a_flags);
                a = a->a_next;
            } while (a != NULL);
        }

        if ((a = red->red_expand) == NULL) {
            printf("\tNo Expand Methods\n");
        } else {
            do {
                printf("\tE %d %d\n", a->a_action, a->a_flags);
                a = a->a_next;
            } while (a != NULL);
        }
        printf("\n");
    }

    return;
}


#ifdef HAVE_LDAP
void
red_close_ldap_dbs(void) {
    struct simta_red *red;
    struct action *   a;

    for (red = simta_red_hosts; red != NULL; red = red->red_next) {
        for (a = red->red_receive; a != NULL; a = a->a_next) {
            if (a->a_ldap != NULL) {
                simta_ldap_unbind(a->a_ldap);
            }
        }

        for (a = red->red_expand; a != NULL; a = a->a_next) {
            if (a->a_ldap != NULL) {
                simta_ldap_unbind(a->a_ldap);
            }
        }
    }

    return;
}
#endif /* HAVE_LDAP */


struct simta_red *
red_host_lookup_(char *host_name, struct simta_red **redp) {
    int               d;
    char *            dot = NULL;
    struct simta_red *red = *redp;

    if (simta_domain_trailing_dot != 0) {
        dot = host_name + strlen(host_name) - 1;
        if (*dot == '.') {
            *dot = '\0';
        } else {
            dot = NULL;
        }
    }

    for (; red != NULL; red = red->red_next) {
        if ((d = strcasecmp(host_name, red->red_host_name)) == 0) {
            break;
        } else if (d > 0) {
            red = NULL;
            break;
        }
    }

    if (dot != NULL) {
        *dot = '.';
    }

    return (red);
}


struct simta_red *
red_host_lookup(char *host_name) {
    return red_host_lookup_(host_name, &simta_red_hosts);
}


/* this function only takes the RE of RED in to consideration at the
     * moment.  This will obviously change.
     */

struct action *
red_action_add(struct simta_red *red, int red_type, int action, char *fname) {
    struct action * a;
    struct action **insert;
    int             flags = 0;

    switch (red_type) {
    case RED_CODE_R:
        flags = ACTION_SUFFICIENT;
        for (insert = &(red->red_receive); *insert != NULL;
                insert = &((*insert)->a_next))
            ;
        break;

    case RED_CODE_r:
        flags = ACTION_REQUIRED;
        for (insert = &(red->red_receive); *insert != NULL;
                insert = &((*insert)->a_next))
            ;
        break;

    case RED_CODE_E:
        for (insert = &(red->red_expand); *insert != NULL;
                insert = &((*insert)->a_next))
            ;
        break;

    default:
        syslog(LOG_ERR, "red_action_add: invalid red_type");
        return (NULL);
    }

    a = calloc(1, sizeof(struct action));

    /* note that while we're still using an int payload in the expansion
     * structure, it might change in the future.  This would be a great
     * place to store information like LDAP settings to remote servers,
     * etc.
     */
    *insert = a;
    a->a_action = action;
    a->a_flags = flags;
    if (fname != NULL) {
        a->a_fname = strdup(fname);
    }

    return (a);
}


struct simta_red *
red_host_add(char *host_name) {
    struct simta_red * red;
    struct simta_red **insert;
    int                d;

    for (insert = &simta_red_hosts; *insert != NULL;
            insert = &((*insert)->red_next)) {
        if ((d = strcasecmp((*insert)->red_host_name, host_name)) == 0) {
            return (*insert);
        } else if (d < 0) {
            break;
        }
    }

    red = calloc(1, sizeof(struct simta_red));
    red->red_host_name = strdup(host_name);
    red->red_next = *insert;
    *insert = red;

    return (red);
}


/* Default RED actions are:
     *     R ALIAS simta_default_alias_db
     *     E ALIAS simta_default_alias_db
     *     R PASSWORD simta_default_password_file
     *     E PASSWORD simta_default_password_file
     */

int
red_action_default(struct simta_red *red) {
    if (red->red_receive == NULL) {
#ifdef HAVE_LMDB
        red_action_add(
                red, RED_CODE_R, EXPANSION_TYPE_ALIAS, simta_default_alias_db);
#endif /* HAVE_LMDB */

        red_action_add(red, RED_CODE_R, EXPANSION_TYPE_PASSWORD,
                simta_default_passwd_file);
    }

    if (red->red_expand == NULL) {
#ifdef HAVE_LMDB
        red_action_add(
                red, RED_CODE_E, EXPANSION_TYPE_ALIAS, simta_default_alias_db);
#endif /* HAVE_LMDB */

        red_action_add(red, RED_CODE_E, EXPANSION_TYPE_PASSWORD,
                simta_default_passwd_file);
    }

    if (red->red_deliver_type == 0) {
        red->red_deliver_type = RED_DELIVER_BINARY;
    }

    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
