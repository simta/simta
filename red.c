/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

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


void
red_host_insert(const char *hostname, ucl_object_t *config) {
    ucl_object_t *obj = NULL;

    obj = ucl_object_ref(simta_config_obj("domain"));
    ucl_object_insert_key(obj, config, hostname, 0, true);
    ucl_object_unref(obj);
}

const ucl_object_t *
red_host_lookup(const char *hostname, bool create) {
    ucl_object_t *      res = NULL;
    const ucl_object_t *jail = NULL;
    yastr               key = NULL;
    const char *        buf = NULL;

    key = yaslauto(hostname);
    yasltolower(key);
    yasltrim(key, ".");

    res = ucl_object_ref(ucl_object_lookup(simta_config_obj("domain"), key));

    if ((res == NULL) && create) {
        res = ucl_object_new();
        ucl_object_insert_key(res,
                ucl_object_copy(simta_config_obj("defaults.red.deliver")),
                "deliver", 0, false);
        ucl_object_insert_key(res,
                ucl_object_copy(simta_config_obj("defaults.red.receive")),
                "receive", 0, false);
        red_host_insert(key, res);
    }

    if (res) {
        buf = ucl_object_tostring(
                ucl_object_lookup_path(res, "deliver.jail.host"));
        if (buf && (strlen(buf) > 0) && (strcasecmp(buf, hostname) != 0)) {
            jail = red_host_lookup(buf, true);
            if (simta_ucl_toggle(jail, "deliver.punt", "enabled", false)) {
                simta_debuglog(1, "Config: disabled punting for jail host %s",
                        ucl_object_key(jail));
            }
            simta_ucl_toggle(jail, "deliver", "is_jail", true);
        }
    }

    yaslfree(key);
    return (res);
}

bool
red_does_expansion(const ucl_object_t *red) {
    ucl_object_iter_t   i;
    const ucl_object_t *re;

    i = ucl_object_iterate_new(ucl_object_lookup(red, "rule"));
    while ((re = ucl_object_iterate_safe(i, false)) != NULL) {
        if (ucl_object_toboolean(
                    ucl_object_lookup_path(re, "expand.enabled"))) {
            ucl_object_iterate_free(i);
            return (true);
        }
    }

    ucl_object_iterate_free(i);
    return (false);
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
