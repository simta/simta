/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <syslog.h>

#include "simta.h"
#include "simta_ucl.h"

bool
simta_ucl_toggle(const ucl_object_t *base, const char *path, const char *key,
        bool value) {
    const ucl_object_t *path_const;
    ucl_object_t *      path_obj;

    path_const = ucl_object_lookup(base, path);
    if (ucl_object_toboolean(ucl_object_lookup(path_const, key)) != value) {
        path_obj = ucl_object_ref(path_const);
        ucl_object_replace_key(
                path_obj, ucl_object_frombool(value), key, 0, false);
        ucl_object_unref(path_obj);
        return (true);
    }

    return (false);
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
