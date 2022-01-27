/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <syslog.h>

#include "simta.h"
#include "simta_ucl.h"


void
simta_ucl_merge_defaults(
        const ucl_object_t *obj, const char *basepath, const char *path) {
    const ucl_object_t *src;
    ucl_object_t *      copy;
    ucl_object_t *      ref;

    if ((src = ucl_object_lookup(simta_config_obj(basepath), path)) == NULL) {
        /* No defaults to merge */
        return;
    }

    copy = ucl_object_copy(src);

    ref = ucl_object_ref(ucl_object_lookup(obj, path));
    ucl_object_merge(copy, ref, false);
    ucl_object_unref(ref);

    ref = ucl_object_ref(obj);
    ucl_object_replace_key(ref, copy, path, 0, false);
    ucl_object_unref(ref);
}

void
simta_ucl_ensure_array(const ucl_object_t *obj, const char *key) {
    const ucl_object_t *elt;
    ucl_object_t *      ref;
    ucl_object_t *      arr;

    elt = ucl_object_lookup_path(obj, key);
    if (ucl_object_type(elt) == UCL_ARRAY) {
        /* Already an array */
        return;
    }

    ref = ucl_object_ref(obj);
    arr = ucl_object_typed_new(UCL_ARRAY);
    if (elt != NULL) {
        ucl_array_append(arr, ucl_object_ref(elt));
    }
    ucl_object_replace_key(ref, arr, key, 0, false);
    ucl_object_unref(ref);
}

bool
simta_ucl_toggle(const ucl_object_t *base, const char *path, const char *key,
        bool value) {
    const ucl_object_t *path_const;
    ucl_object_t *      path_obj;

    if (path == NULL) {
        path_const = base;
    } else {
        path_const = ucl_object_lookup_path(base, path);
    }

    if (ucl_object_toboolean(ucl_object_lookup(path_const, key)) != value) {
        path_obj = ucl_object_ref(path_const);
        ucl_object_replace_key(
                path_obj, ucl_object_frombool(value), key, 0, false);
        ucl_object_unref(path_obj);
        return (true);
    }

    return (false);
}

void
simta_ucl_object_totimeval(const ucl_object_t *obj, struct timeval *tv) {
    double val;

    val = ucl_object_todouble(obj);
    tv->tv_sec = (time_t)val;
    tv->tv_usec = (val - (time_t)val) * 1000000;
}

void
simta_ucl_object_totimespec(const ucl_object_t *obj, struct timespec *ts) {
    double val;

    val = ucl_object_todouble(obj);
    ts->tv_sec = (time_t)val;
    ts->tv_nsec = (val - (time_t)val) * 1000000000;
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
