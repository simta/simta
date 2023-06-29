/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include "simta_malloc.h"

#ifdef HAVE_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif /* HAVE_JEMALLOC */


void *
simta_malloc(size_t size) {
    void *p;

    size = (size > 0) ? size : 1;
    if ((p = malloc(size)) == NULL) {
        abort();
    }
    return p;
}


void *
simta_calloc(size_t n, size_t size) {
    void *p;

    n = (n > 0) ? n : 1;
    size = (size > 0) ? size : 1;
    if ((p = calloc(n, size)) == NULL) {
        abort();
    }
    return p;
}


void *
simta_realloc(void *oldp, size_t size) {
    void *p;

    if ((p = realloc(oldp, size)) == NULL) {
        abort();
    }
    return p;
}


char *
simta_strdup(const char *s) {
    char  *p;
    size_t len;

    len = strlen(s) + 1;
    if ((p = malloc(len)) == NULL) {
        abort();
    }
    memcpy(p, s, len);
    return p;
}
