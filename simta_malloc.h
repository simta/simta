#ifndef SIMTA_XMALLOC_H
#define SIMTA_XMALLOC_H

#include <stddef.h>
#include <stdlib.h>

void *simta_calloc(size_t, size_t)
        __attribute__((__alloc_size__(1, 2), __malloc__));
void *simta_malloc(size_t) __attribute__((__alloc_size__(1), __malloc__));
void *simta_realloc(void *, size_t)
        __attribute__((__alloc_size__(2), __malloc__));
void  simta_free(void *);
char *simta_strdup(const char *) __attribute__((__nonnull__, __malloc__));

#endif /* SIMTA_XMALLOC_H */
