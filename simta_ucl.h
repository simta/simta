#ifndef SIMTA_UCL_H
#define SIMTA_UCL_H

#include <sys/time.h>
#include <time.h>

#include <ucl.h>

void simta_ucl_merge_defaults(const ucl_object_t *, const char *, const char *);
bool simta_ucl_default(const char *, const char *);
bool simta_ucl_toggle(
        const ucl_object_t *, const char *, const char *, bool value);
void simta_ucl_object_totimeval(const ucl_object_t *, struct timeval *);
void simta_ucl_object_totimespec(const ucl_object_t *, struct timespec *);

#endif /* SIMTA_UCL_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/