#ifndef SIMTA_UCL_H
#define SIMTA_UCL_H

#include <sys/time.h>
#include <time.h>

#include <ucl.h>

struct ucl_parser *simta_ucl_parser(void);
void simta_ucl_merge_defaults(const ucl_object_t *, const char *, const char *);
void simta_ucl_ensure_array(const ucl_object_t *, const char *);
bool simta_ucl_toggle(const ucl_object_t *, const char *, const char *, bool);
ucl_object_t *simta_ucl_object_fromstring(const char *);
ucl_object_t *simta_ucl_object_fromyastr(const yastr);
void  simta_ucl_object_totimeval(const ucl_object_t *, struct timeval *);
void  simta_ucl_object_totimespec(const ucl_object_t *, struct timespec *);
yastr simta_ucl_object_toyastr(const ucl_object_t *);

#endif /* SIMTA_UCL_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
