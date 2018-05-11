#ifndef SIMTA_UCL_H
#define SIMTA_UCL_H

#include <ucl.h>

bool simta_ucl_toggle(
        const ucl_object_t *, const char *, const char *, bool value);

#endif /* SIMTA_UCL_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
