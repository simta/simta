#ifndef SIMTA_SRS_H
#define SIMTA_SRS_H

#include "envelope.h"
#include "red.h"

enum simta_srs_result {
    SRS_OK,
    SRS_BADSYNTAX,
    SRS_EXPIRED,
    SRS_INVALID,
    SRS_SYSERROR,
};

enum simta_srs_result srs_forward(struct envelope *);
enum simta_srs_result srs_reverse(const char *, char **, const char *);
int srs_expand(struct expand *, struct exp_addr *, const ucl_object_t *);
int srs_valid(const char *, const char *);

#endif /* SIMTA_SRS_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
