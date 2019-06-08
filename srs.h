#ifndef SIMTA_SRS_H
#define SIMTA_SRS_H

#include "envelope.h"
#include "red.h"

#define SRS_OK 0
#define SRS_BADSYNTAX 1
#define SRS_EXPIRED 2
#define SRS_INVALID 3
#define SRS_SYSERROR 4

int srs_forward(struct envelope *);
int srs_reverse(const char *, char **, const char *);
int srs_expand(struct expand *, struct exp_addr *, struct action *);
int srs_valid(const char *, const char *);

#endif /* SIMTA_SRS_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
