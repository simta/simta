#ifndef SIMTA_SIMTA_SASL_H
#define SIMTA_SIMTA_SASL_H

#include <sasl/sasl.h>

#include "yasl.h"

struct simta_sasl {
    sasl_conn_t *s_conn;
    const char * s_auth_id;
    const char * s_mech;
    yastr        s_response;
};

simta_result       simta_sasl_init(void);
struct simta_sasl *simta_sasl_server_new(int);
int  simta_sasl_server_auth(struct simta_sasl *, const char *, const char *);
void simta_sasl_free(struct simta_sasl *);
int  simta_sasl_reset(struct simta_sasl *, int);
int  simta_sasl_mechlist(struct simta_sasl *, const char **);

#endif /* SIMTA_SIMTA_SASL_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
