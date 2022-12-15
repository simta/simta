#ifndef SIMTA_SPF_H
#define SIMTA_SPF_H

typedef enum {
    SPF_RESULT_NONE,
    SPF_RESULT_NEUTRAL,
    SPF_RESULT_PASS,
    SPF_RESULT_SOFTFAIL,
    SPF_RESULT_FAIL,
    SPF_RESULT_TEMPERROR,
    SPF_RESULT_PERMERROR,
} simta_spf_result;

struct spf {
    simta_spf_result       spf_result;
    int                    spf_queries;
    int                    spf_void_queries;
    yastr                  spf_localpart;
    yastr                  spf_domain;
    yastr                  spf_helo;
    const struct sockaddr *spf_sockaddr;
};

struct spf *spf_lookup(const char *, const char *, const struct sockaddr *);
const char *spf_result_str(const simta_spf_result);
void        spf_free(struct spf *);

#endif /* SIMTA_SPF_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
