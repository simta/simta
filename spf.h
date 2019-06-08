#ifndef SIMTA_SPF_H
#define SIMTA_SPF_H

#define SPF_RESULT_NONE 0
#define SPF_RESULT_NEUTRAL 1
#define SPF_RESULT_PASS 2
#define SPF_RESULT_SOFTFAIL 3
#define SPF_RESULT_FAIL 4
#define SPF_RESULT_TEMPERROR 5
#define SPF_RESULT_PERMERROR 6

struct spf {
    int                    spf_result;
    int                    spf_queries;
    yastr                  spf_localpart;
    yastr                  spf_domain;
    yastr                  spf_helo;
    const struct sockaddr *spf_sockaddr;
};

struct spf *spf_lookup(const char *, const char *, const struct sockaddr *);
const char *spf_result_str(const int);
void        spf_free(struct spf *);

#endif /* SIMTA_SPF_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
