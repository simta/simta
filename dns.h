#ifndef SIMTA_DNS_H
#define SIMTA_DNS_H

#include <denser.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <yasl.h>

#define DNSL_BLOCK 0
#define DNSL_ACCEPT 1
#define DNSL_LOG_ONLY 2
#define DNSL_TRUST 3

#define DNSL_FLAG_DOMAIN (1 << 0)
#define DNSL_FLAG_HASHED (1 << 1)
#define DNSL_FLAG_SHA1 (1 << 2)
#define DNSL_FLAG_SHA256 (1 << 3)

#define S_MISMATCH "Mismatch"
#define S_ACCEPT "Accept"
#define S_BLOCK "Block"
#define S_LOG_ONLY "Log_Only"
#define S_TRUST "Trust"

#define REVERSE_MATCH 0
#define REVERSE_ERROR 1
#define REVERSE_UNKNOWN 2
#define REVERSE_MISMATCH 3
#define REVERSE_UNRESOLVED 4


struct dnsl_result {
    yastr dnsl_list;
    yastr dnsl_action;
    yastr dnsl_reason;
    yastr dnsl_result;
};

bool                simta_dnsr_init(void);
struct dnsr_result *get_a(const char *);
struct dnsr_result *get_aaaa(const char *);
struct dnsr_result *get_mx(const char *);
struct dnsr_result *get_ptr(const struct sockaddr *);
struct dnsr_result *get_txt(const char *);
yastr               simta_dnsr_str(const struct dnsr_string *);
int                 check_reverse(char *, const struct sockaddr *);
int                 check_hostname(const char *);
bool                dnsr_result_is_cname(struct dnsr_result *);
struct dnsl_result *dnsl_check(
        const char *, const struct sockaddr *, const char *);
void dnsl_result_free(struct dnsl_result *);

#endif /* SIMTA_DNS_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
