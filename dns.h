#ifndef SIMTA_DNS_H
#define SIMTA_DNS_H

#include <denser.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <yasl.h>

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


bool                simta_dnsr_init(void);
struct dnsr_result *get_a(const char *);
struct dnsr_result *get_aaaa(const char *);
struct dnsr_result *get_mx(const char *);
struct dnsr_result *get_ptr(const struct sockaddr *);
struct dnsr_result *get_txt(const char *);
yastr               simta_dnsr_str(const struct dnsr_string *);
int                 check_reverse(yastr *, const struct sockaddr *);
int                 check_hostname(const char *);
bool                dnsr_result_is_cname(struct dnsr_result *);

#endif /* SIMTA_DNS_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
