#ifndef SIMTA_ACL_H
#define SIMTA_ACL_H

#include <netinet/in.h>
#include <yasl.h>


struct acl_result {
    yastr acl_list;
    yastr acl_text_raw;
    yastr acl_text_cooked;
    yastr acl_action;
    yastr acl_reason;
    yastr acl_result;
};

struct acl_result *acl_check(
        const char *, const struct sockaddr *, const char *);
void acl_result_free(struct acl_result *);

#endif /* SIMTA_ACL_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
