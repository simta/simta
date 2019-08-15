#ifndef SIMTA_SIMTA_LDAP_H
#define SIMTA_SIMTA_LDAP_H

#include "expand.h"

/* lds search types */
#define LDS_USER 0x01
#define LDS_GROUP_ERRORS 0x02
#define LDS_GROUP_REQUEST 0x04
#define LDS_GROUP_MEMBERS 0x08
#define LDS_GROUP_OWNER 0x10
#define LDS_GROUP 0xfe
#define LDS_ALL 0xff

/* Special group mail address.  e.g. "groupname-error" */
#define ERROR "error"
#define ERRORS "errors"
#define REQUEST "request"
#define REQUESTS "requests"
#define MEMBERS "members"
#define OWNER "owner"
#define OWNERS "owners"

/* Envelope e_flags bits used by ldap expansion */
#define SUPPRESSNOEMAILERROR (1 << 0)

/* Public functions */
struct simta_ldap *simta_ldap_config(const ucl_object_t *);
void               simta_ldap_reset(void);
int simta_ldap_expand(const ucl_object_t *, struct expand *, struct exp_addr *);
simta_address_status simta_ldap_address_local(
        const ucl_object_t *, char *, char *);
int  simta_mbx_compare(const char *, const char *);
void simta_ldap_unbind(struct simta_ldap *);

#endif /* SIMTA_SIMTA_LDAP_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
