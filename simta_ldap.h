/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */
/*****     ldap.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

struct list {
    char		*l_string;
    struct list		*l_next;
};

/* lds search types */
#define LDS_USER            0x01
#define LDS_GROUP_ERRORS    0x02
#define LDS_GROUP_REQUEST   0x04
#define LDS_GROUP_MEMBERS   0x08
#define LDS_GROUP_OWNER     0x10
#define LDS_GROUP           0xfe
#define LDS_ALL             0xff

/* Special group mail address.  e.g. "groupname-error" */
#define ERROR           "error"
#define ERRORS          "errors"
#define REQUEST         "request"
#define REQUESTS        "requests"
#define MEMBERS         "members"
#define OWNER           "owner"
#define OWNERS          "owners"

/* return codes for ldap_expand */
#define LDAP_SYSERROR		1
#define LDAP_NOT_FOUND		2
#define LDAP_FINAL		3
#define LDAP_EXCLUDE		4

/* return codes for ldap_address_local */
#define LDAP_LOCAL		2
#define LDAP_NOT_LOCAL		3

/* Envelope e_flags bits used by ldap expansion */
#define SUPPRESSNOEMAILERROR    (1<<0)

/* Public functions */
int	simta_ldap_expand ___P(( struct expand *, struct exp_addr * ));
int	simta_ldap_address_local ___P(( char *, char * ));
int	simta_ldap_config ___P(( char * ));
int	simta_mbx_compare ___P(( char *, char * ));

/* Private functions */
int	simta_ldap_value ___P(( LDAPMessage *, char *, struct list * ));
char	*simta_ldap_string ___P(( char *, char *, char * ));

