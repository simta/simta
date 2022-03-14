#ifndef SIMTA_EXPAND_H
#define SIMTA_EXPAND_H

#include <ucl.h>

#include "simta.h"

/* expansion types */
#define EXPANSION_TYPE_PASSWORD 1
#define EXPANSION_TYPE_ALIAS 2
#define EXPANSION_TYPE_LDAP 3
#define EXPANSION_TYPE_GLOBAL_RELAY 4
#define EXPANSION_TYPE_SRS 5

/* return codes for expand_and_deliver(...) */
#define EXPAND_OK 0
#define EXPAND_SYSERROR 1
#define EXPAND_FATAL 2

/* return codes for address expansion */
typedef enum {
    ADDRESS_OK,
    ADDRESS_OK_SPAM,
    ADDRESS_EXCLUDE,
    ADDRESS_NOT_FOUND,
    ADDRESS_SYSERROR,
} simta_address_status;

/* address types */
#define ADDRESS_TYPE_EMAIL 1
#define ADDRESS_TYPE_DEAD 2
#ifdef HAVE_LDAP
#define ADDRESS_TYPE_LDAP 3
#endif /* HAVE_LDAP */

#ifdef HAVE_LDAP
#define STATUS_LDAP_SUPPRESSOR (1 << 2)
#define STATUS_LDAP_SUPPRESSED (1 << 3)
#define STATUS_EMAIL_SENDER (1 << 4)
#define STATUS_NO_EMAIL_SENDER (1 << 5)
#define STATUS_ROOT_PATH (1 << 6)
#define STATUS_NO_ROOT_PATH (1 << 7)
#endif /* HAVE_LDAP */

struct expand_output {
    char *                eo_from;
    char *                eo_hostname;
    struct envelope *     eo_env;
    struct expand_output *eo_next;
};

struct expand {
    struct envelope *exp_env;       /* original envelope */
    struct exp_addr *exp_addr_head; /* list of expanded addresses */
    struct exp_addr *exp_addr_tail;
    struct exp_addr *exp_addr_cursor; /* cursor */
    struct envelope *exp_errors;      /* error envelope list */
#ifdef HAVE_LDAP
    struct envelope *exp_gmailfwding;
#endif /* HAVE_LDAP */
    const ucl_object_t *exp_current_rule;
    int                 exp_max_level;
    int                 exp_entries;
};

#ifdef HAVE_LDAP
struct exp_link {
    struct exp_link *el_next;
    struct exp_addr *el_exp_addr;
};
#endif /* HAVE_LDAP */

struct exp_addr {
    struct exp_addr *   e_addr_next;
    char *              e_addr;    /* address string */
    char *              e_addr_at; /* char the email addresses @ */
    char *              e_addr_from;
    struct envelope *   e_addr_errors; /* address error handle */
    const ucl_object_t *e_addr_parent_rule;
    int                 e_addr_type; /* address data type */
    int                 e_addr_terminal;
    int                 e_addr_max_level;
#ifdef HAVE_LDAP
    int                e_addr_ldap_flags;
    int                e_addr_anti_loop;
    bool               e_addr_requires_permission;
    bool               e_addr_has_permission;
    bool               e_addr_permit_members;
    bool               e_addr_private;
    char *             e_addr_dn;
    yastr              e_addr_owner;
    yastr              e_addr_group_name;
    yastr              e_addr_preface;
    struct stab_entry *e_addr_ok;
    struct envelope *  e_addr_env_moderators;
    struct envelope *  e_addr_env_gmailfwd;
    struct exp_link *  e_addr_parents;
    struct exp_link *  e_addr_children;
#endif /* HAVE_LDAP */
};

/* expand.c */
int              expand(struct envelope *);
struct envelope *eo_lookup(struct expand_output *, char *, char *);
int              eo_insert(struct expand_output **, struct envelope *);

/* address.c */
struct passwd *simta_getpwnam(const char *, const char *);
int            address_error(struct envelope *, char *, char *, char *);
void           expansion_stab_stdout(void *);
simta_result   add_address(
          struct expand *, char *, struct envelope *, int, char *, bool);
struct envelope *    address_bounce_create(struct expand *);
simta_address_status address_expand(struct expand *);
void                 expand_tree_stdout(struct exp_addr *, int);
int                  address_string_recipients(
                         struct expand *, char *, struct exp_addr *, char *);

#ifdef HAVE_LDAP
int   exp_addr_link(struct exp_link **, struct exp_addr *);
void  exp_addr_link_free(struct exp_link *);
bool  unblocked_path_to_root(struct exp_addr *, int);
bool  sender_is_child(struct exp_link *, int);
void  suppress_addrs(struct exp_link *, int);
int   exp_addr_permitted_add(struct exp_addr *, yastr);
void  exp_addr_permitted_destroy(struct exp_addr *);
char *exp_addr_parent_permitted(struct exp_addr *);
#endif /* HAVE_LDAP */

#endif /* SIMTA_EXPAND_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
