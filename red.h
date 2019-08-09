#ifndef SIMTA_RED_H
#define SIMTA_RED_H

#include <stdbool.h>

#include <ucl.h>
#include <yasl.h>

#include "expand.h"

#ifdef HAVE_LMDB
#include "simta_lmdb.h"
#endif /* HAVE_LMDB */


void                red_host_insert(const char *, ucl_object_t *);
const ucl_object_t *red_host_lookup(const char *, bool);
bool                red_does_expansion(const ucl_object_t *);

void red_hosts_stdout(void);
void red_action_stdout(void);

#ifdef HAVE_LMDB
int alias_expand(struct expand *, struct exp_addr *, const ucl_object_t *);
#endif /* HAVE_LMDB */
int password_expand(struct expand *, struct exp_addr *, const ucl_object_t *);
#ifdef HAVE_LDAP
void red_close_ldap_dbs(void);
#endif /* HAVE_LDAP */

#endif /* SIMTA_RED_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
