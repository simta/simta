/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LDAP
#include <ldap.h>
#endif /* HAVE_LDAP */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "header.h"
#include "simta.h"
#include "simta_malloc.h"
#include "simta_util.h"
#include "srs.h"

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#endif

#ifdef HAVE_LMDB
#include "simta_lmdb.h"
#endif /* HAVE_LMDB */


struct envelope *
address_bounce_create(struct expand *exp) {
    struct envelope *bounce_env;

    if ((bounce_env = env_create(simta_dir_fast, NULL, "", exp->exp_env)) ==
            NULL) {
        return (NULL);
    }

    bounce_env->e_next = exp->exp_errors;
    exp->exp_errors = bounce_env;

    return (bounce_env);
}


simta_result
address_string_recipients(struct expand *exp, char *line,
        struct exp_addr *e_addr, char *from, int *count) {
    yastr *split;
    size_t tok_count;

    split = parse_addr_list(line, &tok_count, HEADER_MAILBOX_LIST);
    if (split) {
        for (int i = 0; i < tok_count; i++) {
            if (add_address(exp, split[ i ], e_addr->e_addr_errors,
                        ADDRESS_TYPE_EMAIL, from, false) != SIMTA_OK) {
                yaslfreesplitres(split, tok_count);
                return SIMTA_ERR;
            }
            if (count) {
                (*count)++;
            }
        }

        yaslfreesplitres(split, tok_count);
    }

    return SIMTA_OK;
}


simta_result
add_address(struct expand *exp, char *addr, struct envelope *error_env,
        int addr_type, char *from, bool force_root) {
    struct exp_addr *e;
    char            *domain = NULL;
#ifdef HAVE_LDAP
    struct exp_addr *cursor = NULL;
#endif /* HAVE_LDAP */

    for (e = exp->exp_addr_head; e != NULL; e = e->e_addr_next) {
        if (strcasecmp(addr, e->e_addr) == 0) {
            break;
        }
    }

    if (e == NULL) {
        e = simta_calloc(1, sizeof(struct exp_addr));

        e->e_addr_errors = error_env;
        e->e_addr_type = addr_type;
        if (!force_root) {
            e->e_addr_parent_rule = exp->exp_current_rule;
        }
        exp->exp_entries++;

        if ((addr[ 0 ] == '\0') || (strcasecmp(addr, "postmaster") == 0)) {
            e->e_addr = simta_strdup(simta_postmaster);
        } else {
            e->e_addr = simta_strdup(addr);
        }
        e->e_addr_from = simta_strdup(from);

        /* do syntax checking and special processing */
        if (addr_type == ADDRESS_TYPE_EMAIL) {
            if ((parse_emailaddr(EMAIL_ADDRESS_NORMAL, e->e_addr, NULL,
                         &domain) != SIMTA_OK) ||
                    (domain == NULL)) {
                syslog(LOG_ERR, "add_address <%s>: bad address", e->e_addr);
                goto error;
            }

            e->e_addr_localpart = yaslnew(e->e_addr, domain - e->e_addr - 1);
            e->e_addr_domain = yaslauto(domain);

#ifdef HAVE_LDAP
            /* check to see if the address is the sender */
            if (exp->exp_env->e_mail != NULL) {
                /* compare the address in hand with the sender */
                if (simta_mbx_compare(e->e_addr, exp->exp_env->e_mail) == 0) {
                    /* here we have a match */
                    e->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
                }
            }
#endif /* HAVE_LDAP */
        }

        if (exp->exp_addr_tail == NULL) {
            exp->exp_addr_head = e;
            exp->exp_addr_tail = e;
        } else if (exp->exp_addr_cursor != NULL) {
            if ((e->e_addr_next = exp->exp_addr_cursor->e_addr_next) == NULL) {
                exp->exp_addr_tail = e;
            }
            exp->exp_addr_cursor->e_addr_next = e;
        } else {
            e->e_addr_next = exp->exp_addr_head;
            exp->exp_addr_head = e;
        }
    }

#ifdef HAVE_LDAP
    if (!force_root) {
        cursor = exp->exp_addr_cursor;
    }

    /* add links */
    if (exp_addr_link(&(e->e_addr_parents), cursor) != 0) {
        return SIMTA_ERR;
    }

    if (cursor != NULL) {
        e->e_addr_max_level = cursor->e_addr_max_level + 1;
        if (exp->exp_max_level < e->e_addr_max_level) {
            exp->exp_max_level = e->e_addr_max_level;
        }

        if (exp_addr_link(&(cursor->e_addr_children), e) != 0) {
            return SIMTA_ERR;
        }
    }
#endif /* HAVE_LDAP */

    return SIMTA_OK;

error:
    simta_free(e->e_addr);
    simta_free(e->e_addr_from);
    simta_free(e);
    return SIMTA_ERR;
}


simta_address_status
address_expand(struct expand *exp) {
    struct exp_addr     *e_addr;
    const ucl_object_t  *red = NULL;
    ucl_object_iter_t    iter = NULL;
    const ucl_object_t  *rule = NULL;
    const char          *type = NULL;
    const char          *src = NULL;
    const char          *status = NULL;
    simta_address_status rc = ADDRESS_NOT_FOUND;

    e_addr = exp->exp_addr_cursor;

#ifdef HAVE_LDAP
    if (e_addr->e_addr_type == ADDRESS_TYPE_LDAP) {
        type = "ldap";
        rule = e_addr->e_addr_parent_rule;
        src = ucl_object_tostring(ucl_object_lookup_path(rule, "ldap.uri"));
        rc = simta_ldap_expand(rule, exp, e_addr);
    }
#endif /*  HAVE_LDAP */

    if (e_addr->e_addr_type == ADDRESS_TYPE_EMAIL) {
        if (yasllen(e_addr->e_addr_domain) > SIMTA_MAX_HOST_NAME_LEN) {
            syslog(LOG_ERR, "Expand env <%s>: <%s>: domain too long",
                    exp->exp_env->e_id, e_addr->e_addr);
            return ADDRESS_SYSERROR;
        }

        /* Check to see if domain is off the local host */
        red = red_host_lookup(e_addr->e_addr_domain, false);

        if ((red == NULL) || !red_does_expansion(red)) {
            simta_debuglog(1, "Expand env <%s>: <%s>: expansion complete",
                    exp->exp_env->e_id, e_addr->e_addr);
            return ADDRESS_OK;
        }

        /* Expand user using expansion table for domain */
        iter = ucl_object_iterate_new(ucl_object_lookup(red, "rule"));
        while ((rule = ucl_object_iterate_safe(iter, false)) != NULL) {
            exp->exp_current_rule = rule;

            if (!ucl_object_toboolean(
                        ucl_object_lookup_path(rule, "expand.enabled"))) {
                simta_debuglog(3,
                        "Expand env <%s>: <%s>: skipping non-expand rule %s",
                        exp->exp_env->e_id, e_addr->e_addr,
                        ucl_object_tostring_forced(rule));
                continue;
            }

            type = ucl_object_tostring(ucl_object_lookup(rule, "type"));

            if (strcasecmp(type, "accept") == 0) {
                rc = ADDRESS_OK;
            }

#ifdef HAVE_LMDB
            if (strcasecmp(type, "alias") == 0) {
                src = ucl_object_tostring(
                        ucl_object_lookup_path(rule, "alias.path"));
                rc = alias_expand(exp, e_addr, rule);
            }
#endif /* HAVE_LMDB */

            if (strcasecmp(type, "password") == 0) {
                src = ucl_object_tostring(
                        ucl_object_lookup_path(rule, "password.path"));
                rc = password_expand(exp, e_addr, rule);
            }

            if (strcasecmp(type, "srs") == 0) {
                src = "SRS";
                rc = srs_expand(exp, e_addr, rule);
            }

#ifdef HAVE_LDAP
            if (strcasecmp(type, "ldap") == 0) {
                src = ucl_object_tostring(
                        ucl_object_lookup_path(rule, "ldap.uri"));
                rc = simta_ldap_expand(rule, exp, e_addr);
            }
#endif /* HAVE_LDAP */

            if (rc != ADDRESS_NOT_FOUND) {
                break;
            }
        }
        ucl_object_iterate_free(iter);
    }

    switch (rc) {
    case ADDRESS_SYSERROR:
        status = "error";
        break;

    case ADDRESS_OK:
    case ADDRESS_OK_SPAM:
        status = "terminal";
        break;

    case ADDRESS_EXCLUDE:
        status = "found";
        break;

    case ADDRESS_NOT_FOUND:
        status = "not found";
        break;
    }

    simta_debuglog(1, "Expand.%s env <%s>: <%s>: %s in %s", type,
            exp->exp_env->e_id, e_addr->e_addr, status, src);

    if (rc != ADDRESS_NOT_FOUND) {
        return rc;
    }

    /* If we can't resolve postmaster, add it to the dead queue. */
    if (strncasecmp(e_addr->e_addr, "postmaster@", strlen("postmaster@")) ==
            0) {
        if (strcasecmp(e_addr->e_addr, simta_postmaster) != 0) {
            /* Redirect to local postmaster */
            if (add_address(exp, simta_postmaster, e_addr->e_addr_errors,
                        ADDRESS_TYPE_EMAIL, e_addr->e_addr_from,
                        false) != SIMTA_OK) {
                return ADDRESS_SYSERROR;
            }
            return ADDRESS_EXCLUDE;
        } else {
            /* Send to dead queue */
            e_addr->e_addr_type = ADDRESS_TYPE_DEAD;
            syslog(LOG_ERR,
                    "Expand env <%s>: <%s>: can't resolve postmaster, "
                    "expanding to dead queue",
                    exp->exp_env->e_id, e_addr->e_addr);
            return ADDRESS_OK;
        }
    }

    syslog(LOG_INFO, "Expand env <%s>: <%s>: not found", exp->exp_env->e_id,
            e_addr->e_addr);

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                "address not found: ", e_addr->e_addr, NULL) != 0) {
        /* bounce_text syslogs errors */
        return ADDRESS_SYSERROR;
    }

    return ADDRESS_EXCLUDE;
}


struct passwd *
simta_getpwnam(const char *fname, const char *user) {
    static struct passwd pwent;
    static yastr         buf = NULL;
    SNET                *snet;
    char                *line;
    char                *c;
    size_t               userlen;

    if (strcmp(fname, "/etc/passwd") == 0) {
        /* Use the system password database, which may or may not just read
         * from /etc/passwd.
         */
        return getpwnam(user);
    }

    /* Otherwise, read and parse the passwd-like file ourselves. */
    if ((snet = snet_open(fname, O_RDONLY, 0)) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_getpwnam snet_open %s: %m", fname);
        return (NULL);
    }

    userlen = strlen(user);
    while ((line = snet_getline(snet, NULL)) != NULL) {
        while ((line[ 0 ] == ' ') || (line[ 0 ] == '\t')) {
            /* leading whitespace */
            line++;
        }

        if ((line[ 0 ] == '#') || (line[ 0 ] == '\0')) {
            /* comment or blank line */
            continue;
        }

        /* Match against the username */
        if ((strlen(line) <= userlen) || (line[ userlen ] != ':') ||
                (strncasecmp(user, line, userlen) != 0)) {
            continue;
        }

        /* Ve haf match */
        if (buf == NULL) {
            buf = yaslauto(line);
        } else {
            yaslclear(buf);
            buf = yaslcat(buf, line);
        }
        c = buf;

        /* username */
        pwent.pw_name = c;
        if ((c = strchr(c, ':')) == NULL) {
            continue;
        }
        *c++ = '\0';

        /* password */
        if ((c = strchr(c, ':')) == NULL) {
            continue;
        }
        c++;

        /* uid */
        if ((c = strchr(c, ':')) == NULL) {
            continue;
        }
        c++;

        /* gid */
        if ((c = strchr(c, ':')) == NULL) {
            continue;
        }
        c++;

        /* GECOS */
        pwent.pw_gecos = c;
        if ((c = strchr(c, ':')) == NULL) {
            continue;
        }
        *c++ = '\0';

        /* home */
        pwent.pw_dir = c;
        if ((c = strchr(c, ':')) == NULL) {
            continue;
        }
        *c++ = '\0';

        /* shell */
        pwent.pw_shell = c;

        /* If we made it here we have a matching, valid line */
        break;
    }

    if (snet_close(snet) != 0) {
        syslog(LOG_ERR, "Liberror: simta_getpwnam snet_close: %m");
    }

    if (line) {
        return (&pwent);
    }

    return (NULL);
}


int
password_expand(
        struct expand *exp, struct exp_addr *e_addr, const ucl_object_t *rule) {
    int            ret;
    struct passwd *passwd;
    yastr          fname = NULL;
    yastr          buf;
    size_t         tok_count;
    yastr         *split;

    /* Special handling for /dev/null */
    if (strncasecmp(e_addr->e_addr, "/dev/null@", 10) == 0) {
        syslog(LOG_INFO,
                "Expand.password env <%s>: <%s>: expanded to /dev/null",
                exp->exp_env->e_id, e_addr->e_addr);
        return (ADDRESS_OK);
    }

    /* Check password file */
    passwd = simta_getpwnam(
            ucl_object_tostring(ucl_object_lookup_path(rule, "password.path")),
            e_addr->e_addr_localpart);

    if (passwd == NULL) {
        /* not in passwd file, try next expansion */
        return (ADDRESS_NOT_FOUND);
    }

    ret = ADDRESS_OK;

    /* Check .forward */
    fname = yaslcat(yaslauto(passwd->pw_dir), "/.forward");

    if (access(fname, F_OK) != 0) {
        simta_debuglog(2, "Expand.password env <%s>: <%s>: no .forward",
                exp->exp_env->e_id, e_addr->e_addr);
        return (ADDRESS_OK);
    }

    buf = simta_slurp(fname);
    yaslfree(fname);
    if (buf == NULL) {
        return (ADDRESS_SYSERROR);
    }

    split = yaslsplitlen(buf, yasllen(buf), "\n", 1, &tok_count);
    yaslfree(buf);
    for (int i = 0; i < tok_count; i++) {
        if (yasllen(split[ i ]) == 0) {
            continue;
        }

        if (((split[ i ][ 0 ] == '/') &&
                    (strcmp(split[ i ], "/dev/null") != 0)) ||
                (split[ i ][ 0 ] == '|')) {
            simta_debuglog(1,
                    "Expand.password env <%s>: <%s>: unsupported "
                    ".forward request: %s",
                    exp->exp_env->e_id, e_addr->e_addr, split[ i ]);
            continue;
        }

        if (address_string_recipients(exp, split[ i ], e_addr,
                    e_addr->e_addr_from, NULL) != SIMTA_OK) {
            /* add_address syslogs errors */
            ret = ADDRESS_SYSERROR;
            goto cleanup_forward;
        }

        simta_debuglog(1,
                "Expand.password env <%s>: <%s>: expanded to <%s>: .forward",
                exp->exp_env->e_id, e_addr->e_addr, split[ i ]);
        ret = ADDRESS_EXCLUDE;
    }

cleanup_forward:
    yaslfreesplitres(split, tok_count);
    return (ret);
}


#ifdef HAVE_LMDB
yastr
simta_alias_key(const ucl_object_t *rule, yastr address) {
    char       *paddr;
    const char *subaddr_sep = NULL;

    if (strncasecmp(address, "owner-", 6) == 0) {
        /* Canonicalise sendmail-style owner */
        yaslrange(address, 6, -1);
        address = yaslcat(address, "-errors");
    } else if (((paddr = strrchr(address, '-')) != NULL) &&
               ((strcasecmp(paddr, "-owner") == 0) ||
                       (strcasecmp(paddr, "-owners") == 0) ||
                       (strcasecmp(paddr, "-error") == 0) ||
                       (strcasecmp(paddr, "-request") == 0) ||
                       (strcasecmp(paddr, "-requests") == 0))) {
        /* simta-style owners are all the same for ALIAS.
         * errors is canonical */
        yaslrange(address, 0, paddr - address);
        address = yaslcat(address, "errors");
    }

    /* Handle subaddressing */
    if ((subaddr_sep = ucl_object_tostring(ucl_object_lookup_path(
                 rule, "expand.subaddress_separators"))) != NULL) {
        for (int i = 0; i < strlen(subaddr_sep); i++) {
            yaslrangesepleft(address, subaddr_sep[ i ]);
        }
    }

    return address;
}


int
simta_alias_db_open(const ucl_object_t *rule, struct simta_dbh **dbh) {
    yastr             db_path = NULL;
    struct simta_dbh *new_dbh = NULL;
    int               ret = SIMTA_DB_OK;

    db_path = yaslauto(
            ucl_object_tostring(ucl_object_lookup_path(rule, "alias.path")));
    db_path = yaslcat(db_path, ".db");

    if (access(db_path, F_OK) != 0) {
        syslog(LOG_ERR, "Liberror: simta_alias_db_open access %s: %m", db_path);
        ret = SIMTA_DB_NOTFOUND;
        goto done;
    }

    if ((ret = simta_db_open_r(&new_dbh, db_path)) != SIMTA_DB_OK) {
        syslog(LOG_ERR, "Liberror: simta_alias_db_open simta_db_open_r %s: %s",
                db_path, simta_db_strerror(ret));
        simta_db_close(new_dbh);
        goto done;
    }

    *dbh = new_dbh;
done:
    yaslfree(db_path);
    return ret;
}


int
alias_expand(
        struct expand *exp, struct exp_addr *e_addr, const ucl_object_t *rule) {
    int               ret = ADDRESS_NOT_FOUND;
    yastr             address = NULL;
    yastr             owner = NULL;
    yastr             owner_value = NULL;
    yastr             value = NULL;
    yastr             alias_addr;
    struct simta_dbc *dbcp = NULL, *owner_dbcp = NULL;
    struct simta_dbh *dbh = NULL;

    if ((ret = simta_alias_db_open(rule, &dbh)) != 0) {
        syslog(LOG_ERR, "Liberror: alias_expand simta_db_open_r: %s",
                simta_db_strerror(ret));
        ret = ADDRESS_NOT_FOUND;
        goto done;
    }

    address = simta_alias_key(rule, yasldup(e_addr->e_addr_localpart));

    if ((ret = simta_db_cursor_open(dbh, &dbcp)) != 0) {
        syslog(LOG_ERR, "Liberror: alias_expand simta_db_cursor_open: %s",
                simta_db_strerror(ret));
        ret = ADDRESS_SYSERROR;
        goto done;
    }

    if ((ret = simta_db_cursor_get(dbcp, &address, &value)) != 0) {
        if (ret == SIMTA_DB_NOTFOUND) {
            ret = ADDRESS_NOT_FOUND;
        } else {
            syslog(LOG_ERR, "Liberror: alias_expand simta_db_cursor_get: %s",
                    simta_db_strerror(ret));
            ret = ADDRESS_SYSERROR;
        }
        goto done;
    }

    owner = yasldup(address);
    owner = yaslcat(owner, "-errors");
    if ((ret = simta_db_cursor_open(dbh, &owner_dbcp)) != 0) {
        syslog(LOG_ERR, "Liberror: alias_expand simta_db_cursor_open: %s",
                simta_db_strerror(ret));
        ret = ADDRESS_SYSERROR;
        goto done;
    }
    if ((ret = simta_db_cursor_get(owner_dbcp, &owner, &owner_value)) != 0) {
        if (ret != SIMTA_DB_NOTFOUND) {
            syslog(LOG_ERR, "Liberror: alias_expand simta_db_cursor_get: %s",
                    simta_db_strerror(ret));
            ret = ADDRESS_SYSERROR;
            goto done;
        }
    } else {
        owner = yaslcatprintf(owner, "@%s",
                ucl_object_tostring(
                        ucl_object_lookup(rule, "associated_domain")));
        if ((e_addr->e_addr_errors = address_bounce_create(exp)) == NULL) {
            syslog(LOG_ERR,
                    "Expand.alias env <%s>: <%s>: "
                    "failed creating error env: %s",
                    exp->exp_env->e_id, e_addr->e_addr, owner);
            ret = ADDRESS_SYSERROR;
            goto done;
        }
        if (env_recipient(e_addr->e_addr_errors, owner) != 0) {
            syslog(LOG_ERR,
                    "Expand.alias env <%s>: <%s>: "
                    "failed setting error recip: %s",
                    exp->exp_env->e_id, e_addr->e_addr, owner);
            ret = ADDRESS_SYSERROR;
            goto done;
        }
        e_addr->e_addr_from = simta_strdup(owner);
    }

    for (;;) {
        alias_addr = yaslauto(value);

        if (correct_emailaddr(&alias_addr,
                    simta_config_str("core.masquerade")) != SIMTA_OK) {
            syslog(LOG_INFO, "Expand.alias env <%s>: <%s>: bad expansion <%s>",
                    exp->exp_env->e_id, e_addr->e_addr, alias_addr);
            yaslfree(alias_addr);
        } else {
            if (add_address(exp, alias_addr, e_addr->e_addr_errors,
                        ADDRESS_TYPE_EMAIL, e_addr->e_addr_from,
                        false) != SIMTA_OK) {
                /* add_address syslogs errors */
                ret = ADDRESS_SYSERROR;
                goto done;
            }
            simta_debuglog(1, "Expand.alias env <%s>: <%s>: expanded to <%s>",
                    exp->exp_env->e_id, e_addr->e_addr, alias_addr);
            yaslfree(alias_addr);
        }

        /* Get next db result, if any */
        if ((ret = simta_db_cursor_get(dbcp, &address, &value)) != 0) {
            if (ret != SIMTA_DB_NOTFOUND) {
                syslog(LOG_ERR, "Liberror: alias_expand db_cursor_get: %s",
                        simta_db_strerror(ret));
                ret = ADDRESS_SYSERROR;
            } else {
                /* one or more addresses found in alias db */
                ret = ADDRESS_EXCLUDE;
            }
            goto done;
        }
    }

done:
    yaslfree(address);
    yaslfree(owner);
    yaslfree(value);
    yaslfree(owner_value);
    simta_db_cursor_close(dbcp);
    simta_db_cursor_close(owner_dbcp);
    simta_db_close(dbh);
    return ret;
}
#endif /* HAVE_LMDB */

#ifdef HAVE_LDAP
int
exp_addr_link(struct exp_link **links, struct exp_addr *add) {
    struct exp_link *link;

    for (link = *links; link != NULL; link = link->el_next) {
        if (link->el_exp_addr == add) {
            return (0);
        }
    }

    link = simta_calloc(1, sizeof(struct exp_link));

    link->el_exp_addr = add;
    link->el_next = *links;
    *links = link;

    return (0);
}


void
exp_addr_link_free(struct exp_link *links) {
    struct exp_link *link;

    while ((link = links) != NULL) {
        links = links->el_next;
        simta_free(link);
    }

    return;
}
#endif /* HAVE_LDAP */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
