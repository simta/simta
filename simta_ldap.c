/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <ldap.h>
#include <yasl.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "dn.h"
#include "header.h"
#include "simta.h"
#include "simta_ldap.h"
#include "simta_malloc.h"
#include "simta_statsd.h"
#include "srs.h"

/*
** ldap_search_list -- Contains a parsed uri from the config file.
*/
struct ldap_search_list {
    LDAPURLDesc *            lds_plud;        /* url parsed description */
    int                      lds_rdn_pref;    /* TRUE / FALSE */
    int                      lds_search_type; /* one of USER, GROUP, ALL */
    const char *             lds_string;      /* uri string */
    struct ldap_search_list *lds_next;        /* next uri */
};

/* Values for ldapbind */
#define BINDSASL 2
#define BINDSIMPLE 1
#define BINDANON 0

struct simta_ldap {
    ucl_object_t *           ldap_rule;
    struct ldap_search_list *ldap_searches;
    LDAP *                   ldap_ld;
    int                      ldap_starttls;
    int                      ldap_bind;
    char **                  ldap_attrs;
    const char *             ldap_tls_cert;
    const char *             ldap_tls_key;
    const char *             ldap_tls_cacert;
    const char *             ldap_binddn;
    const char *             ldap_bindpw;
    const char *             ldap_autoreply_host;
    const char *             ldap_autoreply_attr;
    const char *             ldap_autoreply_start_attr;
    const char *             ldap_autoreply_end_attr;
    const char *             ldap_mailfwdattr;
    const char *             ldap_gmailfwdattr;
    const char *             ldap_mailattr;
    const char *             ldap_moderators_attr;
    const char *             ldap_permitted_groups_attr;
    const char *             ldap_permitted_senders_attr;
    const char *             ldap_associated_domain;
};

static int ldapdebug;

/* Object caches */
static ucl_object_t *ldap_configs = NULL;
static ucl_object_t *ldap_connections = NULL;

void                        simta_ldap_unescape(yastr);
simta_result                simta_ld_init(struct simta_ldap *, const yastr);
void                        simta_ldap_unbind(struct simta_ldap *);
static simta_result         simta_ldap_retry(struct simta_ldap *);
static yastr                simta_addr_demangle(const char *);
static simta_address_status simta_ldap_search(
        struct simta_ldap *, char *, int, char *, LDAPMessage **);
static bool  simta_ldap_bool(struct simta_ldap *, LDAPMessage *, const char *);
static yastr simta_ldap_yastr(struct simta_ldap *, LDAPMessage *, const char *);
static time_t simta_ldap_time_t(
        struct simta_ldap *, LDAPMessage *, const char *);
static bool simta_ldap_is_objectclass(
        struct simta_ldap *, LDAPMessage *, const char *);
static yastr simta_ldap_dn_name(struct simta_ldap *, LDAPMessage *);
static int   simta_ldap_name_search(struct simta_ldap *, struct expand *,
          struct exp_addr *, char *, char *, int);
static struct envelope *simta_ldap_envelope_from_attr(struct simta_ldap *,
        LDAPMessage *, struct envelope *, const char *, const char *);
static int  simta_ldap_permitted_create(struct exp_addr *, struct berval **);
static int  simta_ldap_expand_group(struct simta_ldap *, struct expand *,
         struct exp_addr *, int, LDAPMessage *);
static void do_noemail(
        struct simta_ldap *, struct exp_addr *, char *, LDAPMessage *);
static void do_ambiguous(
        struct simta_ldap *, struct exp_addr *, char *, LDAPMessage *);
static bool simta_ldap_check_autoreply(struct simta_ldap *, LDAPMessage *);
static int  simta_ldap_process_entry(struct simta_ldap *, struct expand *,
         struct exp_addr *, int, LDAPMessage *, char *);
static int  simta_ldap_dn_expand(
         struct simta_ldap *, struct expand *, struct exp_addr *);


#ifdef SIMTA_LDAP_DEBUG
/*
** simta_ldap_message_stdout -- Dumps an entry to stdout
*/

static int
simta_ldap_message_stdout(struct simta_ldap *ld, LDAPMessage *m) {
    LDAPMessage *entry;
    LDAPMessage *message;
    char *       dn;
    char *       attribute;
    BerElement * ber;
    char **      values;
    int          idx;

    if ((entry = ldap_first_entry(ld->ldap_ld, m)) == NULL) {
        ldap_perror(ld->ldap_ld, "ldap_first_entry");
        return (-1);
    }

    if ((message = ldap_first_message(ld->ldap_ld, m)) == NULL) {
        ldap_perror(ld->ldap_ld, "ldap_first_message");
        return (-1);
    }

    if ((dn = ldap_get_dn(ld->ldap_ld, message)) == NULL) {
        ldap_perror(ld->ldap_ld, "ldap_get_dn");
        return (-1);
    }

    printf("dn: %s\n", dn);
    ldap_memfree(dn);

    for (attribute = ldap_first_attribute(ld->ldap_ld, message, &ber);
            attribute != NULL;
            attribute = ldap_next_attribute(ld->ldap_ld, message, ber)) {
        printf("%s:\n", attribute);

        if ((values = ldap_get_values(ld->ldap_ld, entry, attribute)) == NULL) {
            ldap_perror(ld->ldap_ld, "ldap_get_values");
            return (-1);
        }

        for (idx = 0; values[ idx ] != NULL; idx++) {
            printf("   %s\n", values[ idx ]);
        }

        ldap_value_free(values);
    }

    ber_free(ber, 0);

    return (0);
}
#endif

static yastr
simta_ldap_dn_name(struct simta_ldap *ld, LDAPMessage *res) {
    char * dn;
    LDAPDN ldn = NULL;
    yastr  retval = NULL;

    dn = ldap_get_dn(ld->ldap_ld, res);
    if (ldap_str2dn(dn, &ldn, LDAP_DN_FORMAT_LDAPV3) != LDAP_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ldap_dn_name ldap_str2dn: "
                "failed to parse %s",
                dn);
        retval = yaslauto("Malformed LDAP result");
    } else {
        retval = yaslnew(
                (*ldn[ 0 ])->la_value.bv_val, (*ldn[ 0 ])->la_value.bv_len);
    }
    ldap_dnfree(ldn);
    ldap_memfree(dn);
    return (retval);
}

void
simta_ldap_unescape(yastr s) {
    char * p;
    size_t i;

    /* Unescape quoted string */
    if (*s == '"') {
        yaslrange(s, 1, -2);
        i = 0;
        for (p = s; *p != '\0'; p++) {
            if (*p == '\\') {
                p++;
            }
            s[ i ] = *p;
            i++;
        }
        s[ i ] = '\0';
        yaslupdatelen(s);
    }

    /* Replace space equivalent characters with spaces. */
    yaslmapchars(s, "._", "  ", 2);
}


#ifdef HAVE_LIBSASL
/*
** SASL Call Back
** This SASL callback works for "EXTERNAL" and "GSSAPI" SASL methods
*/
static int
simta_ldap_sasl_interact(
        LDAP *ld, int unsigned flags, void *defaults, void *in) {

    sasl_interact_t *interact = in;

    while (interact->id != SASL_CB_LIST_END) {
        interact->result = NULL;
        interact->len = 0;
        interact++;
    }

    return LDAP_SUCCESS;
}
#endif


simta_result
simta_ld_init(struct simta_ldap *ld, const yastr key) {
    int         maxambiguous = 10;
    int         protocol = LDAP_VERSION3;
    LDAP *      ldap_ld = NULL;
    int         rc;
    const char *uri;

    uri = ucl_object_tostring(ucl_object_lookup(ld->ldap_rule, "uri"));
    simta_debuglog(1, "LDAP: opening connection to %s", uri);
    statsd_counter("ldap", "connection", 1);

    if ((rc = ldap_initialize(&ldap_ld, uri)) != 0) {
        syslog(LOG_ERR, "Liberror: simta_ld_init ldap_initialize: %s",
                ldap_err2string(rc));
        return SIMTA_ERR;
    }

    if (ldapdebug) {
        if ((ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldapdebug)) !=
                LBER_OPT_SUCCESS) {
            syslog(LOG_ERR,
                    "Liberror: simta_ld_init ber_set_option "
                    "LBER_OPT_DEBUG_LEVEL %d: failed",
                    ldapdebug);
        }
        if ((ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldapdebug)) !=
                LDAP_OPT_SUCCESS) {
            syslog(LOG_ERR,
                    "Liberror: simta_ld_init ldap_set_option "
                    "LDAP_OPT_DEBUG_LEVEL %d: failed",
                    ldapdebug);
        }
    }

    /* Tell libldap to handle EINTR instead of erroring out. */
    if ((ldap_set_option(ldap_ld, LDAP_OPT_RESTART, LDAP_OPT_ON)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_RESTART LDAP_OPT_ON: failed");
        return SIMTA_ERR;
    }

    if ((ldap_set_option(ldap_ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_REFERRALS LDAP_OPT_OFF: failed");
        return SIMTA_ERR;
    }

    if ((ldap_set_option(ldap_ld, LDAP_OPT_SIZELIMIT, (void *)&maxambiguous)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_SIZELIMIT %d: failed",
                maxambiguous);
        return SIMTA_ERR;
    }

    if ((ldap_set_option(ldap_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_PROTOCOL_VERSION %d: failed",
                protocol);
        return SIMTA_ERR;
    }

    ld->ldap_ld = ldap_ld;
    ucl_object_insert_key(ldap_connections,
            ucl_object_new_userdata(NULL, NULL, ldap_ld), key, yasllen(key),
            true);

    return SIMTA_OK;
}

void
simta_ldap_reset(void) {
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;

    if (ldap_connections != NULL) {
        iter = ucl_object_iterate_new(ldap_connections);
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            if (obj->value.ud == NULL) {
                continue;
            }
            simta_debuglog(
                    1, "LDAP: closing connection to %s", ucl_object_key(obj));
            ldap_unbind_ext(obj->value.ud, NULL, NULL);
        }
        ucl_object_iterate_free(iter);

        ucl_object_unref(ldap_connections);
        ldap_connections = ucl_object_typed_new(UCL_OBJECT);
    }

    if (ldap_configs != NULL) {
        ucl_object_unref(ldap_configs);
        ldap_configs = ucl_object_typed_new(UCL_OBJECT);
    }
}

static simta_result
simta_ldap_init(struct simta_ldap *ld) {
    simta_result        retval = SIMTA_ERR;
    int                 ldaprc;
    const ucl_object_t *obj;
    struct berval       creds = {0};
    yastr               key = NULL;

    if (ldap_connections == NULL) {
        ldap_connections = ucl_object_typed_new(UCL_OBJECT);
    }

    if (ld->ldap_ld == NULL) {
        key = yaslauto(
                ucl_object_tostring(ucl_object_lookup(ld->ldap_rule, "uri")));
        key = yaslcatprintf(
                key, ":%s", ld->ldap_binddn ? ld->ldap_binddn : "ANON");

        if ((obj = ucl_object_lookup(ldap_connections, key)) != NULL) {
            ld->ldap_ld = (LDAP *)(obj->value.ud);
            retval = SIMTA_OK;
            goto done;
        }

        if (simta_ld_init(ld, key) != SIMTA_OK) {
            goto done;
        }

#ifdef HAVE_LIBSSL
        if (ld->ldap_starttls) {
            if (ld->ldap_tls_cacert) {
                if ((ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE,
                             ld->ldap_tls_cacert)) != LDAP_OPT_SUCCESS) {
                    syslog(LOG_ERR,
                            "Liberror: simta_ldap_init ldap_set_option "
                            "LDAP_OPT_X_TLS_CACERTFILE %s: %s",
                            ld->ldap_tls_cacert, ldap_err2string(ldaprc));
                    goto done;
                }
            }

            if (ld->ldap_tls_cert) {
                if ((ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE,
                             ld->ldap_tls_cert)) != LDAP_OPT_SUCCESS) {
                    syslog(LOG_ERR,
                            "Liberror: simta_ldap_init ldap_set_option "
                            "LDAP_OPT_X_TLS_CERTFILE %s: %s",
                            ld->ldap_tls_cert, ldap_err2string(ldaprc));
                    goto done;
                }
            }

            if (ld->ldap_tls_key) {
                if ((ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE,
                             ld->ldap_tls_key)) != LDAP_OPT_SUCCESS) {
                    syslog(LOG_ERR,
                            "Liberror: simta_ldap_init ldap_set_option "
                            "LDAP_OPT_X_TLS_KEYFILE %s: %s",
                            ld->ldap_tls_key, ldap_err2string(ldaprc));
                    goto done;
                }
            }

            if ((ldaprc = ldap_start_tls_s(ld->ldap_ld, NULL, NULL)) !=
                    LDAP_SUCCESS) {
                syslog(LOG_ERR,
                        "Liberror: simta_ldap_init ldap_start_tls_s: %s",
                        ldap_err2string(ldaprc));
                if (ld->ldap_starttls == 2) {
                    goto done;
                }
            }
        }
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
        if (ld->ldap_bind == BINDSASL) {
            if ((ldaprc = ldap_sasl_interactive_bind_s(ld->ldap_ld,
                         ld->ldap_binddn, NULL, NULL, NULL, LDAP_SASL_QUIET,
                         simta_ldap_sasl_interact, NULL)) != LDAP_SUCCESS) {
                syslog(LOG_ERR,
                        "Liberror: simta_ldap_init "
                        "ldap_sasl_interactive_bind_s: %s",
                        ldap_err2string(ldaprc));
                goto done;
            }

            /* If a client-side cert specified,  then do a SASL EXTERNAL bind */
        } else if (ld->ldap_tls_cert) {
            if ((ldaprc = ldap_sasl_interactive_bind_s(ld->ldap_ld,
                         ld->ldap_binddn, "EXTERNAL", NULL, NULL,
                         LDAP_SASL_QUIET, simta_ldap_sasl_interact, NULL)) !=
                    LDAP_SUCCESS) {
                syslog(LOG_ERR,
                        "Liberror: simta_ldap_init "
                        "ldap_sasl_interactive_bind_s: %s",
                        ldap_err2string(ldaprc));
                goto done;
            }

        } else {
#endif /* HAVE_LIBSASL */
            if (ld->ldap_bindpw) {
                creds.bv_val = simta_strdup(ld->ldap_bindpw);
                creds.bv_len = strlen(creds.bv_val);
            }
            if ((ldaprc = ldap_sasl_bind_s(ld->ldap_ld, ld->ldap_binddn,
                         LDAP_SASL_SIMPLE, &creds, NULL, NULL, NULL)) !=
                    LDAP_SUCCESS) {
                syslog(LOG_ERR,
                        "Liberror: simta_ldap_init ldap_sasl_bind_s: %s",
                        ldap_err2string(ldaprc));
                goto done;
            }
#ifdef HAVE_LIBSASL
        }
#endif /* HAVE_LIBSASL */
    }

    retval = SIMTA_OK;

done:
    yaslfree(key);

    if (retval != SIMTA_OK) {
        simta_ldap_unbind(ld);
    }
    if (creds.bv_val) {
        free(creds.bv_val);
    }

    return retval;
}

static simta_address_status
simta_ldap_search(struct simta_ldap *ld, char *base, int scope, char *filter,
        LDAPMessage **res) {
    struct timeval       tv_start, tv_now, tv_timeout;
    int                  rc = LDAP_SERVER_DOWN;
    int                  retries;
    simta_address_status retval = ADDRESS_SYSERROR;
    int                  count;

    simta_ucl_object_totimeval(
            ucl_object_lookup_path(ld->ldap_rule, "timeout"), &tv_timeout);

    retries =
            ucl_object_toint(ucl_object_lookup_path(ld->ldap_rule, "retries"));
    if (retries < 1) {
        retries = 1;
    }

    for (; (rc == LDAP_SERVER_DOWN) && (retries > 0); retries--) {
        /* only do the search if we successfully connected */
        if (ld->ldap_ld) {
            simta_gettimeofday(&tv_start);

            rc = ldap_search_ext_s(ld->ldap_ld, base, scope, filter,
                    ld->ldap_attrs, 0, NULL, NULL, &tv_timeout, LDAP_NO_LIMIT,
                    res);

            simta_gettimeofday(&tv_now);
            statsd_timer("ldap", "query", SIMTA_ELAPSED_MSEC(tv_start, tv_now));
        }

        /* if the server went down or we failed to connect, reconnect */
        if ((rc == LDAP_SERVER_DOWN) && retries > 1) {
            statsd_counter("ldap", "retry", 1);
            ldap_msgfree(*res);
            *res = NULL;
            simta_ldap_retry(ld);
        }
    }

    switch (rc) {
    case LDAP_SUCCESS:
        statsd_counter("ldap.query_result", "success", 1);
        if ((count = ldap_count_entries(ld->ldap_ld, *res)) > 0) {
            retval = ADDRESS_OK;
        } else if (count == 0) {
            statsd_counter("ldap.query_result", "not_found", 1);
            retval = ADDRESS_NOT_FOUND;
        }
        break;
    case LDAP_FILTER_ERROR:
    case LDAP_NO_SUCH_OBJECT:
        statsd_counter("ldap.query_result", "error", 1);
        retval = ADDRESS_NOT_FOUND;
        break;
    case LDAP_SIZELIMIT_EXCEEDED:
    case LDAP_TIMELIMIT_EXCEEDED:
        if (ldap_count_entries(ld->ldap_ld, *res) > 0) {
            retval = ADDRESS_OK;
        }
    default:
        syslog(LOG_ERR, "Liberror simta_ldap_search %s: %s", filter,
                ldap_err2string(rc));
        statsd_counter("ldap.query_result", "error", 1);
    }

    return (retval);
}


static bool
simta_ldap_bool(
        struct simta_ldap *ld, LDAPMessage *entry, const char *attribute) {
    struct berval **values;
    bool            retval = false;

    if ((values = ldap_get_values_len(ld->ldap_ld, entry, attribute)) != NULL) {
        if (values[ 0 ] && values[ 0 ]->bv_len == 4 &&
                strncasecmp(values[ 0 ]->bv_val, "TRUE", 4) == 0) {
            retval = true;
        }
        ldap_value_free_len(values);
    }
    return (retval);
}


static yastr
simta_ldap_yastr(
        struct simta_ldap *ld, LDAPMessage *entry, const char *attribute) {
    struct berval **values;
    yastr           buf = NULL;

    if ((values = ldap_get_values_len(ld->ldap_ld, entry, attribute)) != NULL) {
        buf = yaslnew(values[ 0 ]->bv_val, values[ 0 ]->bv_len);
        ldap_value_free_len(values);
    }
    return buf;
}


static time_t
simta_ldap_time_t(
        struct simta_ldap *ld, LDAPMessage *entry, const char *attribute) {
    yastr     buf = NULL;
    time_t    retval = 0;
    struct tm tm_time;
    char *    tz;

    memset(&tm_time, 0, sizeof(struct tm));
    if ((buf = simta_ldap_yastr(ld, entry, attribute)) == NULL) {
        return retval;
    }

    /* RFC 4517 Generalized Time makes everything after the hour optional */

    if ((strptime(buf, "%Y%m%d%H%M%S", &tm_time) != NULL) ||
            (strptime(buf, "%Y%m%d%H%M", &tm_time) != NULL) ||
            (strptime(buf, "%Y%m%d%H", &tm_time) != NULL)) {
        /* We're going to assume that everything is UTC as the gods intended */
        if ((tz = getenv("TZ")) != NULL) {
            tz = strdup(tz);
        }
        setenv("TZ", "", 1);
        tzset();
        retval = mktime(&tm_time);
        if (tz) {
            setenv("TZ", tz, 1);
            free(tz);
        } else {
            unsetenv("TZ");
        }
        tzset();
    } else {
        syslog(LOG_NOTICE,
                "Liberror: simta_ldap_time_t strptime: unable to parse %s",
                buf);
    }

    yaslfree(buf);
    return retval;
}


static bool
simta_ldap_is_objectclass(
        struct simta_ldap *ld, LDAPMessage *e, const char *type) {
    int                 idx;
    struct berval **    values;
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;
    const char *        buf;

    if ((values = ldap_get_values_len(ld->ldap_ld, e, "objectClass")) != NULL) {
        for (idx = 0; values[ idx ] != NULL; idx++) {
            iter = ucl_object_iterate_new(ucl_object_lookup(
                    ucl_object_lookup(ld->ldap_rule, "objectclasses"), type));
            while ((obj = ucl_object_iterate_safe(iter, true)) != NULL) {
                buf = ucl_object_tostring(obj);
                if ((values[ idx ]->bv_len == strlen(buf)) &&
                        strncasecmp(values[ idx ]->bv_val, buf,
                                values[ idx ]->bv_len) == 0) {
                    ucl_object_iterate_free(iter);
                    ldap_value_free_len(values);
                    return (true);
                }
            }
            ucl_object_iterate_free(iter);
        }
        ldap_value_free_len(values);
    }
    return (false);
}

static yastr
simta_ldap_string(char *filter, char *user, char *domain) {
    yastr buf = NULL;
    char *p;
    char *insert;

    buf = yaslMakeRoomFor(yaslempty(), strlen(filter));
    p = filter;

    /* %s -> username, %h -> hostname */
    while (*p != '\0') {
        switch (*p) {
        case '%':
            switch (*(p + 1)) {
            case 's':
                for (insert = user; *insert != '\0'; insert++) {
                    switch (*insert) {
                    case '(':
                    case ')':
                    case '*':
                    case '\\':
                        /* Filter metacharacters are escaped as hex */
                        buf = yaslcatprintf(
                                buf, "\\%02x", (unsigned char)*insert);
                        break;
                    default:
                        buf = yaslcatlen(buf, insert, 1);
                    }
                }

                p += 2;
                break;

            case 'h':
                buf = yaslcat(buf, domain);
                p += 2;
                break;

            case '%':
                /* %% -> copy single % to data buffer */
                buf = yaslcatlen(buf, "%", 1);
                p += 2;
                break;

            default:
                p++;
                break;
            }
            break;

        default:
            buf = yaslcatlen(buf, p, 1);
            p++;
            break;
        }
    }

    return (buf);
}


/*
** Looks at the incoming email address
** looking for "-errors", "-requests", or "-owners"
**
*/
static int
simta_address_type(char *address, const ucl_object_t *rule) {
    int         addrtype;
    char *      paddr;
    const char *subaddr_sep;

    addrtype = LDS_USER; /* default */

    /* Strip off type indicators and record the type */
    if ((paddr = strrchr(address, '-')) != NULL) {
        paddr++;
        if ((strcasecmp(paddr, ERROR) == 0) ||
                (strcasecmp(paddr, ERRORS) == 0)) {
            addrtype = LDS_GROUP_ERRORS;
            *(paddr - 1) = '\0';
        } else if ((strcasecmp(paddr, REQUEST) == 0) ||
                   (strcasecmp(paddr, REQUESTS) == 0)) {
            addrtype = LDS_GROUP_REQUEST;
            *(paddr - 1) = '\0';
        } else if ((strcasecmp(paddr, OWNER) == 0) ||
                   (strcasecmp(paddr, OWNERS) == 0)) {
            addrtype = LDS_GROUP_OWNER;
            *(paddr - 1) = '\0';
        }
    }

    /* Handle subaddressing */
    if ((subaddr_sep = ucl_object_tostring(ucl_object_lookup_path(
                 rule, "expand.subaddress_separators"))) != NULL) {
        for (int i = 0; i < strlen(subaddr_sep); i++) {
            if ((paddr = strchr(address, subaddr_sep[ i ])) != NULL) {
                *paddr = '\0';
            }
        }
    }

    return (addrtype);
}


static void
do_ambiguous(struct simta_ldap *ld, struct exp_addr *e_addr, char *addr,
        LDAPMessage *res) {
    int             idx;
    yastr           rdn;
    yastr           buf;
    struct berval **vals;
    LDAPMessage *   e;

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, addr, ": Ambiguous user",
                NULL) != 0) {
        return;
    }

    for (e = ldap_first_entry(ld->ldap_ld, res); e != NULL;
            e = ldap_next_entry(ld->ldap_ld, e)) {

        rdn = simta_ldap_dn_name(ld, e);

        if (strcasecmp(rdn, addr) == 0) {
            if ((vals = ldap_get_values_len(ld->ldap_ld, e, "cn")) != NULL) {
                yaslclear(rdn);
                rdn = yaslcatlen(rdn, vals[ 0 ]->bv_val, vals[ 0 ]->bv_len);
                ldap_value_free_len(vals);
            }
        }

        if (simta_ldap_is_objectclass(ld, e, "group")) {
            vals = ldap_get_values_len(ld->ldap_ld, e, "description");
        } else {
            vals = ldap_get_values_len(ld->ldap_ld, e, "title");
        }

        if (vals) {
            buf = yaslempty();
            for (idx = 0; vals[ idx ] != NULL; idx++) {
                yaslclear(buf);
                if (idx == 0) {
                    buf = yaslcatyasl(buf, rdn);
                } else {
                    buf = yaslcatlen(buf, "\t", 1);
                }
                buf = yaslcatlen(buf, "\t", 1);
                buf = yaslcatlen(buf, vals[ idx ]->bv_val, vals[ idx ]->bv_len);
                if (bounce_yastr(e_addr->e_addr_errors, TEXT_ERROR, buf) != 0) {
                    yaslfree(buf);
                    return;
                }
            }
            yaslfree(buf);
            buf = NULL;
            ldap_value_free_len(vals);
        } else {
            if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, rdn, NULL,
                        NULL) != 0) {
                return;
            }
        }
        yaslfree(rdn);
    }
}


static void
do_noemail(struct simta_ldap *ld, struct exp_addr *e_addr, char *addr,
        LDAPMessage *res) {
    yastr           rdn;
    struct berval **vals;
    yastr           buf;
    yastr *         split;
    size_t          tok_count;

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, addr,
                ": User has no email address registered.\n", NULL) != 0) {
        return;
    }

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                "\tName, title, postal address and phone for: ", addr,
                NULL) != 0) {
        return;
    }

    /* name */
    rdn = simta_ldap_dn_name(ld, res);
    if (strcasecmp(rdn, addr) == 0) {
        if ((vals = ldap_get_values_len(ld->ldap_ld, res, "cn")) != NULL) {
            yaslclear(rdn);
            rdn = yaslcatlen(rdn, vals[ 0 ]->bv_val, vals[ 0 ]->bv_len);
            ldap_value_free_len(vals);
        }
    }

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t", rdn, NULL) != 0) {
        return;
    }

    yaslfree(rdn);
    buf = yaslempty();

    /* titles or descriptions */
    if (((vals = ldap_get_values_len(ld->ldap_ld, res, "title")) == NULL) &&
            ((vals = ldap_get_values_len(ld->ldap_ld, res, "description")) ==
                    NULL)) {
        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                    "No title or description registered", NULL) != 0) {
            goto error;
        }

    } else {
        for (int i = 0; vals[ i ]; i++) {
            yaslclear(buf);
            buf = yaslcatlen(buf, "\t", 1);
            buf = yaslcatlen(buf, vals[ i ]->bv_val, vals[ i ]->bv_len);
            if (bounce_yastr(e_addr->e_addr_errors, TEXT_ERROR, buf) != 0) {
                goto error;
            }
        }
        ldap_value_free_len(vals);
    }

    /* postal address*/
    if ((vals = ldap_get_values_len(ld->ldap_ld, res, "postaladdress")) ==
            NULL) {
        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                    "No postaladdress registered", NULL) != 0) {
            goto error;
        }

    } else {
        split = yaslsplitlen(
                vals[ 0 ]->bv_val, vals[ 0 ]->bv_len, "$", 1, &tok_count);
        for (int i = 0; i < tok_count; i++) {
            yaslclear(buf);
            buf = yaslcatlen(buf, "\t", 1);
            buf = yaslcatyasl(buf, split[ i ]);
            if (bounce_yastr(e_addr->e_addr_errors, TEXT_ERROR, buf) != 0) {
                yaslfreesplitres(split, tok_count);
                goto error;
            }
        }

        yaslfreesplitres(split, tok_count);
        ldap_value_free_len(vals);
    }

    /* telephone number */
    if ((vals = ldap_get_values_len(ld->ldap_ld, res, "telephoneNumber")) ==
            NULL) {
        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                    "No phone number registered", NULL) != 0) {
            goto error;
        }

    } else {
        for (int i = 0; vals[ i ] != NULL; i++) {
            yaslclear(buf);
            buf = yaslcatlen(buf, "\t", 1);
            buf = yaslcatlen(buf, vals[ i ]->bv_val, vals[ i ]->bv_len);
            if (bounce_yastr(e_addr->e_addr_errors, TEXT_ERROR, buf) != 0) {
                goto error;
            }
        }
        ldap_value_free_len(vals);
        vals = NULL;
    }


error:
    if (vals != NULL) {
        ldap_value_free_len(vals);
    }
    yaslfree(buf);
    return;
}


/*
** Unbind from the directory.
*/

void
simta_ldap_unbind(struct simta_ldap *ld) {
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;

    if ((ld != NULL) && (ld->ldap_ld != NULL)) {
        iter = ucl_object_iterate_new(ldap_connections);
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            if (obj->value.ud == ld->ldap_ld) {
                simta_debuglog(1, "LDAP: closing connection to %s",
                        ucl_object_key(obj));
                ldap_unbind_ext(ld->ldap_ld, NULL, NULL);
                ucl_object_delete_key(ldap_connections, ucl_object_key(obj));
                ld->ldap_ld = NULL;
            }
        }
        ucl_object_iterate_free(iter);
    }
    return;
}


static simta_result
simta_ldap_retry(struct simta_ldap *ld) {
    simta_ldap_unbind(ld);
    if (simta_ldap_init(ld) != SIMTA_OK) {
        return SIMTA_ERR;
    }
    return SIMTA_OK;
}


simta_address_status
simta_ldap_address_local(const ucl_object_t *rule, char *name, char *domain) {
    yastr                    dup_name;
    simta_address_status     rc = ADDRESS_NOT_FOUND;
    yastr                    search_string;
    struct ldap_search_list *lds;
    LDAPMessage *            res = NULL;
    LDAPMessage *            entry;
    struct berval **         vals;
    struct simta_ldap *      ld;

    if ((ld = simta_ldap_config(rule)) == NULL) {
        return ADDRESS_SYSERROR;
    }

    if (simta_ldap_init(ld) != SIMTA_OK) {
        return ADDRESS_SYSERROR;
    }

    dup_name = yaslauto(name);
    simta_ldap_unescape(dup_name);

    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    (void)simta_address_type(dup_name, rule);

    /* for each base string in ldap_searches:
     *     - Build search string
     *     - query the LDAP db with the search string
     */
    for (lds = ld->ldap_searches; lds != NULL; lds = lds->lds_next) {
        search_string =
                simta_ldap_string(lds->lds_plud->lud_filter, dup_name, domain);

        rc = simta_ldap_search(ld, lds->lds_plud->lud_dn,
                lds->lds_plud->lud_scope, search_string, &res);

        yaslfree(search_string);

        if (rc == ADDRESS_SYSERROR) {
            ldap_msgfree(res);
            yaslfree(dup_name);
            simta_ldap_unbind(ld);
            return ADDRESS_SYSERROR;
        } else if (rc == ADDRESS_OK) {
            break;
        }

        ldap_msgfree(res);
        res = NULL;
    }

    yaslfree(dup_name);

    if (rc != ADDRESS_NOT_FOUND) {
        entry = ldap_first_entry(ld->ldap_ld, res);

        /* FIXME: this should be configurable. */
        if (!simta_ldap_bool(ld, entry, "realtimeblocklist")) {
            rc = ADDRESS_OK_SPAM;
        }

        if (simta_ldap_is_objectclass(ld, entry, "person")) {
            if ((vals = ldap_get_values_len(
                         ld->ldap_ld, entry, ld->ldap_mailfwdattr)) == NULL) {
                rc = ADDRESS_NOT_FOUND;
            } else {
                ldap_value_free_len(vals);
            }
        }
    }

    if (res) {
        ldap_msgfree(res);
    }

    return (rc);
}

static int
simta_ldap_permitted_create(struct exp_addr *e, struct berval **list) {
    yastr buf = NULL;

    if (list == NULL) {
        return (0);
    }

    for (int i = 0; list[ i ]; i++) {
        buf = yaslnew(list[ i ]->bv_val, list[ i ]->bv_len);
        dn_normalize_case(buf);
        if (exp_addr_permitted_add(e, buf) != 0) {
            yaslfree(buf);
            return (1);
        }
    }
    return (0);
}

static struct envelope *
simta_ldap_envelope_from_attr(struct simta_ldap *ld, LDAPMessage *entry,
        struct envelope *parent, const char *sender, const char *attr) {
    struct berval ** attr_values = NULL;
    struct envelope *env = NULL;
    yastr            buf = NULL;

    buf = yaslempty();
    if ((attr_values = ldap_get_values_len(ld->ldap_ld, entry, attr)) != NULL) {
        if (parent->e_n_exp_level < simta_exp_level_max) {
            buf = yaslempty();

            if ((env = env_create(simta_dir_fast, NULL, sender, parent)) ==
                    NULL) {
                goto error;
            }

            for (int i = 0; attr_values[ i ]; i++) {
                yaslclear(buf);
                buf = yaslcatlen(buf, attr_values[ i ]->bv_val,
                        attr_values[ i ]->bv_len);
                if (env_string_recipients(env, buf) != 0) {
                    env_rcpt_free(env);
                    goto error;
                }
            }
        }
    }

error:
    yaslfree(buf);
    ldap_value_free_len(attr_values);
    return env;
}

static int
simta_ldap_expand_group(struct simta_ldap *ld, struct expand *exp,
        struct exp_addr *e_addr, int type, LDAPMessage *entry) {
    int               retval = ADDRESS_SYSERROR;
    int               valfound = 0;
    struct berval **  dnvals = NULL;
    struct berval **  mailvals = NULL;
    char *            dn = NULL;
    yastr             group_name = NULL;
    yastr             group_email = NULL;
    char *            errmsg = NULL;
    struct berval **  permitted_domains = NULL;
    struct berval **  permitted_groups = NULL;
    char *            ndn = NULL; /* a "normalized dn" */
    yastr             buf = NULL;
    int               rc;
    yastr             senderbuf = NULL;
    int               suppressnoemail = 0;
    struct berval **  senderlist = NULL;
    struct recipient *r = NULL;
    struct envelope * permitted_env = NULL;

    if ((dn = ldap_get_dn(ld->ldap_ld, entry)) == NULL) {
        syslog(LOG_ERR,
                "Liberror: simta_ldap_expand_group ldap_get_dn: failed");
        return (ADDRESS_SYSERROR);
    }

    buf = yaslempty();

    if (e_addr->e_addr_dn == NULL) {
        dn_normalize_case(dn);
        e_addr->e_addr_dn = simta_strdup(dn);
    }

    if (simta_ldap_bool(ld, entry, "suppressnoemailerror")) {
        suppressnoemail = 1;
    }

    group_name = simta_ldap_dn_name(ld, entry);
    e_addr->e_addr_group_name = yasldup(group_name);
    yasltolower(group_name);
    group_email = yaslcatprintf(
            yasldup(group_name), "@%s", ld->ldap_associated_domain);
    yaslmapchars(group_email, " ", ".", 1);

    e_addr->e_addr_owner = yaslcatprintf(
            yasldup(group_name), "-owner@%s", ld->ldap_associated_domain);
    yaslmapchars(e_addr->e_addr_owner, " ", ".", 1);

    senderbuf = yaslempty();
    if (*(e_addr->e_addr_from) != '\0') {
        /*
        * You can't send mail to groups that have no associatedDomain.
        */
        senderbuf = yaslcatprintf(senderbuf, "%s-errors@%s", group_name,
                ld->ldap_associated_domain);
        yaslmapchars(senderbuf, " ", ".", 1);

        if ((e_addr->e_addr_errors = address_bounce_create(exp)) == NULL) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: failed creating error env %s",
                    exp->exp_env->e_id, e_addr->e_addr, dn);
            goto error;
        }

        if (!is_emailaddr(senderbuf)) {
            yaslclear(senderbuf);
            bounce_text(e_addr->e_addr_errors, TEXT_WARNING,
                    "Illegal email group name: ", group_name, NULL);
        }

        if (env_recipient(e_addr->e_addr_errors, senderbuf) != 0) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: "
                    "failed setting error recipient %s",
                    exp->exp_env->e_id, e_addr->e_addr, dn);
            goto error;
        }
    }

    switch (type) {
    case LDS_GROUP_ERRORS:
        dnvals = ldap_get_values_len(ld->ldap_ld, entry, "errorsto");
        mailvals = ldap_get_values_len(ld->ldap_ld, entry, "rfc822errorsto");
        errmsg = ": Group exists but has no errors-to address\n";

        if ((dnvals == NULL) && (mailvals == NULL)) {
            dnvals = ldap_get_values_len(ld->ldap_ld, entry, "owner");
        }
        break;

    case LDS_GROUP_REQUEST:
        dnvals = ldap_get_values_len(ld->ldap_ld, entry, "requeststo");
        mailvals = ldap_get_values_len(ld->ldap_ld, entry, "rfc822requeststo");
        errmsg = ": Group exists but has no requests-to address\n";

        if ((dnvals == NULL) && (mailvals == NULL)) {
            dnvals = ldap_get_values_len(ld->ldap_ld, entry, "owner");
        }
        break;

    case LDS_GROUP_OWNER:
        dnvals = ldap_get_values_len(ld->ldap_ld, entry, "owner");
        mailvals = NULL;
        errmsg = ": Group exists but has no owners\n";
        break;

    default:
        dnvals = NULL;
        mailvals = NULL;
        errmsg = NULL;

        /* check for group autoreply */
        if (simta_ldap_check_autoreply(ld, entry)) {
            yaslclear(buf);
            buf = yaslcatprintf(
                    buf, "%s@%s", group_name, ld->ldap_autoreply_host);
            yaslmapchars(buf, " ", ".", 1);
            if (add_address(exp, buf, e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL,
                        e_addr->e_addr_from, true) != SIMTA_OK) {
                syslog(LOG_ERR,
                        "Expand.LDAP env <%s>: <%s>: "
                        "failed adding autoreply address: %s",
                        exp->exp_env->e_id, e_addr->e_addr, buf);
            }
        }

        /* check for group email forwarding */
        if (ld->ldap_gmailfwdattr &&
                (mailvals = ldap_get_values_len(
                         ld->ldap_ld, entry, ld->ldap_gmailfwdattr)) != NULL) {
            if (exp->exp_env->e_n_exp_level < simta_exp_level_max) {
                if ((e_addr->e_addr_env_gmailfwd = env_create(simta_dir_fast,
                             NULL, e_addr->e_addr_from, exp->exp_env)) ==
                        NULL) {
                    goto error;
                }

                for (int i = 0; mailvals[ i ]; i++) {
                    yaslclear(buf);
                    buf = yaslcatlen(
                            buf, mailvals[ i ]->bv_val, mailvals[ i ]->bv_len);
                    if (env_string_recipients(
                                e_addr->e_addr_env_gmailfwd, buf) != 0) {
                        env_free(e_addr->e_addr_env_gmailfwd);
                        e_addr->e_addr_env_gmailfwd = NULL;
                        goto error;
                    }
                }

                ldap_value_free_len(mailvals);
                mailvals = NULL;

                if ((r = e_addr->e_addr_env_gmailfwd->e_rcpt) == NULL) {
                    /* no valid email addresses */
                    env_free(e_addr->e_addr_env_gmailfwd);
                    e_addr->e_addr_env_gmailfwd = NULL;
                    bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                            "bad group mail forwarding: ", dn, NULL);
                } else {
                    e_addr->e_addr_env_gmailfwd->e_next = exp->exp_gmailfwding;
                    exp->exp_gmailfwding = e_addr->e_addr_env_gmailfwd;
                }
            } else {
                ldap_value_free_len(mailvals);
                mailvals = NULL;
                bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                        "group mail audit loop: ", dn, NULL);
                break;
            }
        }

        if ((permitted_env = simta_ldap_envelope_from_attr(ld, entry,
                     exp->exp_env, exp->exp_env->e_mail,
                     ucl_object_tostring(ucl_object_lookup_path(ld->ldap_rule,
                             "attributes.permitted_senders")))) != NULL) {
            e_addr->e_addr_requires_permission = true;

            if ((r = permitted_env->e_rcpt) == NULL) {
                /* no valid email addresses */
                bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                        "bad permitted senders: ", dn, NULL);
            } else {
                for (; r != NULL; r = r->r_next) {
                    if (simta_mbx_compare(r->r_rcpt, exp->exp_env->e_mail) ==
                            0) {
                        /* sender matches permitted sender */
                        syslog(LOG_INFO,
                                "Expand.LDAP env <%s>: <%s>: permitted sender "
                                "match %s %s",
                                exp->exp_env->e_id, e_addr->e_addr, r->r_rcpt,
                                exp->exp_env->e_mail);
                        e_addr->e_addr_has_permission = true;
                        break;
                    }
                }
            }

            env_free(permitted_env);
            permitted_env = NULL;
        }

        if ((permitted_domains = ldap_get_values_len(ld->ldap_ld, entry,
                     ucl_object_tostring(ucl_object_lookup_path(ld->ldap_rule,
                             "attributes.permitted_domains")))) != NULL) {
            e_addr->e_addr_requires_permission = true;
            for (int i = 0; permitted_domains[ i ]; i++) {
                yaslclear(buf);
                buf = yaslcatlen(buf, permitted_domains[ i ]->bv_val,
                        permitted_domains[ i ]->bv_len);
                if (simta_domain_check(exp->exp_env->e_mail, buf)) {
                    syslog(LOG_INFO,
                            "Expand.LDAP env <%s>: <%s>: permitted sender "
                            "domain match %s %s",
                            exp->exp_env->e_id, e_addr->e_addr, buf,
                            exp->exp_env->e_mail);
                    e_addr->e_addr_has_permission = true;
                    break;
                }
            }
        }

        if (e_addr->e_addr_requires_permission &&
                !e_addr->e_addr_has_permission) {
            syslog(LOG_INFO,
                    "Expand.LDAP env <%s>: <%s>: no permitted sender match",
                    exp->exp_env->e_id, e_addr->e_addr);
        }

        if (simta_ldap_bool(ld, entry, "membersonly")) {
            e_addr->e_addr_requires_permission = true;
            e_addr->e_addr_permit_members = true;
        }

        e_addr->e_addr_private = simta_ldap_bool(ld, entry, "rfc822private");

        if (e_addr->e_addr_requires_permission &&
                !e_addr->e_addr_has_permission) {
            /* Store the permitted groups, if any. */
            if ((permitted_groups = ldap_get_values_len(
                         ld->ldap_ld, entry, "permittedgroup")) != NULL) {
                if (simta_ldap_permitted_create(e_addr, permitted_groups) !=
                        0) {
                    goto error;
                }
            }

            /* Store the moderators, if any. */
            e_addr->e_addr_env_moderators = simta_ldap_envelope_from_attr(ld,
                    entry, exp->exp_env, senderbuf,
                    ucl_object_tostring(ucl_object_lookup_path(
                            ld->ldap_rule, "attributes.moderators")));

            if (e_addr->e_addr_env_moderators != NULL) {
                if (e_addr->e_addr_env_moderators->e_rcpt == NULL) {
                    /* no valid email addresses */
                    bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                            "bad moderators: ", dn, NULL);
                    env_free(e_addr->e_addr_env_moderators);
                    e_addr->e_addr_env_moderators = NULL;
                } else {
                    if (ucl_object_toboolean(ucl_object_lookup_path(
                                ld->ldap_rule, "permit_moderators"))) {
                        /* Moderators are allowed to email the group. */
                        for (r = e_addr->e_addr_env_moderators->e_rcpt;
                                r != NULL; r = r->r_next) {
                            if (simta_mbx_compare(
                                        r->r_rcpt, exp->exp_env->e_mail) == 0) {
                                /* sender matches moderator */
                                syslog(LOG_INFO,
                                        "Expand.LDAP env <%s>: <%s>: moderator "
                                        "match %s %s",
                                        exp->exp_env->e_id, e_addr->e_addr,
                                        r->r_rcpt, exp->exp_env->e_mail);
                                e_addr->e_addr_has_permission = true;
                                break;
                            }
                        }
                    }

                    if (e_addr->e_addr_env_moderators->e_header_from) {
                        yaslfree(e_addr->e_addr_env_moderators->e_header_from);
                    }
                    e_addr->e_addr_env_moderators->e_header_from =
                            yasldup(group_email);

                    e_addr->e_addr_preface =
                            simta_ucl_object_toyastr(ucl_object_lookup_path(
                                    ld->ldap_rule, "moderation_preface"));
                }
            }
        }

        dnvals = ldap_get_values_len(ld->ldap_ld, entry, "member");
        mailvals = ldap_get_values_len(ld->ldap_ld, entry, "rfc822mail");

        if (suppressnoemail) {
            e_addr->e_addr_errors->e_flags |= ENV_FLAG_SUPPRESS_NO_EMAIL;
        }
        break;
    } /* end of switch */

    if (dnvals) {
        valfound++;

        for (int i = 0; dnvals[ i ] != NULL; i++) {
            yaslclear(buf);
            buf = yaslcatlen(buf, dnvals[ i ]->bv_val, dnvals[ i ]->bv_len);
            ndn = dn_normalize_case(buf);

            /* If sending to group members
            ** -- change from address to be: group-errors@associateddomaon
            ** -- otherwise use the original sender.
            */
            if ((type == LDS_GROUP_MEMBERS) || (type == LDS_USER)) {
                rc = add_address(exp, ndn, e_addr->e_addr_errors,
                        ADDRESS_TYPE_LDAP, senderbuf, false);
            } else {
                rc = add_address(exp, ndn, e_addr->e_addr_errors,
                        ADDRESS_TYPE_LDAP, e_addr->e_addr_from, false);
            }
            if (rc != SIMTA_OK) {
                syslog(LOG_ERR,
                        "Expand.LDAP env <%s>: <%s>: %s failed adding %s",
                        exp->exp_env->e_id, e_addr->e_addr, dn, buf);
                break;
            }
        }
    }

    if (mailvals) {
        valfound++;
        for (int i = 0; mailvals[ i ] != NULL; i++) {
            yaslclear(buf);
            buf = yaslcatlen(buf, mailvals[ i ]->bv_val, mailvals[ i ]->bv_len);

            if (strchr(buf, '@') != NULL) {
                if ((type == LDS_GROUP_MEMBERS) || (type == LDS_USER)) {
                    rc = address_string_recipients(exp, buf, e_addr, senderbuf);
                } else {
                    rc = address_string_recipients(
                            exp, buf, e_addr, e_addr->e_addr_from);
                }

                if (rc != 0) {
                    syslog(LOG_ERR,
                            "Expand.LDAP env <%s>: <%s>: %s failed adding %s",
                            exp->exp_env->e_id, e_addr->e_addr, dn, buf);
                    break;
                }
            } else {
                simta_debuglog(1,
                        "Expand.LDAP env <%s>: <%s>: "
                        "%s skipping invalid value %s",
                        exp->exp_env->e_id, e_addr->e_addr, dn, buf);
            }
        }
    }

    if ((valfound == 0) && (errmsg != NULL)) {
        bounce_text(e_addr->e_addr_errors, TEXT_ERROR, dn, errmsg, NULL);
    }

    retval = ADDRESS_EXCLUDE;

error:
    yaslfree(group_name);
    yaslfree(group_email);
    yaslfree(buf);
    yaslfree(senderbuf);

    ldap_value_free_len(dnvals);
    ldap_value_free_len(mailvals);
    ldap_value_free_len(permitted_domains);
    ldap_value_free_len(permitted_groups);
    ldap_value_free_len(senderlist);
    ldap_memfree(dn);

    return (retval);
}


static bool
simta_ldap_check_autoreply(struct simta_ldap *ld, LDAPMessage *entry) {
    bool            retval = false;
    time_t          entry_time;
    struct timespec ts_now;
#ifdef CLOCK_REALTIME_COARSE
    clockid_t clock = CLOCK_REALTIME_COARSE;
#else
    clockid_t clock = CLOCK_REALTIME;
#endif /* CLOCK_REALTIME_COARSE */

    /* If we don't do autoreplies at all, we don't need to do this one. */
    if (ld->ldap_autoreply_host == NULL) {
        return false;
    }

    /* Check the static flag. */
    if (ld->ldap_autoreply_attr) {
        retval = simta_ldap_bool(ld, entry, ld->ldap_autoreply_attr);
    }

    if (clock_gettime(clock, &ts_now) != 0) {
        syslog(LOG_ERR, "Syserror: simta_ldap_doautoreply clock_gettime: %s",
                strerror(errno));
        return false;
    }

    /* If the static flag isn't set, check for a dynamic start time. */
    if (!retval && ld->ldap_autoreply_start_attr) {
        entry_time =
                simta_ldap_time_t(ld, entry, ld->ldap_autoreply_start_attr);
        if (entry_time > 0 && ts_now.tv_sec > entry_time) {
            retval = true;
        }
    }

    /* If the end time is in the past we want to disable replies, regardless of
     * whether it's from the static flag or a dynamic start time.
     */
    if (retval && ld->ldap_autoreply_end_attr) {
        entry_time = simta_ldap_time_t(ld, entry, ld->ldap_autoreply_end_attr);
        if (entry_time > 0 && ts_now.tv_sec > entry_time) {
            retval = false;
        }
    }

    return retval;
}

static int
simta_ldap_process_entry(struct simta_ldap *ld, struct expand *exp,
        struct exp_addr *e_addr, int type, LDAPMessage *entry, char *addr) {
    struct berval **values = NULL;
    struct berval **uid = NULL;
    int             retval = ADDRESS_EXCLUDE;
    yastr           buf = NULL;

    if (simta_ldap_is_objectclass(ld, entry, "group")) {
        return (simta_ldap_expand_group(ld, exp, e_addr, type, entry));
    } else if (simta_ldap_is_objectclass(ld, entry, "person")) {
        /* get individual's email address(es) */
        if ((values = ldap_get_values_len(
                     ld->ldap_ld, entry, ld->ldap_mailfwdattr)) == NULL) {
            /*
            ** No mailforwardingaddress
            ** Depending on if we're expanding a group
            ** Bounce it with the appropriate message.
            */
            if (e_addr->e_addr_type != ADDRESS_TYPE_LDAP) {
                do_noemail(ld, e_addr, addr, entry);
            } else {
                if ((e_addr->e_addr_errors->e_flags &
                            ENV_FLAG_SUPPRESS_NO_EMAIL) == 0) {
                    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, addr,
                                " : Group member exists but does not have an "
                                "email address",
                                "\n") != 0) {
                        syslog(LOG_ERR,
                                "Expand.LDAP env <%s>: <%s> "
                                "Failed building bounce message: no email",
                                exp->exp_env->e_id, e_addr->e_addr);
                        retval = ADDRESS_SYSERROR;
                        goto error;
                    }
                }
            }

        } else {
            buf = yaslempty();
            for (int i = 0; values[ i ] != NULL; i++) {
                yaslclear(buf);
                buf = yaslcatlen(buf, values[ i ]->bv_val, values[ i ]->bv_len);
                if (address_string_recipients(
                            exp, buf, e_addr, e_addr->e_addr_from) != 0) {
                    syslog(LOG_ERR,
                            "Expand.LDAP env <%s>: <%s>"
                            "failed adding mailforwardingaddress %s",
                            exp->exp_env->e_id, e_addr->e_addr, addr);
                    retval = ADDRESS_SYSERROR;
                    goto error;
                }
            }

            ldap_value_free_len(values);

            if ((values = ldap_get_values_len(
                         ld->ldap_ld, entry, ld->ldap_mailattr)) != NULL) {
                yaslclear(buf);
                buf = yaslcatlen(buf, values[ 0 ]->bv_val, values[ 0 ]->bv_len);
                if (simta_mbx_compare(buf, exp->exp_env->e_mail) == 0) {
                    e_addr->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
                }
                /* FIXME: can we check other variations of the address here? */
            }

            /*
            * If the user is on vacation, send a copy of the mail to
            * the vacation server.  The address is constructed from
            * the vacationhost (specified in the config file) and
            * the uid.
            */
            if (simta_ldap_check_autoreply(ld, entry)) {
                if ((uid = ldap_get_values_len(ld->ldap_ld, entry, "uid")) !=
                        NULL) {
                    buf = yaslnew(uid[ 0 ]->bv_val, uid[ 0 ]->bv_len);
                    buf = yaslcatprintf(buf, "@%s", ld->ldap_autoreply_host);
                    if (add_address(exp, buf, e_addr->e_addr_errors,
                                ADDRESS_TYPE_EMAIL, e_addr->e_addr_from,
                                false) != SIMTA_OK) {
                        syslog(LOG_ERR,
                                "Expand.LDAP env <%s>: <%s>:"
                                "failed adding autoreply address: %s",
                                exp->exp_env->e_id, e_addr->e_addr, buf);
                    }
                } else {
                    syslog(LOG_ERR,
                            "Expand.LDAP env <%s>: <%s>: user %s "
                            "has autoreplies enabled but doesn't have a uid",
                            exp->exp_env->e_id, e_addr->e_addr, addr);
                }
            }
        }
    } else {
        /* Neither a group nor a person */
        syslog(LOG_ERR,
                "Expand.LDAP env <%s>: <%s>: "
                "Entry is neither person nor group ",
                exp->exp_env->e_id, e_addr->e_addr);
        bounce_text(e_addr->e_addr_errors, TEXT_ERROR, addr,
                " : Entry exists but is neither a group or person", NULL);
    }

error:
    yaslfree(buf);
    ldap_value_free_len(values);
    ldap_value_free_len(uid);
    return (retval);
}


static int
simta_ldap_name_search(struct simta_ldap *ld, struct expand *exp,
        struct exp_addr *e_addr, char *addr, char *domain, int addrtype) {
    int                      rc = ADDRESS_NOT_FOUND;
    int                      match = 0;
    yastr                    search_string;
    LDAPMessage *            res;
    LDAPMessage *            entry;
    struct ldap_search_list *lds;
    yastr                    xdn;
    LDAPMessage *            tmpres = NULL;
    char *                   err;

    /* for each base string in ldap_searches:
     *    If this search string is of the specified addrtype:
     *       - Build search string
     *       - query the LDAP db with the search string
     */
    for (lds = ld->ldap_searches; lds != NULL; lds = lds->lds_next) {
        if (!(lds->lds_search_type & addrtype)) {
            continue;
        }

        /* Fill in the filter string w/ these address and domain strings */
        search_string =
                simta_ldap_string(lds->lds_plud->lud_filter, addr, domain);

        res = NULL;
        rc = simta_ldap_search(ld, lds->lds_plud->lud_dn,
                lds->lds_plud->lud_scope, search_string, &res);

        yaslfree(search_string);

        if (rc == ADDRESS_OK) {
            break;
        }

        ldap_msgfree(res);
        res = NULL;

        if (rc == ADDRESS_SYSERROR) {
            return (rc);
        }
    }

    if (rc == ADDRESS_NOT_FOUND) {
        return (rc);
    }

    switch (ldap_count_entries(ld->ldap_ld, res)) {
    case -1:
        syslog(LOG_ERR,
                "Expand.LDAP env <%s>: <%s>: Error parsing result from server",
                exp->exp_env->e_id, e_addr->e_addr);
        ldap_msgfree(res);
        return (ADDRESS_SYSERROR);

    default:
        /*
        ** More than one match -- if no rdn preference
        ** then bounce w/ ambiguous user
        */
        if (!lds->lds_rdn_pref) {
            do_ambiguous(ld, e_addr, addr, res);
            ldap_msgfree(res);
            return (ADDRESS_EXCLUDE);
        }

        /*
         * giving rdn preference - see if any entries were matched
         * because of their rdn.  If so, collect them to deal with
         * later (== 1 we deliver, > 1 we bounce).
        */
        for (entry = ldap_first_entry(ld->ldap_ld, res); entry != NULL;
                entry = ldap_next_entry(ld->ldap_ld, entry)) {
            xdn = simta_ldap_dn_name(ld, entry);

            if (strcasecmp(xdn, addr) == 0) {
                ldap_delete_result_entry(&res, entry);
                ldap_add_result_entry(&tmpres, entry);
            }
            yaslfree(xdn);
        }

        /* if nothing matched by rdn - go ahead and bounce */
        if (tmpres == NULL) {
            do_ambiguous(ld, e_addr, addr, res);
            ldap_msgfree(res);
            return (ADDRESS_EXCLUDE);

            /* if more than one matched by rdn - bounce with rdn matches */
        } else if ((match = ldap_count_entries(ld->ldap_ld, tmpres)) > 1) {
            do_ambiguous(ld, e_addr, addr, res);
            ldap_msgfree(res);
            ldap_msgfree(tmpres);
            return (ADDRESS_EXCLUDE);

            /* trouble --  tmpres hosed? */
        } else if (match < 0) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: "
                    "Error parsing LDAP result",
                    exp->exp_env->e_id, e_addr->e_addr);
            ldap_msgfree(res);
            ldap_msgfree(tmpres);
            return (ADDRESS_SYSERROR);
        }

        /* otherwise one matched by rdn - send to it */
        ldap_msgfree(res);
        res = tmpres;
        /*
        ** we've sorted this ambiguity out,
        ** so fall thru to next case and process this entry.
        */

    case 1:
        /*
        ** One entry now that matches our address.
        */
        if ((entry = ldap_first_entry(ld->ldap_ld, res)) == NULL) {
            ldap_parse_result(ld->ldap_ld, res, &rc, NULL, &err, NULL, NULL, 0);
            syslog(LOG_ERR,
                    "Liberror: simta_ldap_name_search "
                    "ldap_parse_result: %s",
                    err);
            ldap_memfree(err);
            return (ADDRESS_SYSERROR);
        }
    }

    rc = simta_ldap_process_entry(ld, exp, e_addr, addrtype, entry, addr);

    if (res) {
        ldap_msgfree(res);
    }
    return (rc);
}


static int
simta_ldap_dn_expand(
        struct simta_ldap *ld, struct expand *exp, struct exp_addr *e_addr) {
    char *       search_dn;
    int          rc;
    int          match;
    LDAPMessage *res = NULL;
    LDAPMessage *entry;
    char *       err;

    search_dn = e_addr->e_addr;

    if ((rc = simta_ldap_search(ld, search_dn, LDAP_SCOPE_BASE,
                 "(objectclass=*)", &res)) != ADDRESS_OK) {
        ldap_msgfree(res);
        return rc;
    }

    match = ldap_count_entries(ld->ldap_ld, res);

    if (match == -1) {
        syslog(LOG_ERR,
                "Expand.LDAP env <%s>: <%s>: "
                "Error parsing result from server for dn: %s",
                exp->exp_env->e_id, e_addr->e_addr, search_dn);
        ldap_msgfree(res);
        return ADDRESS_SYSERROR;
    }

    if (match == 0) {
        ldap_msgfree(res);

        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, search_dn,
                    " : Group member does not exist", NULL) != 0) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: "
                    "Failed building no member bounce message: %s",
                    exp->exp_env->e_id, e_addr->e_addr, search_dn);
            return ADDRESS_SYSERROR;
        }
        return ADDRESS_EXCLUDE; /* no entries found */
    }

    if ((entry = ldap_first_entry(ld->ldap_ld, res)) == NULL) {
        ldap_parse_result(ld->ldap_ld, res, &rc, NULL, &err, NULL, NULL, 0);
        syslog(LOG_ERR, "Liberror: simta_ldap_dn_entry ldap_parse_result: %s",
                err);
        ldap_memfree(err);
        ldap_msgfree(res);
        return (ADDRESS_SYSERROR);
    }

    rc = simta_ldap_process_entry(ld, exp, e_addr, LDS_USER, entry, search_dn);

    ldap_msgfree(res);
    return rc;
}


/* this function should return:
     *     ADDRESS_OK if addr is terminal
     *     ADDRESS_NOT_FOUND if addr is not found in the database
     *     ADDRESS_EXCLUDE if addr is an error or expands to other addrs.
     *     ADDRESS_SYSERROR if there is a system error
     *
     * expansion (not system) errors should be reported back to the sender
     * using bounce_text(...);
     */

int
simta_ldap_expand(
        const ucl_object_t *rule, struct expand *exp, struct exp_addr *e_addr) {
    char *             domain;   /* points to domain in address */
    yastr              name;     /* clone of incoming name */
    int                nametype; /* Type of Groupname -- owner, member... */
    int                rc;       /* Universal return code */
    struct simta_ldap *ld;

    if ((ld = simta_ldap_config(rule)) == NULL) {
        return ADDRESS_SYSERROR;
    }

    if ((rc = simta_ldap_init(ld)) != SIMTA_OK) {
        return ADDRESS_SYSERROR;
    }

    if (e_addr->e_addr_type == ADDRESS_TYPE_LDAP) {
        return simta_ldap_dn_expand(ld, exp, e_addr);
    }

    assert(e_addr->e_addr_at != NULL);

    name = yaslnew(e_addr->e_addr, e_addr->e_addr_at - e_addr->e_addr);
    domain = e_addr->e_addr_at + 1;

    simta_ldap_unescape(name);

    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    nametype = simta_address_type(name, rule);
    rc = simta_ldap_name_search(ld, exp, e_addr, name, domain, nametype);
    yaslfree(name);
    return rc;
}


static yastr
simta_addr_demangle(const char *address) {
    yastr u;
    char *p;

    if (srs_reverse(address, &p, simta_config_str("receive.srs.secret")) ==
            SRS_OK) {
        u = yaslauto(p);
        free(p);
    } else {
        u = yaslauto(address);
    }

    /* Strictly speaking we aren't allowed to assume that case doesn't matter
     * in the localpart, but in the real world most systems are
     * case-insensitive.
     */
    yasltolower(u);

    /* Bounce Address Tag Validation (BATV) defines a method for including
     * tagging information in the local-part of the RFC5321.MailFrom address,
     * allowing senders to tag all outgoing mail and reject bounces that aren't
     * to a tagged address.
     *
     * Software that needs to recover the original address can do so by
     * checking for the presence of the tag-type, and if it is present,
     * discarding the local-part up through the second equal sign.
     *
     * The only widespread tag-type right now is prvs, which adds a timestamp
     * and cryptographic checksum. SRS uses a similar tagging scheme but
     * does more extensive transformation and is therefore incompatible with
     * this canonicalisation method.
     */
    if ((strncmp(u, "prvs=", 5) == 0) && ((p = strchr(u + 5, '=')) != NULL)) {
        yaslrange(u, p - u + 1, -1);
    }

    /* Barracuda do their own special version of BATV, which is incompatible
     * with the BATV draft because it uses '==' as the delimiter.
     */
    if ((strncmp(u, "btv1==", 6) == 0) && ((p = strstr(u + 6, "==")) != NULL)) {
        yaslrange(u, p - u + 2, -1);
    }

    return u;
}

int
simta_mbx_compare(const char *addr1, const char *addr2) {
    yastr               addr1_copy = NULL;
    yastr               addr2_copy = NULL;
    char *              p1;
    char *              p2;
    int                 rc = -1;
    const ucl_object_t *red;

    if (addr1 == NULL || addr2 == NULL || *addr1 == '\0' || *addr2 == '\0') {
        return -1;
    }

    /* simplest case */
    if (strcasecmp(addr1, addr2) == 0) {
        return 0;
    }

    /* undo address mangling */
    addr1_copy = simta_addr_demangle(addr1);
    addr2_copy = simta_addr_demangle(addr2);

    rc = strcmp(addr1_copy, addr2_copy);

    if ((rc != 0) &&
            strncmp(addr1_copy, addr2_copy,
                    (strrchr(addr1_copy, '@') - addr1_copy + 1)) == 0) {
        /* Local parts match, check for subdomain match */
        p1 = addr1_copy + yasllen(addr1_copy);
        p2 = addr2_copy + yasllen(addr2_copy);

        while (*p1 == *p2) {
            p1--;
            p2--;
        }
        if (strlen(p1) && strchr(p1, '.')) {
            /* match has at least one domain component, rewind until
             * we only have full components (no p.example.com for
             * ldap.example.com / apep.example.com )
             */
            while (*p1 != '@' && *p1 != '.') {
                p1++;
                p2++;
            }
            while (*p2 != '@' && *p2 != '.') {
                /* The non-matching character in p1 might have been @ or ., e.g.
                 * p1 =  a@b.example.com
                 * p2 - a@ab.example.com
                 * In that case we have more rewinding to do.
                 */
                p2++;
            }

            /* FIXME: this is cleaner than the hardcoded "only two domain
             * components matter", but membersonly processing is still kind
             * of kludgy and full of assumptions.
             */

            p2++;
            /* Check to see if the common parent or any ancestor has
             * `permit_subdomains` enabled.
             */
            while (rc != 0 && p2) {
                if ((red = red_host_lookup(p2, false)) != NULL) {
                    if (ucl_object_toboolean(ucl_object_lookup_path(
                                red, "expand.permit_subdomains"))) {
                        rc = 0;
                    }
                }
                if (rc != 0) {
                    if ((p2 = strchr(p2, '.')) != NULL) {
                        p2++;
                    }
                }
            }
        }
    }

    yaslfree(addr1_copy);
    yaslfree(addr2_copy);

    return rc;
}

bool
simta_domain_check(const char *addr, const char *domain) {
    yastr addr_copy = NULL;
    char *p;
    bool  ret = false;

    if (strrchr(addr, '@') == NULL) {
        return false;
    }

    addr_copy = simta_addr_demangle(addr);
    yaslrange(addr_copy, strrchr(addr_copy, '@') - addr_copy + 1, -1);
    while (!ret && addr_copy) {
        if (strcasecmp(domain, addr_copy) == 0) {
            ret = true;
        } else if ((p = strchr(addr_copy, '.')) != NULL) {
            yaslrange(addr_copy, p - addr_copy + 1, -1);
        } else {
            yaslfree(addr_copy);
            addr_copy = NULL;
        }
    }

    yaslfree(addr_copy);
    return ret;
}

struct simta_ldap *
simta_ldap_config(const ucl_object_t *rule) {
    struct ldap_search_list **lds;
    yastr                     key = NULL;
    const char *              buf;
    int                       i;
    const ucl_object_t *      obj;
    const ucl_object_t *      c_obj;
    ucl_object_iter_t         iter = NULL;
    LDAPURLDesc *             plud;   /* a parsed ldapurl */
    int                       ldaprc; /* ldap return code */
    struct simta_ldap *       ld = NULL;

    if (ldap_configs == NULL) {
        ldap_configs = ucl_object_typed_new(UCL_OBJECT);
    }

    key = yaslcatprintf(yaslempty(), "%p", (void *)rule);

    if ((obj = ucl_object_lookup(ldap_configs, key)) != NULL) {
        yaslfree(key);
        return obj->value.ud;
    }

    ld = simta_calloc(1, sizeof(struct simta_ldap));
    lds = &(ld->ldap_searches);
    ld->ldap_rule = ucl_object_ref(ucl_object_lookup(rule, "ldap"));

    ld->ldap_associated_domain =
            ucl_object_tostring(ucl_object_lookup(rule, "associated_domain"));

    iter = ucl_object_iterate_new(ucl_object_lookup(ld->ldap_rule, "search"));
    while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
        buf = ucl_object_tostring(ucl_object_lookup(obj, "uri"));
        if (ldap_is_ldap_url(buf) == 0) {
            syslog(LOG_ERR, "Config.LDAP %s: URI is not an LDAP URI: %s",
                    ld->ldap_associated_domain, buf);
            goto errexit;
        }

        /* Parse the URL */
        if ((ldaprc = ldap_url_parse(buf, &plud)) != LDAP_URL_SUCCESS) {
            syslog(LOG_ERR, "Config.LDAP %s: URI parse error %d: %s",
                    ld->ldap_associated_domain, ldaprc, buf);
            goto errexit;
        }

        if (plud->lud_filter == NULL) {
            syslog(LOG_ERR,
                    "Config.LDAP %s: URI %s "
                    "doesn't appear to contain a filter",
                    ld->ldap_associated_domain, buf);
            goto errexit;
        }

        *lds = simta_calloc(1, sizeof(struct ldap_search_list));
        (*lds)->lds_string = buf;
        (*lds)->lds_plud = plud;

        if ((c_obj = ucl_object_lookup(obj, "rdnpref")) != NULL) {
            (*lds)->lds_rdn_pref = ucl_object_toboolean(c_obj);
        } else {
            (*lds)->lds_rdn_pref = true;
        }

        if ((c_obj = ucl_object_lookup(obj, "type")) != NULL) {
            buf = ucl_object_tostring(c_obj);
            if (strcasecmp(buf, "all") == 0) {
                (*lds)->lds_search_type = LDS_ALL;
            } else if (strcasecmp(buf, "group") == 0) {
                (*lds)->lds_search_type = LDS_GROUP;
            } else if (strcasecmp(buf, "user") == 0) {
                (*lds)->lds_search_type = LDS_USER;
            } else {
                ldap_free_urldesc(plud);
                free(*lds);
                *lds = NULL;
                syslog(LOG_ERR, "Config.LDAP %s: Unknown search type: %s",
                        ld->ldap_associated_domain, buf);
                goto errexit;
            }
        } else {
            (*lds)->lds_search_type = LDS_ALL;
        }

        (*lds)->lds_next = NULL;
        lds = &((*lds)->lds_next);
    }

    obj = ucl_object_lookup_path(ld->ldap_rule, "attributes.request");
    i = 0;
    ld->ldap_attrs = simta_calloc(ucl_array_size(obj) + 1, sizeof(char *));
    ucl_object_iterate_reset(iter, obj);
    while ((obj = ucl_object_iterate_safe(iter, true)) != NULL) {
        /* ldap_search_ext_s doesn't want const char * for some reason */
        ld->ldap_attrs[ i++ ] = simta_strdup(ucl_object_tostring(obj));
    }

    ldapdebug = ucl_object_toboolean(ucl_object_lookup(ld->ldap_rule, "debug"));

    buf = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "bind.method"));
    if (strcasecmp(buf, "simple") == 0) {
        ld->ldap_bind = BINDSIMPLE;
#ifdef HAVE_LIBSASL
    } else if (strcasecmp(buf, "sasl") == 0) {
        ld->ldap_bind = BINDSASL;
#endif
    }

#ifdef HAVE_LIBSSL
    if (ucl_object_toboolean(
                ucl_object_lookup_path(ld->ldap_rule, "tls.enabled"))) {
        if (ucl_object_toboolean(
                    ucl_object_lookup_path(ld->ldap_rule, "tls.required"))) {
            ld->ldap_starttls = 2;
        } else {
            ld->ldap_starttls = 1;
        }
    }

    ld->ldap_tls_cacert = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "tls.ca"));

    ld->ldap_tls_cert = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "tls.cert"));

    ld->ldap_tls_key = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "tls.key"));
#endif /* HAVE_LIBSSL */

    ld->ldap_bindpw = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "bind.password"));

    ld->ldap_binddn = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "bind.dn"));

    ld->ldap_mailattr = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "attributes.mail"));

    ld->ldap_mailfwdattr = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "attributes.forwarding"));

    ld->ldap_gmailfwdattr = ucl_object_tostring(ucl_object_lookup_path(
            ld->ldap_rule, "attributes.group_forwarding"));

    ld->ldap_autoreply_host = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "autoreply.host"));

    if (!ld->ldap_autoreply_host) {
        /* DEPRECATED */
        ld->ldap_autoreply_host = ucl_object_tostring(
                ucl_object_lookup_path(ld->ldap_rule, "vacation.host"));
    }

    ld->ldap_autoreply_attr = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "attributes.autoreply"));

    if (!ld->ldap_autoreply_attr) {
        /* DEPRECATED */
        ld->ldap_autoreply_attr = ucl_object_tostring(
                ucl_object_lookup_path(ld->ldap_rule, "attributes.vacation"));
    }

    ld->ldap_autoreply_start_attr = ucl_object_tostring(ucl_object_lookup_path(
            ld->ldap_rule, "attributes.autoreply_start"));

    ld->ldap_autoreply_end_attr = ucl_object_tostring(
            ucl_object_lookup_path(ld->ldap_rule, "attributes.autoreply_end"));

    /* check to see that ldap is configured correctly */

    if ((ld->ldap_tls_cert) || (ld->ldap_tls_key)) {
        if (!ld->ldap_tls_cert) {
            syslog(LOG_ERR, "Config.LDAP %s: missing TLS_CERT parameter",
                    ld->ldap_associated_domain);
            goto errexit;
        }
        if (!ld->ldap_tls_key) {
            syslog(LOG_ERR, "Config.LDAP %s: missing TLS_KEY parameter",
                    ld->ldap_associated_domain);
            goto errexit;
        }
    }

    ucl_object_iterate_free(iter);

    ucl_object_insert_key(ldap_configs, ucl_object_new_userdata(NULL, NULL, ld),
            key, 0, true);
    yaslfree(key);
    return ld;

errexit:
    free(ld);
    ucl_object_iterate_free(iter);
    yaslfree(key);

    return NULL;
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
