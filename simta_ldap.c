/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

/* FIXME: nurrr */
#define LDAP_DEPRECATED 1

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

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
#include "srs.h"

#define SIMTA_LDAP_CONF "./simta_ldap.conf"

#define MAXRETRIES 5

#define MAXAMBIGUOUS 10
#define LDAP_TIMEOUT_VAL 180

/* MAXADDRESSLENGTH -- maximum length email address we're gonna process */
#define MAXADDRESSLENGTH 1024
/* ERRORFMTBUFLEN -- Error buffer length process max buffer size. */
#define ERRORFMTBUFLEN 2048

/*
** LDAP attribute names
** noattrs -- is a attribute list when no attributes are needed.
** allattrs -- is a attribute list when all attributes are wanted.  It
**             It is also the default attribute list if no attribute
**             config file directive found.
*/
static char *allattrs[] = {"*", NULL};

/*
** ldap_search_list -- Contains a parsed uri from the config file.
*/
struct ldap_search_list {
    LDAPURLDesc *            lds_plud;        /* url parsed description */
    int                      lds_rdn_pref;    /* TRUE / FALSE */
    int                      lds_search_type; /* one of USER, GROUP, ALL */
    char *                   lds_string;      /* uri string */
    struct ldap_search_list *lds_next;        /* next uri */
};

/* Values for ldapbind */
#define BINDSASL 2
#define BINDSIMPLE 1
#define BINDANON 0

static char **attrs = NULL;

struct simta_ldap {
    struct ldap_search_list *ldap_searches;
    LDAP *                   ldap_ld;
    struct list *            ldap_people;
    struct list *            ldap_groups;
    char *                   ldap_host;
    int                      ldap_port;
    time_t                   ldap_timeout;
    pid_t                    ldap_pid;
    int                      ldap_starttls;
    int                      ldap_bind;
    char *                   ldap_tls_cert;
    char *                   ldap_tls_key;
    char *                   ldap_tls_cacert;
    char *                   ldap_binddn;
    char *                   ldap_bindpw;
    char *                   ldap_vacationhost;
    char *                   ldap_vacationattr;
    char *                   ldap_mailfwdattr;
    char *                   ldap_gmailfwdattr;
    char *                   ldap_mailattr;
    char *                   ldap_associated_domain;
    int                      ldap_ndomain;
};

static int ldapdebug;


char *      simta_ldap_dequote(char *);
int         simta_ld_init(struct simta_ldap *);
void        simta_ldap_unbind(struct simta_ldap *);
static int  simta_ldap_retry(struct simta_ldap *);
static void simta_ldapdomain(int, char *, char **);
static void simta_ldapuser(int, char *, char **, char **);
static int  simta_ldap_value(
         struct simta_ldap *, LDAPMessage *, char *, struct list *);
static int  simta_ldap_name_search(struct simta_ldap *, struct expand *,
         struct exp_addr *, char *, char *, int);
static int  simta_ldap_expand_group(struct simta_ldap *, struct expand *,
         struct exp_addr *, int, LDAPMessage *);
static void do_noemail(
        struct simta_ldap *, struct exp_addr *, char *, LDAPMessage *);
static void do_ambiguous(
        struct simta_ldap *, struct exp_addr *, char *, LDAPMessage *);
static int simta_ldap_process_entry(struct simta_ldap *, struct expand *,
        struct exp_addr *, int, LDAPMessage *, char *);
static int simta_ldap_dn_expand(
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


static void
simta_ldapdomain(int ndomain, char *buf, char **domain) {
    char *pbuf;
    int   dotcnt = 0;

    pbuf = buf + strlen(buf) - 1;

    while (pbuf > buf) {
        if (*pbuf == '.') {
            if (dotcnt == (ndomain - 1)) {
                pbuf++;
                break;
            }
            dotcnt++;
        }
        pbuf--;
    }
    *domain = strdup(pbuf);
    return;
}


char *
simta_ldap_dequote(char *s) {
    char *buf;
    char *r;
    char *w;

    if (*s != '"') {
        return (NULL);
    }

    /* We skip the first character of the input string, so we don't need to
     * allocate extra space for the terminating NULL.
     */
    buf = calloc(1, strlen(s));

    r = s + 1;
    w = buf;

    for (r = s + 1; *r != '\0'; r++) {
        if (*r == '"') {
            return (buf);
        }

        if (*r == '\\') {
            r++;
            if (*r == '\0') {
                break;
            }
        }

        *w = *r;
        w++;
    }

    syslog(LOG_ERR, "LDAP: unterminated quoted string %s", s);
    free(buf);
    return (NULL);
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


int
simta_ld_init(struct simta_ldap *ld) {
    int maxambiguous = MAXAMBIGUOUS;
    int protocol = LDAP_VERSION3;

    if ((ld->ldap_ld = ldap_init(ld->ldap_host, ld->ldap_port)) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_ld_init ldap_init: %m");
        return (1);
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
    if ((ldap_set_option(ld->ldap_ld, LDAP_OPT_RESTART, LDAP_OPT_ON)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_RESTART LDAP_OPT_ON: failed");
        return (1);
    }

    if ((ldap_set_option(ld->ldap_ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_REFERRALS LDAP_OPT_OFF: failed");
        return (1);
    }

    if ((ldap_set_option(ld->ldap_ld, LDAP_OPT_SIZELIMIT,
                (void *)&maxambiguous)) != LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_SIZELIMIT %d: failed",
                maxambiguous);
        return (1);
    }

    if ((ldap_set_option(ld->ldap_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol)) !=
            LDAP_OPT_SUCCESS) {
        syslog(LOG_ERR,
                "Liberror: simta_ld_init ldap_set_option "
                "LDAP_OPT_PROTOCOL_VERSION %d: failed",
                protocol);
        return (1);
    }

    return (0);
}


static int
simta_ldap_init(struct simta_ldap *ld) {
    int ldaprc;

    if ((ld->ldap_ld == NULL) || (ld->ldap_pid != getpid())) {
        if (simta_expand_debug != 0) {
            printf("OPENING LDAP CONNECTION\n");
        }

        ld->ldap_pid = getpid();
        if (simta_ld_init(ld) != 0) {
            goto error;
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
                    goto error;
                }
            }

            if (ld->ldap_tls_cert) {
                if ((ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE,
                             ld->ldap_tls_cert)) != LDAP_OPT_SUCCESS) {
                    syslog(LOG_ERR,
                            "Liberror: simta_ldap_init ldap_set_option "
                            "LDAP_OPT_X_TLS_CERTFILE %s: %s",
                            ld->ldap_tls_cert, ldap_err2string(ldaprc));
                    goto error;
                }
            }

            if (ld->ldap_tls_key) {
                if ((ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE,
                             ld->ldap_tls_key)) != LDAP_OPT_SUCCESS) {
                    syslog(LOG_ERR,
                            "Liberror: simta_ldap_init ldap_set_option "
                            "LDAP_OPT_X_TLS_KEYFILE %s: %s",
                            ld->ldap_tls_key, ldap_err2string(ldaprc));
                    goto error;
                }
            }
        }
#endif /* HAVE_LIBSSL */
    }

#ifdef HAVE_LIBSSL
    if (ld->ldap_starttls) {
        if ((ldaprc = ldap_start_tls_s(ld->ldap_ld, NULL, NULL)) !=
                LDAP_SUCCESS) {
            syslog(LOG_ERR, "Liberror: simta_ldap_init ldap_start_tls_s: %s",
                    ldap_err2string(ldaprc));
            if (ld->ldap_starttls == 2) {
                goto error;
            }
            /*
            ** Start-TLS Failed -- default to anonymous binding.
            */
            ld->ldap_bind = BINDANON;
            if (ld->ldap_tls_cert) {
                free(ld->ldap_tls_cert);
                ld->ldap_tls_cert = NULL;
            }

            if (simta_ldap_retry(ld) != 0) {
                goto error;
            }
        }
    }
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    if (ld->ldap_bind == BINDSASL) {
        if ((ldaprc = ldap_sasl_interactive_bind_s(ld->ldap_ld, ld->ldap_binddn,
                     NULL, NULL, NULL, LDAP_SASL_QUIET,
                     simta_ldap_sasl_interact, NULL)) != LDAP_SUCCESS) {
            syslog(LOG_ERR,
                    "Liberror: simta_ldap_init "
                    "ldap_sasl_interactive_bind_s: %s",
                    ldap_err2string(ldaprc));
            goto error;
        }

        /* If a client-side cert specified,  then do a SASL EXTERNAL bind */
    } else if (ld->ldap_tls_cert) {
        if ((ldaprc = ldap_sasl_interactive_bind_s(ld->ldap_ld, ld->ldap_binddn,
                     "EXTERNAL", NULL, NULL, LDAP_SASL_QUIET,
                     simta_ldap_sasl_interact, NULL)) != LDAP_SUCCESS) {
            syslog(LOG_ERR,
                    "Liberror: simta_ldap_init "
                    "ldap_sasl_interactive_bind_s: %s",
                    ldap_err2string(ldaprc));
            goto error;
        }

    } else {
#endif /* HAVE_LIBSASL */
        if (ld->ldap_binddn && ((ld->ldap_bind == BINDSIMPLE) ||
                                       (ld->ldap_bind == BINDANON))) {
            if ((ldaprc = ldap_bind_s(ld->ldap_ld, ld->ldap_binddn,
                         ld->ldap_bindpw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS) {
                syslog(LOG_ERR, "Liberror: simta_ldap_init ldap_bind_s: %s",
                        ldap_err2string(ldaprc));
                goto error;
            }
        }

#ifdef HAVE_LIBSASL
    }
#endif /* HAVE_LIBSASL */
    return (0);

error:
    simta_ldap_unbind(ld);
    return (ADDRESS_SYSERROR);
}


/*
** This function looks thru the attribute "attr" values
** for the first matching value in the "master" list
*/


static int
simta_ldap_value(struct simta_ldap *ld, LDAPMessage *e, char *attr,
        struct list *master) {
    int          idx;
    char **      values;
    struct list *l;

    if ((values = ldap_get_values(ld->ldap_ld, e, attr)) != NULL) {
        for (idx = 0; values[ idx ] != NULL; idx++) {
            for (l = master; l != NULL; l = l->l_next) {
                if (strcasecmp(values[ idx ], l->l_string) == 0) {
                    ldap_value_free(values);
                    return (1);
                }
            }
        }
        ldap_value_free(values);
    }
    return (0);
}


/* return a statically allocated string if all goes well, NULL if not.
     *
     *     - Build search string where:
     *         + %s -> username
     *         + %h -> hostname
     */

static char *
simta_ldap_string(char *filter, char *user, char *domain) {
    size_t        len;
    static size_t buf_len = 0;
    static char * buf = NULL;
    char *        c;
    char *        d;
    char *        insert;
    size_t        place;

    /* make sure buf is big enough search url */
    if ((len = strlen(filter) + 1) > buf_len) {
        buf = realloc(buf, len);
        buf_len = len;
    }

    d = buf;
    c = filter;

    while (*c != '\0') {
        switch (*c) {
        case '%':
            switch (*(c + 1)) {
            case 's':
                /* if needed, resize buf to handle upcoming insert */
                if ((len += (2 * strlen(user))) > buf_len) {
                    place = (size_t)(d - buf);
                    buf = realloc(buf, len);
                    d = buf + place;
                    buf_len = len;
                }

                /* insert word */
                for (insert = user; *insert != '\0'; insert++) {
                    switch (*insert) {

                    case '.':
                    case '_':
                        *d = ' ';
                        break;

                    case '(':
                    case ')':
                    case '*':
                        *d++ = '\\'; /*  Fall Thru */

                    default:
                        *d = *insert;
                    }
                    d++;
                }

                /* advance read cursor */
                c += 2;
                break;

            case 'h':
                /* if needed, resize buf to handle upcoming insert */
                if ((len += strlen(domain)) > buf_len) {
                    place = (size_t)(d - buf);
                    buf = realloc(buf, len);
                    d = buf + place;
                    buf_len = len;
                }

                /* insert word */
                for (insert = domain; *insert != '\0'; insert++) {
                    *d = *insert;
                    d++;
                }

                /* advance read cursor */
                c += 2;
                break;

            case '%':
                /* %% -> copy single % to data buffer */
                *d = *c;
                /* advance cursors */
                c += 2;
                d++;
                break;

            default:
                c++;
                break;
            }
            break;

        default:
            /* raw character, copy to data buffer */
            *d = *c;

            /* advance cursors */
            d++;
            c++;
            break;
        }
    }

    *d = '\0';

    return (buf);
}


/*
** Looks at the incoming email address
** looking for "-errors", "-requests", or "-owners"
**
*/
static int
simta_address_type(char *address) {
    int   addrtype;
    char *paddr;

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
    if (simta_subaddr_separator &&
            ((paddr = strchr(address, simta_subaddr_separator)) != NULL)) {
        *paddr = '\0';
    }

    return (addrtype);
}


static void
do_ambiguous(struct simta_ldap *ld, struct exp_addr *e_addr, char *addr,
        LDAPMessage *res) {
    int          idx;
    char *       dn;
    char *       rdn;
    char **      ufn;
    char **      vals;
    LDAPMessage *e;

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, addr, ": Ambiguous user",
                NULL) != 0) {
        return;
    }

    for (e = ldap_first_entry(ld->ldap_ld, res); e != NULL;
            e = ldap_next_entry(ld->ldap_ld, e)) {
        dn = ldap_get_dn(ld->ldap_ld, e);
        ufn = ldap_explode_dn(dn, 1);
        rdn = strdup(ufn[ 0 ]);
        ldap_value_free(ufn);
        free(dn);

        if (strcasecmp(rdn, addr) == 0) {
            if ((vals = ldap_get_values(ld->ldap_ld, e, "cn")) != NULL) {
                rdn = strdup(vals[ 0 ]);
                ldap_value_free(vals);
            }
        }

        if ((ld->ldap_groups != NULL) &&
                (simta_ldap_value(ld, e, "objectClass", ld->ldap_groups) > 0)) {
            vals = ldap_get_values(ld->ldap_ld, e, "description");
        } else {
            vals = ldap_get_values(ld->ldap_ld, e, "title");
        }

        if (vals && vals[ 0 ]) {
            if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, rdn, "\t",
                        vals[ 0 ]) != 0) {
                return;
            }

            for (idx = 1; vals && vals[ idx ] != NULL; idx++) {
                if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t\t",
                            vals[ idx ], NULL) != 0) {
                    return;
                }
            }
            ldap_value_free(vals);
        } else {
            if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, rdn, NULL,
                        NULL) != 0) {
                return;
            }
        }
        free(rdn);
    }
}


static void
do_noemail(struct simta_ldap *ld, struct exp_addr *e_addr, char *addr,
        LDAPMessage *res) {
    int    idx;
    char * dn;
    char * rdn;
    char **ufn;
    char **vals;
    char * pnl;
    char * pstart;

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
    dn = ldap_get_dn(ld->ldap_ld, res);
    ufn = ldap_explode_dn(dn, 1);
    rdn = strdup(ufn[ 0 ]);
    if (strcasecmp(rdn, addr) == 0) {
        if ((vals = ldap_get_values(ld->ldap_ld, res, "cn")) != NULL) {
            free(rdn);
            rdn = strdup(vals[ 0 ]);
            ldap_value_free(vals);
        }
    }

    if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t", rdn, NULL) != 0) {
        return;
    }

    free(dn);
    free(rdn);
    ldap_value_free(ufn);

    /* titles or descriptions */
    if (((vals = ldap_get_values(ld->ldap_ld, res, "title")) == NULL) &&
            ((vals = ldap_get_values(ld->ldap_ld, res, "description")) ==
                    NULL)) {
        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                    "No title or description registered", NULL) != 0) {
            ldap_value_free(vals);
            return;
        }

    } else {
        for (idx = 0; vals[ idx ] != NULL; idx++) {
            if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                        vals[ idx ], NULL) != 0) {
                ldap_value_free(vals);
                return;
            }
        }
        ldap_value_free(vals);
    }

    /* postal address*/
    if ((vals = ldap_get_values(ld->ldap_ld, res, "postaladdress")) == NULL) {
        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                    "No postaladdress registered", NULL) != 0) {
            ldap_value_free(vals);
            return;
        }

    } else {
        for (pstart = vals[ 0 ]; pstart; pstart = pnl) {
            pnl = strchr(pstart, '$');
            if (pnl) {
                *pnl = '\0';
                pnl++;
            }

            if (strlen(pstart)) {
                if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t", pstart,
                            NULL) != 0) {
                    ldap_value_free(vals);
                    return;
                }
            }
        }
        ldap_value_free(vals);
    }

    /* telephone number */
    if ((vals = ldap_get_values(ld->ldap_ld, res, "telephoneNumber")) == NULL) {
        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                    "No phone number registered", NULL) != 0) {
            ldap_value_free(vals);
            return;
        }

    } else {
        for (idx = 0; vals[ idx ] != NULL; idx++) {
            if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, "\t",
                        vals[ idx ], NULL) != 0) {
                ldap_value_free(vals);
                return;
            }
        }

        ldap_value_free(vals);
    }

    return;
}


/*
** Unbind from the directory.
*/

void
simta_ldap_unbind(struct simta_ldap *ld) {
    if ((ld != NULL) && (ld->ldap_ld != NULL)) {
        ldap_unbind(ld->ldap_ld);
        ld->ldap_ld = NULL;

        if (simta_expand_debug != 0) {
            printf("CLOSING LDAP CONNECTION\n");
        }
    }
    return;
}


static int
simta_ldap_retry(struct simta_ldap *ld) {
    simta_ldap_unbind(ld);
    if (simta_ldap_init(ld) != 0) {
        return (1);
    }
    return (0);
}


/* this function should return:
     *     ADDRESS_SYSERROR if there is an error
     *     LDAP_LOCAL if addr is found in the db
     *     LDAP_NOT_LOCAL if addr is not found in the db
     */

int
simta_ldap_address_local(struct simta_ldap *ld, char *name, char *domain) {
    char *                   dup_name;
    char *                   pname;
    char *                   dq;
    int                      rc;
    int                      count = 0; /* Number of ldap entries found */
    char *                   search_string;
    struct ldap_search_list *lds;
    LDAPMessage *            res = NULL;
    LDAPMessage *            entry;
    struct timeval           timeout;
    char **                  vals;

    if ((ld->ldap_ld == NULL) || (ld->ldap_pid != getpid())) {
        if ((rc = simta_ldap_init(ld)) != 0) {
            return (rc);
        }
    }

    dup_name = strdup(name);

    if ((dq = simta_ldap_dequote(dup_name)) != NULL) {
        free(dup_name);
        dup_name = dq;
    }

    /*
    ** Strip . and _
    */
    for (pname = dup_name; *pname; pname++) {
        if (*pname == '.' || *pname == '_')
            *pname = ' ';
    }

    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    (void)simta_address_type(dup_name);

    /* for each base string in ldap_searches:
     *     - Build search string
     *     - query the LDAP db with the search string
     */
    for (lds = ld->ldap_searches; lds != NULL; lds = lds->lds_next) {
        search_string =
                simta_ldap_string(lds->lds_plud->lud_filter, dup_name, domain);
        if (search_string == NULL) {
            free(dup_name);
            return (ADDRESS_SYSERROR);
        }

        timeout.tv_sec = ld->ldap_timeout;
        timeout.tv_usec = 0;

        rc = ldap_search_st(ld->ldap_ld, lds->lds_plud->lud_dn,
                lds->lds_plud->lud_scope, search_string, attrs, 0, &timeout,
                &res);

        if ((rc != LDAP_SUCCESS) && (rc != LDAP_SIZELIMIT_EXCEEDED)) {
            syslog(LOG_ERR,
                    "Liberror: simta_ldap_address_local "
                    "ldap_search_st: %s",
                    ldap_err2string(rc));
            ldap_msgfree(res);
            free(dup_name);
            simta_ldap_unbind(ld);
            return (ADDRESS_SYSERROR);
        }

        if ((count = ldap_count_entries(ld->ldap_ld, res))) {
            break;
        }

        ldap_msgfree(res);
        res = NULL;
    }

    free(dup_name);

    if (count == 0) {
        rc = LDAP_NOT_LOCAL;
    } else {
        rc = LDAP_LOCAL;
        entry = ldap_first_entry(ld->ldap_ld, res);

        if ((vals = ldap_get_values(ld->ldap_ld, entry, "realtimeblocklist")) !=
                NULL) {
            if (strcasecmp(vals[ 0 ], "TRUE") == 0) {
                rc = LDAP_LOCAL_RBL;
            }
            ldap_value_free(vals);
        }

        if ((ld->ldap_people != NULL) &&
                (simta_ldap_value(ld, entry, "objectClass", ld->ldap_people) ==
                        1)) {
            if ((vals = ldap_get_values(
                         ld->ldap_ld, entry, ld->ldap_mailfwdattr)) == NULL) {
                rc = LDAP_NOT_LOCAL;
            } else {
                ldap_value_free(vals);
            }
        }
    }

    if (res) {
        ldap_msgfree(res);
    }

    return (rc);
}


static int
simta_ldap_expand_group(struct simta_ldap *ld, struct expand *exp,
        struct exp_addr *e_addr, int type, LDAPMessage *entry) {
    int    valfound = 0;
    int    moderator_error = 0;
    char **dnvals;
    char **mailvals;
    char * dn;
    char * errmsg;
    int    idx; /* universal iterator */

    char **memonly;   /* Members Only attribute values */
    char **private;   /* Private Members Only attribute value */
    char **moderator; /* Moderator attribute values */
    char **permitted; /* permittedgroup attribute values */

    char *attrval;
    char *ndn; /* a "normalized dn" */

    int    rc;
    char **vals;
    char **rdns;
    char * senderbuf;
    char * psender;
    int    suppressnoemail = 0;
    int    mo_group = 0;
    char **senderlist;
    char * permitted_addr;
    int    permitted_sender = 0;

    struct recipient *     r = NULL;
    struct string_address *sa;

    if ((dn = ldap_get_dn(ld->ldap_ld, entry)) == NULL) {
        syslog(LOG_ERR,
                "Liberror: simta_ldap_expand_group ldap_get_dn: failed");
        return (ADDRESS_SYSERROR);
    }

    if (e_addr->e_addr_dn == NULL) {
        dn_normalize_case(dn);
        e_addr->e_addr_dn = strdup(dn);
    }

    if ((vals = ldap_get_values(ld->ldap_ld, entry, "suppressNoEmailError")) !=
            NULL) {
        if (strcasecmp(vals[ 0 ], "TRUE") == 0) {
            suppressnoemail = 1;
        }
        ldap_value_free(vals);
    }

    rdns = ldap_explode_dn(dn, 1);

    e_addr->e_addr_owner =
            malloc(strlen(rdns[ 0 ]) + strlen(ld->ldap_associated_domain) + 8);
    sprintf(e_addr->e_addr_owner, "%s-owner@%s", rdns[ 0 ],
            ld->ldap_associated_domain);

    for (psender = e_addr->e_addr_owner; *psender; psender++) {
        if (*psender == ' ') {
            *psender = '.';
        }
    }

    if (*(e_addr->e_addr_from) == '\0') {
        senderbuf = strdup("");

    } else {
        /*
        * You can't send mail to groups that have no associatedDomain.
        */
        senderbuf = malloc(
                strlen(rdns[ 0 ]) + strlen(ld->ldap_associated_domain) + 12);

        sprintf(senderbuf, "%s-errors@%s", rdns[ 0 ],
                ld->ldap_associated_domain);
        for (psender = senderbuf; *psender; psender++) {
            if (*psender == ' ') {
                *psender = '.';
            }
        }

        if ((e_addr->e_addr_errors = address_bounce_create(exp)) == NULL) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: failed creating error env %s",
                    exp->exp_env->e_id, e_addr->e_addr, dn);
            free(senderbuf);
            ldap_memfree(dn);
            ldap_value_free(rdns);
            return ADDRESS_SYSERROR;
        }

        if (is_emailaddr(senderbuf) == 0) {
            free(senderbuf);
            senderbuf = strdup("");
            bounce_text(e_addr->e_addr_errors, TEXT_WARNING,
                    "Illegal email group name: ", rdns[ 0 ], NULL);
        }

        if (env_recipient(e_addr->e_addr_errors, senderbuf) != 0) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: "
                    "failed setting error recipient %s",
                    exp->exp_env->e_id, e_addr->e_addr, dn);
            free(senderbuf);
            ldap_memfree(dn);
            ldap_value_free(rdns);
            return ADDRESS_SYSERROR;
        }
    }

    ldap_value_free(rdns);

    switch (type) {
    case LDS_GROUP_ERRORS:
        dnvals = ldap_get_values(ld->ldap_ld, entry, "errorsto");
        mailvals = ldap_get_values(ld->ldap_ld, entry, "rfc822errorsto");
        errmsg = ": Group exists but has no errors-to address\n";

        if ((dnvals == NULL) && (mailvals == NULL)) {
            dnvals = ldap_get_values(ld->ldap_ld, entry, "owner");
        }
        break;

    case LDS_GROUP_REQUEST:
        dnvals = ldap_get_values(ld->ldap_ld, entry, "requeststo");
        mailvals = ldap_get_values(ld->ldap_ld, entry, "rfc822requeststo");
        errmsg = ": Group exists but has no requests-to address\n";

        if ((dnvals == NULL) && (mailvals == NULL)) {
            dnvals = ldap_get_values(ld->ldap_ld, entry, "owner");
        }
        break;

    case LDS_GROUP_OWNER:
        dnvals = ldap_get_values(ld->ldap_ld, entry, "owner");
        mailvals = NULL;
        errmsg = ": Group exists but has no owners\n";
        break;

    default:
        dnvals = NULL;
        mailvals = NULL;
        errmsg = NULL;

        /* check for group email forwarding (google) */
        if (ld->ldap_gmailfwdattr &&
                (mailvals = ldap_get_values(
                         ld->ldap_ld, entry, ld->ldap_gmailfwdattr)) != NULL) {
            if (exp->exp_env->e_n_exp_level < simta_exp_level_max) {
                if ((e_addr->e_addr_env_gmailfwd = env_create(simta_dir_fast,
                             NULL, e_addr->e_addr_from, exp->exp_env)) ==
                        NULL) {
                    ldap_value_free(mailvals);
                    ldap_memfree(dn);
                    free(senderbuf);
                    return (ADDRESS_SYSERROR);
                }

                for (idx = 0; mailvals[ idx ] != NULL; idx++) {
                    if (env_string_recipients(e_addr->e_addr_env_gmailfwd,
                                mailvals[ idx ]) != 0) {
                        env_free(e_addr->e_addr_env_gmailfwd);
                        e_addr->e_addr_env_gmailfwd = NULL;
                        ldap_value_free(mailvals);
                        ldap_memfree(dn);
                        free(senderbuf);
                        return (ADDRESS_SYSERROR);
                    }
                }

                ldap_value_free(mailvals);
                mailvals = NULL;

                if ((r = e_addr->e_addr_env_gmailfwd->e_rcpt) == NULL) {
                    /* no valid email addresses */
                    env_free(e_addr->e_addr_env_gmailfwd);
                    e_addr->e_addr_env_gmailfwd = NULL;
                    bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                            /* FIXME: addr? (???) */
                            "bad group mail forwarding: ", dn, NULL);
                }
                e_addr->e_addr_env_gmailfwd->e_next = exp->exp_gmailfwding;
                exp->exp_gmailfwding = e_addr->e_addr_env_gmailfwd;
            } else {
                ldap_value_free(mailvals);
                mailvals = NULL;
                bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                        "group mail audit loop: ", dn, NULL);
                break;
            }
        }

        if ((memonly = ldap_get_values(ld->ldap_ld, entry, "membersonly")) !=
                NULL) {
            if (strcasecmp(memonly[ 0 ], "TRUE") == 0) {
                if (((exp->exp_env->e_mail != NULL) &&
                            (*(exp->exp_env->e_mail) != '\0')) &&
                        ((senderlist = ldap_get_values(ld->ldap_ld, entry,
                                  "permitted_sender")) != NULL)) {
                    for (idx = 0; senderlist[ idx ] != NULL; idx++) {
                        sa = string_address_init(senderlist[ idx ]);

                        while ((permitted_addr = string_address_parse(sa)) !=
                                NULL) {
                            if (simta_mbx_compare(ld->ldap_ndomain,
                                        permitted_addr,
                                        exp->exp_env->e_mail) == 0) {
                                permitted_sender = 1;
                                break;
                            }
                        }

                        string_address_free(sa);

                        if (permitted_sender != 0) {
                            break;
                        }
                    }

                    ldap_value_free(senderlist);
                }

                if (permitted_sender == 0) {
                    mo_group = 1;
                }
            }
            ldap_value_free(memonly);
        }

        if ((permitted_sender == 0) &&
                ((moderator = ldap_get_values(
                          ld->ldap_ld, entry, "moderator")) != NULL)) {
            if (exp->exp_env->e_n_exp_level < simta_exp_level_max) {
                if ((e_addr->e_addr_env_moderated = env_create(simta_dir_fast,
                             NULL, exp->exp_env->e_mail, exp->exp_env)) ==
                        NULL) {
                    ldap_value_free(moderator);
                    ldap_memfree(dn);
                    free(senderbuf);
                    return (ADDRESS_SYSERROR);
                }

                for (idx = 0; moderator[ idx ] != NULL; idx++) {
                    if (env_string_recipients(e_addr->e_addr_env_moderated,
                                moderator[ idx ]) != 0) {
                        env_free(e_addr->e_addr_env_moderated);
                        e_addr->e_addr_env_moderated = NULL;
                        ldap_value_free(moderator);
                        ldap_memfree(dn);
                        free(senderbuf);
                        return (ADDRESS_SYSERROR);
                    }
                }

                ldap_value_free(moderator);

                if ((r = e_addr->e_addr_env_moderated->e_rcpt) == NULL) {
                    /* no valid email addresses */
                    env_free(e_addr->e_addr_env_moderated);
                    e_addr->e_addr_env_moderated = NULL;
                    moderator_error = 1;
                    bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                            "bad moderator: ", dn, NULL);
                }

                for (; r != NULL; r = r->r_next) {
                    if (simta_mbx_compare(ld->ldap_ndomain, r->r_rcpt,
                                exp->exp_env->e_mail) == 0) {
                        /* sender matches moderator in moderator env */
                        syslog(LOG_INFO,
                                "Expand.LDAP env <%s>: <%s>: "
                                "Moderator match %s %s",
                                exp->exp_env->e_id, e_addr->e_addr, r->r_rcpt,
                                exp->exp_env->e_mail);
                        break;
                    }
                }

                syslog(LOG_INFO,
                        "Expand.LDAP env <%s>: <%s>: no moderator match",
                        exp->exp_env->e_id, e_addr->e_addr);

            } else {
                bounce_text(e_addr->e_addr_errors, TEXT_ERROR,
                        "moderator mail loop: ", dn, NULL);
                break;
            }
        }

        if (r != NULL) {
            /* sender matches moderator in moderator env */
            env_free(e_addr->e_addr_env_moderated);
            e_addr->e_addr_env_moderated = NULL;

        } else if ((mo_group) && (permitted_sender == 0)) {
            e_addr->e_addr_ldap_flags |= STATUS_LDAP_MEMONLY;

            if ((private = ldap_get_values(
                         ld->ldap_ld, entry, "rfc822private")) != NULL) {
                if (strcasecmp(private[ 0 ], "TRUE") == 0) {
                    e_addr->e_addr_ldap_flags |= STATUS_LDAP_PRIVATE;
                }
                ldap_value_free(private);
            }

            if (exp_addr_link(&(exp->exp_memonly), e_addr) != 0) {
                ldap_memfree(dn);
                free(senderbuf);
                return (ADDRESS_SYSERROR);
            }

            if ((permitted = ldap_get_values(
                         ld->ldap_ld, entry, "permittedgroup")) != NULL) {
                if (permitted_create(e_addr, permitted) != 0) {
                    ldap_value_free(permitted);
                    free(senderbuf);
                    ldap_memfree(dn);
                    return (ADDRESS_SYSERROR);
                }
                ldap_value_free(permitted);
            }
        }

        if (((e_addr->e_addr_env_moderated == NULL) &&
                    (moderator_error == 0)) ||
                (e_addr->e_addr_ldap_flags & STATUS_LDAP_MEMONLY)) {
            dnvals = ldap_get_values(ld->ldap_ld, entry, "member");
            mailvals = ldap_get_values(ld->ldap_ld, entry, "rfc822mail");
        }

        if (suppressnoemail) {
            e_addr->e_addr_errors->e_flags |= ENV_FLAG_SUPPRESS_NO_EMAIL;
        }
        break;
    } /* end of switch */

    if (dnvals) {
        valfound++;

        for (idx = 0; dnvals[ idx ] != NULL; idx++) {
            ndn = dn_normalize_case(dnvals[ idx ]);

            /* If sending to group members
            ** -- change from address to be: group-errors@associateddomaon
            ** -- otherwise use the original sender.
            */
            if ((type == LDS_GROUP_MEMBERS) || (type == LDS_USER)) {
                rc = add_address(exp, ndn, e_addr->e_addr_errors,
                        ADDRESS_TYPE_LDAP, senderbuf);
            } else {
                rc = add_address(exp, ndn, e_addr->e_addr_errors,
                        ADDRESS_TYPE_LDAP, e_addr->e_addr_from);
            }
            if (rc != 0) {
                syslog(LOG_ERR,
                        "Expand.LDAP env <%s>: <%s>: %s failed adding %s",
                        exp->exp_env->e_id, e_addr->e_addr, dn, dnvals[ idx ]);
                break;
            }
        }
        ldap_value_free(dnvals);
    }

    if (mailvals) {
        valfound++;
        for (idx = 0; mailvals[ idx ] != NULL; idx++) {
            attrval = mailvals[ idx ];

            if (strchr(attrval, '@') != NULL) {
                if ((type == LDS_GROUP_MEMBERS) || (type == LDS_USER)) {
                    rc = address_string_recipients(
                            exp, attrval, e_addr, senderbuf);
                } else {
                    rc = address_string_recipients(
                            exp, attrval, e_addr, e_addr->e_addr_from);
                }

                if (rc != 0) {
                    syslog(LOG_ERR,
                            "Expand.LDAP env <%s>: <%s>: %s failed adding %s",
                            exp->exp_env->e_id, e_addr->e_addr, dn, attrval);
                    break;
                }
            }
        }
        ldap_value_free(mailvals);
    }

    if ((valfound == 0) && (errmsg != NULL)) {
        bounce_text(e_addr->e_addr_errors, TEXT_ERROR, dn, errmsg, NULL);
    }

    free(senderbuf);
    ldap_memfree(dn);
    return (ADDRESS_EXCLUDE);
}


static int
simta_ldap_process_entry(struct simta_ldap *ld, struct expand *exp,
        struct exp_addr *e_addr, int type, LDAPMessage *entry, char *addr) {
    char **values;
    char **uid;
    char **onvacation;
    int    idx;
    int    result;
    char * attrval;
    char   buf[ 1024 ];

    if ((ld->ldap_groups != NULL) && (simta_ldap_value(ld, entry, "objectClass",
                                              ld->ldap_groups) == 1)) {
        result = simta_ldap_expand_group(ld, exp, e_addr, type, entry);
        return (result);
    }

    /* it wasn't a group  -- check if it's a people */
    if ((ld->ldap_people != NULL) && (simta_ldap_value(ld, entry, "objectClass",
                                              ld->ldap_people) == 1)) {

        /* get individual's email address(es) */
        if ((values = ldap_get_values(
                     ld->ldap_ld, entry, ld->ldap_mailfwdattr)) == NULL) {
            /*
            ** This guy has no mailforwardingaddress
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
                        return (ADDRESS_SYSERROR);
                    }
                }
            }

        } else {
            for (idx = 0; values[ idx ] != NULL; idx++) {
                attrval = values[ idx ];
                if (address_string_recipients(
                            exp, attrval, e_addr, e_addr->e_addr_from) != 0) {
                    syslog(LOG_ERR,
                            "Expand.LDAP env <%s>: <%s>"
                            "failed adding mailforwardingaddress %s",
                            exp->exp_env->e_id, e_addr->e_addr, addr);
                    ldap_value_free(values);
                    return (ADDRESS_SYSERROR);
                }
            }

            ldap_value_free(values);

            if ((values = ldap_get_values(
                         ld->ldap_ld, entry, ld->ldap_mailattr)) != NULL) {
                if (simta_mbx_compare(ld->ldap_ndomain, values[ 0 ],
                            exp->exp_env->e_mail) == 0) {
                    e_addr->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
                }
                ldap_value_free(values);
            }

            /*
            * If the user is on vacation, send a copy of the mail to
            * the vacation server.  The address is constructed from
            * the vacationhost (specified in the config file) and
            * the uid. FIXME: this this attr should be configurable
            */
            onvacation = NULL;
            if ((ld->ldap_vacationhost != NULL) &&
                    (ld->ldap_vacationattr != NULL) &&
                    ((onvacation = ldap_get_values(ld->ldap_ld, entry,
                              ld->ldap_vacationattr)) != NULL) &&
                    (strcasecmp(onvacation[ 0 ], "TRUE") == 0)) {

                if ((uid = ldap_get_values(ld->ldap_ld, entry, "uid")) !=
                        NULL) {
                    snprintf(buf, sizeof(buf), "%s@%s", uid[ 0 ],
                            ld->ldap_vacationhost);
                    if (add_address(exp, buf, e_addr->e_addr_errors,
                                ADDRESS_TYPE_EMAIL, e_addr->e_addr_from) != 0) {
                        syslog(LOG_ERR,
                                "Expand.LDAP env <%s>: <%s>:"
                                "failed adding vacation address: %s",
                                exp->exp_env->e_id, e_addr->e_addr, buf);
                    }
                    ldap_value_free(uid);

                } else {
                    syslog(LOG_ERR,
                            "Expand.LDAP env <%s>: <%s>: user %s "
                            "is on vacation but doesn't have a uid",
                            exp->exp_env->e_id, e_addr->e_addr, addr);
                }
            }

            if (onvacation) {
                ldap_value_free(onvacation);
            }
        }

        return (ADDRESS_EXCLUDE);

    } else {
        /* Neither a group, or a person */
        syslog(LOG_ERR,
                "Expand.LDAP env <%s>: <%s>: "
                "Entry is neither person nor group ",
                exp->exp_env->e_id, e_addr->e_addr);
        bounce_text(e_addr->e_addr_errors, TEXT_ERROR, addr,
                " : Entry exists but is neither a group or person", NULL);
        return (ADDRESS_EXCLUDE);
    }
}


static int
simta_ldap_name_search(struct simta_ldap *ld, struct expand *exp,
        struct exp_addr *e_addr, char *addr, char *domain, int addrtype) {
    int                      rc;
    int                      match = 0;
    char *                   search_string;
    LDAPMessage *            res;
    LDAPMessage *            entry;
    struct ldap_search_list *lds;

    LDAPMessage *  tmpres = NULL;
    char *         dn;
    char **        xdn;
    struct timeval timeout;
    int            retrycnt = 0;

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
        if ((search_string = simta_ldap_string(
                     lds->lds_plud->lud_filter, addr, domain)) == NULL) {
            return (ADDRESS_SYSERROR);
        }

    startsearch:
        timeout.tv_sec = ld->ldap_timeout;
        timeout.tv_usec = 0;
        res = NULL;
        rc = ldap_search_st(ld->ldap_ld, lds->lds_plud->lud_dn,
                lds->lds_plud->lud_scope, search_string, attrs, 0, &timeout,
                &res);

        /* if the address is illegal in LDAP, we can't find it */
        /* (this can also happen if the container isn't there) */
        if ((rc == LDAP_FILTER_ERROR) || (rc == LDAP_NO_SUCH_OBJECT)) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: "
                    "ldap_search_st %s %s failed: %s",
                    exp->exp_env->e_id, e_addr->e_addr, lds->lds_plud->lud_dn,
                    search_string, ldap_err2string(rc));
            return (ADDRESS_NOT_FOUND);
        }

        /*
        ** After a long idle time,  the connection can be closed
        ** by the ldap server.  A long idle time can result if we
        ** are processing a really long queue of mail.
        ** If connection timeout, restart the connection.
        */
        if (rc == LDAP_SERVER_DOWN) {
            ldap_msgfree(res);

            retrycnt++;
            if (retrycnt > MAXRETRIES) {
                return (ADDRESS_SYSERROR);
            }

            if (simta_ldap_retry(ld) != 0) {
                return (ADDRESS_SYSERROR);
            }
            goto startsearch;
        }

        if ((rc != LDAP_SUCCESS) && (rc != LDAP_SIZELIMIT_EXCEEDED) &&
                (rc != LDAP_TIMELIMIT_EXCEEDED)) {
            syslog(LOG_ERR,
                    "Liberror: simta_ldap_name_search ldap_search_st %s: %s",
                    search_string, ldap_err2string(rc));
            ldap_msgfree(res);
            return (ADDRESS_SYSERROR);
        }

        if ((match = ldap_count_entries(ld->ldap_ld, res)) != 0) {
            break;
        }

        ldap_msgfree(res);

        /* Search timeout w/ no matches -- generate a temporary failure */
        if (rc == LDAP_TIMELIMIT_EXCEEDED) {
            return (ADDRESS_SYSERROR);
        }
    }

    switch (match) {
    case 0:
        return (ADDRESS_NOT_FOUND); /* no entries found */

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
            dn = ldap_get_dn(ld->ldap_ld, entry);
            xdn = ldap_explode_dn(dn, 1);

            /* FIXME: bad (why?), but how else can we do it? */
            if (strcasecmp(xdn[ 0 ], addr) == 0) {
                ldap_delete_result_entry(&res, entry);
                ldap_add_result_entry(&tmpres, entry);
            }
            ldap_value_free(xdn);
            free(dn);
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
            syslog(LOG_ERR,
                    "Liberror: simta_ldap_name_search ldap_first_entry: %s",
                    ldap_err2string(ldap_result2error(ld->ldap_ld, res, 1)));
            return (ADDRESS_SYSERROR);
        }
    }

    rc = simta_ldap_process_entry(ld, exp, e_addr, addrtype, entry, addr);

    ldap_msgfree(res);
    return (rc);
}


static int
simta_ldap_dn_expand(
        struct simta_ldap *ld, struct expand *exp, struct exp_addr *e_addr) {
    char *         search_dn;
    int            rc;
    int            match;
    LDAPMessage *  res;
    LDAPMessage *  entry;
    struct timeval timeout;

    search_dn = e_addr->e_addr;
    timeout.tv_sec = ld->ldap_timeout;
    timeout.tv_usec = 0;
    res = NULL;

    rc = ldap_search_st(ld->ldap_ld, search_dn, LDAP_SCOPE_BASE,
            "(objectclass=*)", attrs, 0, &timeout, &res);

    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED &&
            rc != LDAP_TIMELIMIT_EXCEEDED && rc != LDAP_NO_SUCH_OBJECT) {

        syslog(LOG_ERR, "Liberror: simta_ldap_dn_expand ldap_search_st: %s",
                ldap_err2string(rc));
        ldap_msgfree(res);
        simta_ldap_unbind(ld);
        return (ADDRESS_SYSERROR);
    }

    match = ldap_count_entries(ld->ldap_ld, res);

    if (match == -1) {
        syslog(LOG_ERR,
                "Expand.LDAP env <%s>: <%s>: "
                "Error parsing result from server for dn: %s",
                exp->exp_env->e_id, e_addr->e_addr, search_dn);
        ldap_msgfree(res);
        return (ADDRESS_SYSERROR);
    }

    if (match == 0) {
        ldap_msgfree(res);

        if (bounce_text(e_addr->e_addr_errors, TEXT_ERROR, search_dn,
                    " : Group member does not exist", NULL) != 0) {
            syslog(LOG_ERR,
                    "Expand.LDAP env <%s>: <%s>: "
                    "Failed building no member bounce message: %s",
                    exp->exp_env->e_id, e_addr->e_addr, search_dn);
            return (ADDRESS_SYSERROR);
        }
        return (ADDRESS_EXCLUDE); /* no entries found */
    }

    if ((entry = ldap_first_entry(ld->ldap_ld, res)) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_ldap_dn_entry ldap_first_entry: %s",
                ldap_err2string(ldap_result2error(ld->ldap_ld, res, 1)));
        ldap_msgfree(res);
        return (ADDRESS_SYSERROR);
    }

    rc = simta_ldap_process_entry(ld, exp, e_addr, LDS_USER, entry, search_dn);

    ldap_msgfree(res);
    return (rc);
}


/* this function should return:
     *     ADDRESS_NOT_FOUND if addr is not found in the database
     *     LDAP_FINAL if addr is a terminal expansion
     *     ADDRESS_EXCLUDE if addr is an error, and/or expands to other addrs.
     *     ADDRESS_SYSERROR if there is a system error
     *
     * expansion (not system) errors should be reported back to the sender
     * using bounce_text(...);
     *
     */

int
simta_ldap_expand(
        struct simta_ldap *ld, struct expand *exp, struct exp_addr *e_addr) {
    char *domain;   /* points to domain in address */
    char *name;     /* clone of incoming name */
    char *pname;    /* pointer for traversing name */
    char *dq;       /* dequoted name */
    int   nametype; /* Type of Groupname -- owner, member... */
    int   rc;       /* Universal return code */

    if ((ld->ldap_ld == NULL) || (ld->ldap_pid != getpid())) {
        if ((rc = simta_ldap_init(ld)) != 0) {
            return (rc);
        }
    }

    if (e_addr->e_addr_type == ADDRESS_TYPE_LDAP) {
        rc = simta_ldap_dn_expand(ld, exp, e_addr);
        return (rc);
    }

    if (e_addr->e_addr_at == NULL) {
        panic("simta_ldap_expand: e_addr->e_addr_at is NULL");
    }

    *e_addr->e_addr_at = '\0';
    name = strdup(e_addr->e_addr);
    *e_addr->e_addr_at = '@';

    if ((dq = simta_ldap_dequote(name)) != NULL) {
        free(name);
        name = dq;
    }

    domain = e_addr->e_addr_at + 1;

    /*
    ** We still want to strip . and _
    */
    for (pname = name; *pname; pname++) {
        if ((*pname == '.') || (*pname == '_')) {
            *pname = ' ';
        }
    }
    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    nametype = simta_address_type(name);
    rc = simta_ldap_name_search(ld, exp, e_addr, name, domain, nametype);
    free(name);
    return (rc);
}


static void
simta_ldapuser(int ndomain, char *buf, char **user, char **domain) {
    yastr u;
    char *p;

    *domain = NULL;

    if (simta_srs_secret && srs_reverse(buf, &p, simta_srs_secret) == SRS_OK) {
        u = yaslauto(p);
        free(p);
    } else {
        u = yaslauto(buf);
    }

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
    if ((strncasecmp(u, "prvs=", 5) == 0) &&
            ((p = strchr(u + 5, '=')) != NULL)) {
        yaslrange(u, p - u + 1, -1);
    }

    /* Barracuda do their own special version of BATV, which is incompatible
     * with the BATV draft because it uses '==' as the delimiter.
     */
    if ((strncasecmp(u, "btv1==", 6) == 0) &&
            ((p = strstr(u + 6, "==")) != NULL)) {
        yaslrange(u, p - u + 2, -1);
    }

    if ((p = strrchr(u, '@')) != NULL) {
        p++;
        simta_ldapdomain(ndomain, p, domain);
        yaslrange(u, 0, p - u - 2);
    } else {
        *domain = strdup("");
    }

    *user = strdup(u);
    yaslfree(u);
}


int
simta_mbx_compare(int ndomain, char *addr1, char *addr2) {
    char *local1;
    char *domain1;
    char *local2;
    char *domain2;

    int rc = -1;

    if (addr1 == NULL || addr2 == NULL || *addr1 == '\0' || *addr2 == '\0') {
        return (-1);
    }

    simta_ldapuser(ndomain, addr1, &local1, &domain1);
    simta_ldapuser(ndomain, addr2, &local2, &domain2);

    if ((rc = strcasecmp(local1, local2)) == 0) {
        rc = strcasecmp(domain1, domain2);
    }

    free(local1);
    free(domain1);
    free(local2);
    free(domain2);

    return (rc);
}


/*
     * given a config filename, this function sets up the search strings,
     * etc, that ldap needs later on.  This function is called *before*
     * simta becomes a daemon, so errors on stderr are ok.  Note that
     * we should still syslog all errors.
     */

struct simta_ldap *
simta_ldap_config(char *fname, char *domain) {
    int   fd = 0;
    SNET *snet = NULL;

    int                       lineno = 0;
    char *                    line;
    char *                    c;
    struct ldap_search_list **lds;
    struct list *             l_new;
    struct list **            add;
    yastr *                   av = NULL;
    int                       ac = 0;
    int                       acidx;
    int                       attridx;
#ifdef HAVE_LIBSSL
    int intval;
#endif                       /* HAVE_LIBSSL */
    LDAPURLDesc *      plud; /* a parsed ldapurl */
    int                rdnpref;
    int                search_type;
    int                ldaprc; /* ldap return code */
    struct simta_ldap *ret = NULL;
    struct simta_ldap *ld;

    /* open fname */
    if ((fd = open(fname, O_RDONLY, 0)) < 0) {
        syslog(LOG_ERR, "Syserror: simta_ldap_config open %s: %m", fname);
        goto errexit;
    }

    if ((snet = snet_attach(fd, 1024 * 1024)) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_ldap_config snet_attach: %m");
        goto errexit;
    }

    ld = calloc(1, sizeof(struct simta_ldap));
    lds = &(ld->ldap_searches);
    ld->ldap_timeout = LDAP_TIMEOUT_VAL;
    ld->ldap_ndomain = 2;

    while ((line = snet_getline(snet, NULL)) != NULL) {
        lineno++;

        if ((line[ 0 ] == '#') || (line[ 0 ] == '\0')) {
            continue;
        }

        if (av) {
            yaslfreesplitres(av, ac);
        }

        if ((av = yaslsplitargs(line, &ac)) == NULL) {
            syslog(LOG_ERR,
                    "Config.LDAP %s:%d: yaslsplitargs returned NULL: %s", fname,
                    lineno, line);
            goto errexit;
        }

        if ((strcasecmp(av[ 0 ], "uri") == 0) ||
                (strcasecmp(av[ 0 ], "url") == 0)) {
            if (ac < 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }

            if (ldap_is_ldap_url(av[ 1 ]) == 0) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: URI is not an LDAP URI: %s",
                        fname, lineno, line);
                goto errexit;
            }

            /* Parse the URL */
            if ((ldaprc = ldap_url_parse(av[ 1 ], &plud)) != LDAP_URL_SUCCESS) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: URI parse error %d: %s",
                        fname, lineno, ldaprc, line);
                goto errexit;
            }

            rdnpref = 0;
            search_type = 0;
            acidx = 2;
            while (acidx < ac) {
                if (strcasecmp(av[ acidx ], "rdnpref") == 0) {
                    rdnpref = 1;
                } else if (strncasecmp(av[ acidx ], "searchtype=", 11) == 0) {
                    c = &av[ acidx ][ 11 ];
                    if (strcasecmp(c, "ALL") == 0) {
                        search_type = LDS_ALL;
                    } else if (strcasecmp(c, "GROUP") == 0) {
                        search_type = LDS_GROUP;
                    } else if (strcasecmp(c, "USER") == 0) {
                        search_type = LDS_USER;
                    } else {
                        ldap_free_urldesc(plud);
                        syslog(LOG_ERR,
                                "Config.LDAP %s:%d: "
                                "Unknown searchtype in URI: %s",
                                fname, lineno, line);
                        goto errexit;
                    }
                } else {
                    ldap_free_urldesc(plud);
                    syslog(LOG_ERR, "%s:%d:%s", fname, lineno, line);
                    syslog(LOG_ERR,
                            "Config.LDAP %s:%d: Unknown extension in URI: %s",
                            fname, lineno, line);
                    goto errexit;
                }
                acidx++;
            }

            *lds = calloc(1, sizeof(struct ldap_search_list));
            (*lds)->lds_string = strdup(av[ 1 ]);
            (*lds)->lds_plud = plud;
            (*lds)->lds_rdn_pref = rdnpref;
            (*lds)->lds_search_type = search_type;
            (*lds)->lds_next = NULL;
            lds = &((*lds)->lds_next);

        } else if (strcasecmp(av[ 0 ], "attributes") == 0) {
            if (ac < 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }

            attrs = calloc((unsigned)ac, sizeof(char *));

            for (acidx = 1, attridx = 0; acidx < ac; acidx++, attridx++) {
                attrs[ attridx ] = strdup(av[ acidx ]);
            }

        } else if (strcasecmp(av[ 0 ], "host") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_host = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "port") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_port = atoi(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "timeout") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_timeout = (time_t)atoi(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "ldapdebug") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ldapdebug = atoi(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "ldapbind") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }

            if (strcasecmp(av[ 1 ], "SIMPLE") == 0) {
                ld->ldap_bind = BINDSIMPLE;
#ifdef HAVE_LIBSASL
            } else if (strcasecmp(av[ 1 ], "SASL") == 0) {
                ld->ldap_bind = BINDSASL;
#endif
            } else if (strcasecmp(av[ 1 ], "ANONYMOUS") == 0) {
                ld->ldap_bind = BINDANON;
            } else {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Invalid ldapbind value: %s",
                        fname, lineno, line);
                goto errexit;
            }

#ifdef HAVE_LIBSSL
        } else if (strcasecmp(av[ 0 ], "starttls") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            intval = atoi(av[ 1 ]);
            if ((intval < 0) || (intval > 2)) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Invalid starttls value: %s",
                        fname, lineno, line);
                goto errexit;
            }
            ld->ldap_starttls = intval;

        } else if (strcasecmp(av[ 0 ], "TLS_CACERT") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_tls_cacert = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "TLS_CERT") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_tls_cert = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "TLS_KEY") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_tls_key = strdup(av[ 1 ]);

#endif /* HAVE_LIBSSL */
        } else if (strcasecmp(av[ 0 ], "domaincomponentcount") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_ndomain = atoi(av[ 1 ]);

        } else if ((strcasecmp(av[ 0 ], "bindpw") == 0) ||
                   (strcasecmp(av[ 0 ], "bindpassword") == 0)) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_bindpw = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "binddn") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            ld->ldap_binddn = strdup(av[ 1 ]);

        } else if ((strcasecmp(av[ 0 ], "oc") == 0) ||
                   (strcasecmp(av[ 0 ], "objectclass") == 0)) {
            if (ac != 3) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }

            if (strcasecmp(av[ 1 ], "person") == 0) {
                add = &ld->ldap_people;
            } else if (strcasecmp(av[ 1 ], "group") == 0) {
                add = &ld->ldap_groups;
            } else {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Unknown objectclass: %s",
                        fname, lineno, line);
                goto errexit;
            }

            /* av [ 2] is a objectclass name */
            l_new = calloc(1, sizeof(struct list));
            l_new->l_string = strdup(av[ 2 ]);
            l_new->l_next = *add;
            *add = l_new;

        } else if (strcasecmp(av[ 0 ], "mail") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            if (ld->ldap_mailattr) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Can't set mail twice",
                        fname, lineno);
                goto errexit;
            }
            ld->ldap_mailattr = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "mailforwardingattr") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            if (ld->ldap_mailfwdattr) {
                syslog(LOG_ERR,
                        "Config.LDAP %s:%d: Can't set mailforwardingattr twice",
                        fname, lineno);
                goto errexit;
            }
            ld->ldap_mailfwdattr = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "groupmailforwardingattr") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            if (ld->ldap_gmailfwdattr) {
                syslog(LOG_ERR,
                        "Config.LDAP %s:%d: "
                        "Can't set groupmailfowardingattr twice",
                        fname, lineno);
                goto errexit;
            }
            ld->ldap_gmailfwdattr = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "vacationhost") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            if (ld->ldap_vacationhost) {
                syslog(LOG_ERR,
                        "Config.LDAP %s:%d: Can't set vacationhost twice",
                        fname, lineno);
                goto errexit;
            }
            ld->ldap_vacationhost = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "vacationattr") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            if (ld->ldap_vacationattr) {
                syslog(LOG_ERR,
                        "Config.LDAP %s:%d: Can't set vacationattr twice",
                        fname, lineno);
                goto errexit;
            }
            ld->ldap_vacationattr = strdup(av[ 1 ]);

        } else if (strcasecmp(av[ 0 ], "associateddomain") == 0) {
            if (ac != 2) {
                syslog(LOG_ERR, "Config.LDAP %s:%d: Missing value: %s", fname,
                        lineno, line);
                goto errexit;
            }
            if (ld->ldap_associated_domain) {
                syslog(LOG_ERR,
                        "Config.LDAP %s:%d: Can't set associateddomain twice",
                        fname, lineno);
                goto errexit;
            }
            ld->ldap_associated_domain = strdup(av[ 1 ]);
        } else {
            syslog(LOG_ERR, "Config.LDAP %s:%d: Unknown config option: %s",
                    fname, lineno, line);
            goto errexit;
        }
    }
    /* check to see that ldap is configured correctly */

    if (ld->ldap_people == NULL) {
        syslog(LOG_ERR, "Config.LDAP %s: No ldap people objectclass specified",
                fname);
        goto errexit;
    }
    if (ld->ldap_searches == NULL) {
        syslog(LOG_ERR, "Config.LDAP %s: No ldap searches specified", fname);
        goto errexit;
    }
    if (!ld->ldap_host) {
        syslog(LOG_ERR, "Config.LDAP %s: No ldap server specified", fname);
        goto errexit;
    }
    if (ld->ldap_port <= 0) {
        ld->ldap_port = 389;
    }
    if (ld->ldap_timeout <= 0) {
        ld->ldap_timeout = LDAP_TIMEOUT_VAL;
    }
    if (!ld->ldap_mailattr) {
        ld->ldap_mailattr = strdup("mail");
    }
    if (!ld->ldap_mailfwdattr) {
        ld->ldap_mailfwdattr = strdup("mail");
    }
    if ((ld->ldap_tls_cert) || (ld->ldap_tls_key)) {
        if (!ld->ldap_tls_cert) {
            syslog(LOG_ERR, "Config.LDAP %s: missing TLS_CERT parameter",
                    fname);
            goto errexit;
        }
        if (!ld->ldap_tls_key) {
            syslog(LOG_ERR, "Config.LDAP %s: missing TLS_KEY parameter", fname);
            goto errexit;
        }
    }
    if ((ld->ldap_starttls) &&
            ((ld->ldap_bind == BINDSASL) || (ld->ldap_bind == BINDSIMPLE))) {
        syslog(LOG_ERR,
                "Config.LDAP %s: "
                "Cannot have both starttls and ldapbind configured",
                fname);
        goto errexit;
    }

    if (ld->ldap_associated_domain == NULL) {
        ld->ldap_associated_domain = strdup(domain);
    }

    if (attrs == NULL) {
        attrs = allattrs;
    }

    ret = ld;

errexit:
    if (av) {
        yaslfreesplitres(av, ac);
    }
    if (snet) {
        if (snet_close(snet) != 0) {
            syslog(LOG_ERR, "Liberror: simta_ldap_config snet_close: %m");
        }
        fd = 0;
    }
    if (fd) {
        if (close(fd)) {
            syslog(LOG_ERR, "Syserror: simta_ldap_config close: %m");
        }
    }
    return (ret);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
