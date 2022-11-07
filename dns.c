/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

#ifdef HAVE_LIBIDN2
#include <idn2.h>
#endif /* HAVE_LIBIDN2 */

#include "dns.h"
#include "red.h"
#include "simta.h"
#include "simta_malloc.h"
#include "simta_statsd.h"

static struct dnsr_result *get_address(const char *, int);

bool
simta_dnsr_init(void) {
    const ucl_object_t *dns_config;

    if (simta_dnsr) {
        return (true);
    }

    if ((simta_dnsr = dnsr_new()) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_dnsr_init dnsr_new: %s",
                strerror(errno));
        return (false);
    }
    if ((dns_config = simta_config_obj("core.dns")) != NULL) {
        dnsr_nameserver_port(simta_dnsr,
                ucl_object_tostring(ucl_object_lookup(dns_config, "host")),
                ucl_object_tostring_forced(
                        ucl_object_lookup(dns_config, "port")));
    }

    return (true);
}

static struct dnsr_result *
get_address(const char *hostname, int qtype) {
    struct dnsr_result *result;
    const char *        lookup_hostname;
    int                 rc;
    const ucl_object_t *obj;
    struct timeval *    timeout = NULL;
    struct timeval      tv_timeout;

#ifdef HAVE_LIBIDN2
    char *idna = NULL;
#endif /* HAVE_LIBIDN2 */

    lookup_hostname = hostname;

    if (!simta_dnsr_init()) {
        return (NULL);
    }

#ifdef HAVE_LIBIDN2
    if (simta_check_charset(hostname) == SIMTA_CHARSET_UTF8) {
        if ((rc = idn2_to_ascii_8z(hostname, &idna,
                     IDN2_NONTRANSITIONAL | IDN2_NFC_INPUT)) != IDN2_OK) {
            syslog(LOG_ERR, "Liberror: get_address idn2_to_ascii_8z: %s",
                    idn2_strerror(rc));
            return (NULL);
        }
        lookup_hostname = idna;
    }
#endif /* HAVE_LIBIDN2 */

    rc = dnsr_query(simta_dnsr, qtype, DNSR_CLASS_IN, lookup_hostname);

#ifdef HAVE_LIBIDN2
    free(idna);
#endif /* HAVE_LIBIDN2 */

    if (rc < 0) {
        syslog(LOG_ERR, "Liberror: get_address dnsr_query: %d %s: %s", qtype,
                hostname, dnsr_err2string(dnsr_errno(simta_dnsr)));
        return (NULL);
    }

    if ((obj = simta_config_obj("core.dns.timeout")) != NULL) {
        timeout = &tv_timeout;
        simta_ucl_object_totimeval(obj, timeout);
    }

    if ((result = dnsr_result(simta_dnsr, timeout)) == NULL) {
        syslog(LOG_ERR, "Liberror: get_address dnsr_result: %d %s: %s", qtype,
                hostname, dnsr_err2string(dnsr_errno(simta_dnsr)));
        return (NULL);
    }

    return (result);
}

struct dnsr_result *
get_a(const char *hostname) {
    return get_address(hostname, DNSR_TYPE_A);
}

struct dnsr_result *
get_aaaa(const char *hostname) {
    return get_address(hostname, DNSR_TYPE_AAAA);
}

/* RFC 5321 2.3.5 Domain Names
 * Only resolvable, fully-qualified, domain names (FQDNs) are permitted when
 * domain names are used in SMTP.  In other words, names that can be resolved
 * to MX RRs or address (i.e. A or AAAA) RRs (as discussed in section 5) are
 * permitted, as are CNAME RRs whose targets can be resolved, in turn, to MX
 * or address RRs.  Local nicknames or unqualified names MUST NOT be used.
 */

struct dnsr_result *
get_mx(const char *hostname) {
    struct dnsr_result *result = NULL;

    result = get_address(hostname, DNSR_TYPE_MX);

    return (result);
}

struct dnsr_result *
get_ptr(const struct sockaddr *sa) {
    struct dnsr_result *result = NULL;
    char *              hostname;

    if (!simta_dnsr_init()) {
        return (NULL);
    }

    if ((hostname = dnsr_ntoptr(simta_dnsr, sa->sa_family,
                 ((sa->sa_family == AF_INET)
                                 ? (void *)&(
                                           ((struct sockaddr_in *)sa)->sin_addr)
                                 : (void *)&(((struct sockaddr_in6 *)sa)
                                                     ->sin6_addr)),
                 NULL)) == NULL) {
        syslog(LOG_ERR, "Liberror: get_ptr dnsr_ntoptr: %s",
                dnsr_err2string(dnsr_errno(simta_dnsr)));
        return (NULL);
    }

    result = get_address(hostname, DNSR_TYPE_PTR);
    free(hostname);
    return (result);
}


struct dnsr_result *
get_txt(const char *hostname) {
    return (get_address(hostname, DNSR_TYPE_TXT));
}

yastr
simta_dnsr_str(const struct dnsr_string *data) {
    yastr                     str;
    const struct dnsr_string *s;

    str = yaslempty();
    for (s = data; s; s = s->s_next) {
        str = yaslcat(str, s->s_string);
    }

    return (str);
}

int
check_reverse(char *dn, const struct sockaddr *sa) {
    int                 i, j;
    int                 ret = REVERSE_UNKNOWN;
    struct dnsr_result *result_ptr = NULL, *result_a = NULL;

    if ((result_ptr = get_ptr(sa)) == NULL) {
        return (REVERSE_ERROR);
    }

    for (i = 0; i < result_ptr->r_ancount; i++) {
        if (result_ptr->r_answer[ i ].rr_type == DNSR_TYPE_PTR) {
            /* Get A record on PTR result */
            if (sa->sa_family == AF_INET6) {
                result_a = get_aaaa(result_ptr->r_answer[ i ].rr_dn.dn_name);
            } else {
                result_a = get_a(result_ptr->r_answer[ i ].rr_dn.dn_name);
            }

            if (result_a == NULL) {
                ret = REVERSE_ERROR;
                goto error;
            }

            ret = REVERSE_MISMATCH;

            /* Verify A record matches IP */
            for (j = 0; j < result_a->r_ancount; j++) {
                if ((sa->sa_family == AF_INET6) &&
                        (result_a->r_answer[ j ].rr_type == DNSR_TYPE_AAAA)) {
                    if (memcmp(&(result_a->r_answer[ j ].rr_aaaa.aaaa_address),
                                &(((struct sockaddr_in6 *)sa)->sin6_addr),
                                sizeof(struct in6_addr)) == 0) {
                        ret = REVERSE_MATCH;
                    }
                } else if ((sa->sa_family == AF_INET) &&
                           (result_a->r_answer[ j ].rr_type == DNSR_TYPE_A)) {
                    if (memcmp(&(result_a->r_answer[ j ].rr_a.a_address),
                                &(((struct sockaddr_in *)sa)->sin_addr),
                                sizeof(struct in_addr)) == 0) {
                        ret = REVERSE_MATCH;
                    }

                } else {
                    simta_debuglog(2,
                            "DNS: check_reverse %s: uninteresting dnsr type: "
                            "%d",
                            result_a->r_answer[ j ].rr_name,
                            result_a->r_answer[ j ].rr_type);
                }

                if (ret == REVERSE_MATCH) {
                    if (dn) {
                        strncpy(dn, result_ptr->r_answer[ i ].rr_dn.dn_name,
                                DNSR_MAX_NAME);
                    }
                    dnsr_free_result(result_a);
                    dnsr_free_result(result_ptr);
                    return (ret);
                }
            }
            dnsr_free_result(result_a);

        } else {
            simta_debuglog(2,
                    "DNS: check_reverse %s: uninteresting dnsr type: %d",
                    result_ptr->r_answer[ i ].rr_name,
                    result_ptr->r_answer[ i ].rr_type);
        }
    }

error:
    dnsr_free_result(result_ptr);
    return (ret);
}

int
check_hostname(const char *hostname) {
    struct dnsr_result *result;

    if ((result = get_mx(hostname)) == NULL) {
        return (-1);
    }
    if (result->r_ancount > 0) {
        dnsr_free_result(result);
        return (0);
    }
    dnsr_free_result(result);

    if ((result = get_a(hostname)) == NULL) {
        return (-1);
    }
    if (result->r_ancount > 0) {
        dnsr_free_result(result);
        return (0);
    }
    dnsr_free_result(result);

    if ((result = get_aaaa(hostname)) == NULL) {
        return (-1);
    }
    if (result->r_ancount > 0) {
        dnsr_free_result(result);
        return (0);
    }
    dnsr_free_result(result);

    return (1);
}

bool
dnsr_result_is_cname(struct dnsr_result *r) {
    if (r) {
        for (int i = 0; i < r->r_ancount; i++) {
            if (r->r_answer[ i ].rr_type == DNSR_TYPE_CNAME) {
                return true;
            }
        }
    }
    return false;
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
