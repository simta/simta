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

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "dns.h"
#include "red.h"
#include "simta.h"
#include "simta_malloc.h"
#include "simta_statsd.h"

#ifdef HAVE_LIBSSL
#include "md.h"
#endif /* HAVE_LIBSSL */

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

struct dnsl_result *
dnsl_check(const char *chain, const struct sockaddr *sa, const char *text) {
    const ucl_object_t *chain_obj;
    const ucl_object_t *list;
    ucl_object_iter_t   iter;
#ifdef HAVE_LIBSSL
    struct message_digest md;
#endif /* HAVE_LIBSSL */
    const char *        lookup_base;
    yastr               lookup = NULL;
    char *              ptrbuf = NULL;
    const char *        buf;
    char                sa_ip[ INET6_ADDRSTRLEN ];
    yastr               ip = NULL;
    yastr               reason = NULL;
    yastr               statsd_name = NULL;
    const char *        dnsl_action;
    struct dnsr_result *result;
    struct sockaddr_in  sin;
    int                 i;
    struct dnsl_result *ret = NULL;

    if (sa) {
        if (getnameinfo((struct sockaddr *)sa,
                    ((sa->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in)),
                    sa_ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) != 0) {
            syslog(LOG_ERR, "Syserror: dnsl_check getnameinfo: %m");
            strcpy(sa_ip, "INVALID");
        }
    }

    if (((chain_obj = simta_config_obj(chain)) == NULL) ||
            (ucl_array_size(chain_obj) == 0)) {
        simta_debuglog(1, "DNS List: no lists in '%s' chain", chain);
        return (NULL);
    }

#ifdef HAVE_LIBSSL
    md_init(&md);
#endif /* HAVE_LIBSSL */

    iter = ucl_object_iterate_new(chain_obj);

    while ((list = ucl_object_iterate_safe(iter, false)) != NULL) {
        lookup_base = ucl_object_tostring(ucl_object_lookup(list, "list"));

        if (sa) {
            /* RFC 5782 2.1 IP Address DNSxL
             * An IPv4 address DNSxL has a structure adapted from that of the
             * rDNS. (The rDNS, reverse DNS, is the IN-ADDR.ARPA [RFC1034] and
             * IP6.ARPA [RFC3596] domains used to map IP addresses to domain
             * names.)  Each IPv4 address listed in the DNSxL has a
             * corresponding DNS entry.  The entry's name is created by
             * reversing the order of the octets of the text representation
             * of the IP address, and appending the domain name of the DNSxL.
             *
             * RFC 5782 2.4 IPv6 DNSxLs
             * The structure of DNSxLs based on IPv6 addresses is adapted from
             * that of the IP6.ARPA domain defined in [RFC3596].  Each entry's
             * name MUST be a 32-component hex nibble-reversed IPv6 address
             * suffixed by the DNSxL domain.
             */
            if ((ptrbuf = dnsr_ntoptr(simta_dnsr, sa->sa_family,
                         ((sa->sa_family == AF_INET)
                                         ? (void *)&(((struct sockaddr_in *)sa)
                                                             ->sin_addr)
                                         : (void *)&(((struct sockaddr_in6 *)sa)
                                                             ->sin6_addr)),
                         lookup_base)) == NULL) {
                syslog(LOG_ERR, "DNS List [%s]: dnsr_ntoptr failed: %s", sa_ip,
                        lookup_base);
                continue;
            }
            lookup = yaslauto(ptrbuf);
            free(ptrbuf);

        } else {
            lookup = yaslauto(text);
            if (ucl_object_toboolean(ucl_object_lookup(list, "domain_only"))) {
                yaslrange(lookup, strrchr(lookup, '@') - lookup + 1, -1);
            }
            yasltolower(lookup);

#ifdef HAVE_LIBSSL
            if ((buf = ucl_object_tostring(
                         ucl_object_lookup(list, "algorithm"))) != NULL) {
                md_reset(&md, buf);
                md_update(&md, lookup, yasllen(lookup));
                md_finalize(&md);
                yaslclear(lookup);
                lookup = yaslcat(lookup, md.md_b16);
            }
#endif /* HAVE_LIBSSL */

            lookup = yaslcatlen(lookup, ".", 1);
            lookup = yaslcat(lookup, lookup_base);
        }

        if ((result = get_a(lookup)) == NULL) {
            simta_debuglog(1, "DNS List [%s]: Timeout: %s", sa ? sa_ip : text,
                    lookup_base);
            yaslfree(lookup);
            continue;
        }

        for (i = 0; i < result->r_ancount; i++) {
            /* RFC 5782 2.1 IP Address DNSxL
             * Each entry in the DNSxL MUST have an A record. DNSBLs SHOULD
             * have a TXT record that describes the reason for the entry.
             * DNSWLs MAY have a TXT record that describes the reason for
             * the entry.  The contents of the A record MUST NOT be used as
             * an IP address.  The A record contents conventionally have the
             * value 127.0.0.2, but MAY have other values as described below
             * in Section 2.3. The TXT record describes the reason that the IP
             * address is listed in the DNSxL, and is often used as the text
             * of an SMTP error response when an SMTP client attempts to send
             * mail to a server using the list as a DNSBL, or as explanatory
             * text when the DNSBL is used in a scoring spam filter.
             */
            if ((result->r_answer[ i ].rr_type == DNSR_TYPE_A) &&
                    (ip == NULL)) {
                memset(&sin, 0, sizeof(struct sockaddr_in));
                memcpy(&(sin.sin_addr.s_addr), &(result->r_answer[ 0 ].rr_a),
                        sizeof(struct in_addr));
                ip = yaslauto(inet_ntoa(sin.sin_addr));
            }
        }

        dnsr_free_result(result);

        if ((result = get_txt(lookup)) == NULL) {
            simta_debuglog(1, "DNS List [%s]: Timeout: %s", sa ? sa_ip : text,
                    lookup_base);
        } else {
            for (i = 0; i < result->r_ancount; i++) {
                if ((result->r_answer[ i ].rr_type == DNSR_TYPE_TXT) &&
                        (reason == NULL)) {
                    reason = simta_dnsr_str(
                            result->r_answer[ i ].rr_txt.txt_data);
                }
            }
            dnsr_free_result(result);
        }

        if (ip) {
            if (reason == NULL) {
                if ((buf = ucl_object_tostring(
                             ucl_object_lookup(list, "message"))) != NULL) {
                    reason = yaslauto(buf);
                } else {
                    reason = yaslauto("local policy");
                }
            }

            dnsl_action = ucl_object_tostring(ucl_object_lookup(list, ip));
            if (!dnsl_action) {
                dnsl_action =
                        ucl_object_tostring(ucl_object_lookup(list, "action"));
            }

            simta_debuglog(1, "DNS List [%s]: Found in %s list %s: %s / %s",
                    sa ? sa_ip : text, dnsl_action, lookup_base, ip,
                    reason ? reason : "Unknown");

            if (strcasecmp(dnsl_action, "log_only") != 0) {
                ret = simta_calloc(1, sizeof(struct dnsl_result));
                ret->dnsl_list = yaslauto(lookup_base);
                ret->dnsl_action = yaslauto(dnsl_action);
                ret->dnsl_reason = reason;
                ret->dnsl_result = ip;
            }
        }

        yaslfree(lookup);

        if (ret) {
            statsd_name = yaslcatprintf(
                    yaslmapchars(yaslauto(lookup_base), ".", "_", 1), ".%s",
                    ret->dnsl_action);
            statsd_counter("dnsl", statsd_name, 1);
            yaslfree(statsd_name);
            statsd_name = NULL;
            ucl_object_iterate_free(iter);
#ifdef HAVE_LIBSSL
            md_cleanup(&md);
#endif /* HAVE_LIBSSL */
            return ret;
        }

        simta_debuglog(1, "DNS List [%s]: Unlisted in list %s",
                sa ? sa_ip : text, lookup_base);

        yaslfree(ip);
        ip = NULL;
        yaslfree(reason);
        reason = NULL;
    }

    simta_debuglog(1, "DNS List [%s]: chain %s exhausted, no matches",
            sa ? sa_ip : text, chain);


    ucl_object_iterate_free(iter);
#ifdef HAVE_LIBSSL
    md_cleanup(&md);
#endif /* HAVE_LIBSSL */

    return NULL;
}

void
dnsl_result_free(struct dnsl_result *res) {
    if (res) {
        yaslfree(res->dnsl_list);
        yaslfree(res->dnsl_action);
        yaslfree(res->dnsl_reason);
        yaslfree(res->dnsl_result);
        free(res);
    }
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
