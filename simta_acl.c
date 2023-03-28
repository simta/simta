/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "dns.h"
#include "red.h"
#include "simta.h"
#include "simta_acl.h"
#include "simta_malloc.h"
#include "simta_statsd.h"

#ifdef HAVE_LIBSSL
#include "md.h"
#endif /* HAVE_LIBSSL */

static void acl_lookup_dns(
        struct acl_result *, const char *, const struct sockaddr *);
static void acl_lookup_file(
        struct acl_result *, const char *, const struct sockaddr *);


static void
acl_lookup_dns(
        struct acl_result *res, const char *domain, const struct sockaddr *sa) {
    struct dnsr_result *dns_result;
    struct sockaddr_in  sin;
    char               *ptrbuf = NULL;
    yastr               lookup = NULL;

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
                     domain)) == NULL) {
            syslog(LOG_ERR, "DNS List [%s]: dnsr_ntoptr failed: %s",
                    res->acl_text_raw, domain);
            return;
        }
        lookup = yaslauto(ptrbuf);
    } else {
        lookup = yasldup(res->acl_text_cooked);
        lookup = yaslcatlen(lookup, ".", 1);
        lookup = yaslcat(lookup, domain);
    }

    if ((dns_result = get_a(lookup)) == NULL) {
        simta_debuglog(
                1, "ACL [%s]: DNS timeout: %s", res->acl_text_raw, domain);
        yaslfree(lookup);
        return;
    }

    for (int i = 0; i < dns_result->r_ancount; i++) {
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
        if ((dns_result->r_answer[ i ].rr_type == DNSR_TYPE_A) &&
                (res->acl_result == NULL)) {
            memset(&sin, 0, sizeof(struct sockaddr_in));
            memcpy(&(sin.sin_addr.s_addr), &(dns_result->r_answer[ 0 ].rr_a),
                    sizeof(struct in_addr));
            res->acl_result = yaslauto(inet_ntoa(sin.sin_addr));
        }
    }
    dnsr_free_result(dns_result);

    if (res->acl_result) {
        if ((dns_result = get_txt(lookup)) == NULL) {
            simta_debuglog(
                    1, "ACL [%s]: DNS timeout: %s", res->acl_text_raw, domain);
        } else {
            for (int i = 0; i < dns_result->r_ancount; i++) {
                if ((dns_result->r_answer[ i ].rr_type == DNSR_TYPE_TXT) &&
                        (res->acl_reason == NULL)) {
                    res->acl_reason = simta_dnsr_str(
                            dns_result->r_answer[ i ].rr_txt.txt_data);
                }
            }
            dnsr_free_result(dns_result);
        }
    }

    yaslfree(lookup);
}


static void
acl_lookup_file(
        struct acl_result *res, const char *fname, const struct sockaddr *sa) {
    SNET         *snet = NULL;
    size_t        tok_count;
    yastr        *split;
    const char   *data;
    bool          matched = false;
    unsigned long cidr;
    char         *p;

    if ((snet = snet_open(fname, O_RDONLY, 0, 1024 * 1024)) == NULL) {
        syslog(LOG_ERR, "Liberror: acl_lookup_file snet_open %s: %m", fname);
        return;
    }

    while ((res->acl_result == NULL) &&
            ((data = snet_getline(snet, NULL)) != NULL)) {
        split = yaslsplitargs(data, &tok_count);
        if (tok_count > 0) {
            if (sa) {
                if ((p = strchr(split[ 0 ], '/')) != NULL) {
                    /* Adjust the string to exclude the netmask. */
                    *p = '\0';
                    yaslupdatelen(split[ 0 ]);
                    /* Parse the netmask. */
                    errno = 0;
                    cidr = strtoul(p + 1, NULL, 10);
                    if (errno) {
                        simta_debuglog(2,
                                "Liberror: acl_lookup_file strtoul %s: %m",
                                p + 1);
                        cidr = 255;
                    }
                    if ((sa->sa_family == AF_INET) && cidr > 32) {
                        cidr = 32;
                    } else if ((sa->sa_family == AF_INET) && cidr > 128) {
                        cidr = 128;
                    }
                } else {
                    cidr = (sa->sa_family == AF_INET) ? 32 : 64;
                }

                if (simta_cidr_compare(cidr, sa, NULL, split[ 0 ]) == 0) {
                    matched = true;
                }
            } else if (strcasecmp(split[ 0 ], res->acl_text_cooked) == 0) {
                matched = true;
            }
            if (matched) {
                if (tok_count > 1) {
                    res->acl_reason = yasldup(split[ 1 ]);
                    if (tok_count > 2) {
                        res->acl_result = yasldup(split[ 2 ]);
                    }
                }

                if (!res->acl_result) {
                    res->acl_result = yasldup(split[ 0 ]);
                }
            }
        }
        yaslfreesplitres(split, tok_count);
    }

    if (snet_close(snet) < 0) {
        syslog(LOG_ERR, "Liberror: acl_lookup_file snet_close %s: %m", fname);
    }
}


struct acl_result *
acl_check(const char *chain, const struct sockaddr *sa, const char *text) {
    const ucl_object_t *chain_obj;
    const ucl_object_t *list;
    ucl_object_iter_t   iter;
#ifdef HAVE_LIBSSL
    struct message_digest md;
#endif /* HAVE_LIBSSL */
    const char        *lookup_base;
    yastr              lookup_text = NULL;
    const char        *buf;
    char               sa_ip[ INET6_ADDRSTRLEN ];
    const char        *acl_type;
    yastr              statsd_name = NULL;
    const char        *acl_action = NULL;
    struct acl_result *ret = NULL;

    if (((chain_obj = simta_config_obj(chain)) == NULL) ||
            (ucl_array_size(chain_obj) == 0)) {
        simta_debuglog(1, "ACL: no lists in %s chain", chain);
        return NULL;
    }

    statsd_counter("acl_chain", chain, 1);

    ret = simta_calloc(1, sizeof(struct acl_result));

    if (sa) {
        if (getnameinfo((struct sockaddr *)sa,
                    ((sa->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in)),
                    sa_ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) != 0) {
            syslog(LOG_ERR, "Syserror: acl_check getnameinfo: %m");
            strcpy(sa_ip, "INVALID");
        }
        ret->acl_text_raw = yaslauto(sa_ip);
    } else {
        ret->acl_text_raw = yaslauto(text);
    }

#ifdef HAVE_LIBSSL
    md_init(&md);
#endif /* HAVE_LIBSSL */

    iter = ucl_object_iterate_new(chain_obj);
    while ((list = ucl_object_iterate_safe(iter, false)) != NULL) {
        lookup_base = ucl_object_tostring(ucl_object_lookup(list, "list"));

        if (sa == NULL) {
            ret->acl_text_cooked = yaslauto(text);
            if (ucl_object_toboolean(ucl_object_lookup(list, "domain_only"))) {
                yaslrangeseprright(ret->acl_text_cooked, '@');
            }
            yasltolower(ret->acl_text_cooked);

#ifdef HAVE_LIBSSL
            if ((buf = ucl_object_tostring(
                         ucl_object_lookup(list, "algorithm"))) != NULL) {
                md_reset(&md, buf);
                md_update(&md, ret->acl_text_cooked,
                        yasllen(ret->acl_text_cooked));
                md_finalize(&md);
                yaslclear(ret->acl_text_cooked);
                ret->acl_text_cooked = yaslcat(ret->acl_text_cooked, md.md_b16);
            }
#endif /* HAVE_LIBSSL */
        }

        acl_type = ucl_object_tostring(ucl_object_lookup(list, "type"));
        if (acl_type && (strcasecmp(acl_type, "file") == 0)) {
            acl_lookup_file(ret, lookup_base, sa);
        } else {
            acl_lookup_dns(ret, lookup_base, sa);
        }

        if (ret->acl_result) {
            if (ret->acl_reason == NULL) {
                if ((buf = ucl_object_tostring(
                             ucl_object_lookup(list, "message"))) != NULL) {
                    ret->acl_reason = yaslauto(buf);
                } else {
                    ret->acl_reason = yaslauto("local policy");
                }
            }

            /* Check for an overridden action (e.g. for lists that contain
             * multiple types of entries, or return a specific value to
             * indicate that your query has been denied.
             *
             * We could probably limit this more, but checking for '.' is
             * cheap and will avoid any possibility of collision with the
             * normal config attributes.
             */
            if (strchr(ret->acl_result, '.') != NULL) {
                acl_action = ucl_object_tostring(
                        ucl_object_lookup(list, ret->acl_result));
            }

            if (!acl_action) {
                acl_action =
                        ucl_object_tostring(ucl_object_lookup(list, "action"));
            }

            simta_debuglog(1, "ACL [%s]: Found in %s list %s: %s / %s",
                    ret->acl_text_raw, acl_action, lookup_base, ret->acl_result,
                    ret->acl_reason);

            if (strcasecmp(acl_action, "log_only") == 0) {
                yaslfree(ret->acl_result);
                yaslfree(ret->acl_reason);
                ret->acl_result = NULL;
                ret->acl_reason = NULL;
            } else {
                ret->acl_list = yaslauto(lookup_base);
                ret->acl_action = yaslauto(acl_action);
            }
        }

        yaslfree(lookup_text);

        if (ret->acl_result) {
            statsd_name = yaslcatprintf(
                    yaslmapchars(yaslauto(lookup_base), "./", "__", 2), ".%s",
                    ret->acl_action);
            statsd_counter("acl", statsd_name, 1);
            yaslfree(statsd_name);
            statsd_name = NULL;
            ucl_object_iterate_free(iter);
#ifdef HAVE_LIBSSL
            md_cleanup(&md);
#endif /* HAVE_LIBSSL */
            return ret;
        }

        simta_debuglog(1, "ACL [%s]: Unlisted in list %s", ret->acl_text_raw,
                lookup_base);
    }

    simta_debuglog(1, "ACL [%s]: chain %s exhausted, no matches",
            ret->acl_text_raw, chain);

    acl_result_free(ret);
    ucl_object_iterate_free(iter);
#ifdef HAVE_LIBSSL
    md_cleanup(&md);
#endif /* HAVE_LIBSSL */

    return NULL;
}

void
acl_result_free(struct acl_result *res) {
    if (res) {
        yaslfree(res->acl_list);
        yaslfree(res->acl_text_raw);
        yaslfree(res->acl_text_cooked);
        yaslfree(res->acl_action);
        yaslfree(res->acl_reason);
        yaslfree(res->acl_result);
        free(res);
    }
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
