/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

#ifdef HAVE_LIBSSL
#include "md.h"
#endif /* HAVE_LIBSSL */

static struct dnsr_result *get_address(const char *, int);


static struct dnsr_result *
get_address(const char *hostname, int qtype) {
    struct dnsr_result *result;
    const char *        lookup_hostname;
    int                 rc;

#ifdef HAVE_LIBIDN2
    char *idna = NULL;
#endif /* HAVE_LIBIDN2 */

    lookup_hostname = hostname;

    if (simta_dnsr == NULL) {
        if ((simta_dnsr = dnsr_new()) == NULL) {
            syslog(LOG_ERR, "Liberror: get_address dnsr_new: %m");
            return (NULL);
        }
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

    if ((result = dnsr_result(simta_dnsr, NULL)) == NULL) {
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
    int                 i;
    struct dnsr_result *result = NULL;
    struct simta_red *  red;

    result = get_address(hostname, DNSR_TYPE_MX);

    if (simta_dns_auto_config == 0) {
        return (result);
    }

    if (result->r_ancount == 0) {
        return (result);
    }

    /* Check to see if hostname is mx'ed to us
     * Only do dynamic configuration when exchange matches our
     * actual host name and is highest preference MX.  Others must be
     * configured by hand.
     */
    /* FIXME: is this broken?  no check for preference as comments suggest */
    for (i = 0; i < result->r_ancount; i++) {
        switch (result->r_answer[ i ].rr_type) {
        case DNSR_TYPE_CNAME:
            if (strcasecmp(simta_hostname,
                        result->r_answer[ i ].rr_cname.cn_name) == 0) {
                if ((red = red_host_lookup(
                             result->r_answer[ i ].rr_cname.cn_name)) == NULL) {
                    if ((red = red_host_add(result->r_answer[ i ].rr_name)) ==
                            NULL) {
                        dnsr_free_result(result);
                        return (NULL);
                    }
                    if (red_action_default(red) != 0) {
                        return (NULL);
                    }
                }
            }
            break;

        case DNSR_TYPE_MX:
            if ((strcasecmp(simta_hostname,
                         result->r_answer[ i ].rr_mx.mx_exchange) == 0) &&
                    (result->r_answer[ i ].rr_mx.mx_preference <=
                            result->r_answer[ 0 ].rr_mx.mx_preference)) {
                if ((red = red_host_lookup(result->r_answer[ i ].rr_name)) ==
                        NULL) {
                    if ((red = red_host_add(result->r_answer[ i ].rr_name)) ==
                            NULL) {
                        dnsr_free_result(result);
                        return (NULL);
                    }
                    if (red_action_default(red) != 0) {
                        return (NULL);
                    }
                }
            }
            break;

        default:
            simta_debuglog(2, "get_mx: %s: uninteresting dnsr type: %d",
                    result->r_answer[ i ].rr_name,
                    result->r_answer[ i ].rr_type);
            break;
        }
    }

    return (result);
}

struct dnsr_result *
get_ptr(const struct sockaddr *sa) {
    struct dnsr_result *result = NULL;
    char *              hostname;

    if (simta_dnsr == NULL) {
        if ((simta_dnsr = dnsr_new()) == NULL) {
            syslog(LOG_ERR, "Liberror: get_ptr dnsr_new: %m");
            return (NULL);
        }
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

struct simta_red *
host_local(char *hostname) {
    struct simta_red *  red;
    struct dnsr_result *result;

    /* Check for hostname in host table */
    if ((red = red_host_lookup(hostname)) != NULL) {
        return (red);
    }

    if (simta_dns_auto_config == 0) {
        return (NULL);
    }

    if ((result = get_mx(hostname)) == NULL) {
        return (NULL);
    }

    /* Check for an answer */
    if (result->r_ancount == 0) {
        dnsr_free_result(result);
        return (NULL);
    }

    /* Check to see if host has been added to host table */
    if ((red = red_host_lookup(hostname)) != NULL) {
        dnsr_free_result(result);
        return (red);
    }

    dnsr_free_result(result);

    return (NULL);
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

struct dnsl_result *
dnsl_check(const char *chain, const struct sockaddr *sa, const char *text) {
    struct dll_entry *chain_dll;
    struct dnsl *     list;
#ifdef HAVE_LIBSSL
    struct message_digest md;
#endif /* HAVE_LIBSSL */
    char *              lookup = NULL;
    char                sa_ip[ INET6_ADDRSTRLEN ];
    yastr               ip = NULL;
    yastr               reason = NULL;
    yastr               mangled = NULL;
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

    if ((chain_dll = dll_lookup(simta_dnsl_chains, chain)) == NULL) {
        syslog(LOG_INFO, "DNS List: no lists in the '%s' chain", chain);
        return (NULL);
    }

#ifdef HAVE_LIBSSL
    md_init(&md);
#endif /* HAVE_LIBSSL */

    for (list = (struct dnsl *)chain_dll->dll_data; list != NULL;
            list = list->dnsl_next) {
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
            if ((lookup = dnsr_ntoptr(simta_dnsr, sa->sa_family,
                         ((sa->sa_family == AF_INET)
                                         ? (void *)&(((struct sockaddr_in *)sa)
                                                             ->sin_addr)
                                         : (void *)&(((struct sockaddr_in6 *)sa)
                                                             ->sin6_addr)),
                         list->dnsl_domain)) == NULL) {
                syslog(LOG_ERR, "DNS List [%s]: dnsr_ntoptr failed: %s", sa_ip,
                        list->dnsl_domain);
                continue;
            }

#ifdef HAVE_LIBSSL
        } else if (strcmp(chain, "email") == 0) {
            mangled = yaslauto(text);
            if (list->dnsl_flags & DNSL_FLAG_DOMAIN) {
                yaslrange(mangled, strrchr(mangled, '@') - mangled + 1, -1);
            }
            yasltolower(mangled);
            /* Hashed address lookup */
            if (list->dnsl_flags & DNSL_FLAG_HASHED) {
                if (list->dnsl_flags & DNSL_FLAG_SHA256) {
                    md_reset(&md, "sha256");
                } else {
                    md_reset(&md, "sha1");
                }
                md_update(&md, mangled, yasllen(mangled));
                md_finalize(&md);
                lookup = malloc(
                        strlen(list->dnsl_domain) + strlen(md.md_b16) + 2);
                sprintf(lookup, "%s.%s", md.md_b16, list->dnsl_domain);
            } else if (list->dnsl_flags & DNSL_FLAG_DOMAIN) {
                lookup =
                        malloc(strlen(list->dnsl_domain) + strlen(mangled) + 2);
                sprintf(lookup, "%s.%s", mangled, list->dnsl_domain);
            } else {
                syslog(LOG_INFO,
                        "DNS List [%s]: refusing to do unhashed lookup on %s",
                        text, list->dnsl_domain);
            }
            yaslfree(mangled);
#endif /* HAVE_LIBSSL */

        } else {
            /* Preformatted text lookup */
            lookup = malloc(strlen(list->dnsl_domain) + strlen(text) + 2);
            sprintf(lookup, "%s.%s", text, list->dnsl_domain);
        }

        if ((result = get_a(lookup)) == NULL) {
            simta_debuglog(1, "DNS List [%s]: Timeout: %s", sa ? sa_ip : text,
                    list->dnsl_domain);
            free(lookup);
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
                    list->dnsl_domain);
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
            if ((reason == NULL) && (list->dnsl_default_reason)) {
                reason = yasldup(list->dnsl_default_reason);
            }

            simta_debuglog(1, "DNS List [%s]: Found in %s list %s: %s / %s",
                    sa ? sa_ip : text, list->dnsl_type_text, list->dnsl_domain,
                    ip, reason ? reason : "Unknown");

            if (list->dnsl_type != DNSL_LOG_ONLY) {
                ret = calloc(1, sizeof(struct dnsl_result));
                ret->dnsl = list;
                ret->dnsl_reason = reason;
                ret->dnsl_result = ip;
            }
        }

        free(lookup);

        if (ret) {
#ifdef HAVE_LIBSSL
            md_cleanup(&md);
#endif /* HAVE_LIBSSL */
            return (ret);
        }

        simta_debuglog(1, "DNS List [%s]: Unlisted in %s list %s",
                sa ? sa_ip : text, list->dnsl_type_text, list->dnsl_domain);

        yaslfree(ip);
        ip = NULL;
        yaslfree(reason);
        reason = NULL;
    }

    simta_debuglog(1, "DNS List [%s]: chain %s exhausted, no matches",
            sa ? sa_ip : text, chain);

#ifdef HAVE_LIBSSL
    md_cleanup(&md);
#endif /* HAVE_LIBSSL */

    return (NULL);
}

void
dnsl_result_free(struct dnsl_result *res) {
    if (res) {
        yaslfree(res->dnsl_reason);
        yaslfree(res->dnsl_result);
        free(res);
    }
}

int
dnsl_add(const char *chain, int type, const char *domain, const char *reason) {
    struct dll_entry *chain_dll;
    struct dnsl *     prev;
    struct dnsl *     dnsl;
    char *            text;
    yastr             chainflags = NULL;
    yastr *           split;
    size_t            tok_count;
    char *            flags;
    int               i;

    switch (type) {
    default:
        syslog(LOG_ERR, "dnsl_add type out of range: %d", type);
        return (1);

    case DNSL_TRUST:
        text = S_TRUST;
        break;

    case DNSL_ACCEPT:
        text = S_ACCEPT;
        break;

    case DNSL_LOG_ONLY:
        text = S_LOG_ONLY;
        break;

    case DNSL_BLOCK:
        text = S_BLOCK;
        break;
    }

    dnsl = calloc(1, sizeof(struct dnsl));

    dnsl->dnsl_type = type;
    dnsl->dnsl_type_text = text;

    dnsl->dnsl_domain = yaslauto(domain);

    if (reason) {
        dnsl->dnsl_default_reason = yaslauto(reason);
    }

    chainflags = yaslauto(chain);
    if ((flags = strchr(chainflags, '/')) != NULL) {
        *flags = '\0';
        flags++;
        split = yaslsplitlen(flags, strlen(flags), "/", 1, &tok_count);
        for (i = 0; i < tok_count; i++) {
            if (strcasecmp(split[ i ], "DOMAIN") == 0) {
                dnsl->dnsl_flags |= DNSL_FLAG_DOMAIN;
            } else if (strcasecmp(split[ i ], "SHA1") == 0) {
                dnsl->dnsl_flags |= DNSL_FLAG_HASHED | DNSL_FLAG_SHA1;
            } else if (strcasecmp(split[ i ], "SHA256") == 0) {
                dnsl->dnsl_flags |= DNSL_FLAG_HASHED | DNSL_FLAG_SHA256;
            }
        }
        yaslfreesplitres(split, tok_count);
    }

    chain_dll = dll_lookup_or_create(&simta_dnsl_chains, chainflags);
    if ((prev = (struct dnsl *)chain_dll->dll_data) == NULL) {
        chain_dll->dll_data = dnsl;
    } else {
        for (; prev->dnsl_next != NULL; prev = prev->dnsl_next)
            ;
        prev->dnsl_next = dnsl;
    }

    yaslfree(chainflags);
    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
