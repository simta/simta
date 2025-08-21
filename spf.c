/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#include <yasl.h>

#include "dns.h"
#include "simta.h"
#include "simta_malloc.h"
#include "simta_util.h"
#include "spf.h"


typedef enum {
    SPF_MECHANISM_UNKNOWN,
    SPF_MECHANISM_MODIFIER,
    SPF_MECHANISM_ALL,
    SPF_MECHANISM_INCLUDE,
    SPF_MECHANISM_A,
    SPF_MECHANISM_MX,
    SPF_MECHANISM_PTR,
    SPF_MECHANISM_IP4,
    SPF_MECHANISM_IP6,
    SPF_MECHANISM_EXISTS,
} spf_mechanism_type;

struct spf_mechanism {
    simta_spf_result   qualifier;
    bool               has_qualifier;
    spf_mechanism_type type;
    yastr              domain_spec;
    unsigned long      cidr;
    unsigned long      cidr6;
};

static simta_spf_result spf_check_host(struct spf *, const yastr);
static simta_result     spf_validate_hostname(const yastr, bool);
static simta_spf_result spf_check_a(
        struct spf *, const yastr, unsigned long, unsigned long, const char *);
static simta_spf_result spf_check_mx(
        struct spf *, const yastr, struct spf_mechanism *);
static simta_spf_result spf_check_ptr(
        struct spf *, const yastr, struct spf_mechanism *);
static simta_spf_result spf_check_exists(
        struct spf *, const yastr, struct spf_mechanism *);
static yastr spf_macro_expand(struct spf *, const yastr, const yastr, bool);
static yastr spf_parse_domainspec(struct spf *, const yastr, yastr);
static yastr spf_parse_domainspec_cidr(
        struct spf *, const yastr, yastr, unsigned long *, unsigned long *);
static simta_result spf_parse_ipx(
        struct spf *, const yastr, yastr, unsigned long *, int);


const char *
spf_result_str(const simta_spf_result res) {
    switch (res) {
    case SPF_RESULT_PASS:
        return "pass";
    case SPF_RESULT_FAIL:
        return "fail";
    case SPF_RESULT_SOFTFAIL:
        return "softfail";
    case SPF_RESULT_NEUTRAL:
        return "neutral";
    case SPF_RESULT_NONE:
        return "none";
    case SPF_RESULT_TEMPERROR:
        return "temperror";
    case SPF_RESULT_PERMERROR:
        return "permerror";
    }
    return "INVALID";
}


void
spf_free(struct spf *s) {
    if (s) {
        yaslfree(s->spf_localpart);
        yaslfree(s->spf_domain);
        yaslfree(s->spf_helo);
    }
    simta_free(s);
}

static simta_result
spf_validate_hostname(const yastr domain, bool strict) {
    simta_result retval = SIMTA_ERR;
    size_t       tok_count = 0;
    yastr       *split = NULL;

    /* RFC 7208 4.3 Initial Processing
     * If the <domain> is malformed (e.g., label longer than 63 characters,
     * zero-length label not at the end, etc.) or is not a multi-label
     * domain name, or if the DNS lookup returns "Name Error" (RCODE 3, also
     * known as "NXDOMAIN" [RFC2308]), check_host() immediately returns the
     * result "none".
     */

    /* Overlength domain */
    if (yasllen(domain) > 255) {
        return SIMTA_ERR;
    }

    /* Non-ASCII characters */
    if (simta_check_charset(domain) != SIMTA_CHARSET_ASCII) {
        return SIMTA_ERR;
    }

    split = yaslsplitlen(domain, yasllen(domain), ".", 1, &tok_count);

    /* must be a multi-label domain name */
    if (tok_count < 2) {
        goto done;
    }
    if ((tok_count == 2) && (yasllen(split[ 1 ]) == 0)) {
        goto done;
    }

    for (int i = 0; i < tok_count; i++) {
        /* Overlength label */
        if (yasllen(split[ i ]) > 63) {
            goto done;
        }

        if (yasllen(split[ i ]) == 0) {
            if (i < tok_count - 1) {
                /* Empty label not at the end */
                goto done;
            }
            continue;
        }

        for (char *c = split[ i ]; *c; c++) {
            if (*c == '-') {
                /* hyphen is valid as long as it's not at an extremity */
                if (c != split[ i ] && *(c + 1)) {
                    continue;
                }
            } else if (!strict) {
                continue;
            }
            if (isalnum(*c) || *c == '_') {
                continue;
            }
            /* Invalid character found. */
            goto done;
        }

        if ((i == tok_count - 1) || (yasllen(split[ i + 1 ]) == 0)) {
            /* RFC 7208 7.1 Formal Specification
             * toplabel         = ( *alphanum ALPHA *alphanum ) /
             *                    ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
             */
            bool found_alpha = false;
            for (char *c = split[ i ]; *c; c++) {
                if (isalpha(*c) || *c == '-') {
                    found_alpha = true;
                } else if (!isalnum(*c)) {
                    goto done;
                }
            }
            if (!found_alpha) {
                goto done;
            }
        }
    }

    retval = SIMTA_OK;
done:
    yaslfreesplitres(split, tok_count);
    return retval;
}


static yastr
spf_macro_expand(
        struct spf *s, const yastr domain, const yastr macro, bool truncate) {
    bool   rtransform;
    long   dtransform, i, j;
    char  *p, *pp;
    char   delim;
    yastr  expanded;
    yastr  tmp;
    yastr  escaped;
    yastr *split;
    size_t tok_count;

    expanded = yaslempty();
    tmp = yaslempty();

    for (p = macro; *p != '\0'; p++) {
        if (*p != '%') {
            expanded = yaslcatlen(expanded, p, 1);
            continue;
        }
        p++;
        switch (*p) {
        case '%':
            expanded = yaslcat(expanded, "%");
            break;
        case '_':
            expanded = yaslcat(expanded, "_");
            break;
        case '-':
            expanded = yaslcat(expanded, "%20");
            break;
        case '{':
            p++;
            switch (*p) {
            case 'S':
            case 's':
                yaslclear(tmp);
                tmp = yaslcatprintf(
                        tmp, "%s@%s", s->spf_localpart, s->spf_domain);
                break;
            case 'L':
            case 'l':
                tmp = yaslcpy(tmp, s->spf_localpart);
                break;
            case 'O':
            case 'o':
                tmp = yaslcpy(tmp, s->spf_domain);
                break;
            case 'D':
            case 'd':
                tmp = yaslcpy(tmp, domain);
                break;
            case 'I':
            case 'i':
                if (s->spf_sockaddr->sa_family == AF_INET) {
                    tmp = yaslgrowzero(tmp, INET_ADDRSTRLEN);
                    if (inet_ntop(s->spf_sockaddr->sa_family,
                                &((struct sockaddr_in *)s->spf_sockaddr)
                                         ->sin_addr,
                                tmp, (socklen_t)yasllen(tmp)) == NULL) {
                        goto error;
                    }
                    yaslupdatelen(tmp);
                } else {
                    uint8_t *ip6 = ((struct sockaddr_in6 *)s->spf_sockaddr)
                                           ->sin6_addr.s6_addr;
                    for (int i = 0; i < 16; i++) {
                        tmp = yaslcatprintf(tmp, "%x.%x",
                                (ip6[ i ] >> 4) & 0x0f, ip6[ i ] & 0x0f);
                        if (i < 15) {
                            tmp = yaslcat(tmp, ".");
                        }
                    }
                }
                break;
            case 'P':
            case 'p':
                /* This is overly complex and should not be used,
                 * so we're not going to implement it. */
                tmp = yaslcpy(tmp, "unknown");
                break;
            case 'V':
            case 'v':
                tmp = yaslcpy(tmp, (s->spf_sockaddr->sa_family == AF_INET6)
                                           ? "ip6"
                                           : "in-addr");
                break;
            case 'H':
            case 'h':
                tmp = yaslcpy(tmp, s->spf_helo);
                break;
            default:
                syslog(LOG_WARNING, "SPF %s [%s]: invalid macro-letter: %c",
                        s->spf_domain, domain, *p);
                goto error;
            }

            if (isupper(*p)) {
                /* RFC 7208 7.3 Macro Processing Details
                 * Uppercase macros expand exactly as their lowercase
                 * equivalents, and are then URL escaped. URL escaping MUST be
                 * performed for characters not in the "unreserved" set, which
                 * is defined in [RFC3986].
                 */
                escaped = simta_url_escape(tmp);
                yaslfree(tmp);
                tmp = escaped;
            }
            p++;

            /* Check for transformers */
            dtransform = 0;
            rtransform = false;
            if (isdigit(*p)) {
                dtransform = strtoul(p, &pp, 10);
                p = pp;
            }

            if (*p == 'r') {
                rtransform = true;
                p++;
            }

            delim = '\0';
            for (pp = p; *pp != '\0'; pp++) {
                if (*pp == '}') {
                    p = pp;
                    break;
                }
                switch (*pp) {
                /* RFC 7208 7.1 Formal Specification
                 * delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
                 */
                case '.':
                case '-':
                case '+':
                case ',':
                case '/':
                case '_':
                case '=':
                    if (delim != '\0') {
                        /* If we already have a delimiter, replace all occurrences
                         * of the new delimiter with it.
                         */
                        tmp = yaslmapchars(tmp, pp, &delim, 1);
                    } else {
                        delim = *pp;
                    }
                    break;
                default:
                    syslog(LOG_WARNING, "SPF %s [%s]: invalid delimiter: %c",
                            s->spf_domain, domain, *pp);
                    goto error;
                }
            }

            if (rtransform || (dtransform > 0) || (delim != '\0')) {
                if (delim == '\0') {
                    delim = '.';
                }
                split = yaslsplitlen(tmp, yasllen(tmp), &delim, 1, &tok_count);
                yaslclear(tmp);
                if (rtransform) {
                    if ((dtransform > 0) && (tok_count > dtransform)) {
                        j = dtransform;
                    } else {
                        j = tok_count;
                    }
                    for (i = j - 1; i >= 0; i--) {
                        if (yasllen(tmp) > 0) {
                            tmp = yaslcat(tmp, ".");
                        }
                        tmp = yaslcatyasl(tmp, split[ i ]);
                    }
                } else {
                    if ((dtransform > 0) && (tok_count > dtransform)) {
                        j = tok_count - dtransform;
                    } else {
                        j = 0;
                    }
                    for (i = j; i < tok_count; i++) {
                        if (yasllen(tmp) > 0) {
                            tmp = yaslcat(tmp, ".");
                        }
                        tmp = yaslcatyasl(tmp, split[ i ]);
                    }
                }
                yaslfreesplitres(split, tok_count);
            }
            expanded = yaslcatyasl(expanded, tmp);
            break;
        default:
            syslog(LOG_WARNING, "SPF %s [%s]: invalid macro-expand: %s",
                    s->spf_domain, domain, p);
            goto error;
        }
    }

    if (yaslcmp(macro, expanded)) {
        simta_debuglog(3, "SPF %s [%s]: expanded %s to %s", s->spf_domain,
                domain, macro, expanded);
    }

    if (truncate) {
        /* RFC 7208 7.3 Macro Processing Details
         *
         * When the result of macro expansion is used in a domain name query, if
         * the expanded domain name exceeds 253 characters (the maximum length
         * of a domain name in this format), the left side is truncated to fit,
         * by removing successive domain labels (and their following dots) until
         * the total length does not exceed 253 characters.
         */
        while (yasllen(expanded) > 253) {
            yaslrangesepright(expanded, '.');
            simta_debuglog(3, "SPF %s [%s]: truncated expansion to %s",
                    s->spf_domain, domain, expanded);
        }
    }

    yaslfree(tmp);
    return expanded;

error:
    yaslfree(tmp);
    yaslfree(expanded);
    return NULL;
}


static yastr
spf_parse_domainspec(struct spf *s, yastr domain, yastr dsc) {
    yastr domain_spec;

    if (dsc[ 0 ] == ':') {
        yaslrange(dsc, 1, -1);
        domain_spec = spf_macro_expand(s, domain, dsc, true);
    } else {
        domain_spec = yasldup(domain);
    }

    if (spf_validate_hostname(domain_spec, true) != SIMTA_OK) {
        yaslfree(domain_spec);
        return NULL;
    }

    return domain_spec;
}


static yastr
spf_parse_domainspec_cidr(struct spf *s, yastr domain, yastr dsc,
        unsigned long *cidr, unsigned long *cidr6) {
    char *p;
    yastr tmp, domain_spec;

    if (dsc[ 0 ] == ':') {
        yaslrange(dsc, 1, -1);
        tmp = yasldup(dsc);
        if ((p = strchr(tmp, '/')) != NULL) {
            yaslrange(tmp, 0, (p - tmp - 1));
            yaslrange(dsc, (p - tmp), -1);
        } else {
            yaslclear(dsc);
        }

        domain_spec = spf_macro_expand(s, domain, tmp, true);

        if (domain_spec == NULL) {
            /* Macro expansion failed, probably a syntax problem. */
            syslog(LOG_INFO, "SPF %s [%s]: macro expansion failed for %s",
                    s->spf_domain, domain, tmp);
            yaslfree(tmp);
            return NULL;
        }

        if (strcasecmp(tmp, domain_spec) == 0) {
            /* No macro expansion happened, validate the hostname */
            if (spf_validate_hostname(domain_spec, true) != SIMTA_OK) {
                syslog(LOG_INFO, "SPF %s [%s]: invalid hostname %s",
                        s->spf_domain, domain, tmp);
                yaslfree(tmp);
                yaslfree(domain_spec);
                return NULL;
            }
        }

        yaslfree(tmp);
    } else if (spf_validate_hostname(domain, true) != SIMTA_OK) {
        return NULL;
    } else {
        domain_spec = yasldup(domain);
    }

    *cidr = 32;
    *cidr6 = 128;

    /* Should be one of:
     * //<cidr6>
     * /<cidr4>
     * /<cidr4>//<cidr6>
     */
    if (dsc[ 0 ] == '/') {
        p = dsc + 1;
        /* IPv4 CIDR */
        if (*p != '/') {
            *cidr = strtoul(dsc + 1, &p, 10);
            if (*p == '/') {
                p++;
            }
        }
        /* We should be pointing at the second / in the IPv6 CIDR if it exists */
        if (*p == '/') {
            *cidr6 = strtoul(p + 1, &p, 10);
        }
        if ((*cidr > 32) || (*cidr6 > 128) || (*p != '\0')) {
            syslog(LOG_INFO,
                    "SPF %s [%s]: failed parsing CIDR mask %s (%ld/%ld)",
                    s->spf_domain, domain, dsc, *cidr, *cidr6);
            yaslfree(domain_spec);
            return NULL;
        }
    }

    return domain_spec;
}


static simta_result
spf_parse_ipx(struct spf *s, const yastr domain, yastr ip, unsigned long *cidr,
        int addr_family) {
    int              rc;
    simta_result     retval = SIMTA_OK;
    struct addrinfo *ip_ai = NULL;
    struct addrinfo  hints;
    char             sa_ip[ INET6_ADDRSTRLEN ];
    unsigned long    cidr_default;
    char            *p;

    cidr_default = (addr_family == AF_INET6) ? 128 : 32;

    if ((p = strchr(ip, '/')) != NULL) {
        char *end;
        errno = 0;
        *cidr = strtoul(p + 1, &end, 10);
        if (errno || (*end != '\0')) {
            syslog(LOG_INFO, "SPF %s [%s]: failed parsing CIDR mask %s: %m",
                    s->spf_domain, domain, p + 1);
            return SIMTA_ERR;
        }
        if (*cidr > cidr_default) {
            syslog(LOG_INFO, "SPF %s [%s]: invalid CIDR mask: %ld",
                    s->spf_domain, domain, *cidr);
            return SIMTA_ERR;
        }
        yaslrangesepleft(ip, '/');
    } else {
        *cidr = cidr_default;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = addr_family;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if ((rc = getaddrinfo(ip, NULL, &hints, &ip_ai)) != 0) {
        syslog(LOG_INFO, "SPF %s [%s]: failed parsing IP %s: %m", s->spf_domain,
                domain, ip);
        return SIMTA_ERR;
    }
    if (addr_family == AF_INET) {
        /* getaddrinfo() will accept truncated IPs, but we don't want to. */
        if (getnameinfo(ip_ai->ai_addr,
                    ((addr_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                               : sizeof(struct sockaddr_in)),
                    sa_ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) != 0) {
            syslog(LOG_INFO,
                    "SPF %s [%s]: getnameinfo() failed validating %s: %m",
                    s->spf_domain, domain, ip);
            retval = SIMTA_ERR;
        } else if (strcmp(sa_ip, ip) != 0) {
            syslog(LOG_INFO,
                    "SPF %s [%s]: mismatch parsing IP %s: getaddrinfo() "
                    "returned %s",
                    s->spf_domain, domain, ip, sa_ip);
            retval = SIMTA_ERR;
        }
    }

    freeaddrinfo(ip_ai);
    return retval;
}


static simta_spf_result
spf_check_a(struct spf *s, const yastr domain, unsigned long cidr,
        unsigned long cidr6, const char *a) {
    int                     rr_type = DNSR_TYPE_A;
    unsigned long           ecidr = cidr;
    struct sockaddr_storage sa;

    struct dnsr_result *dnsr_res;

    if (s->spf_sockaddr->sa_family == AF_INET6) {
        rr_type = DNSR_TYPE_AAAA;
        ecidr = cidr6;
        if ((dnsr_res = get_aaaa(a)) == NULL) {
            syslog(LOG_WARNING, "SPF %s [%s]: AAAA lookup %s failed",
                    s->spf_domain, domain, a);
            return SPF_RESULT_TEMPERROR;
        }
    } else {
        if ((dnsr_res = get_a(a)) == NULL) {
            syslog(LOG_WARNING, "SPF %s [%s]: A lookup %s failed",
                    s->spf_domain, domain, a);
            return SPF_RESULT_TEMPERROR;
        }
    }

    if (dnsr_res->r_ancount == 0) {
        s->spf_void_queries++;
    }

    for (int i = 0; i < dnsr_res->r_ancount; i++) {
        if (dnsr_res->r_answer[ i ].rr_type == rr_type) {
            sa.ss_family = s->spf_sockaddr->sa_family;
            if (sa.ss_family == AF_INET6) {
                memcpy(&(((struct sockaddr_in6 *)&sa)->sin6_addr),
                        &(dnsr_res->r_answer[ i ].rr_aaaa.aaaa_address),
                        sizeof(struct in6_addr));
            } else {
                memcpy(&(((struct sockaddr_in *)&sa)->sin_addr),
                        &(dnsr_res->r_answer[ i ].rr_a.a_address),
                        sizeof(struct in_addr));
            }
            if (simta_cidr_compare(ecidr, s->spf_sockaddr,
                        (struct sockaddr *)&sa, NULL) == 0) {
                dnsr_free_result(dnsr_res);
                return SPF_RESULT_PASS;
            }
        }
    }

    dnsr_free_result(dnsr_res);
    return SPF_RESULT_FAIL;
}


static simta_spf_result
spf_check_exists(
        struct spf *s, const yastr domain, struct spf_mechanism *mech) {
    struct dnsr_result *dnsr_res;
    simta_spf_result    ret = SPF_RESULT_FAIL;

    if (spf_validate_hostname(mech->domain_spec, true) != SIMTA_OK) {
        /* The record syntax was valid, but we ended up with an invalid hostname
         * (possibly due to macro expansion).
         */
        syslog(LOG_INFO, "SPF %s [%s]: skipping bad domain lookup %s",
                s->spf_domain, domain, mech->domain_spec);
        return SPF_RESULT_FAIL;
    }

    if ((dnsr_res = get_a(mech->domain_spec)) == NULL) {
        syslog(LOG_INFO, "SPF %s [%s]: A lookup %s failed", s->spf_domain,
                domain, mech->domain_spec);
        return SPF_RESULT_TEMPERROR;
    }

    if (dnsr_res->r_ancount > 0) {
        ret = SPF_RESULT_PASS;
    }

    dnsr_free_result(dnsr_res);
    return ret;
}


static simta_spf_result
spf_check_mx(struct spf *s, const yastr domain, struct spf_mechanism *mech) {
    struct dnsr_result *dnsr_res;
    simta_spf_result    rc;
    simta_spf_result    ret = SPF_RESULT_FAIL;
    int                 queries = 0;

    if (spf_validate_hostname(mech->domain_spec, true) != SIMTA_OK) {
        /* The record syntax was valid, but we ended up with an invalid hostname
         * (possibly due to macro expansion).
         */
        syslog(LOG_INFO, "SPF %s [%s]: skipping bad domain lookup %s",
                s->spf_domain, domain, mech->domain_spec);
        return SPF_RESULT_FAIL;
    }

    if ((dnsr_res = get_mx(mech->domain_spec)) == NULL) {
        syslog(LOG_INFO, "SPF %s [%s]: MX lookup %s failed", s->spf_domain,
                domain, mech->domain_spec);
        return SPF_RESULT_TEMPERROR;
    }

    for (int i = 0; i < dnsr_res->r_ancount; i++) {
        if (dnsr_res->r_answer[ i ].rr_type != DNSR_TYPE_MX) {
            continue;
        }

        if (strlen(dnsr_res->r_answer[ i ].rr_mx.mx_exchange) == 0) {
            /* Null MX, no lookup needed. */
            goto cleanup;
        }

        /* RFC 7208 4.6.4 DNS Lookup Limits
         * the evaluation of each "MX" record MUST NOT result in
         * querying more than 10 address records -- either "A" or "AAAA"
         * resource records.  If this limit is exceeded, the "mx" mechanism MUST
         * produce a "permerror" result.
         */
        queries++;
        if (queries > 10) {
            ret = SPF_RESULT_PERMERROR;
            goto cleanup;
        }

        rc = spf_check_a(s, domain, mech->cidr, mech->cidr6,
                dnsr_res->r_answer[ i ].rr_mx.mx_exchange);
        switch (rc) {
        case SPF_RESULT_PASS:
        case SPF_RESULT_TEMPERROR:
        case SPF_RESULT_PERMERROR:
            ret = rc;
            goto cleanup;
        default:
            break;
        }
    }

cleanup:
    dnsr_free_result(dnsr_res);
    return ret;
}


static simta_spf_result
spf_check_ptr(struct spf *s, const yastr domain, struct spf_mechanism *mech) {
    struct dnsr_result *dnsr_res;
    simta_spf_result    ret = SPF_RESULT_FAIL;
    int                 queries = 0;
    yastr               entry_domain;

    if ((dnsr_res = get_ptr(s->spf_sockaddr)) == NULL) {
        /* RFC 7208 5.5 "ptr" (do not use )
         * If a DNS error occurs while doing the PTR RR lookup,
         * then this mechanism fails to match.
         */
        syslog(LOG_INFO, "SPF %s [%s]: PTR lookup failed", s->spf_domain,
                domain);
        return SPF_RESULT_FAIL;
    }

    for (int i = 0; i < dnsr_res->r_ancount; i++) {
        if (dnsr_res->r_answer[ i ].rr_type != DNSR_TYPE_PTR) {
            continue;
        }

        entry_domain = yaslauto(dnsr_res->r_answer[ i ].rr_dn.dn_name);
        while ((yasllen(entry_domain) > yasllen(mech->domain_spec)) &&
                strchr(entry_domain, '.')) {
            yaslrangesepright(entry_domain, '.');
        }
        if (strcasecmp(entry_domain, mech->domain_spec) != 0) {
            /* No point in checking whether this is a valid reverse, we won't
             * accept it.
             */
            simta_debuglog(2,
                    "SPF %s [%s]: skipping validation of uninteresting PTR %s",
                    s->spf_domain, domain,
                    dnsr_res->r_answer[ i ].rr_dn.dn_name);
            yaslfree(entry_domain);
            continue;
        }
        yaslfree(entry_domain);

        /* We only care if it's a pass; like the initial PTR query,
	 * DNS errors are treated as a non-match rather than an error.
	 */
        /* RFC 7208 4.6.4 DNS Lookup Limits
	 * the evaluation of each "PTR" record MUST NOT result in
	 * querying more than 10 address records -- either "A" or
	 * "AAAA" resource records.  If this limit is exceeded, all
	 * records other than the first 10 MUST be ignored.
	 */
        queries++;
        if (queries > 10) {
            syslog(LOG_INFO, "SPF %s [%s]: PTR lookup record limit exceeded",
                    s->spf_domain, domain);
            goto cleanup;
        }

        if (spf_check_a(s, domain, 32, 128,
                    dnsr_res->r_answer[ i ].rr_dn.dn_name) == SPF_RESULT_PASS) {
            simta_debuglog(2, "SPF %s [%s]: validated PTR %s", s->spf_domain,
                    domain, dnsr_res->r_answer[ i ].rr_dn.dn_name);
            ret = SPF_RESULT_PASS;
            goto cleanup;
        }
    }

cleanup:
    dnsr_free_result(dnsr_res);
    return ret;
}


static simta_spf_result
spf_check_host(struct spf *s, const yastr domain) {
    simta_spf_result      rc;
    simta_spf_result      ret = SPF_RESULT_NONE;
    struct dnsr_result   *dnsr_res;
    yastr                 txt = NULL;
    yastr                 record = NULL;
    yastr                 redirect = NULL;
    yastr                 exp = NULL;
    size_t                tok_count = 0;
    yastr                *split = NULL;
    ucl_object_t         *mech_list = NULL;
    ucl_object_iter_t     iter = NULL;
    const ucl_object_t   *obj;
    struct spf_mechanism *mech;

    if (spf_validate_hostname(domain, false) != SIMTA_OK) {
        syslog(LOG_INFO, "SPF %s [%s]: invalid domain", s->spf_domain, domain);
        return SPF_RESULT_NONE;
    }

    /* RFC 7208 3.1 DNS Resource Records
     * SPF records MUST be published as a DNS TXT (type 16) Resource Record
     * (RR) [RFC1035] only.
     */
    if ((dnsr_res = get_txt(domain)) == NULL) {
        syslog(LOG_WARNING, "SPF %s [%s]: TXT lookup %s failed", s->spf_domain,
                domain, domain);
        return SPF_RESULT_TEMPERROR;
    }

    for (int i = 0; i < dnsr_res->r_ancount; i++) {
        if (dnsr_res->r_answer[ i ].rr_type == DNSR_TYPE_TXT) {
            txt = simta_dnsr_str(dnsr_res->r_answer[ i ].rr_txt.txt_data);

            /* RFC 7208 4.5 Selecting Records
             * Starting with the set of records that were returned by the
             * lookup, discard records that do not begin with a version section
             * of exactly "v=spf1".  Note that the version section is
             * terminated by either an SP character or the end of the record.
             */
            if ((strncasecmp(txt, "v=spf1", 6) == 0) &&
                    ((txt[ 6 ] == ' ') || (txt[ 6 ] == '\0'))) {
                if (record != NULL) {
                    /* RFC 7208 3.2 Multiple DNS Records
                     * A domain name MUST NOT have multiple records that would
                     * cause an authorization check to select more than one
                     * record.
                     */
                    syslog(LOG_ERR,
                            "SPF %s [%s]: multiple v=spf1 records found",
                            s->spf_domain, domain);
                    ret = SPF_RESULT_PERMERROR;
                    yaslfree(txt);
                    txt = NULL;
                    goto cleanup;
                }
                record = txt;
                txt = NULL;
            }

            yaslfree(txt);
            txt = NULL;
        }
    }

    if (record == NULL) {
        simta_debuglog(
                1, "SPF %s [%s]: no SPF record found", s->spf_domain, domain);
        goto cleanup;
    }

    simta_debuglog(2, "SPF %s [%s]: record: %s", s->spf_domain, domain, record);

    /* RFC 7208 4.6 Record Evaluation
     * The syntax of the record is validated first, and if there are any syntax
     * errors anywhere in the record, check_host() returns immediately with the
     * result "permerror", without further interpretation or evaluation.
     */

    /* RFC 7208 3.1
     * SPF records MUST be published as a DNS TXT (type 16) Resource Record
     * (RR) [RFC1035] only.  The character content of the record is encoded
     * as [US-ASCII].
     */
    if (simta_check_charset(record) != SIMTA_CHARSET_ASCII) {
        syslog(LOG_INFO, "SPF %s [%s]: non-ASCII characters in record",
                s->spf_domain, domain);
        ret = SPF_RESULT_PERMERROR;
        goto cleanup;
    }

    split = yaslsplitlen(record, yasllen(record), " ", 1, &tok_count);
    mech_list = ucl_object_typed_new(UCL_ARRAY);

    /* Start at 1, 0 is v=spf1 */
    for (int i = 1; i < tok_count; i++) {
        /* multiple spaces in a record will result in empty elements */
        if (yasllen(split[ i ]) == 0) {
            continue;
        }

        mech = simta_calloc(1, sizeof(struct spf_mechanism));
        ucl_array_append(mech_list, ucl_object_new_userdata(NULL, NULL, mech));

        /* RFC 7208 4.6.2 Mechanisms
         * The possible qualifiers, and the results they cause check_host() to
         * return, are as follows:
         *
         * "+" pass
         * "-" fail
         * "~" softfail
         * "?" neutral
         *
         * The qualifier is optional and defaults to "+".
         */
        mech->qualifier = SPF_RESULT_PASS;
        mech->has_qualifier = true;
        switch (*split[ i ]) {
        case '+':
            mech->qualifier = SPF_RESULT_PASS;
            yaslrange(split[ i ], 1, -1);
            break;
        case '-':
            mech->qualifier = SPF_RESULT_FAIL;
            yaslrange(split[ i ], 1, -1);
            break;
        case '~':
            mech->qualifier = SPF_RESULT_SOFTFAIL;
            yaslrange(split[ i ], 1, -1);
            break;
        case '?':
            mech->qualifier = SPF_RESULT_NEUTRAL;
            yaslrange(split[ i ], 1, -1);
            break;
        default:
            mech->has_qualifier = false;
            break;
        }

        if (strncasecmp(split[ i ], "redirect=", 9) == 0) {
            mech->type = SPF_MECHANISM_MODIFIER;
            yaslrange(split[ i ], 9, -1);
            if (redirect) {
                syslog(LOG_INFO,
                        "SPF %s [%s]: invalid extra redirect modifier %s "
                        "(already redirecting to %s)",
                        s->spf_domain, domain, split[ i ], redirect);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
            if ((redirect = spf_macro_expand(s, domain, split[ i ], true)) ==
                    NULL) {
                syslog(LOG_INFO, "SPF %s [%s]: macro expansion failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
            if (spf_validate_hostname(redirect, true) != SIMTA_OK) {
                syslog(LOG_INFO, "SPF %s [%s]: invalid redirect to %s",
                        s->spf_domain, domain, redirect);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
        } else if (strncasecmp(split[ i ], "exp=", 4) == 0) {
            mech->type = SPF_MECHANISM_MODIFIER;
            yaslrange(split[ i ], 4, -1);
            if (exp) {
                syslog(LOG_INFO, "SPF %s [%s]: invalid extra exp modifier",
                        s->spf_domain, domain);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
            if ((exp = spf_macro_expand(s, domain, split[ i ], true)) == NULL) {
                syslog(LOG_INFO, "SPF %s [%s]: macro expansion failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
            if (spf_validate_hostname(exp, true) != SIMTA_OK) {
                syslog(LOG_INFO, "SPF %s [%s]: invalid explanation %s",
                        s->spf_domain, domain, exp);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
        } else if (strcasecmp(split[ i ], "all") == 0) {
            mech->type = SPF_MECHANISM_ALL;

        } else if (strncasecmp(split[ i ], "include:", 8) == 0) {
            mech->type = SPF_MECHANISM_INCLUDE;
            yaslrange(split[ i ], 8, -1);
            if ((mech->domain_spec = spf_macro_expand(
                         s, domain, split[ i ], true)) == NULL) {
                /* Macro expansion failed, probably a syntax problem. */
                syslog(LOG_INFO, "SPF %s [%s]: macro expansion failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }

        } else if ((strcasecmp(split[ i ], "a") == 0) ||
                   (strncasecmp(split[ i ], "a:", 2) == 0) ||
                   (strncasecmp(split[ i ], "a/", 2) == 0)) {
            mech->type = SPF_MECHANISM_A;

            yaslrange(split[ i ], 1, -1);

            if ((mech->domain_spec = spf_parse_domainspec_cidr(s, domain,
                         split[ i ], &(mech->cidr), &(mech->cidr6))) == NULL) {
                /* Macro expansion failed, probably a syntax problem. */
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }

        } else if ((strcasecmp(split[ i ], "mx") == 0) ||
                   (strncasecmp(split[ i ], "mx:", 3) == 0) ||
                   (strncasecmp(split[ i ], "mx/", 3) == 0)) {
            mech->type = SPF_MECHANISM_MX;
            yaslrange(split[ i ], 2, -1);

            if ((mech->domain_spec = spf_parse_domainspec_cidr(s, domain,
                         split[ i ], &(mech->cidr), &(mech->cidr6))) == NULL) {
                /* Macro expansion failed, probably a syntax problem. */
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }

        } else if ((strcasecmp(split[ i ], "ptr") == 0) ||
                   (strncasecmp(split[ i ], "ptr:", 4) == 0)) {
            mech->type = SPF_MECHANISM_PTR;

            yaslrange(split[ i ], 3, -1);
            if ((mech->domain_spec = spf_parse_domainspec(
                         s, domain, split[ i ])) == NULL) {
                /* Macro expansion failed, probably a syntax problem. */
                syslog(LOG_INFO, "SPF %s [%s]: parsing failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }

        } else if (strncasecmp(split[ i ], "ip4:", 4) == 0) {
            mech->type = SPF_MECHANISM_IP4;

            yaslrange(split[ i ], 4, -1);
            if (spf_parse_ipx(s, domain, split[ i ], &(mech->cidr), AF_INET) !=
                    SIMTA_OK) {
                syslog(LOG_INFO, "SPF %s [%s]: parsing failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }

            mech->domain_spec = yasldup(split[ i ]);

        } else if (strncasecmp(split[ i ], "ip6:", 4) == 0) {
            mech->type = SPF_MECHANISM_IP6;

            yaslrange(split[ i ], 4, -1);
            if (spf_parse_ipx(s, domain, split[ i ], &(mech->cidr6),
                        AF_INET6) != SIMTA_OK) {
                syslog(LOG_INFO, "SPF %s [%s]: parsing failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }

            mech->domain_spec = yasldup(split[ i ]);

        } else if (strncasecmp(split[ i ], "exists:", 7) == 0) {
            mech->type = SPF_MECHANISM_EXISTS;

            yaslrange(split[ i ], 7, -1);
            if ((mech->domain_spec = spf_macro_expand(
                         s, domain, split[ i ], true)) == NULL) {
                /* Macro expansion failed, probably a syntax problem. */
                syslog(LOG_INFO, "SPF %s [%s]: macro expansion failed for %s",
                        s->spf_domain, domain, split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
            if (strcasecmp(mech->domain_spec, split[ i ]) == 0) {
                /* Check the syntax if it's not an expanded macro. */
                if (spf_validate_hostname(mech->domain_spec, true) !=
                        SIMTA_OK) {
                    syslog(LOG_INFO,
                            "SPF %s [%s]: hostname validation failed for %s",
                            s->spf_domain, domain, mech->domain_spec);
                    ret = SPF_RESULT_PERMERROR;
                    goto cleanup;
                }
            }

        } else {
            /* Check to see if it's an unknown modifier */
            char *p = split[ i ];
            if (isalpha(*p)) {
                while (isalnum(*p) || (*p == '-') || (*p == '_') ||
                        (*p == '.')) {
                    p++;
                }

                if (*p == '=') {
                    /* RFC 7208 6 Modifier Definitions
                     * Unrecognized modifiers MUST be ignored
                     */
                    mech->type = SPF_MECHANISM_MODIFIER;
                    /* Expand the macro, since we should still fail for bad syntax. */
                    if ((mech->domain_spec = spf_macro_expand(
                                 s, domain, p + 1, false)) == NULL) {
                        /* Macro expansion failed, probably a syntax problem. */
                        syslog(LOG_INFO,
                                "SPF %s [%s]: macro expansion failed for %s",
                                s->spf_domain, domain, p + 1);
                        ret = SPF_RESULT_PERMERROR;
                        goto cleanup;
                    }
                    simta_debuglog(1, "SPF %s [%s]: unknown modifier %s",
                            s->spf_domain, domain, split[ i ]);
                }
            }

            if (mech->type != SPF_MECHANISM_MODIFIER) {
                syslog(LOG_INFO, "SPF %s [%s]: unknown %s mechanism %s",
                        s->spf_domain, domain, spf_result_str(mech->qualifier),
                        split[ i ]);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            }
        }

        if (mech->type == SPF_MECHANISM_MODIFIER && mech->has_qualifier) {
            syslog(LOG_INFO,
                    "SPF %s [%s]: syntax error: modifier %s has a qualifier",
                    s->spf_domain, domain, split[ i ]);
            ret = SPF_RESULT_PERMERROR;
            goto cleanup;
        }
    }

    /* Now that we've fully parsed the record, we can process it. */
    iter = ucl_object_iterate_new(mech_list);
    while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
        mech = obj->value.ud;

        /* RFC 7208 4.6.4 DNS Lookup Limits
         * Some mechanisms and modifiers (collectively, "terms") cause DNS
         * queries at the time of evaluation [...] SPF implementations MUST
         * limit the total number of those terms to 10 during SPF evaluation,
         * to avoid unreasonable load on the DNS.  If this limit is exceeded,
         * the implementation MUST return "permerror".
         */
        /* In real life strictly enforcing a limit of ten will break SPF
         * evaluation of multiple major domains, so we allow setting a higher
         * limit.
         */
        if (s->spf_queries > simta_config_int("receive.spf.query_limit")) {
            syslog(LOG_WARNING, "SPF %s [%s]: DNS lookup limit exceeded",
                    s->spf_domain, domain);
            ret = SPF_RESULT_PERMERROR;
            goto cleanup;
        }

        /* RFC 7208 4.6.4 DNS Lookup Limits
         * As described at the end of Section 11.1, there may be cases where it
         * is useful to limit the number of "terms" for which DNS queries return
         * either a positive answer (RCODE 0) with an answer count of 0, or a
         * "Name Error" (RCODE 3) answer.  These are sometimes collectively
         * referred to as "void lookups".  SPF implementations SHOULD limit
         * "void lookups" to two.  An implementation MAY choose to make such a
         * limit configurable.  In this case, a default of two is RECOMMENDED.
         * Exceeding the limit produces a "permerror" result.
         */
        if (s->spf_void_queries >
                simta_config_int("receive.spf.void_query_limit")) {
            syslog(LOG_WARNING, "SPF %s [%s]: DNS void query limit exceeded",
                    s->spf_domain, domain);
            ret = SPF_RESULT_PERMERROR;
            goto cleanup;
        }

        switch (mech->type) {
        case SPF_MECHANISM_MODIFIER:
            /* Nothing to do. */
            break;
        case SPF_MECHANISM_UNKNOWN:
            /* blivet */
            syslog(LOG_WARNING,
                    "SPF %s [%s]: unknown mechanism during processing, this is "
                    "probably a bug",
                    s->spf_domain, domain);
            break;
        case SPF_MECHANISM_ALL:
            simta_debuglog(2, "SPF %s [%s]: matched all: %s", s->spf_domain,
                    domain, spf_result_str(mech->qualifier));
            ret = mech->qualifier;
            goto cleanup;
        case SPF_MECHANISM_INCLUDE:
            s->spf_queries++;
            simta_debuglog(2, "SPF %s [%s]: include %s", s->spf_domain, domain,
                    mech->domain_spec);
            rc = spf_check_host(s, mech->domain_spec);
            switch (rc) {
            case SPF_RESULT_NONE:
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            case SPF_RESULT_PASS:
                ret = mech->qualifier;
                goto cleanup;
            case SPF_RESULT_TEMPERROR:
            case SPF_RESULT_PERMERROR:
                ret = rc;
                goto cleanup;
            default:
                break;
            }
            break;
        case SPF_MECHANISM_A:
            s->spf_queries++;

            if (spf_validate_hostname(mech->domain_spec, true) != SIMTA_OK) {
                /* The record syntax was valid, but we ended up with an invalid
                 * hostname (possibly due to macro expansion).
                 */
                syslog(LOG_INFO, "SPF %s [%s]: skipping bad domain lookup %s",
                        s->spf_domain, domain, mech->domain_spec);
                rc = SPF_RESULT_FAIL;
            } else {
                rc = spf_check_a(
                        s, domain, mech->cidr, mech->cidr6, mech->domain_spec);
            }

            switch (rc) {
            case SPF_RESULT_PASS:
                simta_debuglog(2, "SPF %s [%s]: matched a %s/%ld/%ld: %s",
                        s->spf_domain, domain, mech->domain_spec, mech->cidr,
                        mech->cidr6, spf_result_str(mech->qualifier));
                ret = mech->qualifier;
                goto cleanup;
            case SPF_RESULT_TEMPERROR:
                ret = rc;
                goto cleanup;
            default:
                break;
            }
            break;
        case SPF_MECHANISM_MX:
            s->spf_queries++;
            rc = spf_check_mx(s, domain, mech);
            switch (rc) {
            case SPF_RESULT_PASS:
                simta_debuglog(2, "SPF %s [%s]: matched mx %s/%ld/%ld: %s",
                        s->spf_domain, domain, mech->domain_spec, mech->cidr,
                        mech->cidr6, spf_result_str(mech->qualifier));
                ret = mech->qualifier;
                goto cleanup;
            case SPF_RESULT_TEMPERROR:
            case SPF_RESULT_PERMERROR:
                ret = rc;
                goto cleanup;
            default:
                break;
            }

            break;
        case SPF_MECHANISM_PTR:
            s->spf_queries++;
            if (spf_check_ptr(s, domain, mech) == SPF_RESULT_PASS) {
                simta_debuglog(2, "SPF %s [%s]: matched ptr %s: %s",
                        s->spf_domain, domain, mech->domain_spec,
                        spf_result_str(mech->qualifier));
                ret = mech->qualifier;
                goto cleanup;
            }
            break;
        case SPF_MECHANISM_IP4:
            if (s->spf_sockaddr->sa_family != AF_INET) {
                break;
            }
            switch (simta_cidr_compare(
                    mech->cidr, s->spf_sockaddr, NULL, mech->domain_spec)) {
            case -1:
                syslog(LOG_INFO,
                        "SPF %s [%s]: simta_cidr_compare failed for %s",
                        s->spf_domain, domain, mech->domain_spec);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            case 0:
                simta_debuglog(2, "SPF %s [%s]: matched ip4 %s/%ld: %s",
                        s->spf_domain, domain, mech->domain_spec, mech->cidr,
                        spf_result_str(mech->qualifier));
                ret = mech->qualifier;
                goto cleanup;
            default:
                break;
            }
            break;
        case SPF_MECHANISM_IP6:
            if (s->spf_sockaddr->sa_family != AF_INET6) {
                break;
            }
            switch (simta_cidr_compare(
                    mech->cidr6, s->spf_sockaddr, NULL, mech->domain_spec)) {
            case -1:
                syslog(LOG_INFO,
                        "SPF %s [%s]: simta_cidr_compare failed for %s",
                        s->spf_domain, domain, mech->domain_spec);
                ret = SPF_RESULT_PERMERROR;
                goto cleanup;
            case 0:
                simta_debuglog(2, "SPF %s [%s]: matched ip6 %s/%ld: %s",
                        s->spf_domain, domain, mech->domain_spec, mech->cidr6,
                        spf_result_str(mech->qualifier));
                ret = mech->qualifier;
                goto cleanup;
            default:
                break;
            }
            break;
        case SPF_MECHANISM_EXISTS:
            s->spf_queries++;
            rc = spf_check_exists(s, domain, mech);
            switch (rc) {
            case SPF_RESULT_PASS:
                simta_debuglog(2, "SPF %s [%s]: matched exists %s: %s",
                        s->spf_domain, domain, mech->domain_spec,
                        spf_result_str(mech->qualifier));
                ret = mech->qualifier;
                goto cleanup;
            case SPF_RESULT_TEMPERROR:
                ret = rc;
                goto cleanup;
            default:
                break;
            }
            break;
        }
    }

    if (redirect != NULL) {
        s->spf_queries++;
        ret = spf_check_host(s, redirect);
        if (ret == SPF_RESULT_NONE) {
            ret = SPF_RESULT_PERMERROR;
        }
    } else {
        /* RFC 7208 4.7 Default Result
         * If none of the mechanisms match and there is no "redirect" modifier,
         * then the check_host() returns a result of "neutral", just as if
         * "?all" were specified as the last directive.
         */
        ret = SPF_RESULT_NEUTRAL;
        simta_debuglog(2, "SPF %s [%s]: default result: %s", s->spf_domain,
                domain, spf_result_str(ret));
    }

cleanup:
    if (split) {
        yaslfreesplitres(split, tok_count);
    }
    if (mech_list) {
        if (iter) {
            ucl_object_iterate_reset(iter, mech_list);
        } else {
            iter = ucl_object_iterate_new(mech_list);
        }
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            mech = obj->value.ud;
            yaslfree(mech->domain_spec);
            simta_free(mech);
        }
        ucl_object_unref(mech_list);
    }
    if (iter) {
        ucl_object_iterate_free(iter);
    }
    yaslfree(record);
    yaslfree(redirect);
    yaslfree(exp);
    dnsr_free_result(dnsr_res);
    return ret;
}


struct spf *
spf_lookup(const char *helo, const char *email, const struct sockaddr *addr) {
    char       *p;
    struct spf *s;

    s = simta_calloc(1, sizeof(struct spf));
    s->spf_queries = 0;
    s->spf_sockaddr = addr;
    s->spf_helo = yaslauto(helo);

    if (strlen(email) == 0) {
        /* RFC 7208 2.4 The "MAIL FROM" Identity
         * When the reverse-path is null, this document defines the "MAIL FROM"
         * identity to be the mailbox composed of the local-part "postmaster"
         * and the "HELO" identity
         */
        s->spf_domain = yaslauto(helo);
        s->spf_localpart = yaslauto("postmaster");
    } else if ((p = strrchr(email, '@')) != NULL) {
        s->spf_domain = yaslauto(p + 1);
        s->spf_localpart = yaslnew(email, (size_t)(p - email));
    } else {
        /* RFC 7208 4.3 Initial Processing
         * If the <sender> has no local-part, substitute the string
         * "postmaster" for the local-part.
         */
        s->spf_domain = yaslauto(email);
        s->spf_localpart = yaslauto("postmaster");
    }

    simta_debuglog(2, "SPF %s: localpart %s", s->spf_domain, s->spf_localpart);

    s->spf_result = spf_check_host(s, s->spf_domain);

    return s;
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
