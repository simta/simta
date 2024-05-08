/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "envelope.h"
#include "header.h"
#include "queue.h"
#include "simta_malloc.h"

static int   cfws_len(const char *);
static int   domain_literal_len(const char *);
static int   dot_atom_text_len(const char *);
static void  header_exceptions(struct line_file *);
static void  header_masquerade(struct line *);
static void  header_remove(struct dll_entry *, struct receive_headers *);
static int   header_singleton(const char *, const struct rfc822_header *);
static yastr header_string(struct line *);
static bool  is_dot_atom_text(int);
static yastr parse_addr_spec(const char *, int *);
static yastr parse_mid(struct line *);
static int   quoted_string_len(const char *);


static int
cfws_len(const char *c) {
    int comment = 0;
    int i;

    for (i = 0;; i++) {
        switch (c[ i ]) {
        case ' ':
        case '\t':
            break;

        case '(':
            comment++;
            break;

        case ')':
            comment--;

            if (comment < 0) {
                /* Unexpected closing parend */
                return (-1);
            }
            break;

        case '\\':
            i++;

            if (c[ i ] == '\0') {
                /* EOL after \ */
                return (-1);
            }
            break;

        case '\0':
            if (comment != 0) {
                /* At least one unclosed parend */
                return (-1);
            } else {
                return (i);
            }

        default:
            if (comment == 0) {
                return (i);
            }
        }
    }
}

static int
domain_literal_len(const char *l) {
    int i;

    if (l[ 0 ] != '[') {
        return (0);
    }

    for (i = 1; l[ i ] != '\0'; i++) {
        switch (l[ i ]) {
        case ']':
            return (i + 1);
        case '\\':
            i++;
        default:
            break;
        }
    }

    return (-1);
}

static int
dot_atom_text_len(const char *d) {
    int i;

    for (i = 0; is_dot_atom_text(d[ i ]); i++)
        ;
    return (i);
}

static int
quoted_string_len(const char *q) {
    int i;

    if (q[ 0 ] != '"') {
        return (0);
    }

    for (i = 1; q[ i ] != '\0'; i++) {
        switch (q[ i ]) {
        case '"':
            return (i + 1);
        case '\\':
            i++;
            break;
        default:
            break;
        }
    }

    return (-1);
}


static yastr
parse_addr_spec(const char *addr, int *l) {
    yastr       buf;
    const char *start;
    int         len;

    buf = yaslempty();

    if ((len = cfws_len(addr)) < 0) {
        syslog(LOG_INFO, "parse_addr_spec %s: cfws_len failed: %s", addr, addr);
        goto error;
    }

    start = addr + len;

    if (*start == '"') {
        if ((len = quoted_string_len(start)) < 0) {
            syslog(LOG_INFO, "parse_addr_spec %s: quoted_string_len failed: %s",
                    addr, start);
            goto error;
        }
    } else if ((len = dot_atom_text_len(start)) < 0) {
        syslog(LOG_INFO, "parse_addr_spec %s: dot_atom_text_len failed: %s",
                addr, start);
        goto error;
    }

    buf = yaslcatlen(buf, start, (size_t)len);
    start += len;

    if (*start != '@') {
        syslog(LOG_INFO, "parse_addr_spec %s: expected @: %s", addr, start);
        goto error;
    }

    if ((len = dot_atom_text_len(start + 1)) < 0) {
        syslog(LOG_INFO, "parse_addr_spec %s: dot_atom_text_len failed: %s",
                addr, start);
        goto error;
    }
    buf = yaslcatlen(buf, start, (size_t)(len + 1));

    *l = start + len + 1 - addr;
    return (buf);

error:
    yaslfree(buf);
    return (NULL);
}

static void
header_exceptions(struct line_file *lf) {
    char *c;
    char *end;

    if ((lf == NULL) || (lf->l_first == NULL)) {
        /* empty message */
        return;
    }

    /* mail(1) on Solaris gives non-rfc compliant first header line */
    c = lf->l_first->line_data;

    if (strncasecmp(c, "From ", 5) == 0) {
        c += 5;
        for (end = c; (*end > 33) && (*end < 126); end++)
            ;

        /* if "From "word ..., rewrite header "From:"word'\0' */
        if ((end - c) > 0) {
            *(lf->l_first->line_data + 4) = ':';
            *end = '\0';
        }
    }
}


int
header_file_out(struct line_file *lf, FILE *file) {
    struct line *l;
    int          rc, data_written = 0;

    for (l = lf->l_first; l != NULL; l = l->line_next) {
        if ((rc = fprintf(file, "%s\n", l->line_data)) < 0) {
            return (rc);
        }
        data_written += rc;
    }

    return (data_written);
}

static yastr
header_string(struct line *l) {
    yastr buf;

    buf = yaslauto(l->line_data);
    yaslrangesepright(buf, ':');
    for (l = l->line_next; l != NULL; l = l->line_next) {
        if ((*(l->line_data) != ' ') && (*(l->line_data) != '\t')) {
            break;
        }
        buf = yaslcat(buf, l->line_data);
    }

    return buf;
}

/* RFC 5322 3.3 Date and Time Specification
 * date-time       =   [ day-of-week "," ] date time [CFWS]
 * day-of-week     =   ([FWS] day-name) / obs-day-of-week
 * day-name        =   "Mon" / "Tue" / "Wed" / "Thu" /
 *                     "Fri" / "Sat" / "Sun"
 * date            =   day month year
 * day             =   ([FWS] 1*2DIGIT FWS) / obs-day
 * month           =   "Jan" / "Feb" / "Mar" / "Apr" /
 *                     "May" / "Jun" / "Jul" / "Aug" /
 *                     "Sep" / "Oct" / "Nov" / "Dec"
 * year            =   (FWS 4*DIGIT FWS) / obs-year
 * time            =   time-of-day zone
 * time-of-day     =   hour ":" minute [ ":" second ]
 * zone            =   (FWS ( "+" / "-" ) 4DIGIT) / obs-zone
 *
 * %T and %z are defined in ISO C99; C89 compilers might
 * not support them.
 */
yastr
rfc5322_timestamp() {
    time_t     clock;
    struct tm *tm;
    yastr      retval = NULL;

    if (time(&clock) < 0) {
        syslog(LOG_ERR, "Syserror: rfc5322_timestamp time: %m");
    } else if ((tm = localtime(&clock)) == NULL) {
        syslog(LOG_ERR, "Syserror: rfc5322_timestamp localtime: %m");
    } else {
        /* timestamps are at most 31 characters long. */
        retval = yaslMakeRoomFor(yaslempty(), 32);
        if (strftime(retval, 32, "%a, %d %b %Y %T %z", tm) == 0) {
            syslog(LOG_ERR, "Syserror: rfc5322_timestamp strftime: %m");
            yaslfree(retval);
            retval = NULL;
        }
        yaslupdatelen(retval);
    }

    return retval;
}

static yastr
parse_mid(struct line *l) {
    yastr buf;
    int   len;
    char *c;

    buf = header_string(l);

    simta_debuglog(2, "parse_mid: %s", buf);

    if ((len = cfws_len(buf)) < 0) {
        syslog(LOG_INFO, "parse_mid: cfws_len failed: %s", buf);
        goto error;
    }

    yaslrange(buf, len, -1);

    if (*buf != '<') {
        syslog(LOG_NOTICE, "parse_mid: expected '<': %s", buf);
        goto error;
    }

    yaslrange(buf, 1, -1);

    if ((len = quoted_string_len(buf)) < 0) {
        syslog(LOG_INFO, "parse_mid: quoted_string_len failed: %s", buf);
        goto error;
    } else if ((len == 0) && (len = dot_atom_text_len(buf)) < 0) {
        syslog(LOG_INFO, "parse_mid: dot_atom_text_len failed: %s", buf);
        goto error;
    }

    c = buf + len;

    if (*c != '@') {
        syslog(LOG_NOTICE, "parse_mid: expected '@': %s", buf);
        goto error;
    }

    c++;

    if (*c == '[') {
        if ((len = domain_literal_len(c)) < 0) {
            syslog(LOG_INFO, "parse_mid: domain_literal_len failed: %s", c);
            goto error;
        }

    } else {
        if ((len = dot_atom_text_len(c)) < 0) {
            syslog(LOG_INFO, "parse_mid: dot_atom_text_len failed: %s", c);
            goto error;
        }
    }

    c += len;

    if (*c != '>') {
        syslog(LOG_NOTICE, "parse_mid: expected '>': %s", c);
        goto error;
    }

    if (((len = cfws_len(c + 1)) > 0) && (*(c + 1 + len) != '\0')) {
        syslog(LOG_NOTICE, "parse_mid: illegal extra content: %s", c + 1);
        goto error;
    }

    yaslrange(buf, 0, c - buf - 1);
    return (buf);

error:
    yaslfree(buf);
    return (NULL);
}

/* return 0 if line is the next line in header block lf */
/* RFC 5322 2.1 General Description
 * A message consists of header fields (collectively called "the header
 * section of the message") followed, optionally, by a body.  The header
 * section is a sequence of lines of characters with special syntax as
 * defined in this specification. The body is simply a sequence of
 * characters that follows the header section and is separated from the
 * header section by an empty line (i.e., a line with nothing preceding
 * the CRLF).
 */

/* RFC 5322 2.2 Header Fields
 * space (SP, ASCII value 32) and horizontal tab (HTAB, ASCII value 9)
 * characters (together known as the white space characters, WSP)
 */
int
header_text(int line_no, char *line, struct receive_headers *rh, char **msg) {
    char                 *c;
    yastr                 key;
    int                   len;
    struct line          *l;
    struct rfc822_header *h;
    struct dll_entry     *dentry = NULL;

    if (rh == NULL) {
        return (-1);
    }

    if (rh->r_state == R_HEADER_END) {
        return (1);
    }

    /* null line means that message data begins */
    if ((*line) == '\0') {
        rh->r_state = R_HEADER_END;
        return (1);

    } else if ((*line == ' ') || (*line == '\t')) {
        /* if line is not the first line it could be header FWS */
        if (line_no == 1) {
            rh->r_state = R_HEADER_END;
            return (1);
        }

    } else {
        /* check to see if it's a proper field name followed by a colon */
        if (((c = strchr(line, ':')) == NULL) || ((len = (c - line)) < 1)) {
            rh->r_state = R_HEADER_END;
            return (1);
        }
        key = yaslnew(line, (size_t)len);
        yasltolower(key);
        dentry = dll_lookup_or_create(&(rh->r_headers_index), key);
        yaslfree(key);
    }

    rh->r_state = R_HEADER_READ;
    if (rh->r_headers == NULL) {
        rh->r_headers = line_file_create();
    }

    l = line_append(rh->r_headers, line, COPY);
    l->line_no = line_no;

    if (dentry) {
        if ((h = dentry->dll_data) == NULL) {
            h = simta_calloc(1, sizeof(struct rfc822_header));
            dentry->dll_data = h;
        }
        h->h_count++;
        ll_nokey_insert(&(h->h_lines), l, NULL);
    }

    return (0);
}

static void
header_masquerade(struct line *l) {
    yastr        inbuf, outbuf;
    yastr       *split;
    size_t       tok_count;
    int          i;
    struct line *next;

    inbuf = header_string(l);
    outbuf = yaslcat(yaslnew(l->line_data, (size_t)(strchr(l->line_data, ':') -
                                                    l->line_data)),
            ": ");

    split = yaslsplitlen(inbuf, yasllen(inbuf), ",", 1, &tok_count);
    yaslfree(inbuf);
    for (i = 0; i < tok_count; i++) {
        yasltrim(split[ i ], " \t");
        if (strchr(split[ i ], '@') == NULL) {
            split[ i ] = yaslcatprintf(
                    split[ i ], "@%s", simta_config_str("core.masquerade"));
        }
    }
    outbuf = yaslcat(outbuf, yasljoinyasl(split, tok_count, ", ", 2));
    yaslfreesplitres(split, tok_count);

    free(l->line_data);
    l->line_data = simta_strdup(outbuf);
    yaslfree(outbuf);

    l = l->line_next;
    while (l && ((*(l->line_data) == ' ') || (*(l->line_data) == '\t'))) {
        next = l->line_next;
        l->line_prev->line_next = next;
        if (next) {
            next->line_prev = l->line_prev;
        }
        free(l->line_data);
        free(l);
        l = next;
    }
}

static void
header_remove(struct dll_entry *dentry, struct receive_headers *rh) {
    struct line          *l;
    struct line         **lp;
    struct rfc822_header *mh;

    /* Delete the line(s) belonging to this header */
    mh = dentry->dll_data;
    l = mh->h_lines->st_data;

    if (l->line_prev != NULL) {
        lp = &(l->line_prev->line_next);
    } else {
        lp = &(rh->r_headers->l_first);
    }

    for (l = l->line_next; l != NULL; l = l->line_next) {
        if ((*(l->line_data) != ' ') && (*(l->line_data) != '\t')) {
            break;
        }
    }

    /* At this point, l is the line after the header we're deleting. */
    *lp = l;

    /* Remove the header from the index. */
    dll_remove_entry(&(rh->r_headers_index), dentry);
}

int
header_check(struct receive_headers *rh, bool read_headers,
        bool correct_headers, bool simsend) {
    struct line          *l;
    struct rfc822_header *mh;
    struct dll_entry     *dentry;
    int                   ret = 0;
    int                   i;
    size_t                tok_count;
    yastr                 buf = NULL;
    yastr                 tmp;
    yastr                *split;
    yastr                 daytime = NULL;

    /* RFC 5322 3.6 Field definitions
 *  Field           Min number      Max number      Notes
 *
 *  orig-date       1               1
 *
 *  from            1               1               See sender and 3.6.2
 *
 *  sender          0*              1               MUST occur with multi-
 *                                                  address from - see 3.6.2
 *
 *  reply-to        0               1
 *
 *  to              0               1
 *
 *  cc              0               1
 *
 *  bcc             0               1
 *
 *  message-id      0*              1               SHOULD be present - see
 *                                                  3.6.4
 *
 *  in-reply-to     0*              1               SHOULD occur in some
 *                                                  replies - see 3.6.4
 *
 *  references      0*              1               SHOULD occur in some
 *                                                  replies - see 3.6.4
 *
 *  subject         0               1
 *
 * header_check() might add missing fields.
 */

    buf = yaslempty();

    /* check headers for known mail clients behaving badly */
    if (simsend) {
        header_exceptions(rh->r_headers);
    }

    if ((dentry = dll_lookup(rh->r_headers_index, "received")) != NULL) {
        rh->r_received_count =
                ((struct rfc822_header *)dentry->dll_data)->h_count;
    }

    /* From: */
    if ((dentry = dll_lookup(rh->r_headers_index, "from")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("From", mh);
        tmp = header_string(mh->h_lines->st_data);
        split = parse_addr_list(tmp, &tok_count, HEADER_MAILBOX_LIST);
        if ((split == NULL) && simsend) {
            yaslfree(tmp);
            header_masquerade(mh->h_lines->st_data);
            tmp = header_string(mh->h_lines->st_data);
            split = parse_addr_list(tmp, &tok_count, HEADER_MAILBOX_LIST);
        }

        if (tok_count != 1) {
            syslog(LOG_INFO,
                    "header_check: parse_addr_list returned "
                    "an unexpected number of From addresses: %s",
                    tmp);
        }

        if (split == NULL) {
            if (correct_headers && strlen(rh->r_env->e_mail)) {
                /* Bad From:, we should regenerate it. */
                header_remove(dentry, rh);
                dentry = NULL;
            } else {
                ret++;
            }
        } else {
            rh->r_env->e_header_from = yasldup(split[ 0 ]);
            yaslfreesplitres(split, tok_count);
        }

        yaslfree(tmp);
    }

    if (dentry == NULL) {
        if (correct_headers) {
            syslog(LOG_INFO,
                    "header_check: generating new From header using "
                    "RFC5321.MailFrom");
            if (rh->r_headers == NULL) {
                rh->r_headers = line_file_create();
            }
            yaslclear(buf);
            buf = yaslcatprintf(buf, "From: %s", rh->r_env->e_mail);
            line_prepend(rh->r_headers, buf, COPY);
        } else {
            syslog(LOG_INFO, "header_check: missing From header");
            ret++;
        }
    }

    /* Sender: */
    if ((dentry = dll_lookup(rh->r_headers_index, "sender")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("Sender", mh);
    }

    /* Date: */
    if ((dentry = dll_lookup(rh->r_headers_index, "date")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("Date", mh);
    } else if (correct_headers) {
        /* generate Date: header */
        if ((daytime = rfc5322_timestamp()) == NULL) {
            ret = -1;
            goto error;
        }
        if (rh->r_headers == NULL) {
            rh->r_headers = line_file_create();
        }
        yaslclear(buf);
        buf = yaslcatprintf(buf, "Date: %s", daytime);
        yaslfree(daytime);
        daytime = NULL;
        line_prepend(rh->r_headers, buf, COPY);
    } else {
        syslog(LOG_INFO, "header_check: missing Date header");
        ret++;
    }

    /* Message-ID: */
    dentry = dll_lookup(rh->r_headers_index, "message-id");
    if (dentry != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("Message-ID", mh);
        tmp = parse_mid(mh->h_lines->st_data);
        if (tmp == NULL) {
            if (correct_headers) {
                /* Bad Message-ID, we should regenerate it. */
                header_remove(dentry, rh);
                dentry = NULL;
            } else {
                ret++;
            }
        } else {
            rh->r_env->e_mid = tmp;
            tmp = NULL;
        }
    }

    if ((dentry == NULL) && correct_headers) {
        /* generate Message-ID: header */
        if (rh->r_headers == NULL) {
            rh->r_headers = line_file_create();
        }
        yaslclear(buf);
        buf = yaslcatprintf(buf, "%s@%s", rh->r_env->e_id, simta_hostname);
        rh->r_env->e_mid = yasldup(buf);
        yaslclear(buf);
        buf = yaslcatprintf(buf, "Message-ID: <%s>", rh->r_env->e_mid);
        line_prepend(rh->r_headers, buf, COPY);
    }

    /* To: */
    if ((dentry = dll_lookup(rh->r_headers_index, "to")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("To", mh);
        tmp = header_string(mh->h_lines->st_data);
        split = parse_addr_list(tmp, &tok_count, HEADER_ADDRESS_LIST);

        if ((split == NULL) && simsend) {
            yaslfree(tmp);
            header_masquerade(mh->h_lines->st_data);
            tmp = header_string(mh->h_lines->st_data);
            split = parse_addr_list(tmp, &tok_count, HEADER_ADDRESS_LIST);
        }

        if (split == NULL) {
            ret++;
        } else {
            if (read_headers) {
                for (i = 0; i < tok_count; i++) {
                    env_recipient(rh->r_env, split[ i ]);
                }
            }
            yaslfreesplitres(split, tok_count);
        }
        yaslfree(tmp);
    }

    /* Cc: */
    if ((dentry = dll_lookup(rh->r_headers_index, "cc")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("Cc", mh);
        tmp = header_string(mh->h_lines->st_data);
        split = parse_addr_list(tmp, &tok_count, HEADER_ADDRESS_LIST);

        if ((split == NULL) && simsend) {
            yaslfree(tmp);
            header_masquerade(mh->h_lines->st_data);
            tmp = header_string(mh->h_lines->st_data);
            split = parse_addr_list(tmp, &tok_count, HEADER_ADDRESS_LIST);
        }

        if (split == NULL) {
            ret++;
        } else {
            if (read_headers) {
                for (i = 0; i < tok_count; i++) {
                    env_recipient(rh->r_env, split[ i ]);
                }
            }
            yaslfreesplitres(split, tok_count);
        }
        yaslfree(tmp);
    }

    /* Bcc: */
    if ((dentry = dll_lookup(rh->r_headers_index, "bcc")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("Bcc", mh);
        l = mh->h_lines->st_data;
        tmp = header_string(l);
        split = parse_addr_list(tmp, &tok_count, HEADER_ADDRESS_LIST);

        if ((split == NULL) && simsend) {
            yaslfree(tmp);
            header_masquerade(mh->h_lines->st_data);
            tmp = header_string(mh->h_lines->st_data);
            split = parse_addr_list(tmp, &tok_count, HEADER_ADDRESS_LIST);
        }

        if (split == NULL) {
            ret++;
        } else {
            if (read_headers) {
                for (i = 0; i < tok_count; i++) {
                    env_recipient(rh->r_env, split[ i ]);
                }
            }
            yaslfreesplitres(split, tok_count);
        }

        if (simsend) {
            header_remove(dentry, rh);
        }
    }

    /* Mime-Version: */
    if (dll_lookup(rh->r_headers_index, "mime-version")) {
        rh->r_env->e_8bitmime = true;
    }

    /* Subject: */
    if ((dentry = dll_lookup(rh->r_headers_index, "subject")) != NULL) {
        mh = dentry->dll_data;
        ret += header_singleton("Subject", mh);
        tmp = header_string(mh->h_lines->st_data);
        yasltrim(tmp, " \t");
        rh->r_env->e_subject = tmp;
        tmp = NULL;
    }

error:
    yaslfree(buf);
    return (ret);
}

static int
header_singleton(const char *name, const struct rfc822_header *h) {
    if (h->h_count > 1) {
        syslog(LOG_NOTICE, "header_singleton: too many '%s' headers: %d", name,
                h->h_count);
        return (1);
    }
    return (0);
}

/* RFC 5322 3.2.1 Quoted characters
     * quoted-pair     =   ("\" (VCHAR / WSP)) / obs-qp
     *
     * RFC 5322 3.2.2 Folding White Space and Comments
     * FWS             =   ([*WSP CRLF] 1*WSP) /  obs-FWS
     * ctext           =   %d33-39 /          ; Printable US-ASCII
     *                     %d42-91 /          ;  characters not including
     *                     %d93-126 /         ;  "(", ")", or "\"
     *                     obs-ctext
     * ccontent        =   ctext / quoted-pair / comment
     * comment         =   "(" *([FWS] ccontent) [FWS] ")"
     * CFWS            =   (1*([FWS] comment) [FWS]) / FWS
     *
     * RFC 5322 3.2.3 Atom
     * atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
     *                     "!" / "#" /        ;  characters not including
     *                     "$" / "%" /        ;  specials.  Used for atoms.
     *                     "&" / "'" /
     *                     "*" / "+" /
     *                     "-" / "/" /
     *                     "=" / "?" /
     *                     "^" / "_" /
     *                     "`" / "{" /
     *                     "|" / "}" /
     *                     "~"
     * atom            =   [CFWS] 1*atext [CFWS]
     * dot-atom-text   =   1*atext *("." 1*atext)
     * dot-atom        =   [CFWS] dot-atom-text [CFWS]
     * specials        =   "(" / ")" /        ; Special characters that do
     *                     "<" / ">" /        ;  not appear in atext
     *                     "[" / "]" /
     *                     ":" / ";" /
     *                     "@" / "\" /
     *                     "," / "." /
     *                     DQUOTE
     *
     * RFC 5322 3.2.4 Quoted Strings
     * qtext           =   %d33 /             ; Printable US-ASCII
     *                     %d35-91 /          ;  characters not including
     *                     %d93-126 /         ;  "\" or the quote character
     *                     obs-qtext
     * qcontent        =   qtext / quoted-pair
     * quoted-string   =   [CFWS]
     *                     DQUOTE *([FWS] qcontent) [FWS] DQUOTE
     *                     [CFWS]
     *
     * RFC 5322 3.2.5 Miscellaneous Tokens
     * word            =   atom / quoted-string
     * phrase          =   1*word / obs-phrase
     *
     * RFC 5322 3.4 Address Specification:
     *
     * address         =   mailbox / group
     * mailbox         =   name-addr / addr-spec
     * name-addr       =   [display-name] angle-addr
     * angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS]
     *                     obs-angle-addr
     * group           =   display-name ":" [group-list] ";" [CFWS]
     * display-name    =   phrase
     * mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
     * address-list    =   (address *("," address)) / obs-addr-list
     * group-list      =   mailbox-list / CFWS / obs-group-list
     *
     * RFC 5322 3.4.1 Addr-Spec Specification
     *
     * addr-spec       =   local-part "@" domain
     * local-part      =   dot-atom / quoted-string / obs-local-part
     * domain          =   dot-atom / domain-literal / obs-domain
     * domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
     * dtext           =   %d33-90 /          ; Printable US-ASCII
     *                     %d94-126 /         ;  characters not including
     *                     obs-dtext          ;  "[", "]", or "\"
     */


/*
 * ( dot-atom-text | quoted-string )
 *
 * ( dot-atom-text | quoted-string ) '@' ( dot-atom-text | domain-literal )
 */

bool
is_emailaddr(char *addr) {
    if (parse_emailaddr(EMAIL_ADDRESS_NORMAL, addr, NULL, NULL) == SIMTA_OK) {
        return true;
    }

    return false;
}


simta_result
parse_emailaddr(int mode, char *addr, char **user, char **domain) {
    char *u;
    char *d;
    char *end;
    char *at;
    char *eol;

    /* make sure mode is in range */
    switch (mode) {
    case RFC_821_MAIL_FROM:
    case RFC_821_RCPT_TO:
    case EMAIL_ADDRESS_NORMAL:
        break;

    default:
        return SIMTA_ERR;
    }

    u = addr;

    if (u == NULL) {
        return SIMTA_ERR;
    }

    if (mode != EMAIL_ADDRESS_NORMAL) {
        if (*u != '<') {
            return SIMTA_ERR;
        }
        u++;
    }

    if (*u == '\0') {
        if (mode == EMAIL_ADDRESS_NORMAL) {
            return SIMTA_OK;
        }
        return SIMTA_ERR;

    } else if (*u == '@') {
        if (mode == EMAIL_ADDRESS_NORMAL) {
            return SIMTA_ERR;
        }

        /* do at-domain-literal - consume domain */
        u++;
        if (*u == '[') {
            if ((end = token_domain_literal(u)) == NULL) {
                return SIMTA_ERR;
            }
        } else {
            if ((end = token_domain(u)) == NULL) {
                return SIMTA_ERR;
            }
        }
        end++;

        while (*end == ',') {
            u = end + 1;

            if (*u != '@') {
                return SIMTA_ERR;
            }

            /* consume domain */
            u++;
            if (*u == '[') {
                if ((end = token_domain_literal(u)) == NULL) {
                    return SIMTA_ERR;
                }
            } else {
                if ((end = token_domain(u)) == NULL) {
                    return SIMTA_ERR;
                }
            }
            end++;
        }

        if (*end != ':') {
            return SIMTA_ERR;
        }

        u = end + 1;
    }

    if (user) {
        *user = u;
    }

    /* consume the user portion of the address */

    /* <> is a valid address for MAIL FROM commands */
    if (*u == '>') {
        if ((mode == RFC_821_MAIL_FROM) && (*(u + 1) == '\0')) {
            *u = '\0';
            *domain = NULL;
            return SIMTA_OK;
        }

        return SIMTA_ERR;

    } else if (*u == '"') {
        if ((end = token_quoted_string(u)) == NULL) {
            return SIMTA_ERR;
        }

    } else {
        if ((end = token_dot_atom_text(u)) == NULL) {
            return SIMTA_ERR;
        }
    }

    at = end + 1;

    /* RFC 5321 2.3.5 Domain Names
     * The reserved mailbox name "postmaster" may be used in a RCPT
     * command without domain qualification (see section 4.1.1.3) and
     * MUST be accepted if so used.
     */

    if (((*at == '\0') && (mode == EMAIL_ADDRESS_NORMAL)) ||
            ((*at == '>') && (mode == RFC_821_RCPT_TO))) {
        if (strncasecmp(u, "postmaster", strlen("postmaster")) != 0) {
            return SIMTA_ERR;
        }

        if (domain) {
            *domain = NULL;
        }

        return SIMTA_OK;
    }

    if (*at != '@') {
        return SIMTA_ERR;
    }

    /* consume the domain portion of the address */

    d = at + 1;

    if (strlen(d) > SIMTA_MAX_HOST_NAME_LEN) {
        return SIMTA_ERR;
    }

    if (domain) {
        *domain = d;
    }

    if (*d == '[') {
        if ((end = token_domain_literal(d)) == NULL) {
            return SIMTA_ERR;
        }

    } else {
        if ((end = token_domain(d)) == NULL) {
            return SIMTA_ERR;
        }
    }

    eol = end + 1;

    if (mode != EMAIL_ADDRESS_NORMAL) {
        if ((*eol != '>') || (*(eol + 1) != '\0')) {
            return SIMTA_ERR;
        }

        *eol = '\0';

    } else if (*eol != '\0') {
        return SIMTA_ERR;
    }

    return SIMTA_OK;
}


simta_result
correct_emailaddr(yastr *addr, const char *masquerade) {
    char *c;

    c = *addr;

    /* consume localpart */
    if (*c == '"') {
        if ((c = token_quoted_string(c)) == NULL) {
            return SIMTA_ERR;
        }

    } else {
        if ((c = token_dot_atom_text(c)) == NULL) {
            return SIMTA_ERR;
        }
    }

    /* Next token can be '@' followed by a domain, or '\0' and we'll
     * append the masquerade domain. Anything else is an error.
     */

    c++;
    if (*c == '@') {
        c++;

        if (*c == '[') {
            if ((c = token_domain_literal(c)) == NULL) {
                return SIMTA_ERR;
            }

        } else {
            if ((c = token_domain(c)) == NULL) {
                return SIMTA_ERR;
            }
        }

        if (*(c + 1) != '\0') {
            return SIMTA_ERR;
        }

    } else if (*c == '\0') {
        *addr = yaslcatprintf(*addr, "@%s", masquerade);
    } else {
        return SIMTA_ERR;
    }

    return SIMTA_OK;
}


char *
skip_cws(char *start) {
    char *c;
    int   comment_mode = 0;

    for (c = start;; c++) {
        switch (*c) {
        case ' ':
        case '\t':
            break;

        case '\0':
            return (NULL);

        case '(':
            comment_mode++;
            break;

        case ')':
            if (comment_mode != 0) {
                comment_mode = 0;
            } else {
                return (c);
            }
            break;

        default:
            if (comment_mode == 0) {
                return (c);
            }
            break;
        }
    }
}


/* RFC 5322 3.4 Address Specification
 *
 * address         =   mailbox / group
 * mailbox         =   name-addr / addr-spec
 * name-addr       =   [display-name] angle-addr
 * angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
 * group           =   display-name ":" [group-list] ";" [CFWS]
 * display-name    =   phrase
 * mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
 * address-list    =   (address *("," address)) / obs-addr-list
 * group-list      =   mailbox-list / CFWS / obs-group-list
 */
yastr *
parse_addr_list(yastr list, size_t *count, enum address_list_syntax mode) {
    yastr *mboxes, tmp = NULL;
    char  *l;
    int    addr = 0;
    int    len;
    size_t slots = 2;

    mboxes = simta_malloc(slots * sizeof(yastr));
    *count = 0;
    l = list;

    while (*l != '\0') {
        if ((len = cfws_len(l)) < 0) {
            simta_debuglog(1, "parse_addr_list: cfws_len failed: %s", l);
            goto error;
        } else {
            l += len;
        }

        if (*l == '<') {
            addr++;
            l++;
            if ((tmp = parse_addr_spec(l, &len)) == NULL) {
                simta_debuglog(
                        1, "parse_addr_list: parse_addr_spec failed: %s", l);
                goto error;
            }
            l += len;
            if (*l != '>') {
                simta_debuglog(1, "parse_addr_list: expected >: %s", l);
                goto error;
            }
            l++;
        } else if (((len = quoted_string_len(l)) > 0) ||
                   ((len = dot_atom_text_len(l)) > 0)) {
            /* Technically a local-part can be followed by CFWS, but I'm not
             * sure we care enough about that to account for it here.
             */
            if (*(l + len) == '@') {
                if ((tmp = parse_addr_spec(l, &len)) == NULL) {
                    simta_debuglog(1,
                            "parse_addr_list: parse_addr_spec failed: %s", l);
                    /* This might just be a stupid client using an
                     * unquoted quoted-string as the display name, so we
                     * probably shouldn't make it a hard failure. Increment l
                     * to skip the '@'.
                     */
                    l++;
                } else {
                    addr++;
                }
            }
            l += len;
            if (tmp) {
                /* This might be an unquoted address as the display part, which
                 * is invalid but distressingly common.
                 */
                if ((len = cfws_len(l)) < 0) {
                    simta_debuglog(
                            1, "parse_addr_list: cfws_len failed: %s", l);
                    goto error;
                } else {
                    l += len;
                }
                if ((*l != ',') && (*l != '\0')) {
                    simta_debuglog(1,
                            "parse_addr_list: discarding "
                            "address-like string %s from %s",
                            tmp, list);
                    addr--;
                    yaslfree(tmp);
                    tmp = NULL;
                }
            }
        } else if (*l == ',') {
            if (addr != 1) {
                simta_debuglog(1, "parse_addr_list: bad list: %s", l);
                goto error;
            }
            addr = 0;
            l++;
        } else if ((mode == HEADER_ADDRESS_LIST) && (*l == ':')) {
            mode = HEADER_MAILBOX_GROUP;
            l++;
        } else if ((mode == HEADER_MAILBOX_GROUP) && (*l == ';')) {
            addr = 1;
            mode = HEADER_ADDRESS_LIST;
            l++;
        } else if (*l != '\0') {
            simta_debuglog(1, "parse_addr_list: unexpected char: %s", l);
            goto error;
        }

        if (tmp) {
            if (!is_emailaddr(tmp)) {
                simta_debuglog(1, "parse_addr_list: bad address %s", tmp);
                yaslfree(tmp);
            } else {
                if (*count >= slots) {
                    slots *= 2;
                    mboxes = simta_realloc(mboxes, slots * sizeof(yastr));
                }
                mboxes[ *count ] = tmp;
                (*count)++;
            }
            tmp = NULL;
        }
    }

    if (addr != 1) {
        simta_debuglog(1, "parse_addr_list: bad list");
        goto error;
    }

    if (*count > 0) {
        return mboxes;
    }

    free(mboxes);
    return NULL;

error:
    syslog(LOG_INFO, "parse_addr_list: error parsing %s", list);
    if (tmp) {
        yaslfree(tmp);
    }

    yaslfreesplitres(mboxes, *count);

    return NULL;
}

char *
token_quoted_string(char *start) {
    if (*start != '"') {
        return NULL;
    }

    for (;;) {
        start++;

        /* Quoted strings can only contain printable characters */
        if (!isprint(*start)) {
            return NULL;
        }

        switch (*start) {

        case '"':
            /* end of quoted string */
            return start;

        case '\\':
            start++;

            /* RFC 5321 4.1.2 Command Argument Syntax
             *
             * quoted-pairSMTP  = %d92 %d32-126
             *                  ; i.e., backslash followed by any ASCII
             *                  ; graphic (including itself) or SPace
             */
            if (!isprint(*start)) {
                /* not a valid escape */
                return NULL;
            }
            break;

        case '\0':
            /* eol */
            return NULL;

        default:
            /* everything else */
            break;
        }
    }
}


char *
token_domain_literal(char *i) {
    if (*i != '[') {
        return (NULL);
    }

    for (;;) {
        i++;

        switch (*i) {

        case ']':
            /* end of domain literal */
            return (i);

        case '\\':
            i++;

            if (*i == '\0') {
                /* eol */
                return (NULL);
            }
            break;

        case '\0':
            /* eol */
            return (NULL);

        default:
            /* everything else */
            break;
        }
    }
}


static bool
is_dot_atom_text(int c) {
    if (isalpha(c) != 0) {
        return true;
    }

    if (isdigit(c) != 0) {
        return true;
    }

    switch (c) {

    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '/':
    case '=':
    case '?':
    case '^':
    case '_':
    case '`':
    case '{':
    case '|':
    case '}':
    case '~':
    case '.':
        return true;

    default:
        return false;
    }
}


char *
token_domain(char *i) {
    if ((isalpha(*i) == 0) && (isdigit(*i) == 0)) {
        return NULL;
    }

    for (;;) {
        if ((*i == '.') && (*(i + 1) == '.')) {
            return NULL;
        }

        if ((isalpha(*(i + 1)) == 0) && (isdigit(*(i + 1)) == 0) &&
                (*(i + 1) != '.') && (*(i + 1) != '-')) {
            /* rewind to the last letter or digit */
            while (*i == '.' || *i == '-') {
                i--;
            }
            return i;
        }

        i++;
    }
}


char *
token_dot_atom_text(char *start) {
    /* RFC 5322 3.2.3. Atom
     *
     *    dot-atom-text   =   1*atext *("." 1*atext)
     *
     * RFC 5321 4.1.2. Command Argument Syntax
     *
     *    Dot-string     = Atom *("."  Atom)
     *    Atom           = 1*atext
     */

    char *ret = NULL;

    if (!is_dot_atom_text(*start)) {
        return NULL;
    }

    /* A dot-string cannot start with '.' */
    if (*start == '.') {
        return NULL;
    }

    for (;;) {
        /* A '.' on its own does not extend the dot-string. */
        if (*start != '.') {
            ret = start;
        }

        if (!is_dot_atom_text(*(start + 1))) {
            return ret;
        }

        /* '.' must be followed by atext, not another '.' */
        if (*start == '.' && *(start + 1) == '.') {
            return ret;
        }

        start++;
    }
}


void
receive_headers_free(struct receive_headers *r) {
    struct dll_entry     *d;
    struct rfc822_header *h;

    if (r == NULL) {
        return;
    }

    if (r->r_headers) {
        line_file_free(r->r_headers);
    }

    for (d = r->r_headers_index; d; d = d->dll_next) {
        h = d->dll_data;
        ll_free(h->h_lines);
        free(h);
    }

    dll_free(r->r_headers_index);

    free(r);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
