/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

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
#include "red.h"
#include "simta_malloc.h"
#include "simta_statsd.h"
#include "smtp.h"

#ifdef HAVE_LIBSSL
#include "tls.h"
#endif /* HAVE_LIBSSL */

#define S_8BITMIME "8BITMIME"
#define S_SIZE "SIZE"
#define S_STARTTLS "STARTTLS"

static yastr *smtp_getlines(struct deliver *, size_t *count);
static void smtp_consume_response(struct line_file **, yastr *, size_t, char *);
static void smtp_parse_ehlo_banner(struct deliver *, yastr *, size_t);
static smtp_result smtp_reply(int, struct host_q *, struct deliver *);
static void        smtp_snet_eof(struct deliver *, const char *);
static int         smtp_ehlo(struct host_q *, struct deliver *);


static yastr *
smtp_getlines(struct deliver *d, size_t *count) {
    size_t slots = 5;
    yastr *tokens;
    yastr  line;

    tokens = simta_malloc(sizeof(yastr) * slots);
    *count = 0;

    do {
        if ((line = snet_getline_safe(d->d_snet_smtp, NULL)) == NULL) {
            goto error;
        }

        simta_debuglog(3, "Deliver.SMTP response: %s", line);

        if (yasllen(line) < 3) {
            syslog(LOG_INFO, "Deliver.SMTP env <%s>: bad banner syntax: %s",
                    d->d_env ? d->d_env->e_id : "null", line);

            goto error;
        }

        if (!isdigit((int)line[ 0 ]) || !isdigit((int)line[ 1 ]) ||
                !isdigit((int)line[ 2 ])) {
            syslog(LOG_INFO, "Deliver.SMTP env <%s>: bad banner syntax: %s",
                    d->d_env ? d->d_env->e_id : "null", line);
            goto error;
        }

        if (line[ 3 ] != '\0' && line[ 3 ] != ' ' && line[ 3 ] != '-') {
            syslog(LOG_INFO, "Deliver.SMTP env <%s>: bad banner syntax: %s",
                    d->d_env ? d->d_env->e_id : "null", line);
            goto error;
        }

        if (slots < *count + 1) {
            slots *= 2;
            tokens = simta_realloc(tokens, sizeof(yastr) * slots);
        }
        tokens[ *count ] = line;
        (*count)++;
    } while (line[ 3 ] == '-');

    return tokens;

error:
    free(tokens);
    *count = 0;
    return NULL;
}


static void
smtp_consume_response(
        struct line_file **err_text, yastr *lines, size_t count, char *error) {
    if (err_text != NULL) {
        if (*err_text == NULL) {
            *err_text = line_file_create();
        } else {
            line_append(*err_text, "", COPY);
        }

        line_append(*err_text, error, COPY);

        for (int i = 0; i < count; i++) {
            line_append(*err_text, lines[ i ], COPY);
        }
    }

    yaslfreesplitres(lines, count);
}

static void
smtp_parse_ehlo_banner(struct deliver *d, yastr *lines, size_t count) {
    char *c;
    int   size;

    for (int i = 0; i < count; i++) {
        /* Parse SMTP extensions that we care about */
        c = lines[ i ] + 4;

        if ((strncasecmp(S_8BITMIME, c, strlen(S_8BITMIME)) == 0)) {
            for (c += strlen(S_8BITMIME); isspace(*c); c++)
                ;
            if (*c == '\0') {
                simta_debuglog(2, "Deliver.SMTP env <%s>: 8BITMIME supported",
                        d->d_env->e_id);
                d->d_esmtp_8bitmime = true;
            }
        } else if ((strncasecmp(S_SIZE, c, strlen(S_SIZE)) == 0)) {
            for (c += strlen(S_SIZE); isspace(*c); c++)
                ;
            if (*c == '\0') {
                simta_debuglog(2, "Deliver.SMTP env <%s>: SIZE supported",
                        d->d_env->e_id);
                d->d_esmtp_size = -1;
            } else {
                /* Quirk: handle broken simta versions */
                if (*c == '=') {
                    c++;
                }
                errno = 0;
                size = strtol(c, NULL, 0);
                if ((errno == EINVAL) || (errno == ERANGE)) {
                    syslog(LOG_WARNING,
                            "Deliver.SMTP env <%s>: "
                            "error parsing SIZE parameter: %s",
                            d->d_env->e_id, c);
                } else {
                    simta_debuglog(2,
                            "Deliver.SMTP env <%s>: SIZE supported: %d",
                            d->d_env->e_id, size);
                    d->d_esmtp_size = size;
                }
            }
        } else if ((strncasecmp(S_STARTTLS, c, strlen(S_STARTTLS)) == 0)) {
            for (c += strlen(S_STARTTLS); isspace(*c); c++)
                ;
            if (*c == '\0') {
                simta_debuglog(2, "Deliver.SMTP env <%s>: STARTTLS supported",
                        d->d_env->e_id);
                d->d_esmtp_starttls = true;
            }
        }
    }

    yaslfreesplitres(lines, count);
}


static smtp_result
smtp_reply(int smtp_command, struct host_q *hq, struct deliver *d) {
    yastr *lines;
    size_t count = 0;
    char  *c;
    char   old;

    if ((lines = smtp_getlines(d, &count)) == NULL) {
        smtp_snet_eof(d, "smtp_reply: snet_get_smtp_response");
        return SMTP_BAD_CONNECTION;
    }

    switch (*lines[ 0 ]) {
    /* 2xx responses indicate success */
    case '2':
        statsd_counter("deliver.smtp_response", "2xx", 1);
        switch (smtp_command) {
        case SMTP_CONNECT:
            /* Loop detection
             * RFC 5321 4.2 SMTP Replies
             * Greeting = "220 " ( Domain / address-literal )
             *            [ SP textstring ] CRLF /
             *            ( "220-" (Domain / address-literal)
             *            [ SP textstring ] CRLF
             *            *( "220-" [ textstring ] CRLF )
             *            "220" [ SP textstring ] CRLF )
             *
             * "Greeting" appears only in the 220 response that announces that
             * the server is opening its part of the connection.
             *
             * RFC 5321 4.3.1 Sequencing Overview
             * Note: all the greeting-type replies have the official name (the
             * fully-qualified primary domain name) of the server host as the
             * first word following the reply code.  Sometimes the host will
             * have no meaningful name.  See Section 4.1.3 for a discussion of
             * alternatives in these situations.
             *
             * RFC 5321 4.1.2 Command Argument Syntax
             * Domain         = sub-domain *("." sub-domain)
             * sub-domain     = Let-dig [Ldh-str]
             * Let-dig        = ALPHA / DIGIT
             * Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
             * address-literal  = "[" ( IPv4-address-literal /
             *                    IPv6-address-literal /
             *                    General-address-literal ) "]"
             *                    ; See Section 4.1.3
             */

            free(hq->hq_smtp_hostname);

            if (yasllen(lines[ 0 ]) > 4) {
                c = lines[ 0 ] + 4;

                if (*c == '[') {
                    /* Make sure there's a closing bracket */
                    for (c++; *c != ']'; c++) {
                        if (*c == '\0') {
                            syslog(LOG_ERR,
                                    "Connect.out [%s] %s: Failed: "
                                    "illegal hostname in SMTP banner: %s",
                                    d->d_ip, hq->hq_hostname, lines[ 0 ]);
                            smtp_consume_response(&(hq->hq_err_text), lines,
                                    count, "Illegal hostname in banner");
                            return SMTP_ERROR;
                        }
                    }
                }
                for (c++; *c != '\0'; c++) {
                    if ((*c == ']') || (isspace(*c) != 0)) {
                        break;
                    }
                }

                old = *c;
                *c = '\0';
                hq->hq_smtp_hostname = simta_strdup(lines[ 0 ] + 4);
                *c = old;
            } else {
                hq->hq_smtp_hostname = simta_strdup(S_UNKNOWN_HOST);
            }

            if (strcmp(hq->hq_smtp_hostname, simta_hostname) == 0) {
                syslog(LOG_ERR,
                        "Connect.out [%s] %s: Failed: banner mail loop: %s",
                        d->d_ip, hq->hq_hostname, lines[ 0 ]);

                /* Loop - connected to self */
                smtp_consume_response(
                        &(hq->hq_err_text), lines, count, "Mail loop detected");
                return SMTP_ERROR;
            }

            syslog(LOG_NOTICE, "Connect.out [%s] %s: Accepted: %s: %s", d->d_ip,
                    hq->hq_hostname, hq->hq_smtp_hostname, lines[ 0 ]);

            break;

        case SMTP_RSET:
        case SMTP_QUIT:
            break;

        case SMTP_HELO:
            syslog(LOG_INFO, "Deliver.SMTP env <%s>: HELO reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            break;

        case SMTP_EHLO:
            syslog(LOG_INFO, "Deliver.SMTP env <%s>: EHLO reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_parse_ehlo_banner(d, lines, count);
            return SMTP_OK;
            break;

        case SMTP_STARTTLS:
            syslog(LOG_INFO, "Deliver.SMTP env <%s>: STARTTLS reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            break;

        case SMTP_MAIL:
            syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: From <%s> Accepted: %s",
                    d->d_env->e_id, d->d_env->e_mail, lines[ 0 ]);
            break;

        case SMTP_RCPT:
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: To <%s> From <%s> Accepted: %s",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
                    lines[ 0 ]);
            d->d_rcpt->r_status = R_ACCEPTED;
            d->d_n_rcpt_accepted++;
            break;

        /* 2xx is actually an error for DATA */
        case SMTP_DATA:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: Message Tempfailed: [%s] %s: %s",
                    d->d_env->e_id, d->d_ip, hq->hq_smtp_hostname, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP DATA reply");
            return SMTP_OK;

        case SMTP_DATA_EOF:
            d->d_delivered = 1;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: "
                    "Message Accepted [%s] %s: transmitted %ld/%ld: %s",
                    d->d_env->e_id, d->d_ip, hq->hq_smtp_hostname, d->d_sent,
                    d->d_size, lines[ 0 ]);
            break;

        default:
            panic("smtp_reply smtp_command out of range");
        }

        smtp_consume_response(NULL, lines, count, NULL);
        return SMTP_OK;

    /* 3xx is success for DATA,
     * fall through to case default for all other commands
     */
    case '3':
        /* FIXME: non-DATA 3xx responses will be double-counted */
        statsd_counter("deliver.smtp_response", "3xx", 1);
        if (smtp_command == SMTP_DATA) {
            /* consume success banner */
            smtp_consume_response(NULL, lines, count, NULL);
            return SMTP_OK;
        }

    default:
        /* note that we treat default as a tempfail and fall through */

    /* 4xx responses indicate temporary failure */
    case '4':
        statsd_counter("deliver.smtp_response", "4xx", 1);
        switch (smtp_command) {
        case SMTP_CONNECT:
            syslog(LOG_NOTICE,
                    "Connect.out [%s] %s: Tempfailed: SMTP banner: %s", d->d_ip,
                    hq->hq_hostname, lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP CONNECT reply");
            return SMTP_ERROR;

        case SMTP_HELO:
            syslog(LOG_WARNING,
                    "Deliver.SMTP env <%s>: Tempfail HELO reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP HELO reply");
            return SMTP_ERROR;

        case SMTP_EHLO:
            syslog(LOG_WARNING,
                    "Deliver.SMTP env <%s>: Tempfail EHLO reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP EHLO reply");
            return SMTP_ERROR;

        case SMTP_STARTTLS:
            syslog(LOG_WARNING,
                    "Deliver.SMTP env <%s>: Tempfail STARTTLS reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_consume_response(&(hq->hq_err_text), lines, count,
                    "Bad SMTP STARTTLS reply");
            return SMTP_ERROR;

        case SMTP_MAIL:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: From <%s> Tempfailed: %s",
                    d->d_env->e_id, d->d_env->e_mail, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP MAIL FROM reply");
            return SMTP_OK;

        case SMTP_RCPT:
            d->d_rcpt->r_status = R_TEMPFAIL;
            d->d_n_rcpt_tempfailed++;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: To <%s> From <%s> Tempfailed: %s",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
                    lines[ 0 ]);
            smtp_consume_response(&(d->d_rcpt->r_err_text), lines, count,
                    "Bad SMTP RCPT TO reply");
            return SMTP_OK;

        case SMTP_DATA:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
            syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: Tempfailed %s [%s]: %s",
                    d->d_env->e_id, hq->hq_smtp_hostname, d->d_ip, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP DATA reply");
            return SMTP_OK;

        case SMTP_DATA_EOF:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_TEMPFAIL;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: Tempfailed %s [%s]: "
                    "transmitted %ld/%ld: %s",
                    d->d_env->e_id, hq->hq_smtp_hostname, d->d_ip, d->d_sent,
                    d->d_size, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP DATA_EOF reply");
            return SMTP_OK;

        case SMTP_RSET:
            syslog(LOG_WARNING,
                    "Deliver.SMTP env <%s>: Tempfail RSET reply: %s",
                    d->d_env ? d->d_env->e_id : "null", lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP RSET reply");
            return SMTP_ERROR;

        case SMTP_QUIT:
            syslog(LOG_WARNING,
                    "Deliver.SMTP env <%s>: Tempfail QUIT reply: %s",
                    d->d_env ? d->d_env->e_id : "null", lines[ 0 ]);
            smtp_consume_response(NULL, lines, count, NULL);
            return SMTP_OK;

        default:
            panic("smtp_reply smtp_command out of range");
        }

    /* all other responses are hard failures */
    case '5':
        statsd_counter("deliver.smtp_response", "5xx", 1);
        switch (smtp_command) {
        case SMTP_CONNECT:
            hq->hq_status = SIMTA_HOST_BOUNCE;
            syslog(LOG_NOTICE, "Connect.out [%s] %s: Failed: SMTP banner: %s",
                    d->d_ip, hq->hq_hostname, lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP CONNECT reply");
            return SMTP_ERROR;

        case SMTP_HELO:
            syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: Fail HELO reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP HELO reply");
            return SMTP_ERROR;

        case SMTP_EHLO:
            syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: Fail EHLO reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP EHLO reply");
            return SMTP_ERROR;

        case SMTP_STARTTLS:
            syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: Fail STARTTLS reply: %s",
                    d->d_env->e_id, lines[ 0 ]);
            smtp_consume_response(&(hq->hq_err_text), lines, count,
                    "Bad SMTP STARTTLS reply");
            return SMTP_ERROR;

        case SMTP_MAIL:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
            syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: From <%s> Failed: %s",
                    d->d_env->e_id, d->d_env->e_mail, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP MAIL FROM reply");
            return SMTP_OK;

        case SMTP_RCPT:
            if (d->d_env->e_bounceable) {
                d->d_rcpt->r_status = R_FAILED;
                d->d_n_rcpt_failed++;
            } else {
                /* demote it to a tempfail, unbounceable hosts aren't
                 * allowed to bounce mail. */
                d->d_rcpt->r_status = R_TEMPFAIL;
                d->d_n_rcpt_tempfailed++;
            }
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: To <%s> From <%s> Failed: %s",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
                    lines[ 0 ]);
            smtp_consume_response(&(d->d_rcpt->r_err_text), lines, count,
                    "Bad SMTP RCPT TO reply");
            return SMTP_OK;

        case SMTP_DATA:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: Message Failed: [%s] %s: %s",
                    d->d_env->e_id, d->d_ip, hq->hq_smtp_hostname, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP DATA reply");
            return SMTP_OK;

        case SMTP_DATA_EOF:
            d->d_env->e_flags = d->d_env->e_flags | ENV_FLAG_BOUNCE;
            syslog(LOG_NOTICE,
                    "Deliver.SMTP env <%s>: Failed %s [%s]: "
                    "transmitted %ld/%ld: %s",
                    d->d_env->e_id, hq->hq_smtp_hostname, d->d_ip, d->d_sent,
                    d->d_size, lines[ 0 ]);
            smtp_consume_response(&(d->d_env->e_err_text), lines, count,
                    "Bad SMTP DATA_EOF reply");
            return SMTP_OK;

        case SMTP_RSET:
            syslog(LOG_WARNING, "Deliver.SMTP env <%s>: Fail RSET reply: %s",
                    d->d_env ? d->d_env->e_id : "null", lines[ 0 ]);
            smtp_consume_response(
                    &(hq->hq_err_text), lines, count, "Bad SMTP RSET reply");
            return SMTP_ERROR;

        case SMTP_QUIT:
            syslog(LOG_WARNING, "Deliver.SMTP env <%s>: Fail QUIT reply: %s",
                    d->d_env ? d->d_env->e_id : "null", lines[ 0 ]);
            smtp_consume_response(NULL, lines, count, NULL);
            return SMTP_OK;

        default:
            panic("smtp_reply smtp_command out of range");
        }
    }

    /* this is here to suppress a compiler warning */
    abort();
}

int
smtp_ehlo(struct host_q *hq, struct deliver *d) {
    /* Reset state */
    d->d_esmtp_8bitmime = false;
    d->d_esmtp_size = 0;
    d->d_esmtp_starttls = false;

    /* (Re)send EHLO */
    if (snet_writef(d->d_snet_smtp, "EHLO %s\r\n", simta_hostname) < 0) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: EHLO: snet_writef failed: %m",
                d->d_env->e_id);
        return (SMTP_BAD_CONNECTION);
    }

    return smtp_reply(SMTP_EHLO, hq, d);
}

smtp_result
smtp_connect(struct host_q *hq, struct deliver *d) {
    smtp_result    retval;
    struct timeval tv_wait;
#ifdef HAVE_LIBSSL
    int               rc;
    int               tls_required = 0;
    const char       *ciphers;
    SSL_CTX          *ssl_ctx = NULL;
    const SSL_CIPHER *ssl_cipher;
#endif /* HAVE_LIBSSL */

    simta_ucl_object_totimeval(
            simta_config_obj("deliver.timeout.command"), &tv_wait);
    snet_timeout(
            d->d_snet_smtp, SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait);

#ifdef HAVE_LIBSSL
    simta_ucl_object_totimeval(
            simta_config_obj("deliver.timeout.tls"), &tv_wait);
    if (tv_wait.tv_sec != 0) {
        snet_timeout(d->d_snet_smtp, SNET_SSL_CONNECT_TIMEOUT, &tv_wait);
    }
#endif /* HAVE_LIBSSL */

    if ((retval = smtp_reply(SMTP_CONNECT, hq, d)) != SMTP_OK) {
        return retval;
    }

#ifdef HAVE_LIBSSL
    if (ucl_object_toboolean(
                ucl_object_lookup_path(hq->hq_red, "deliver.tls.enabled"))) {
        if (ucl_object_toboolean(ucl_object_lookup_path(
                    hq->hq_red, "deliver.tls.required"))) {
            tls_required = 1;
        } else {
            tls_required = 0;
        }
    } else {
        tls_required = -1;
    }
#endif /* HAVE_LIBSSL */

    retval = smtp_ehlo(hq, d);

    switch (retval) {
    default:
        panic("smtp_connect: smtp_reply out of range");

    case SMTP_BAD_CONNECTION:
        break;

    case SMTP_OK:
#ifdef HAVE_LIBSSL
        if (tls_required == -1) {
            break;
        }

        if (!d->d_esmtp_starttls) {
            if (tls_required > 0) {
                syslog(LOG_ERR,
                        "Deliver.SMTP env <%s>: "
                        "TLS required, STARTTLS not available",
                        d->d_env->e_id);
                return SMTP_ERROR;
            } else {
                break;
            }
        }

        simta_debuglog(3, "Deliver.SMTP: smtp_connect snet_starttls");

        if (snet_writef(d->d_snet_smtp, "%s\r\n", S_STARTTLS) < 0) {
            syslog(LOG_ERR,
                    "Deliver.SMTP env <%s>: STARTTLS: snet_writef failed: %m",
                    d->d_env->e_id);
            return SMTP_BAD_CONNECTION;
        }

        if ((retval = smtp_reply(SMTP_STARTTLS, hq, d)) != SMTP_OK) {
            return retval;
        }

        ciphers = ucl_object_tostring(
                ucl_object_lookup_path(hq->hq_red, "deliver.tls.ciphers"));

        if ((ssl_ctx = tls_client_setup(ciphers)) == NULL) {
            syslog(LOG_ERR, "Liberror: smtp_connect tls_client_setup: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            if (tls_required > 0) {
                syslog(LOG_WARNING,
                        "Deliver.SMTP env <%s>: "
                        "TLS required, tls_client_setup error",
                        d->d_env->e_id);
                return SMTP_ERROR;
            } else {
                return SMTP_BAD_TLS;
            }

        } else if ((rc = snet_starttls(d->d_snet_smtp, ssl_ctx, 0)) != 1) {
            syslog(LOG_ERR, "Liberror: smtp_connect snet_starttls: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(ssl_ctx);
            if (tls_required > 0) {
                return SMTP_BAD_CONNECTION;
            } else {
                return SMTP_BAD_TLS;
            }

        } else if (tls_client_cert(hq->hq_hostname, d->d_snet_smtp->sn_ssl)) {
            if (ucl_object_toboolean(ucl_object_lookup_path(
                        hq->hq_red, "deliver.tls.verify"))) {
                SSL_CTX_free(ssl_ctx);
                syslog(LOG_WARNING,
                        "Deliver.SMTP env <%s>: "
                        "TLS cert required, tls_client_cert error",
                        d->d_env->e_id);
                return SMTP_ERROR;
            }
        }

        if ((ssl_cipher = SSL_get_current_cipher(d->d_snet_smtp->sn_ssl)) !=
                NULL) {
            syslog(LOG_INFO,
                    "Deliver.SMTP env <%s>: "
                    "TLS established. Protocol: %s Cipher: %s",
                    d->d_env->e_id, SSL_get_version(d->d_snet_smtp->sn_ssl),
                    SSL_CIPHER_get_name(ssl_cipher));
        }

        SSL_CTX_free(ssl_ctx);

        /* RFC 3207 4.2
         *
         * Upon completion of the TLS handshake, the SMTP protocol is reset to
         * the initial state (the state in SMTP after a server issues a 220
         * service ready greeting).  The server MUST discard any knowledge
         * obtained from the client, such as the argument to the EHLO command,
         * which was not obtained from the TLS negotiation itself.  The client
         * MUST discard any knowledge obtained from the server, such as the list
         * of SMTP service extensions, which was not obtained from the TLS
         * negotiation itself.  The client SHOULD send an EHLO command as the
         * first command after a successful TLS negotiation.
         */

        if ((retval = smtp_ehlo(hq, d)) != SMTP_OK) {
            return retval;
        }
#endif /* HAVE_LIBSSL */
        break;

    case SMTP_ERROR:
#ifdef HAVE_LIBSSL
        if (tls_required > 0) {
            syslog(LOG_ERR,
                    "Deliver.SMTP env <%s>: TLS required, EHLO unsupported",
                    d->d_env->e_id);
            return SMTP_ERROR;
        }
#endif /* HAVE_LIBSSL */
        /* say HELO */
        /* RFC 5321 2.2.1 Background
         * (However, for compatibility with older conforming implementations,
         * SMTP clients and servers MUST support the original HELO mechanisms
         * as a fallback.)
         *
         * RFC 5321 3.2 Client Initiation
         * For a particular connection attempt, if the server returns a
         * "command not recognized" response to EHLO, the client SHOULD be
         * able to fall back and send HELO.
         */

        if (snet_writef(d->d_snet_smtp, "HELO %s\r\n", simta_hostname) < 0) {
            syslog(LOG_ERR,
                    "Deliver.SMTP env <%s>: HELO: snet_writef failed: %m",
                    d->d_env->e_id);
            return SMTP_BAD_CONNECTION;
        }
        retval = smtp_reply(SMTP_HELO, hq, d);
    }

    return retval;
}

smtp_result
smtp_send(struct host_q *hq, struct deliver *d) {
    int            rc;
    smtp_result    retval;
    int            max_rcpts = 0;
    int            rcpts_attempted = 0;
    char          *line;
    char          *timer_type;
    struct timeval tv_session = {0, 0};
    struct timeval tv_session_timeout;
    struct timeval tv_line_timeout;
    struct timeval tv_now;
    struct timeval tv_wait;

    simta_ucl_object_totimeval(
            simta_config_obj("deliver.timeout.command"), &tv_wait);
    snet_timeout(
            d->d_snet_smtp, SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait);

    if ((d->d_esmtp_size > 0) && (d->d_size > d->d_esmtp_size)) {
        syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: Message is too large for %s",
                d->d_env->e_id, hq->hq_smtp_hostname);

        /* Set the error message */
        if (d->d_env->e_err_text == NULL) {
            d->d_env->e_err_text = line_file_create();
        }
        if (line_append(d->d_env->e_err_text, "", COPY) == NULL) {
            syslog(LOG_ERR, "smtp_send line_append failed");
            return SMTP_ERROR;
        }
        if (line_append(d->d_env->e_err_text,
                    "This message exceeds the size limit for the recipient "
                    "domain.",
                    COPY) == NULL) {
            syslog(LOG_ERR, "smtp_send line_append failed");
            return SMTP_ERROR;
        }

        d->d_env->e_flags |= ENV_FLAG_BOUNCE;
        return SMTP_OK;
    }

    syslog(LOG_INFO,
            "Deliver.SMTP env <%s>: Attempting remote delivery: %s (%s)",
            d->d_env->e_id, hq->hq_hostname, hq->hq_smtp_hostname);

    /* MAIL FROM: */
    /* RFC 6152 2 Framework for the 8-bit MIME Transport Extension
     *  one optional parameter using the keyword BODY is added to the
     *  MAIL command.  The value associated with this parameter is a
     *  keyword indicating whether a 7-bit message (in strict compliance
     *  with [RFC5321]) or a MIME message (in strict compliance with
     *  [RFC2046] and [RFC2045]) with arbitrary octet content is being
     *  sent.  The syntax of the value is as follows, using the ABNF
     *  notation of [RFC5234]:
     *
     *  body-value = "7BIT" / "8BITMIME"
     */

    if (d->d_esmtp_8bitmime && d->d_env->e_8bitmime) {
        simta_debuglog(1, "Deliver.SMTP env <%s>: Delivering as 8BITMIME",
                d->d_env->e_id);
        rc = snet_writef(d->d_snet_smtp, "MAIL FROM:<%s> BODY=8BITMIME\r\n",
                d->d_env->e_mail);
    } else {
        rc = snet_writef(
                d->d_snet_smtp, "MAIL FROM:<%s>\r\n", d->d_env->e_mail);
    }

    if (rc < 0) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: MAIL: snet_writef failed: %m",
                d->d_env->e_id);
        return SMTP_BAD_CONNECTION;
    }

    if ((retval = smtp_reply(SMTP_MAIL, hq, d)) != SMTP_OK) {
        return retval;
    }

    /* check to see if the sender failed */
    if ((d->d_env->e_flags & ENV_FLAG_BOUNCE) ||
            (d->d_env->e_flags & ENV_FLAG_TEMPFAIL)) {
        return SMTP_OK;
    }

    /* RCPT TOs: */
    assert(d->d_env->e_rcpt != NULL);

    if (hq->hq_red != NULL) {
        max_rcpts = ucl_object_toint(ucl_object_lookup_path(
                hq->hq_red, "deliver.connection.max_rcpts"));
    }

    for (d->d_rcpt = d->d_env->e_rcpt; d->d_rcpt != NULL;
            d->d_rcpt = d->d_rcpt->r_next) {
        /* If we've already tried the maximum number of message recipients for
         * this domain, skip trying this recipient.
         */
        if ((max_rcpts > 0) && (rcpts_attempted >= max_rcpts)) {
            d->d_rcpt->r_status = R_TEMPFAIL;
            d->d_n_rcpt_tempfailed++;
            syslog(LOG_INFO,
                    "Deliver.SMTP env <%s>: To <%s> From <%s> Skipped: "
                    "reached max recipients: %d",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
                    max_rcpts);

            continue;
        }
        rcpts_attempted++;

        if (*(d->d_rcpt->r_rcpt) != '\0') {
            rc = snet_writef(
                    d->d_snet_smtp, "RCPT TO:<%s>\r\n", d->d_rcpt->r_rcpt);
        } else {
            rc = snet_writef(d->d_snet_smtp, "RCPT TO:<postmaster>\r\n");
        }
        if (rc < 0) {
            syslog(LOG_ERR,
                    "Deliver.SMTP env <%s>: RCPT: snet_writef failed: %m",
                    d->d_env->e_id);
            return SMTP_BAD_CONNECTION;
        }

        if ((retval = smtp_reply(SMTP_RCPT, hq, d)) != SMTP_OK) {
            return retval;
        }
    }

    if (d->d_n_rcpt_accepted == 0) {
        /* no rcpts succeded */
        d->d_delivered = 1;
        syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: no valid recipients",
                d->d_env->e_id);
        return SMTP_OK;
    }

    simta_debuglog(1, "Deliver.SMTP env <%s>: Sending DATA", d->d_env->e_id);

    /* say DATA */
    if (snet_writef(d->d_snet_smtp, "DATA\r\n") < 0) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: DATA: snet_writef failed: %m",
                d->d_env->e_id);
        return SMTP_BAD_CONNECTION;
    }

    if ((retval = smtp_reply(SMTP_DATA, hq, d)) != SMTP_OK) {
        return retval;
    }

    /* check to see if DATA failed */
    if ((d->d_env->e_flags & ENV_FLAG_BOUNCE) ||
            (d->d_env->e_flags & ENV_FLAG_TEMPFAIL)) {
        return SMTP_OK;
    }

    if (strcmp(d->d_env->e_dir, simta_dir_fast) == 0) {
        simta_ucl_object_totimeval(
                simta_config_obj("deliver.timeout.fast_data_session"),
                &tv_session_timeout);
        simta_ucl_object_totimeval(
                simta_config_obj("deliver.timeout.fast_data_line"),
                &tv_line_timeout);
    } else {
        simta_ucl_object_totimeval(
                simta_config_obj("deliver.timeout.data_session"),
                &tv_session_timeout);
        simta_ucl_object_totimeval(
                simta_config_obj("deliver.timeout.data_line"),
                &tv_line_timeout);
    }

    for (;;) {
        if (tv_session_timeout.tv_sec > 0) {
            if (simta_gettimeofday(&tv_now) != 0) {
                return SMTP_ERROR;
            }
            if (tv_session.tv_sec == 0) {
                tv_session.tv_sec = tv_now.tv_sec + tv_session_timeout.tv_sec;
            }
            if (tv_now.tv_sec >= tv_session.tv_sec) {
                syslog(LOG_NOTICE, "Deliver.SMTP env <%s>: Message: Timeout %s",
                        d->d_env->e_id, S_DATA_SESSION);
                return SMTP_BAD_CONNECTION;
            }
            if (tv_line_timeout.tv_sec > (tv_session.tv_sec - tv_now.tv_sec)) {
                timer_type = S_DATA_SESSION;
                tv_wait.tv_sec = tv_session.tv_sec - tv_now.tv_sec;
            } else {
                timer_type = S_DATA_LINE;
                tv_wait.tv_sec = tv_line_timeout.tv_sec;
            }
        } else {
            timer_type = S_DATA_LINE;
            tv_wait.tv_sec = tv_line_timeout.tv_sec;
        }
        tv_wait.tv_usec = 0;
        snet_timeout(d->d_snet_smtp, SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT,
                &tv_wait);

        /* read DFile */
        if ((line = snet_getline(d->d_snet_dfile, &tv_wait)) == NULL) {
            break;
        }

        /* transmit message, do not transmit premature SMTP EOF */
        if (*line == '.') {
            /* don't send EOF */
            rc = snet_writef(d->d_snet_smtp, ".%s\r\n", line);
        } else {
            rc = snet_writef(d->d_snet_smtp, "%s\r\n", line);
        }

        if (rc < 0) {
            if (errno == ETIMEDOUT) {
                syslog(LOG_ERR, "Deliver.SMTP env <%s>: Message: Timeout %s",
                        d->d_env->e_id, timer_type);
                return SMTP_BAD_CONNECTION;
            } else {
                syslog(LOG_ERR,
                        "Deliver.SMTP env <%s>: Message: "
                        "snet_writef failed: %m",
                        d->d_env->e_id);
            }
            return SMTP_BAD_CONNECTION;
        }

        d->d_sent += strlen(line) + 1;
    }

    /* send SMTP EOF */
    if (snet_writef(d->d_snet_smtp, ".\r\n", &tv_wait) < 0) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: EOF: snet_writef failed: %m",
                d->d_env->e_id);
        return SMTP_BAD_CONNECTION;
    }

    return smtp_reply(SMTP_DATA_EOF, hq, d);
}


smtp_result
smtp_rset(struct host_q *hq, struct deliver *d) {
    struct timeval tv_wait;

    simta_ucl_object_totimeval(
            simta_config_obj("deliver.timeout.command"), &tv_wait);
    snet_timeout(
            d->d_snet_smtp, SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait);

    /* say RSET */
    if (snet_writef(d->d_snet_smtp, "RSET\r\n") < 0) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: RSET: snet_writef failed: %m",
                d->d_env ? d->d_env->e_id : "null");
        return SMTP_BAD_CONNECTION;
    }

    return smtp_reply(SMTP_RSET, hq, d);
}


void
smtp_quit(struct host_q *hq, struct deliver *d) {
    struct timeval tv_wait;

    simta_ucl_object_totimeval(
            simta_config_obj("deliver.timeout.command"), &tv_wait);
    snet_timeout(
            d->d_snet_smtp, SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait);

    /* say QUIT */
    if (snet_writef(d->d_snet_smtp, "QUIT\r\n") < 0) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: QUIT: snet_writef failed: %m",
                d->d_env ? d->d_env->e_id : "null");
        return;
    }

    smtp_reply(SMTP_QUIT, hq, d);

    return;
}

static void
smtp_snet_eof(struct deliver *d, const char *infix) {
    if (snet_eof(d->d_snet_smtp)) {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: %s: unexpected EOF",
                d->d_env ? d->d_env->e_id : "null", infix);
    } else {
        syslog(LOG_ERR, "Deliver.SMTP env <%s>: %s failed: %m",
                d->d_env ? d->d_env->e_id : "null", infix);
    }
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
