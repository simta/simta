/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBOPENARC
#include <openarc/arc.h>
#endif /* HAVE_LIBOPENARC */

#ifdef HAVE_LIBOPENDKIM
#include <opendkim/dkim.h>
#endif /* HAVE_LIBOPENDKIM */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#ifndef LIBWRAP_ALLOW_FACILITY
#define LIBWRAP_ALLOW_FACILITY LOG_AUTH
#endif
#ifndef LIBWRAP_ALLOW_SEVERITY
#define LIBWRAP_ALLOW_SEVERITY LOG_INFO
#endif
#ifndef LIBWRAP_DENY_FACILITY
#define LIBWRAP_DENY_FACILITY LOG_AUTH
#endif
#ifndef LIBWRAP_DENY_SEVERITY
#define LIBWRAP_DENY_SEVERITY LOG_WARNING
#endif
int allow_severity = LIBWRAP_ALLOW_FACILITY | LIBWRAP_ALLOW_SEVERITY;
int deny_severity = LIBWRAP_DENY_FACILITY | LIBWRAP_DENY_SEVERITY;
#endif /* HAVE_LIBWRAP */

#include "argcargv.h"
#include "dmarc.h"
#include "dns.h"
#include "header.h"
#include "queue.h"
#include "simta_malloc.h"
#include "simta_statsd.h"
#include "spf.h"
#include "srs.h"

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#endif /* HAVE_LDAP */

#ifdef HAVE_LIBSASL
#include "simta_sasl.h"
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include "md.h"
#include "tls.h"
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LMDB
#include "simta_lmdb.h"
#include <lmdb.h>
#endif /* HAVE_LMDB */

#define SIMTA_EXTENSION_SIZE (1 << 0)
#define SIMTA_EXTENSION_8BITMIME (1 << 1)

#define SIMTA_PROXY_HEADERLEN 536

extern char *version;

enum smtp_mode {
    SMTP_MODE_NORMAL,
    SMTP_MODE_DISABLED,
    SMTP_MODE_REFUSE,
    SMTP_MODE_UNAUTHENTICATED,
    SMTP_MODE_INSECURE,
    SMTP_MODE_GLOBAL_RELAY,
    SMTP_MODE_TEMPFAIL,
    SMTP_MODE_TARPIT,
};

struct receive_data {
    SNET *                  r_snet;
    struct envelope *       r_env;
    int                     r_ac;
    char **                 r_av;
    struct sockaddr *       r_sa;
    char *                  r_ip;
    int                     r_write_before_banner;
    int                     r_data_success;
    int                     r_data_attempt;
    int                     r_mail_success;
    int                     r_mail_attempt;
    int                     r_rcpt_success;
    int                     r_rcpt_attempt;
    int                     r_esmtp;
    int                     r_tls;
    int                     r_auth;
    int                     r_dns_match;
    int                     r_dnsl_checked;
    struct dnsl_result *    r_dnsl_result;
    char *                  r_hello;
    char *                  r_smtp_command;
    const char *            r_remote_hostname;
    struct command *        r_commands;
    int                     r_ncommands;
    enum smtp_mode          r_smtp_mode;
    ucl_object_t *          r_smtp_extensions;
    const char *            r_auth_id;
    struct timeval          r_tv_inactivity;
    struct timeval          r_tv_session;
    struct timeval          r_tv_accepted;
    struct spf *            r_spf;
    struct dmarc *          r_dmarc;
    enum simta_dmarc_result r_dmarc_result;
    int                     r_bad_headers;

#ifdef HAVE_LIBOPENARC
    ARC_LIB *r_arc;
#endif /* HAVE_LIBOPENARC */

#ifdef HAVE_LIBOPENDKIM
    DKIM_LIB *r_dkim;
#endif /* HAVE_LIBOPENDKIM */

#ifdef HAVE_LIBSSL
    struct message_digest r_md;
    struct message_digest r_md_body;
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    struct simta_sasl *r_sasl;
    int                r_failedauth;
#endif /* HAVE_LIBSASL */
};

#ifdef HAVE_LIBSASL
#define BASE64_BUF_SIZE 21848 /* per RFC 2222bis: ((16k / 3 ) +1 ) * 4 */
#endif                        /* HAVE_LIBSASL */

#define RECEIVE_OK 0x0000
#define RECEIVE_SYSERROR 0x0001
#define RECEIVE_CLOSECONNECTION 0x0010

#define S_421_DECLINE "Service not available: closing transmission channel"
#define S_451_DECLINE                                                          \
    "Requested action aborted: "                                               \
    "service temporarily unavailable"
#define S_451_MESSAGE "Message Tempfailed"
#define S_554_MESSAGE "Message Failed"
#define S_MAXCONNECT "Maximum connections exceeded"
#define S_TIMEOUT "Connection length exceeded"
#define S_CLOSING "closing transmission channel"
#define S_UNKNOWN "unknown"
#define S_UNRESOLVED "Unresolved"
#define S_DENIED "Access denied for IP"

/* return codes for address_expand */
#define LOCAL_ADDRESS 1
#define NOT_LOCAL 2
#define LOCAL_ERROR 3
#define LOCAL_ADDRESS_RBL 4

#define NO_ERROR 0
#define PROTOCOL_ERROR 1
#define SYSTEM_ERROR 2

struct command {
    const char *c_name;
    int (*c_func)(struct receive_data *);
};

static yastr       env_string(const char *, const char *);
static const char *iprev_authresult_str(struct receive_data *);
static int         proxy_accept(struct receive_data *);
static int         auth_init(struct receive_data *, struct simta_socket *);
static int content_filter(struct receive_data *, char **, struct timeval *);
static int run_content_filter(struct receive_data *, char **);
static simta_address_status local_address(char *, char *, const ucl_object_t *);
static int                  hello(struct receive_data *, char *);
static int                  reset(struct receive_data *);
static int                  deliver_accepted(struct receive_data *, int);
static int                  f_helo(struct receive_data *);
static int                  f_ehlo(struct receive_data *);
static int                  f_auth(struct receive_data *);
static int                  f_mail(struct receive_data *);
static int                  f_rcpt(struct receive_data *);
static int                  f_data(struct receive_data *);
static int                  f_rset(struct receive_data *);
static int                  f_noop(struct receive_data *);
static int                  f_quit(struct receive_data *);
static int                  f_help(struct receive_data *);
static int                  f_not_implemented(struct receive_data *);
static int                  f_bad_sequence(struct receive_data *);
static int                  f_disabled(struct receive_data *);
static int                  f_insecure(struct receive_data *);
static int                  f_off(struct receive_data *);
static void set_smtp_mode(struct receive_data *, const char *, const char *);
static void tarpit_sleep(struct receive_data *);
static void log_bad_syntax(struct receive_data *);
static int  smtp_write_banner(
         struct receive_data *, int, const char *, const char *);

#ifdef HAVE_LIBOPENDKIM
static const char *simta_dkim_authresult_str(DKIM_SIGERROR);
#endif /* HAVE_LIBOPENDKIM */

#ifdef HAVE_LIBSASL
static void update_sasl_extension(struct receive_data *);
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
static int f_starttls(struct receive_data *);
static int start_tls(struct receive_data *, SSL_CTX *);
#endif /* HAVE_LIBSSL */

static struct command smtp_commands[] = {
        {"HELO", f_helo},
        {"EHLO", f_ehlo},
        {"MAIL", f_mail},
        {"RCPT", f_rcpt},
        {"DATA", f_data},
        {"RSET", f_rset},
        {"NOOP", f_noop},
        {"QUIT", f_quit},
        {"HELP", f_help},
        {"VRFY", f_not_implemented},
        {"EXPN", f_not_implemented},
#ifdef HAVE_LIBSSL
        {"STARTTLS", f_starttls},
#endif /* HAVE_LIBSSL */
        {"AUTH", f_auth},
};

static struct command tarpit_commands[] = {
        {"HELO", f_helo},
        {"EHLO", f_ehlo},
        {"MAIL", f_mail},
        {"RCPT", f_rcpt},
        {"DATA", f_data},
        {"RSET", f_rset},
        {"NOOP", f_off},
        {"QUIT", f_quit},
        {"HELP", f_off},
        {"VRFY", f_off},
        {"EXPN", f_off},
#ifdef HAVE_LIBSSL
        {"STARTTLS", f_starttls},
#endif /* HAVE_LIBSSL */
        {"AUTH", f_off},
};

static struct command tempfail_commands[] = {
        {"HELO", f_helo},
        {"EHLO", f_ehlo},
        {"MAIL", f_off},
        {"RCPT", f_off},
        {"DATA", f_data},
        {"RSET", f_rset},
        {"NOOP", f_noop},
        {"QUIT", f_quit},
        {"HELP", f_off},
        {"VRFY", f_off},
        {"EXPN", f_off},
#ifdef HAVE_LIBSSL
        {"STARTTLS", f_starttls},
#endif /* HAVE_LIBSSL */
        {"AUTH", f_off},
};

static struct command insecure_commands[] = {
        {"HELO", f_insecure},
        {"EHLO", f_insecure},
        {"MAIL", f_insecure},
        {"RCPT", f_insecure},
        {"DATA", f_insecure},
        {"RSET", f_insecure},
        {"NOOP", f_insecure},
        {"QUIT", f_quit},
        {"HELP", f_insecure},
        {"VRFY", f_insecure},
        {"EXPN", f_insecure},
        {"STARTTLS", f_bad_sequence},
        {"AUTH", f_insecure},
};

static struct command off_commands[] = {
        {"HELO", f_disabled},
        {"EHLO", f_disabled},
        {"MAIL", f_disabled},
        {"RCPT", f_disabled},
        {"DATA", f_disabled},
        {"RSET", f_disabled},
        {"NOOP", f_disabled},
        {"QUIT", f_quit},
        {"HELP", f_disabled},
        {"VRFY", f_disabled},
        {"EXPN", f_disabled},
#ifdef HAVE_LIBSSL
        {"STARTTLS", f_disabled},
#endif /* HAVE_LIBSSL */
        {"AUTH", f_disabled},
};

static struct command unauth_commands[] = {
        {"HELO", f_helo},
        {"EHLO", f_ehlo},
        {"MAIL", f_off},
        {"RCPT", f_bad_sequence},
        {"DATA", f_bad_sequence},
        {"RSET", f_rset},
        {"NOOP", f_noop},
        {"QUIT", f_quit},
        {"HELP", f_help},
        {"VRFY", f_not_implemented},
        {"EXPN", f_not_implemented},
#ifdef HAVE_LIBSSL
        {"STARTTLS", f_starttls},
#endif /* HAVE_LIBSSL */
        {"AUTH", f_auth},
};


static void
set_smtp_mode(struct receive_data *r, const char *mode, const char *msg) {
    enum smtp_mode new_mode = SMTP_MODE_DISABLED;

    if (strcmp(mode, "global_relay") == 0) {
        new_mode = SMTP_MODE_GLOBAL_RELAY;
    } else if (strcmp(mode, "insecure") == 0) {
        new_mode = SMTP_MODE_INSECURE;
    } else if (strcmp(mode, "normal") == 0) {
        new_mode = SMTP_MODE_NORMAL;
    } else if (strcmp(mode, "refuse") == 0) {
        new_mode = SMTP_MODE_REFUSE;
    } else if (strcmp(mode, "tarpit") == 0) {
        new_mode = SMTP_MODE_TARPIT;
    } else if (strcmp(mode, "tempfail") == 0) {
        new_mode = SMTP_MODE_TEMPFAIL;
    } else if (strcmp(mode, "unauthenticated") == 0) {
        new_mode = SMTP_MODE_UNAUTHENTICATED;
    }
    r->r_smtp_mode = new_mode;

    syslog(LOG_INFO, "Receive [%s] %s: SMTP mode %s: %s", r->r_ip,
            r->r_remote_hostname, mode, msg);

    switch (r->r_smtp_mode) {
    case SMTP_MODE_DISABLED:
        r->r_commands = off_commands;
        r->r_ncommands = sizeof(off_commands) / sizeof(off_commands[ 0 ]);
        break;
    case SMTP_MODE_INSECURE:
        r->r_commands = insecure_commands;
        r->r_ncommands =
                sizeof(insecure_commands) / sizeof(insecure_commands[ 0 ]);
        break;
    case SMTP_MODE_TARPIT:
        r->r_commands = tarpit_commands;
        r->r_ncommands = sizeof(tarpit_commands) / sizeof(tarpit_commands[ 0 ]);
        simta_ucl_toggle(
                simta_config, "receive.data.content_filter", "enabled", false);
        break;
    case SMTP_MODE_TEMPFAIL:
        r->r_commands = tempfail_commands;
        r->r_ncommands =
                sizeof(tempfail_commands) / sizeof(tempfail_commands[ 0 ]);
        simta_ucl_toggle(
                simta_config, "receive.data.content_filter", "enabled", false);
        break;
    case SMTP_MODE_UNAUTHENTICATED:
        r->r_commands = unauth_commands;
        r->r_ncommands = sizeof(unauth_commands) / sizeof(unauth_commands[ 0 ]);
        break;
    default:
        r->r_commands = smtp_commands;
        r->r_ncommands = sizeof(smtp_commands) / sizeof(smtp_commands[ 0 ]);
        break;
    }
}


int
deliver_accepted(struct receive_data *r, int force) {
    struct envelope *e;
    struct host_q *  hq;
    struct timeval   tv_add;
    struct timeval   tv_now;

    if ((r->r_env) && (r->r_env->e_flags & ENV_FLAG_EFILE)) {
        queue_envelope(r->r_env);
        r->r_env = NULL;
    }

    /* FIXME: kludge to avoid a bad interaction with aggressive receipt */
    const char *jail_host = NULL;
    if (((jail_host = simta_config_str("deliver.jail.host")) != NULL) &&
            ((hq = host_q_lookup(jail_host)) != NULL)) {
        while ((e = hq->hq_env_head) != NULL) {
            queue_remove_envelope(e);
            env_move(e, simta_dir_slow);
            env_free(e);
        }
    }

    /* If the queue is empty we don't need to process it. */
    if ((simta_unexpanded_q == NULL) ||
            (simta_unexpanded_q->hq_env_head == NULL)) {
        return (RECEIVE_OK);
    }

    if (force ||
            (strcasecmp(simta_config_str("receive.queue.strategy"), "slow") ==
                    0) ||
            ((simta_config_int("receive.queue.aggression") > 0) &&
                    (simta_fast_files >=
                            simta_config_int("receive.queue.aggression")))) {
        if ((r->r_snet == NULL) && (simta_proc_stab == NULL)) {
            /* no connection and no outstanding children, run the queue */
            timerclear(&r->r_tv_accepted);
            if (q_runner() != 0) {
                return (RECEIVE_SYSERROR);
            }

        } else if (simta_q_runner_slow <
                   simta_config_int("receive.queue.max_runners")) {
            timerclear(&r->r_tv_accepted);
            if (simta_child_q_runner(simta_unexpanded_q) != 0) {
                statsd_counter("receive.q_runners", "errored", 1);
                return (RECEIVE_SYSERROR);
            }
            statsd_counter("receive.q_runners", "launched", 1);

            /* clean mailbag */
            while (simta_unexpanded_q->hq_env_head != NULL) {
                e = simta_unexpanded_q->hq_env_head;
                simta_debuglog(
                        3, "deliver_accepted: freeing env <%s>", e->e_id);
                simta_unexpanded_q->hq_env_head = e->e_next;
                env_free(e);
            }
            simta_unexpanded_q->hq_entries = 0;
            simta_fast_files = 0;

        } else {
            syslog(LOG_NOTICE,
                    "Receive [%s] %s: %d messages queued with no room for more "
                    "children, deferring launch",
                    r->r_ip, r->r_remote_hostname, simta_fast_files);
            statsd_counter("receive.q_runners", "deferred", 1);

            if (simta_gettimeofday(&tv_now) == SIMTA_OK) {
                simta_ucl_object_totimeval(
                        simta_config_obj("receive.queue.timer"), &tv_add);
                timeradd(&tv_now, &tv_add, &r->r_tv_accepted);
            }
        }
    }

    return (RECEIVE_OK);
}


int
reset(struct receive_data *r) {
    if (deliver_accepted(r, 0) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    if (r->r_env != NULL) {
        syslog(LOG_INFO, "Receive [%s] %s: env <%s>: Message Failed: Abandoned",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id);
        statsd_counter("receive.messages", "abandoned", 1);
        env_free(r->r_env);
        r->r_env = NULL;
    }

    if (r->r_dmarc) {
        dmarc_reset(r->r_dmarc);
    }

    return (RECEIVE_OK);
}


static int
hello(struct receive_data *r, char *hostname) {
    /* If they're saying hello again, we want the new value for the trace
     * field.
     */
    if (r->r_hello != NULL) {
        free(r->r_hello);
    }

    /*
     * RFC 5321 4.1.4 Order of Commands
     * An SMTP server MAY verify that the domain name argument in the EHLO
     * command actually corresponds to the IP address of the client. However,
     * if the verification fails, the server MUST NOT refuse to accept
     * a message on that basis.
     *
     * We don't verify.
     */

    r->r_hello = simta_strdup(hostname);
    return (RECEIVE_OK);
}


static void
tarpit_sleep(struct receive_data *r) {
    struct timespec t;

    if (r->r_smtp_mode != SMTP_MODE_TARPIT &&
            r->r_smtp_mode != SMTP_MODE_TEMPFAIL) {
        return;
    }

    simta_ucl_object_totimespec(simta_config_obj("receive.smtp.tarpit"), &t);

    if (nanosleep(&t, NULL) != 0) {
        syslog(LOG_ERR, "Syserror: tarpit_sleep nanosleep: %m");
    }
}


/*
 * SMTP Extensions RFC.
 */

static void
log_bad_syntax(struct receive_data *r) {
    statsd_counter("receive.smtp_commands", "badsyntax", 1);
    simta_debuglog(1, "Receive [%s] %s: Bad syntax: %s", r->r_ip,
            r->r_remote_hostname, r->r_smtp_command);
    return;
}


static int
smtp_write_banner(struct receive_data *r, int reply_code, const char *msg,
        const char *arg) {
    const char *boilerplate;
    int         ret = RECEIVE_OK;
    int         rc;
    int         hostname = 0;

    switch (reply_code) {
    case 211:
        hostname = 1;
        boilerplate = "simta";
        break;

    case 220:
        hostname = 1;
        boilerplate = "Simple Internet Message Transfer Agent ready";
        break;

    case 221:
        hostname = 1;
        ret = RECEIVE_CLOSECONNECTION;
        boilerplate = "Service closing transmission channel";
        break;

    case 235:
        boilerplate = "Authentication successful";
        break;

    case 250:
        boilerplate = "OK";
        break;

    case 334:
        boilerplate = "";
        break;

    case 354:
        boilerplate = "Start mail input; end with <CRLF>.<CRLF>";
        break;

    default:
        syslog(LOG_ERR,
                "Receive [%s] %s: "
                "smtp_write_banner: reply_code out of range: %d",
                r->r_ip, r->r_remote_hostname, reply_code);
        reply_code = 421;
        /* fall through to 421 */
    case 421:
        boilerplate = "Local error in processing: closing transmission channel";
        ret = RECEIVE_CLOSECONNECTION;
        hostname = 1;
        break;

    case 432:
        boilerplate = "A password transition is needed";
        break;

    case 451:
        boilerplate = "Local error in processing: requested action aborted";
        break;

    case 454:
        boilerplate = "Temporary authentication failure";
        break;

    case 500:
        boilerplate = "Command unrecognized";
        break;

    case 501:
        boilerplate = "Syntax error in parameters or arguments";
        break;

    case 502:
        boilerplate = "Command not implemented";
        break;

    case 503:
        boilerplate = "Bad sequence of commands";
        break;

    case 504:
        boilerplate = "Unrecognized authentication type";
        break;

    case 530:
        boilerplate = "Authentication required";
        break;

    case 534:
        boilerplate = "Authentication mechanism is too weak";
        break;

    case 535:
        boilerplate = "Authentication credentials invalid";
        break;

    case 538:
        boilerplate =
                "Encryption required for requested authentication "
                "mechanism";
        break;

    case 550:
        boilerplate = "Requested action failed";
        break;

    case 552:
        boilerplate = "Message exceeds fixed maximum message size";
        break;

    case 554:
        boilerplate = "Transaction failed";
        break;

    case 555:
        boilerplate = "Command parameter not recognized or not implemented";
        break;
    }

    if (hostname) {
        if (arg != NULL) {
            rc = snet_writef(r->r_snet, "%d %s %s: %s\r\n", reply_code,
                    simta_hostname, msg ? msg : boilerplate, arg);

        } else {
            rc = snet_writef(r->r_snet, "%d %s %s\r\n", reply_code,
                    simta_hostname, msg ? msg : boilerplate);
        }

    } else {
        if (arg != NULL) {
            rc = snet_writef(r->r_snet, "%d %s: %s\r\n", reply_code,
                    msg ? msg : boilerplate, arg);

        } else {
            rc = snet_writef(r->r_snet, "%d %s\r\n", reply_code,
                    msg ? msg : boilerplate);
        }
    }

    if (rc < 0) {
        syslog(LOG_ERR,
                "Receive [%s] %s: "
                "smtp_write_banner snet_writef failed: %m",
                r->r_ip, r->r_remote_hostname);
        return (RECEIVE_CLOSECONNECTION);
    }

    return (ret);
}


static int
f_helo(struct receive_data *r) {
    tarpit_sleep(r);

    if (r->r_ac != 2) {
        log_bad_syntax(r);
        return (smtp_write_banner(r, 501, NULL,
                "RFC 5321 section 4.1.1.1: \"HELO\" SP Domain CRLF"));
    }

    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    if (hello(r, r->r_av[ 1 ]) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    return (smtp_write_banner(r, 250, "Hello", r->r_av[ 1 ]));
}


static int
f_ehlo(struct receive_data *r) {
    yastr               buf = NULL;
    ucl_object_iter_t   iter = NULL;
    const ucl_object_t *obj;

    tarpit_sleep(r);

    /* RFC 5321 4.1.4 Order of Commands
     * A session that will contain mail transactions MUST first be
     * initialized by the use of the EHLO command.  An SMTP server SHOULD
     * accept commands for non-mail transactions (e.g., VRFY or EXPN)
     * without this initialization.
     */
    if (r->r_ac != 2) {
        log_bad_syntax(r);
        return smtp_write_banner(r, 501, NULL,
                "RFC 5321 section 4.1.1.1: \"EHLO\" SP Domain CRLF");
    }

    /* RFC 5321 4.1.4 Order of Commands
     * An EHLO command MAY be issued by a client later in the session.  If it
     * is issued after the session begins and the EHLO command is acceptable
     * to the SMTP server, the SMTP server MUST clear all buffers and reset
     * the state exactly as if a RSET command had been issued.  In other words,
     * the sequence of RSET followed immediately by EHLO is redundant, but not
     * harmful other than in the performance cost of executing unnecessary
     * commands.
     */
    if (reset(r) != RECEIVE_OK) {
        return RECEIVE_SYSERROR;
    }

    /* RFC 5321 2.3.5 Domain Names
     * The domain name given in the EHLO command MUST be either a primary host
     * name (a domain name that resolves to an address RR) or, if the host has
     * no name, an address literal as described in section 4.1.3 and discussed
     * further in in the EHLO discussion of Section 4.1.4.
     */

    if (hello(r, r->r_av[ 1 ]) != RECEIVE_OK) {
        return RECEIVE_SYSERROR;
    }

    if (snet_writef(r->r_snet, "%d-%s Hello %s\r\n", 250, simta_hostname,
                r->r_av[ 1 ]) < 0) {
        syslog(LOG_ERR, "Liberror: f_ehlo snet_writef: %m");
        return RECEIVE_CLOSECONNECTION;
    }

    iter = ucl_object_iterate_new(r->r_smtp_extensions);
    buf = yaslempty();
    obj = ucl_object_iterate_safe(iter, false);
    while (obj != NULL) {
        yaslclear(buf);
        buf = yaslcat(buf, ucl_object_key(obj));
        if (ucl_object_type(obj) != UCL_NULL) {
            buf = yaslcatprintf(buf, " %s", ucl_object_tostring_forced(obj));
        }
        obj = ucl_object_iterate_safe(iter, false);
        if (snet_writef(r->r_snet, "%d%s%s\r\n", 250, obj ? "-" : " ", buf) <
                0) {
            syslog(LOG_ERR, "Liberror: f_ehlo snet_writef: %m");
            return RECEIVE_CLOSECONNECTION;
        }
    }
    yaslfree(buf);
    ucl_object_iterate_free(iter);

    r->r_esmtp = 1;
    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    return RECEIVE_OK;
}


static int
f_mail_usage(struct receive_data *r) {
    log_bad_syntax(r);

    if (snet_writef(r->r_snet,
                "501-Syntax violates RFC 5321 section 4.1.1.2:\r\n"
                "501-     \"MAIL FROM:\" (\"<>\" / Reverse-Path ) "
                "[ SP Mail-parameters ] CRLF\r\n"
                "501-         Reverse-path = Path\r\n"
                "501          Path = \"<\" [ A-d-l \":\" ] Mailbox \">\"\r\n") <
            0) {
        syslog(LOG_ERR, "Syserror: f_mail_usage snet_writef: %m");
        return (RECEIVE_CLOSECONNECTION);
    }

    if (deliver_accepted(r, 0) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    return (RECEIVE_OK);
}


static int
f_mail(struct receive_data *r) {
    int                 rc;
    int                 i;
    int                 parameters;
    int                 seen_extensions = 0;
    int                 eightbit = 0;
    long int            message_size;
    char *              addr;
    char *              domain;
    char *              endptr;
    struct dnsl_result *dnsl_result;

    r->r_mail_attempt++;

    syslog(LOG_INFO, "Receive [%s] %s: start of mail transaction", r->r_ip,
            r->r_remote_hostname);

    tarpit_sleep(r);

    if (r->r_ac < 2) {
        return (f_mail_usage(r));
    }

    if ((r->r_ac >= 3) && (strcasecmp(r->r_av[ 1 ], "FROM:") == 0)) {
        /* Incorrect, but people are bad at standards: "MAIL FROM: <foo>" */
        if (parse_emailaddr(RFC_821_MAIL_FROM, r->r_av[ 2 ], &addr, &domain) !=
                0) {
            return (f_mail_usage(r));
        }
        parameters = 3;

    } else {
        if (strncasecmp(r->r_av[ 1 ], "FROM:", strlen("FROM:")) != 0) {
            return (f_mail_usage(r));
        }

        /* Correct: "MAIL FROM:<foo>" */
        if (parse_emailaddr(RFC_821_MAIL_FROM, r->r_av[ 1 ] + strlen("FROM:"),
                    &addr, &domain) != 0) {
            return (f_mail_usage(r));
        }
        parameters = 2;
    }

    for (i = parameters; i < r->r_ac; i++) {
        if (strncasecmp(r->r_av[ i ], "SIZE", strlen("SIZE")) == 0) {
            /* RFC 1870 Message Size Declaration */
            if (seen_extensions & SIMTA_EXTENSION_SIZE) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: "
                        "duplicate SIZE specified: %s",
                        r->r_ip, r->r_remote_hostname, r->r_smtp_command);
                return (smtp_write_banner(
                        r, 501, NULL, "duplicate SIZE specified"));
            } else {
                seen_extensions = seen_extensions | SIMTA_EXTENSION_SIZE;
            }

            if (strncasecmp(r->r_av[ i ], "SIZE=", strlen("SIZE=")) != 0) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: "
                        "invalid SIZE parameter: %s",
                        r->r_ip, r->r_remote_hostname, r->r_smtp_command);
                return (smtp_write_banner(
                        r, 501, NULL, "invalid SIZE command"));
            }

            message_size = strtol(r->r_av[ i ] + strlen("SIZE="), &endptr, 10);

            if ((*(r->r_av[ i ] + strlen("SIZE=")) == '\0') ||
                    (*endptr != '\0') || (message_size == LONG_MIN) ||
                    (message_size == LONG_MAX) || (message_size < 0)) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: "
                        "invalid SIZE parameter: %s",
                        r->r_ip, r->r_remote_hostname, r->r_smtp_command);
                return (smtp_write_banner(r, 501,
                        "Syntax Error: invalid SIZE parameter",
                        r->r_av[ i ] + strlen("SIZE=")));
            }

            if (message_size >
                    simta_config_int("receive.data.limits.message_size")) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: "
                        "message SIZE too large: %s",
                        r->r_ip, r->r_remote_hostname, r->r_smtp_command);
                return (smtp_write_banner(r, 552, NULL, NULL));
            }

            /* RFC 4954 5 The AUTH Parameter to the MAIL FROM command
         *
         * If the server trusts the authenticated identity of the client to
         * assert that the message was originally submitted by the supplied
         * <mailbox>, then the server SHOULD supply the same <mailbox> in an
         * AUTH parameter when relaying the message to any other server which
         * supports the AUTH extension.
         *
         * For this reason, servers that advertise support for this extension
         * MUST support the AUTH parameter to the MAIL FROM command even when
         * the client has not authenticated itself to the server.
         *
         * [...]
         *
         * Note that an implementation which is hard-coded to treat all clients
         * as being insufficiently trusted is compliant with this specification.
         * In that case, the implementation does nothing more than parse and
         * discard syntactically valid AUTH parameters to the MAIL FROM command,
         * and supply AUTH=<> parameters to any servers that it authenticates
         * to.
         */
        } else if (strncasecmp(r->r_av[ i ], "AUTH=", strlen("AUTH=")) == 0) {
            syslog(LOG_INFO, "Receive [%s] %s: claimed %s", r->r_ip,
                    r->r_remote_hostname, r->r_av[ i ]);

            /* RFC 6152 2 Framework for the 8-bit MIME Transport Extension
         *
         * one optional parameter using the keyword BODY is added to the
         * MAIL command.  The value associated with this parameter is a
         * keyword indicating whether a 7-bit message (in strict compliance
         * with [RFC5321]) or a MIME message (in strict compliance with
         * [RFC2046] and [RFC2045]) with arbitrary octet content is being
         * sent.  The syntax of the value is as follows, using the ABNF
         * notation of [RFC5234]:
         *
         * body-value = "7BIT" / "8BITMIME"
         */
        } else if (strncasecmp(r->r_av[ i ], "BODY=", strlen("BODY=")) == 0) {
            if (seen_extensions & SIMTA_EXTENSION_8BITMIME) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: "
                        "duplicate BODY specified: %s",
                        r->r_ip, r->r_remote_hostname, r->r_smtp_command);
                return (smtp_write_banner(
                        r, 501, NULL, "duplicate BODY specified"));
            } else {
                seen_extensions = seen_extensions | SIMTA_EXTENSION_8BITMIME;
            }

            if (strncasecmp(r->r_av[ i ] + strlen("BODY="), "8BITMIME",
                        strlen("8BITMIME")) == 0) {
                eightbit = 1;
            } else if (strncasecmp(r->r_av[ i ] + strlen("BODY="), "7BIT",
                               strlen("7BIT")) != 0) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: "
                        "unrecognized BODY value: %s",
                        r->r_ip, r->r_remote_hostname, r->r_smtp_command);
                return (smtp_write_banner(r, 501,
                        "Syntax Error: invalid BODY parameter",
                        r->r_av[ i ] + strlen("BODY=")));
            }

        } else {
            syslog(LOG_INFO,
                    "Receive [%s] %s: "
                    "unsupported SMTP extension: %s",
                    r->r_ip, r->r_remote_hostname, r->r_smtp_command);

            return smtp_write_banner(r, 555, NULL, r->r_av[ i ]);
        }
    }

    /* We have a maximum of 5 minutes (RFC 5321 4.5.3.2.2) before we must
     * return something to a "MAIL" command.  Soft failures can either be
     * accepted (trusted) or the soft failures can be passed along. "451"
     * is probably the correct error.
     */

    if (*addr != '\0') {
        if ((dnsl_result = dnsl_check(
                     "receive.mail_from.dns_list", NULL, addr)) != NULL) {
            if (strcmp(dnsl_result->dnsl_action, "block") == 0) {
                syslog(LOG_NOTICE,
                        "Receive [%s] %s: From <%s>: "
                        "DNS list %s: Blocked: %s (%s)",
                        r->r_ip, r->r_remote_hostname, addr,
                        dnsl_result->dnsl_list, dnsl_result->dnsl_result,
                        dnsl_result->dnsl_reason);
                rc = smtp_write_banner(r, 550, dnsl_result->dnsl_reason, addr);
                dnsl_result_free(dnsl_result);
                return (rc);
            }
            dnsl_result_free(dnsl_result);
        }
    }

    if ((domain != NULL) &&
            (strcasecmp(simta_config_str("receive.smtp.mode"), "MSA") != 0)) {
        rc = check_hostname(domain);

        if (rc < 0) {
            syslog(LOG_ERR,
                    "Receive [%s] %s: From <%s>: check_hostname %s: failed",
                    r->r_ip, r->r_remote_hostname, addr, domain);
            return (smtp_write_banner(r, 451, NULL, NULL));
        } else if (rc > 0) {
            syslog(LOG_NOTICE, "Receive [%s] %s: From <%s>: Unknown host: %s",
                    r->r_ip, r->r_remote_hostname, addr, domain);
            return (smtp_write_banner(r, 550, S_UNKNOWN_HOST, domain));
        }
    }

    /*
     * RFC 5321 4.1.4 Order of Commands
     * MAIL (or SEND, SOML, or SAML) MUST NOT be sent if a mail transaction
     * is already open, i.e., it should be sent only if no mail transaction
     * had been started in the session, or if the previous one successfully
     * concluded with a successful DATA command, or if the previous one was
     * aborted, e.g., with a RSET or new EHLO.
     *
     * This restriction is not adhered to in practice, so we treat it like a
     * RSET.
     */
    if (reset(r) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    if ((r->r_env = env_create(simta_dir_fast, NULL, addr, NULL)) == NULL) {
        return (RECEIVE_SYSERROR);
    }

    if (eightbit) {
        r->r_env->e_8bitmime = true;
    }

#ifdef HAVE_LIBOPENDKIM
    if (simta_config_bool("deliver.dkim.enabled") &&
            simta_config_bool("receive.dkim.sign")) {
        r->r_env->e_flags |= ENV_FLAG_DKIMSIGN;
    }
#endif /* HAVE_LIBOPENDKIM */

#ifdef HAVE_LIBSSL
    if (simta_config_bool("receive.data.checksum.enabled")) {
        md_reset(&r->r_md, simta_config_str("receive.data.checksum.algorithm"));
    }
#endif /* HAVE_LIBSSL */

    if (simta_config_bool("receive.spf.enabled")) {
        spf_free(r->r_spf);
        r->r_spf = spf_lookup(r->r_hello, addr, r->r_sa);
        syslog(LOG_INFO, "Receive [%s] %s: env <%s>: From <%s>: SPF result: %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                spf_result_str(r->r_spf->spf_result));
        switch (r->r_spf->spf_result) {
        case SPF_RESULT_TEMPERROR:
            if (simta_config_bool("receive.spf.strict") ||
                    simta_config_bool("receive.dmarc.strict")) {
                syslog(LOG_ERR,
                        "Receive [%s] %s: env <%s>: From <%s>: "
                        "SPF Tempfailed: transient SPF lookup failure",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr);
                if (reset(r) != RECEIVE_OK) {
                    return (RECEIVE_SYSERROR);
                }
                return (smtp_write_banner(r, 451, NULL, NULL));
            }
            break;
        case SPF_RESULT_FAIL:
            if (simta_config_bool("receive.spf.strict")) {
                syslog(LOG_ERR,
                        "Receive [%s] %s: env <%s>: From <%s>: SPF reject",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr);
                if (reset(r) != RECEIVE_OK) {
                    return (RECEIVE_SYSERROR);
                }
                return (smtp_write_banner(
                        r, 554, "Rejected by local policy (SPF fail)", NULL));
            }
            break;
        case SPF_RESULT_PASS:
            if (r->r_dmarc) {
                dmarc_spf_result(r->r_dmarc, r->r_spf->spf_domain);
            }
            break;
        }
    }

    syslog(LOG_NOTICE, "Receive [%s] %s: env <%s>: From <%s>: Accepted",
            r->r_ip, r->r_remote_hostname, r->r_env->e_id, r->r_env->e_mail);

    if ((rc = srs_forward(r->r_env)) != SRS_OK) {
        syslog(LOG_ERR, "Liberror: f_mail srs_forward: failed: %d", rc);
        return (smtp_write_banner(r, 451, NULL, NULL));
    } else if (r->r_env->e_mail_orig != NULL) {
        syslog(LOG_NOTICE,
                "Receive [%s] %s: env <%s>: "
                "Rewrote RFC5321.MailFrom to <%s>",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                r->r_env->e_mail);
    }
    r->r_mail_success++;

    r->r_tv_inactivity.tv_sec = 0;
    return (smtp_write_banner(r, 250, NULL, NULL));
}


static int
f_rcpt_usage(struct receive_data *r) {
    log_bad_syntax(r);

    if (snet_writef(r->r_snet,
                "501-Syntax violates RFC 5321 section 4.1.1.3:\r\n"
                "501-     \"RCPT TO:\" (\"<Postmaster@\" domain \">\" / "
                "\"<Postmaster>\" / Forward-Path ) "
                "[ SP Rcpt-parameters ] CRLF\r\n"
                "501-         Forward-path = Path\r\n"
                "501          Path = \"<\" [ A-d-l \":\" ] Mailbox \">\"\r\n") <
            0) {
        syslog(LOG_ERR, "Syserror: f_rcpt_usage snet_writef: %m");
        return (RECEIVE_CLOSECONNECTION);
    }
    return (RECEIVE_OK);
}


static int
f_rcpt(struct receive_data *r) {
    int                 rc;
    int                 parameters;
    char *              addr;
    char *              domain;
    const ucl_object_t *red;

    r->r_rcpt_attempt++;

    tarpit_sleep(r);

    /* Must already have "MAIL FROM:", and no valid message */
    if ((r->r_env == NULL) || ((r->r_env->e_flags & ENV_FLAG_EFILE) != 0)) {
        return (f_bad_sequence(r));
    }

    if (r->r_ac < 2) {
        return f_rcpt_usage(r);
    }

    if ((r->r_ac >= 3) && (strcasecmp(r->r_av[ 1 ], "TO:") == 0)) {
        /* Technically incorrect: "RCPT TO: <foo>" */
        if (parse_emailaddr(RFC_821_RCPT_TO, r->r_av[ 2 ], &addr, &domain) !=
                0) {
            return f_rcpt_usage(r);
        }

        parameters = 3;

    } else {
        if (strncasecmp(r->r_av[ 1 ], "TO:", strlen("TO:")) != 0) {
            return (f_mail_usage(r));
        }

        /* Correct: "RCPT TO:<foo>" */
        if (parse_emailaddr(RFC_821_RCPT_TO, r->r_av[ 1 ] + strlen("TO:"),
                    &addr, &domain) != 0) {
            return f_rcpt_usage(r);
        }

        parameters = 2;
    }

    /* We do not currently implement any RCPT parameters */
    if (parameters < r->r_ac) {
        syslog(LOG_INFO,
                "Receive [%s] %s: "
                "unsupported SMTP extension: %s",
                r->r_ip, r->r_remote_hostname, r->r_smtp_command);

        return smtp_write_banner(r, 555, NULL, r->r_av[ parameters ]);
    }

    /* RFC 5321 3.6.1 Source Routes and Relaying
     * SMTP servers MAY decline to act as mail relays or to accept addresses
     * that specify source routes.  When route information is encountered,
     * SMTP servers MAY ignore the route information and simply send to the
     * final destination specified as the last element in the route and
     * SHOULD do so.
     */

    /*
     * We're not currently going to parse for the "%-hack".  This sort
     * of relay is heavily discouraged due to SPAM abuses.
     */

    /*
     * Again, soft failures can either be accepted (trusted) or the soft
     * failures can be passed along.  "451" is probably the correct soft
     * error.
     */


    if (domain && (r->r_smtp_mode == SMTP_MODE_NORMAL)) {
        /*
         * Here we do an initial lookup in our domain table.  This is
         * our best opportunity to decline recipients that are not
         * local or unknown, since if we give an error the connecting
         * client generates the bounce.
         */
        if ((rc = check_hostname(domain)) != 0) {
            if (rc < 0) {
#ifdef HAVE_LIBSSL
                if (simta_config_bool("receive.data.checksum.enabled")) {
                    md_update(&r->r_md, addr, strlen(addr));
                }
#endif /* HAVE_LIBSSL */
                syslog(LOG_ERR,
                        "Receive [%s] %s: env <%s>: "
                        "To <%s> From <%s>: Tempfailed: "
                        "check_hostname %s failed",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                        r->r_env->e_mail, domain);
                return (smtp_write_banner(r, 451, NULL, NULL));
            }

            syslog(LOG_INFO,
                    "Receive [%s] %s: env <%s>: "
                    "To <%s> From <%s>: Failed: Unknown domain",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                    r->r_env->e_mail);

            return (smtp_write_banner(r, 550, S_UNKNOWN_HOST, domain));
        }

        if (((red = red_host_lookup(domain, false)) == NULL)) {
            if (r->r_smtp_mode == SMTP_MODE_NORMAL) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: env <%s>: "
                        "To <%s> From <%s>: Failed: Domain not local",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                        r->r_env->e_mail);
                if (snet_writef(r->r_snet,
                            "551 User not local to <%s>: please try <%s>\r\n",
                            simta_hostname, domain) < 0) {
                    syslog(LOG_ERR, "Syserror: f_rcpt snet_writef: %m");
                    return (RECEIVE_CLOSECONNECTION);
                }
                return (RECEIVE_OK);
            }

        } else {
            /*
             * For local mail, we now have 5 minutes (RFC 5321 4.5.3.2.3)
             * to decline to receive the message.  If we're in the
             * default configuration, we check the passwd and alias file.
             * Other configurations use "mailer" specific checks.
             */

            /* RFC 5321 section 3.6.2 Mail eXchange Records and Relaying
             * A relay SMTP server is usually the target of a DNS MX record
             * that designates it, rather than the final delivery system.
             * The relay server may accept or reject the task of relaying
             * the mail in the same way it accepts or rejects mail for
             * a local user.  If it accepts the task, it then becomes an
             * SMTP client, establishes a transmission channel to the next
             * SMTP server specified in the DNS (according to the rules
             * in section 5), and sends it the mail.  If it declines to
             * relay mail to a particular address for policy reasons, a 550
             * response SHOULD be returned.
             */

            switch (local_address(addr, domain, red)) {
            case ADDRESS_NOT_FOUND:
                syslog(LOG_INFO,
                        "Receive [%s] %s: env <%s>: "
                        "To <%s> From <%s>: Failed: User not local",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                        r->r_env->e_mail);
                return (smtp_write_banner(r, 550, NULL, "User not found"));

            case ADDRESS_SYSERROR:
                syslog(LOG_ERR,
                        "Receive [%s] %s: env <%s>: local_address %s: failed",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr);

#ifdef HAVE_LIBSSL
                if (simta_config_bool("receive.data.checksum.enabled")) {
                    md_update(&r->r_md, addr, strlen(addr));
                }
#endif /* HAVE_LIBSSL */

                return (smtp_write_banner(r, 451, NULL, NULL));

            case ADDRESS_OK:
                if (!r->r_dnsl_checked) {
                    r->r_dnsl_result = dnsl_check(
                            "receive.rcpt_to.dns_list", r->r_sa, NULL);
                    r->r_dnsl_checked = 1;
                }

                if (r->r_dnsl_result == NULL) {
                    syslog(LOG_INFO,
                            "Receive [%s] %s: env <%s>: "
                            "To <%s> From <%s>: "
                            "not found on any DNS lists in the 'user' chain",
                            r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                            r->r_env->e_mail);
                    break;
                }

                if (strcmp(r->r_dnsl_result->dnsl_action, "block") == 0) {
                    syslog(LOG_NOTICE,
                            "Receive [%s] %s: env <%s>: "
                            "To <%s> From <%s>: DNS list %s: Blocked: %s (%s)",
                            r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                            r->r_env->e_mail, r->r_dnsl_result->dnsl_list,
                            r->r_dnsl_result->dnsl_result,
                            r->r_dnsl_result->dnsl_reason);
                    if (snet_writef(r->r_snet, "550 <%s> %s %s: %s: %s\r\n",
                                simta_hostname, S_DENIED, r->r_ip,
                                r->r_dnsl_result->dnsl_list,
                                r->r_dnsl_result->dnsl_reason) < 0) {
                        syslog(LOG_ERR,
                                "Receive [%s] %s: env <%s>: "
                                "f_rcpt snet_writef: %m",
                                r->r_ip, r->r_remote_hostname, r->r_env->e_id);
                        return RECEIVE_CLOSECONNECTION;
                    }
                    return RECEIVE_OK;
                } else if ((strcmp(r->r_dnsl_result->dnsl_action, "accept") ==
                                   0) ||
                           (strcmp(r->r_dnsl_result->dnsl_action, "trust") ==
                                   0)) {
                    syslog(LOG_INFO,
                            "Receive [%s] %s: env <%s>: "
                            "To <%s> From <%s>: DNS list %s: Accepted: %s (%s)",
                            r->r_ip, r->r_remote_hostname, r->r_env->e_id, addr,
                            r->r_env->e_mail, r->r_dnsl_result->dnsl_list,
                            r->r_dnsl_result->dnsl_result,
                            r->r_dnsl_result->dnsl_reason);
                    break;
                }
                break;

            case ADDRESS_OK_SPAM:
                break;

            default:
                panic("f_rcpt local_address return out of range");
            }
        }
    }

    if (env_recipient(r->r_env, addr) != 0) {
        return (RECEIVE_SYSERROR);
    }

    r->r_rcpt_success++;
    syslog(LOG_NOTICE, "Receive [%s] %s: env <%s>: To <%s> From <%s>: Accepted",
            r->r_ip, r->r_remote_hostname, r->r_env->e_id,
            r->r_env->e_rcpt->r_rcpt, r->r_env->e_mail);

#ifdef HAVE_LIBSSL
    if (simta_config_bool("receive.data.checksum.enabled")) {
        md_update(&r->r_md, addr, strlen(addr));
    }
#endif /* HAVE_LIBSSL */

    r->r_tv_inactivity.tv_sec = 0;
    return (smtp_write_banner(r, 250, NULL, NULL));
}


static int
f_data(struct receive_data *r) {
    FILE *                  dff = NULL;
    int                     calculate_timers = 1;
    int                     banner = 0;
    int                     dfile_fd = -1;
    int                     ret_code = RECEIVE_SYSERROR;
    int                     rc;
    int                     header_only = 0;
    int                     header = 1;
    int                     line_no = 0;
    int                     filter_result = MESSAGE_TEMPFAIL;
    int                     f_result;
    int                     read_err = NO_ERROR;
    size_t                  line_len;
    char *                  line;
    char *                  msg;
    const char *            jail_host = NULL;
    const char *            failure_message = NULL;
    char *                  filter_message = NULL;
    const char *            system_message = NULL;
    const char *            timer_type = NULL;
    const char *            session_timer = NULL;
    struct timeval *        tv_session = NULL;
    struct timeval          tv_data_session;
    struct timeval          tv_wait;
    struct timeval *        tv_timeout = NULL;
    struct timeval          tv_line;
    struct timeval          tv_add = {0, 0};
    struct timeval          tv_filter = {0, 0};
    struct timeval          tv_now = {0, 0};
    char                    daytime[ RFC822_TIMESTAMP_LEN ];
    struct receive_headers *rh = NULL;
    unsigned int            data_wrote = 0;
    unsigned int            data_read = 0;
    struct envelope *       env_bounce;
    struct dnsl_result *    dnsl_result = NULL;
    yastr                   authresults = NULL;
    yastr                   authresults_tmp = NULL;
    int          authresults_plain = !simta_config_bool("receive.arc.enabled");
    yastr        with = NULL;
    struct line *l;
    yastr        dkim_buf = NULL;
    int          dkim_body_started = 0;
#ifdef HAVE_LIBOPENARC
    ARC_MESSAGE *        arc = NULL;
    ARC_STAT             arc_result = ARC_STAT_INTERNAL;
    ARC_HDRFIELD *       arc_seal = NULL;
    yastr                arc_key = NULL;
    const char *         arc_err;
    const unsigned char *arc_err_unsigned;
    yastr                arc_authservid = NULL;
    yastr                arc_selector = NULL;
    yastr                arc_domain = NULL;
#endif /* HAVE_LIBOPENARC */
#ifdef HAVE_LIBOPENDKIM
    int            i;
    DKIM *         dkim = NULL;
    DKIM_STAT      dkim_result;
    DKIM_SIGINFO **dkim_sigs;
    DKIM_SIGERROR  dkim_error;
    char *         dkim_domain = NULL;
    char *         dkim_selector = NULL;
#endif /* HAVE_LIBOPENDKIM */

    r->r_data_attempt++;

    tarpit_sleep(r);

    /* RFC 5321 4.1.1 Command Semantics and Syntax
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */
    if (r->r_ac != 1) {
        log_bad_syntax(r);
        return (smtp_write_banner(
                r, 501, NULL, "RFC 5321 section 4.1.1.4 \"DATA\" CRLF"));
    }

    /* RFC 5321 3.3
     * If there was no MAIL, or no RCPT, command, or all such commands
     * were rejected, the server MAY return a "command out of sequence"
     * (503) or "no valid recipients" (554) reply in response to the DATA
     * command.
     *
     * Also note that having already accepted a message is bad.
     * A previous reset is also not a good thing.
     */
    if ((r->r_env == NULL) || ((r->r_env->e_flags & ENV_FLAG_EFILE) != 0)) {
        return (f_bad_sequence(r));
    }

    if ((r->r_smtp_mode == SMTP_MODE_TEMPFAIL) ||
            (r->r_smtp_mode == SMTP_MODE_TARPIT)) {
        /* Read the data and discard it */
        read_err = PROTOCOL_ERROR;
    } else {
        if (r->r_env->e_rcpt == NULL) {
            return (smtp_write_banner(r, 554, NULL, "No valid recipients"));
        }

        if ((dfile_fd = env_dfile_open(r->r_env)) < 0) {
            return (-1);
        }

        if ((dff = fdopen(dfile_fd, "w")) == NULL) {
            syslog(LOG_ERR, "Syserror: f_data fdopen: %m");
            if (close(dfile_fd) != 0) {
                syslog(LOG_ERR, "Syserror: f_data close: %m");
            }
            goto error;
        }
        rh = simta_calloc(1, sizeof(struct receive_headers));
        rh->r_env = r->r_env;

        if (simta_config_bool("receive.auth.results.enabled")) {
            /* RFC 7601 3 The "iprev" Authentication Method
             * "iprev" is an attempt to verify that a client appears to be valid
             * based on some DNS queries, which is to say that the IP address is
             * explicitly associated with a domain name.  Upon receiving a
             * session initiation of some kind from a client, the IP address of
             * the client peer is queried for matching names (i.e., a
             * number-to-name translation, also known as a "reverse lookup" or a
             * "PTR" record query).  Once that result is acquired, a lookup of
             * each of the names (i.e., a name-to-number translation, or an "A"
             * or "AAAA" record query) thus retrieved is done. The response to
             * this second check will typically result in at least one mapping
             * back to the client's IP address.
             */
            authresults = yaslcatprintf(yaslempty(),
                    "\n\tiprev=%s policy.iprev=%s (%s)",
                    iprev_authresult_str(r), r->r_ip, r->r_remote_hostname);

            /* RFC 7601 2.7.4 SMTP AUTH
             * SMTP AUTH (defined in [AUTH]) is represented by the "auth" method
             * Its result values are as follows:
             * [...]
             * pass: The SMTP client authenticated to the server reporting the
             * result using the protocol described in [AUTH].
             *
             * [...]
             * The result of AUTH is reported using a ptype of "smtp" and a
             * property of either:
             *
             * o "auth", in which case the value is the authorization identity
             *   generated by the exchange initiated by the AUTH command; or
             *
             * o "mailfrom", in which case the value is the mailbox identified
             *   by the AUTH parameter used with the MAIL FROM command.
             */
            /* We discard the AUTH parameter to MAIL FROM and (when enabled)
             * require auth to send mail, so we only need to include this method
             * if there is a successful auth.
             */
            if (r->r_auth_id) {
                authresults = yaslcatprintf(authresults,
                        ";\n\tauth=pass smtp.auth=%s", r->r_auth_id);
            }

            if (r->r_spf) {
                authresults = yaslcatprintf(authresults,
                        ";\n\tspf=%s smtp.mailfrom=%s@%s",
                        spf_result_str(r->r_spf->spf_result),
                        r->r_spf->spf_localpart, r->r_spf->spf_domain);
            }
        }

        if (simta_config_bool("receive.dkim.enabled") ||
                simta_config_bool("receive.arc.enabled")) {
            dkim_buf = yaslempty();
        }

#ifdef HAVE_LIBOPENARC
        if (simta_config_bool("receive.arc.enabled")) {
            if ((arc = arc_message(r->r_arc, ARC_CANON_RELAXED,
                         ARC_CANON_RELAXED, ARC_SIGN_RSASHA256,
                         ARC_MODE_SIGN | ARC_MODE_VERIFY, &arc_err_unsigned)) ==
                    NULL) {
                syslog(LOG_ERR, "Liberror: f_data arc_message: %s",
                        arc_err_unsigned);
            }
        }
#endif /* HAVE_LIBOPENARC */

#ifdef HAVE_LIBOPENDKIM
        if (simta_config_bool("receive.dkim.enabled")) {
            if ((dkim = dkim_verify(r->r_dkim,
                         (unsigned char *)(r->r_env->e_id), NULL,
                         &dkim_result)) == NULL) {
                syslog(LOG_ERR, "Liberror: f_data dkim_verify: %s",
                        dkim_getresultstr(dkim_result));
                goto error;
            }
        }
#endif /* HAVE_LIBOPENDKIM */

        if (rfc822_timestamp(daytime) != 0) {
            goto error;
        }

        /*
         * At this point, we must have decided what we'll put in the Received:
         * header, since that is the first line in the file.  This is where
         * we might want to put the sender's domain name, if we obtained one.
         */
        /* RFC 5321 4.4 Trace Information
         * Time-stamp-line = "Received:" FWS Stamp <CRLF>
         * Stamp = From-domain By-domain Opt-info [CFWS] ";"
         *         FWS date-time
         * From-domain = "FROM" FWS Extended-Domain
         * By-domain = CFWS "BY" FWS Extended-Domain
         * Extended-Domain = Domain /
         *     ( Domain FWS "(" TCP-info ")" ) /
         *     ( Address-literal FWS "(" TCP-info ")" )
         * TCP-info = Address-literal / ( Domain FWS Address-literal )
         * Opt-info = [Via] [With] [ID] [For]
         *            [Additional-Registered-Clauses]
         * With = CFWS "WITH" FWS Protocol
         * ID = CFWS "ID" FWS ( Atom / msg-id )
         * Protocol = "ESMTP" / "SMTP" / Attdl-Protocol
         */

        if (r->r_esmtp) {
            with = yaslauto("ESMTP");

            if (r->r_tls) {
                with = yaslcat(with, "S");
            }
            if (r->r_auth) {
                with = yaslcat(with, "A");
            }
        } else {
            with = yaslauto("SMTP");
        }

        if (fprintf(dff,
                    "Received: from %s (%s [%s])\n"
                    "\tby %s with %s\n"
                    "\tid %s;\n"
                    "\t%s\n",
                    (r->r_hello == NULL) ? "NULL" : r->r_hello,
                    r->r_remote_hostname, r->r_ip, simta_hostname, with,
                    r->r_env->e_id, daytime) < 0) {
            syslog(LOG_ERR, "Syserror: f_data fprintf: %m");
            goto error;
        }
    }

    r->r_tv_inactivity.tv_sec = 0;

    if (smtp_write_banner(r, 354, NULL, NULL) != RECEIVE_OK) {
        ret_code = RECEIVE_CLOSECONNECTION;
        goto error;
    }

    if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
        goto error;
    }

    /* global smtp session timer */
    if (r->r_tv_session.tv_sec != 0) {
        session_timer = S_GLOBAL_SESSION;
        tv_session = &r->r_tv_session;
    }

    /* smtp data session timer */
    simta_ucl_object_totimeval(
            simta_config_obj("receive.timeout.data"), &tv_add);
    timeradd(&tv_add, &tv_now, &tv_data_session);
    if ((tv_session == NULL) || (timercmp(&tv_data_session, tv_session, <))) {
        session_timer = S_DATA_SESSION;
        tv_session = &tv_data_session;
    }

    for (;;) {
        if (simta_child_signal != 0) {
            if (simta_waitpid(0, NULL, WNOHANG) != 0) {
                goto error;
            }
        }

        if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
            read_err = SYSTEM_ERROR;
        }

        if (calculate_timers == 0) {
            calculate_timers = 1;
        } else {
            simta_ucl_object_totimeval(
                    simta_config_obj("receive.timeout.data_line"), &tv_add);
            timeradd(&tv_add, &tv_now, &tv_line);

            /* use the session timer or the line timer */
            if ((session_timer != NULL) &&
                    (timercmp(tv_session, &tv_line, <))) {
                tv_timeout = tv_session;
                timer_type = session_timer;
            } else {
                tv_timeout = &tv_line;
                timer_type = S_DATA_LINE;
            }
        }

        if (timercmp(&tv_now, tv_timeout, >)) {
            syslog(LOG_NOTICE, "Receive [%s] %s: env <%s>: Data: Timeout %s",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id, timer_type);
            smtp_write_banner(r, 421, S_TIMEOUT, S_CLOSING);
            ret_code = RECEIVE_CLOSECONNECTION;
            goto error;
        }

        timersub(tv_timeout, &tv_now, &tv_wait);

        if ((line = snet_getline(r->r_snet, &tv_wait)) == NULL) {
            if ((errno == EINTR) || (errno == ETIMEDOUT)) {
                calculate_timers = 0;
                continue;
            }

            syslog(LOG_INFO,
                    "Receive [%s] %s: env <%s>: Data: connection dropped",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id);
            goto error;
        }

        line_no++;
        line_len = strlen(line);
        data_read += line_len + 2;

        if (*line == '.') {
            if (strcmp(line, ".") == 0) {
                if ((read_err == NO_ERROR) && (header == 1)) {
                    if (line_no == 1) {
                        syslog(LOG_INFO,
                                "Receive [%s] %s: env <%s>: empty message",
                                r->r_ip, r->r_remote_hostname, r->r_env->e_id);
                        system_message = "No mail data";
                        filter_result = MESSAGE_REJECT;
                        read_err = PROTOCOL_ERROR;
                        break;
                    }
                    header_only = 1;
                } else {
                    break;
                }
            }
            line++;
            line_len--;
        }

        if ((read_err == NO_ERROR) && (header == 1)) {
            msg = NULL;
            if ((f_result = header_text(line_no, line, rh, &msg)) == 0) {
                if (msg != NULL) {
                    simta_debuglog(1, "Receive [%s] %s: env <%s>: %s", r->r_ip,
                            r->r_remote_hostname, r->r_env->e_id, msg);
                }
            } else if (f_result < 0) {
                read_err = SYSTEM_ERROR;
            } else if ((line_no == 1) &&
                       (strcasecmp(simta_config_str("receive.smtp.mode"),
                                "MSA") != 0)) {
                /* Continue reading lines, but reject the message */
                syslog(LOG_INFO,
                        "Receive [%s] %s: env <%s>: no message headers",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id);
                system_message = "Message is not RFC 5322 compliant";
                filter_result = MESSAGE_REJECT;
                read_err = PROTOCOL_ERROR;
                header = 0;
            } else {
                header = 0;
                r->r_bad_headers = 0;
                /* Check and (maybe) correct headers */
                if ((rc = header_check(rh, false,
                             (strcasecmp(simta_config_str("receive.smtp.mode"),
                                      "MSA") == 0),
                             false)) < 0) {
                    ret_code = RECEIVE_CLOSECONNECTION;
                    goto error;
                } else if (rc > 0) {
                    syslog(LOG_INFO,
                            "Receive [%s] %s: env <%s>: "
                            "header_check failed",
                            r->r_ip, r->r_remote_hostname, r->r_env->e_id);
                    if (strcasecmp(simta_config_str("receive.smtp.mode"),
                                "strict") == 0) {
                        /* Continue reading lines, but reject the message */
                        system_message = "Message is not RFC 5322 compliant";
                        filter_result = MESSAGE_REJECT;
                        read_err = PROTOCOL_ERROR;
                    }
                    r->r_bad_headers = 1;
                }

                if (r->r_env->e_header_from) {
                    syslog(LOG_INFO,
                            "Receive [%s] %s: env <%s>: RFC5322.From: %s",
                            r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                            r->r_env->e_header_from);
                    if (r->r_dmarc) {
                        dmarc_lookup(r->r_dmarc,
                                strrchr(r->r_env->e_header_from, '@') + 1);
                    }
                    if ((read_err == NO_ERROR) &&
                            (strcasecmp(r->r_env->e_header_from,
                                     r->r_env->e_mail_orig
                                             ? r->r_env->e_mail_orig
                                             : r->r_env->e_mail) != 0)) {
                        if ((dnsl_result = dnsl_check(
                                     "receive.mail_from.dns_list", NULL,
                                     r->r_env->e_header_from)) != NULL) {
                            if (strcmp(dnsl_result->dnsl_action, "block") ==
                                    0) {
                                syslog(LOG_NOTICE,
                                        "Receive [%s] %s: env <%s>: "
                                        "DNS list %s: Blocked: %s (%s)",
                                        r->r_ip, r->r_remote_hostname,
                                        r->r_env->e_id, dnsl_result->dnsl_list,
                                        dnsl_result->dnsl_result,
                                        dnsl_result->dnsl_reason);
                                system_message = dnsl_result->dnsl_reason;
                                filter_result = MESSAGE_REJECT;
                                read_err = PROTOCOL_ERROR;
                            }
                        }
                    }
                }

                if (rh->r_headers != NULL) {
                    if ((rc = header_file_out(rh->r_headers, dff)) < 0) {
                        syslog(LOG_ERR, "Syserror: f_data fprintf: %m");
                        read_err = SYSTEM_ERROR;
                    } else {
                        data_wrote += (unsigned long)rc;
                    }
                }
                if (dkim_buf && (rh->r_headers != NULL)) {
                    yaslclear(dkim_buf);
                    for (l = rh->r_headers->l_first; l != NULL;
                            l = l->line_next) {
                        if ((*l->line_data != ' ' && *l->line_data != '\t') &&
                                (yasllen(dkim_buf) > 0)) {
#ifdef HAVE_LIBOPENARC
                            if (simta_config_bool("receive.arc.enabled")) {
                                arc_header_field(arc, (unsigned char *)dkim_buf,
                                        yasllen(dkim_buf));
                            }
#endif /* HAVE_LIBOPENARC */
#ifdef HAVE_LIBOPENDKIM
                            if (simta_config_bool("receive.dkim.enabled")) {
                                dkim_header(dkim, (unsigned char *)dkim_buf,
                                        yasllen(dkim_buf));
                            }
#endif /* HAVE_LIBOPENDKIM */
                            yaslclear(dkim_buf);
                        }
                        if (yasllen(dkim_buf)) {
                            dkim_buf = yaslcat(dkim_buf, "\r\n");
                        }
                        dkim_buf = yaslcat(dkim_buf, l->line_data);
                    }
#ifdef HAVE_LIBOPENARC
                    if (simta_config_bool("receive.arc.enabled")) {
                        arc_header_field(arc, (unsigned char *)dkim_buf,
                                yasllen(dkim_buf));
                        arc_result = arc_eoh(arc);
                        simta_debuglog(1,
                                "Receive [%s] %s: env <%s>: arc_eoh: %d",
                                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                                arc_result);
                    }
#endif /* HAVE_LIBOPENARC */
#ifdef HAVE_LIBOPENDKIM
                    if (simta_config_bool("receive.dkim.enabled")) {
                        dkim_header(dkim, (unsigned char *)dkim_buf,
                                yasllen(dkim_buf));
                        dkim_result = dkim_eoh(dkim);
                        simta_debuglog(1,
                                "Receive [%s] %s: env <%s>: dkim_eoh: %s",
                                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                                dkim_getresultstr(dkim_result));
                    }
#endif /* HAVE_LIBOPENDKIM */
                }

                if (*line != '\0') {
                    dkim_body_started = 1;
                    if ((fprintf(dff, "\n")) < 0) {
                        syslog(LOG_ERR, "Syserror: f_data fprintf: %m");
                        read_err = SYSTEM_ERROR;
                    } else {
                        data_wrote++;
                    }
                }

#ifdef HAVE_LIBSSL
                if (simta_config_bool("receive.data.checksum.enabled")) {
                    md_reset(&r->r_md_body,
                            simta_config_str(
                                    "receive.data.checksum.algorithm"));
                }
#endif /* HAVE_LIBSSL */

                if (header_only == 1) {
                    break;
                }
            }
        }

        if ((read_err == NO_ERROR) &&
                ((data_wrote + line_len + 1) >
                        simta_config_int("receive.data.limits.message_size"))) {
            /* If we're going to reach max size, continue reading lines
             * until the '.' otherwise, check message size.
             */
            syslog(LOG_NOTICE,
                    "Receive [%s] %s: env <%s>: Message Failed: "
                    "Message too large",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id);
            system_message = "Message too large";
            filter_result = MESSAGE_REJECT;
            read_err = PROTOCOL_ERROR;
        }

        if ((read_err == NO_ERROR) &&
                (rh->r_received_count >
                        simta_config_int(
                                "receive.data.limits.received_headers"))) {
            syslog(LOG_NOTICE,
                    "Receive [%s] %s: env <%s>: Message Failed: "
                    "Too many Received headers",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id);
            system_message = "Too many Received headers";
            filter_result = MESSAGE_REJECT;
            read_err = PROTOCOL_ERROR;
        }

        if ((read_err == NO_ERROR) && rh->r_seen_before) {
            system_message = "Seen Before";
            filter_message = simta_strdup(rh->r_seen_before);
            filter_result = MESSAGE_DELETE;
            read_err = PROTOCOL_ERROR;
        }

        if (read_err == NO_ERROR) {
            if ((header == 0) && (fprintf(dff, "%s\n", line) < 0)) {
                syslog(LOG_ERR, "Syserror: f_data fprintf: %m");
                read_err = SYSTEM_ERROR;
            } else {
                data_wrote += line_len + 1;
            }
        }

        if ((read_err == NO_ERROR) && (header == 0) && dkim_buf) {
            if (dkim_body_started == 0) {
                /* We are on the blank line between the headers and the body,
                 * which isn't part of the body. */
                dkim_body_started = 1;
            } else {
                dkim_buf = yaslcpylen(dkim_buf, line, line_len);
                dkim_buf = yaslcatlen(dkim_buf, "\r\n", 2);
#ifdef HAVE_LIBOPENARC
                if (simta_config_bool("receive.arc.enabled")) {
                    arc_body(arc, (unsigned char *)dkim_buf, yasllen(dkim_buf));
                }
#endif /* HAVE_LIBOPENARC */
#ifdef HAVE_LIBOPENDKIM
                if (simta_config_bool("receive.dkim.enabled")) {
                    dkim_body(
                            dkim, (unsigned char *)dkim_buf, yasllen(dkim_buf));
                }
#endif /* HAVE_LIBOPENDKIM */
            }
        }

#ifdef HAVE_LIBSSL
        if ((read_err == NO_ERROR) &&
                simta_config_bool("receive.data.checksum.enabled")) {
            /* Only add basic RFC5322 headers to the checksum. */
            if ((header == 0) || (strncasecmp(line, "Date:", 5) == 0) ||
                    (strncasecmp(line, "From:", 5) == 0) ||
                    (strncasecmp(line, "Sender:", 7) == 0) ||
                    (strncasecmp(line, "Reply-To:", 9) == 0) ||
                    (strncasecmp(line, "To:", 3) == 0) ||
                    (strncasecmp(line, "Cc:", 3) == 0) ||
                    (strncasecmp(line, "Bcc:", 4) == 0) ||
                    (strncasecmp(line, "Message-ID:", 11) == 0) ||
                    (strncasecmp(line, "In-Reply-To:", 12) == 0) ||
                    (strncasecmp(line, "References:", 11) == 0) ||
                    (strncasecmp(line, "Subject:", 8) == 0)) {
                md_update(&r->r_md, line, line_len);
            }
            if (header == 0) {
                md_update(&r->r_md_body, line, line_len);
            }
        }
#endif /* HAVE_LIBSSL */
    }

    if (r->r_env->e_flags & ENV_FLAG_DFILE) {
        if (dff != NULL) {
            f_result = fclose(dff);
            dff = NULL;
            if (f_result != 0) {
                syslog(LOG_ERR, "Syserror: f_data fclose 2: %m");
                goto error;
            }
        }

        if (read_err == NO_ERROR) {
            filter_result = MESSAGE_ACCEPT;
        } else {
            if (env_dfile_unlink(r->r_env) != 0) {
                read_err = SYSTEM_ERROR;
            }
        }
    }

    if (read_err != NO_ERROR) {
        goto done;
    }

#ifdef HAVE_LIBSSL
    if (r->r_env->e_flags & ENV_FLAG_DFILE) {
        if (simta_config_bool("receive.data.checksum.enabled")) {
            md_finalize(&r->r_md);
            md_finalize(&r->r_md_body);
            syslog(LOG_INFO,
                    "Receive [%s] %s: env <%s>: Message checksums: %s %s",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                    r->r_md.md_b16, r->r_md_body.md_b16);
        }
    }
#endif /* HAVE_LIBSSL */

    syslog(LOG_INFO, "Receive [%s] %s: env <%s>: Subject: %s", r->r_ip,
            r->r_remote_hostname, r->r_env->e_id, r->r_env->e_subject);

#ifdef HAVE_LIBOPENDKIM
    if (simta_config_bool("receive.dkim.enabled")) {
        dkim_result = dkim_eom(dkim, NULL);
        syslog(LOG_INFO, "Receive [%s] %s: env <%s>: DKIM verify result: %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                dkim_getresultstr(dkim_result));
        if (dkim_getsiglist(dkim, &dkim_sigs, &rc) != DKIM_STAT_OK) {
            rc = -1;
        }
        for (i = 0; i < rc; i++) {
            dkim_domain = (char *)dkim_sig_getdomain(dkim_sigs[ i ]);
            dkim_selector = (char *)dkim_sig_getselector(dkim_sigs[ i ]);
            if (authresults) {
                authresults = yaslcat(authresults, ";\n\tdkim=");
            }
            if ((dkim_sig_getflags(dkim_sigs[ i ]) & DKIM_SIGFLAG_PASSED) &&
                    (dkim_sig_getbh(dkim_sigs[ i ]) == DKIM_SIGBH_MATCH)) {
                syslog(LOG_INFO,
                        "Receive [%s] %s: env <%s>: valid DKIM signature: "
                        "dkim_domain=%s dkim_selector=%s",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                        dkim_domain, dkim_selector);
                if (r->r_dmarc) {
                    dmarc_dkim_result(r->r_dmarc, dkim_domain);
                }
                if (authresults) {
                    authresults = yaslcat(authresults, "pass ");
                }
            } else {
                dkim_error = dkim_sig_geterror(dkim_sigs[ i ]);
                syslog(LOG_INFO,
                        "Receive [%s] %s: env <%s>: invalid DKIM signature: "
                        "dkim_domain=%s dkim_selector=%s dkim_error='%s'",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                        dkim_domain, dkim_selector,
                        dkim_sig_geterrorstr(dkim_error));
                if (authresults) {
                    authresults =
                            yaslcatprintf(authresults, "%s reason=\"%s\" ",
                                    simta_dkim_authresult_str(dkim_error),
                                    dkim_sig_geterrorstr(dkim_error));
                }
            }
            if (authresults) {
                authresults =
                        yaslcatprintf(authresults, "header.d=@%s", dkim_domain);
            }
        }
        if (authresults && (rc == 0)) {
            authresults = yaslcat(authresults, ";\n\tdkim=none");
        }
    }
#endif /* HAVE_LIBOPENDKIM */

    if (r->r_dmarc) {
        r->r_dmarc_result = dmarc_result(r->r_dmarc);
        syslog(LOG_INFO,
                "Receive [%s] %s: env <%s>: dmarc_result=%s "
                "dmarc_domain=%s dmarc_policy=%s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                dmarc_result_str(r->r_dmarc_result), r->r_dmarc->domain,
                dmarc_result_str(r->r_dmarc->policy));
        if (authresults) {
            authresults =
                    yaslcatprintf(authresults, ";\n\tdmarc=%s header.from=%s",
                            dmarc_authresult_str(r->r_dmarc_result),
                            r->r_env->e_header_from);
        }
    }

#ifdef HAVE_LIBOPENARC
    if (simta_config_bool("receive.arc.enabled") &&
            (arc_result == ARC_STAT_OK)) {
        arc_result = arc_eom(arc);
        arc_err = arc_geterror(arc);
        simta_debuglog(1,
                "Receive [%s] %s: env <%s>: ARC verify result: %s (%d / %s)",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                arc_chain_status_str(arc), arc_result,
                arc_err ? arc_err : "no error");
        if (authresults) {
            authresults = yaslcatprintf(
                    authresults, ";\n\tarc=%s", arc_chain_status_str(arc));
        }
    }
#endif /* HAVE_LIBOPENARC */

    if ((r->r_dmarc_result == DMARC_RESULT_REJECT) &&
            simta_config_bool("receive.dmarc.strict")) {
        filter_result = MESSAGE_REJECT;
        system_message = "rejected by DMARC policy";
    }

    if (filter_result == MESSAGE_ACCEPT) {
        filter_result = content_filter(r, &filter_message, &tv_filter);
    }

done:
    if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
        goto error;
    }

    if (tv_filter.tv_sec > 0) {
        statsd_timer("receive", "content_filter",
                SIMTA_ELAPSED_MSEC(tv_filter, tv_now));
    }
    statsd_counter("receive", "message_data", data_read);

    if (filter_result & MESSAGE_BOUNCE) {
        if ((env_bounce = bounce(r->r_env,
                     ((r->r_env->e_flags & ENV_FLAG_DFILE) &&
                             ((filter_result & MESSAGE_DELETE) == 0)),
                     filter_message)) == NULL) {
            goto error;
        }
        queue_envelope(env_bounce);
        syslog(LOG_NOTICE,
                "Receive [%s] %s: env <%s>: Message Bounced: "
                "MID <%s> From <%s>: size %d: %s, %s: Bounce_ID: %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                r->r_env->e_mid ? r->r_env->e_mid : "NULL", r->r_env->e_mail,
                data_read,
                system_message ? system_message : "no system message",
                filter_message, env_bounce->e_id);

        simta_ucl_object_totimeval(
                simta_config_obj("receive.queue.timer"), &tv_add);
        timeradd(&tv_add, &tv_now, &r->r_tv_accepted);
    }

    if (filter_result & MESSAGE_JAIL) {
        if ((r->r_env->e_flags & ENV_FLAG_DFILE) == 0) {
            syslog(LOG_ERR,
                    "Receive [%s] %s: env <%s>: "
                    "no Dfile can't accept message:"
                    "MID <%s> size %d: %s, %s",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                    r->r_env->e_mid ? r->r_env->e_mid : "NULL", data_read,
                    system_message ? system_message : "no system message",
                    filter_message ? filter_message : "no filter message");
        } else if ((jail_host = simta_config_str("deliver.jail.host")) ==
                   NULL) {
            syslog(LOG_WARNING,
                    "Receive [%s] %s: env <%s>: "
                    "content filter returned MESSAGE_JAIL and "
                    "no jail host is configured",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id);
        } else {
            /* remove tfile because we're going to change the hostname */
            if (env_tfile_unlink(r->r_env) != 0) {
                goto error;
            }
            env_hostname(r->r_env, jail_host);

            /* Somewhat perversely, a message jailed by the content filter
             * should be free so that it can be delivered to the next jail.
             */
            r->r_env->e_jailed = false;
            r->r_env->e_puntable = false;

            syslog(LOG_NOTICE,
                    "Receive [%s] %s: env <%s>: "
                    "sending to JAIL_HOST %s",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                    r->r_env->e_hostname);
        }

        /* see if we need to delete the message */
    } else if ((filter_result & MESSAGE_TEMPFAIL) ||
               (filter_result & MESSAGE_REJECT) ||
               (filter_result & MESSAGE_DELETE) ||
               (filter_result & MESSAGE_BOUNCE)) {
        if ((filter_result & MESSAGE_DELETE) &&
                ((filter_result & MESSAGE_BOUNCE) == 0)) {
            syslog(LOG_NOTICE,
                    "Receive [%s] %s: env <%s>: "
                    "Message Deleted by content filter: "
                    "MID <%s> size %d: %s, %s",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                    r->r_env->e_mid ? r->r_env->e_mid : "NULL", data_read,
                    system_message ? system_message : "no system message",
                    filter_message ? filter_message : "no filter message");
        }

        if ((r->r_env->e_flags & ENV_FLAG_DFILE)) {
            if (env_dfile_unlink(r->r_env) != 0) {
                goto error;
            }
        }
    }

    if (r->r_env->e_flags & ENV_FLAG_DFILE) {
#ifdef HAVE_LIBOPENARC
        if (simta_config_bool("receive.auth.results.enabled") &&
                simta_config_bool("receive.arc.enabled")) {
            if (arc_result == ARC_STAT_OK) {
                if ((arc_key = simta_slurp(
                             simta_config_str("receive.arc.key"))) == NULL) {
                    goto error;
                }
                /* FIXME: WTF, openarc? */
                arc_authservid =
                        simta_config_yastr("receive.auth.results.domain");
                arc_selector = simta_config_yastr("receive.arc.selector");
                arc_domain = simta_config_yastr("receive.arc.domain");
                arc_result = arc_getseal(arc, &arc_seal, arc_authservid,
                        arc_selector, arc_domain, (unsigned char *)arc_key,
                        yasllen(arc_key), (unsigned char *)authresults);
                simta_debuglog(1,
                        "Receive [%s] %s: env <%s>: ARC sign result: %d",
                        r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                        arc_result);
                yaslfree(arc_authservid);
                yaslfree(arc_selector);
                yaslfree(arc_domain);
            }

            authresults_tmp = yaslempty();
            if (arc_result == ARC_STAT_OK) {
                for (; arc_seal; arc_seal = arc_hdr_next(arc_seal)) {
                    if (yasllen(authresults_tmp) > 0) {
                        authresults_tmp = yaslcat(authresults_tmp, "\n");
                    }
                    /* Despite the name, arc_hdr_name returns the entire header. */
                    authresults_tmp = yaslcat(authresults_tmp,
                            (char *)arc_hdr_name(arc_seal, NULL));
                }
                yaslstrip(authresults_tmp, "\r");
            }

            /* OpenARC may or may not have returned some headers, depending on
             * whether the ARC chain was already failed when we received the
             * message.
             */
            if (yasllen(authresults_tmp) > 0) {
                yaslfree(authresults);
                authresults = authresults_tmp;
            } else {
                yaslfree(authresults_tmp);
                /* Fall back to adding Authentication-Results. */
                authresults_plain = 1;
            }
        }
#endif /* HAVE_LIBOPENARC */

        if (authresults_plain && authresults) {
            /* RFC 7601 2.2 Formal Definition
            * authres-header = "Authentication-Results:" [CFWS] authserv-id
            *                   [ CFWS authres-version ]
            *                   ( no-result / 1*resinfo ) [CFWS] CRLF
            */

            authresults_tmp =
                    yaslcatprintf(yaslempty(), "Authentication-Results: %s; ",
                            simta_config_str("receive.auth.results.domain"));
            authresults_tmp = yaslcatyasl(authresults_tmp, authresults);
            yaslfree(authresults);
            authresults = authresults_tmp;
            authresults_tmp = NULL;
        }

        if (authresults) {
            if (r->r_env->e_extra_headers != NULL) {
                authresults = yaslcatyasl(
                        yaslcat(authresults, "\n"), r->r_env->e_extra_headers);
                yaslfree(r->r_env->e_extra_headers);
            }
            r->r_env->e_extra_headers = authresults;
            authresults = NULL;
        }

        if (env_outfile(r->r_env) != SIMTA_OK) {
            goto error;
        }

        simta_ucl_object_totimeval(
                simta_config_obj("receive.queue.timer"), &tv_add);
        timeradd(&tv_add, &tv_now, &r->r_tv_accepted);

        r->r_data_success++;

        syslog(LOG_NOTICE,
                "Receive [%s] %s: env <%s>: Message Accepted: "
                "MID <%s> From <%s>: size %d: %s, %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                r->r_env->e_mid ? r->r_env->e_mid : "NULL", r->r_env->e_mail,
                data_read,
                system_message ? system_message : "no system message",
                filter_message ? filter_message : "no filter message");
    }

    if (filter_result & MESSAGE_DISCONNECT) {
        set_smtp_mode(r, "disabled", "filter");
    } else if (filter_result & MESSAGE_TARPIT) {
        set_smtp_mode(r, "tarpit", "filter");
    }

    tarpit_sleep(r);

    failure_message = filter_message;
    if (failure_message == NULL) {
        failure_message = system_message;
    }

    banner++;

    /* TEMPFAIL has precedence over REJECT */
    if (filter_result & MESSAGE_TEMPFAIL) {
        syslog(LOG_INFO,
                "Receive [%s] %s: env <%s>: Tempfail Banner: "
                "MID <%s> size %d: %s, %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                r->r_env->e_mid ? r->r_env->e_mid : "NULL", data_read,
                system_message ? system_message : "no system message",
                filter_message ? filter_message : "no filter message");
        if (smtp_write_banner(r, 451, S_451_MESSAGE, failure_message) !=
                RECEIVE_OK) {
            ret_code = RECEIVE_CLOSECONNECTION;
            goto error;
        }

    } else if (filter_result & MESSAGE_REJECT) {
        syslog(LOG_INFO,
                "Receive [%s] %s: env <%s>: Failed Banner: "
                "MID <%s> size %d: %s, %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                r->r_env->e_mid ? r->r_env->e_mid : "NULL", data_read,
                system_message ? system_message : "no system message",
                filter_message ? filter_message : "no filter message");
        if (smtp_write_banner(r, 554, S_554_MESSAGE, failure_message) !=
                RECEIVE_OK) {
            ret_code = RECEIVE_CLOSECONNECTION;
            goto error;
        }

    } else {
        syslog(LOG_INFO,
                "Receive [%s] %s: env <%s>: Accept Banner: "
                "MID <%s> size %d: %s, %s",
                r->r_ip, r->r_remote_hostname, r->r_env->e_id,
                r->r_env->e_mid ? r->r_env->e_mid : "NULL", data_read,
                system_message ? system_message : "no system message",
                filter_message ? filter_message : "no filter message");
        if (filter_message != NULL) {
            if (snet_writef(r->r_snet, "250 Accepted: (%s): %s\r\n",
                        r->r_env->e_id, filter_message) < 0) {
                syslog(LOG_ERR, "Syserror: f_data snet_writef: %m");
                ret_code = RECEIVE_CLOSECONNECTION;
                goto error;
            }
        } else {
            if (snet_writef(r->r_snet, "250 Accepted: (%s)\r\n",
                        r->r_env->e_id) < 0) {
                syslog(LOG_ERR, "Syserror: f_data snet_writef: %m");
                ret_code = RECEIVE_CLOSECONNECTION;
                goto error;
            }
        }
    }

    /* if we just had a protocol error, we're OK */
    if (read_err != SYSTEM_ERROR) {
        ret_code = RECEIVE_OK;
    }

error:
    receive_headers_free(rh);
    yaslfree(authresults);
    yaslfree(with);
    dnsl_result_free(dnsl_result);

    /* if dff is still open, there was an error and we need to close it */
    if ((dff != NULL) && (fclose(dff) != 0)) {
        syslog(LOG_ERR, "Syserror: f_data fclose 3: %m");
        if (ret_code == RECEIVE_OK) {
            ret_code = RECEIVE_SYSERROR;
        }
    }

    /* if we didn't put a message on the disk, we need to clean up */
    if ((r->r_env->e_flags & ENV_FLAG_EFILE) == 0) {
        /* Dfile no Efile */
        if (r->r_env->e_flags & ENV_FLAG_DFILE) {
            if (env_dfile_unlink(r->r_env) != 0) {
                if (ret_code == RECEIVE_OK) {
                    ret_code = RECEIVE_SYSERROR;
                }
            }
        }

        /* Tfile no Efile */
        if (r->r_env->e_flags & ENV_FLAG_TFILE) {
            if (env_tfile_unlink(r->r_env) != 0) {
                if (ret_code == RECEIVE_OK) {
                    ret_code = RECEIVE_SYSERROR;
                }
            }
        }

        syslog(LOG_NOTICE, "Receive [%s] %s: env <%s>: Message Failed", r->r_ip,
                r->r_remote_hostname, r->r_env->e_id);
        env_free(r->r_env);
        r->r_env = NULL;
    }

    if (filter_message != NULL) {
        free(filter_message);
    }


    yaslfree(dkim_buf);
#ifdef HAVE_LIBOPENARC
    yaslfree(arc_key);
    if (arc) {
        arc_free(arc);
    }
#endif /* HAVE_LIBOPENARC */
#ifdef HAVE_LIBOPENDKIM
    if (dkim != NULL) {
        dkim_free(dkim);
    }
#endif /* HAVE_LIBOPENDKIM */

    /* if we've already given a message result banner,
     * delay the syserror banner
     */
    if ((banner != 0) && (ret_code == RECEIVE_SYSERROR)) {
        set_smtp_mode(r, "disabled", "Syserror");
        return (RECEIVE_OK);
    }

    return (ret_code);
}


static int
f_quit(struct receive_data *r) {
    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    tarpit_sleep(r);

    return (smtp_write_banner(r, 221, NULL, NULL));
}


static int
f_rset(struct receive_data *r) {
    /*
     * We could presume that this indicates another message.  However,
     * since some mailers send this just before "QUIT", and we're
     * checking "MAIL FROM:" as well, there's no need.
     */

    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    if (reset(r) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    tarpit_sleep(r);

    return (smtp_write_banner(r, 250, NULL, NULL));
}


static int
f_noop(struct receive_data *r) {
    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    return (smtp_write_banner(r, 250, "simta", version));
}


static int
f_help(struct receive_data *r) {
    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    if (deliver_accepted(r, 1) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    return (smtp_write_banner(r, 211, NULL, version));
}


/*
     * RFC 5321 3.5.3 Meaning of VRFY or EXPN Success Response
     * A server MUST NOT return a 250 code in response to a VRFY or EXPN
     * command unless it has actually verified the address.  In particular,
     * a server MUST NOT return 250 if all it has done is to verify that the
     * syntax given is valid.  In that case, 502 (Command not implemented)
     * or 500 (Syntax error, command unrecognized) SHOULD be returned.  As
     * stated elsewhere, implementation (in the sense of actually validating
     * addresses and returning information) of VRFY and EXPN are strongly
     * recommended.  Hence, implementations that return 500 or 502 for VRFY
     * are not in full compliance with this specification.
     *
     * RFC 5321 7.3 VRFY, EXPN, and Security
     * As discussed in section 3.5, individual sites may want to disable
     * either or both of VRFY or EXPN for security reasons.  As a corollary
     * to the above, implementations that permit this MUST NOT appear to
     * have verified addresses that are not, in fact, verified.  If a site
     * disables these commands for security reasons, the SMTP server MUST
     * return a 252 response, rather than a code that could be confused with
     * successful or unsuccessful verification.
     */


static int
f_not_implemented(struct receive_data *r) {
    simta_debuglog(1, "Receive [%s] %s: %s", r->r_ip, r->r_remote_hostname,
            r->r_smtp_command);

    if (deliver_accepted(r, 1) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    tarpit_sleep(r);

    return (smtp_write_banner(r, 502, NULL, NULL));
}


static int
f_bad_sequence(struct receive_data *r) {
    simta_debuglog(1, "Receive [%s] %s: Bad Sequence: %s", r->r_ip,
            r->r_remote_hostname, r->r_smtp_command);

    return (smtp_write_banner(r, 503, NULL, NULL));
}


static int
f_disabled(struct receive_data *r) {
    tarpit_sleep(r);

    return smtp_write_banner(r, 421, S_421_DECLINE, NULL);
}

static int
f_insecure(struct receive_data *r) {
    return smtp_write_banner(r, 554, "Refused due to lack of security", NULL);
}

static int
f_off(struct receive_data *r) {
    tarpit_sleep(r);

    return (smtp_write_banner(r, 451, S_451_DECLINE, NULL));
}

#ifdef HAVE_LIBSSL
static int
f_starttls(struct receive_data *r) {
    int      rc;
    SSL_CTX *ssl_ctx;

    if (!simta_config_bool("receive.tls.enabled")) {
        return (f_not_implemented(r));
    }

    tarpit_sleep(r);

    /*
     * Client MUST NOT attempt to start a TLS session if a TLS
     * session is already active.  No mention of what to do if it does...
     */
    if (r->r_tls) {
        syslog(LOG_ERR, "Receive [%s] %s: STARTTLS called twice", r->r_ip,
                r->r_remote_hostname);
        return (RECEIVE_SYSERROR);
    }

    if (r->r_ac != 1) {
        log_bad_syntax(r);
        return (smtp_write_banner(r, 501, NULL, "no parameters allowed"));
    }

    if ((ssl_ctx = tls_server_setup()) == NULL) {
        syslog(LOG_ERR, "Liberror: f_starttls tls_server_setup: %s",
                ERR_error_string(ERR_get_error(), NULL));
        rc = smtp_write_banner(
                r, 454, "TLS not available due to temporary reason", NULL);
    } else {
        rc = smtp_write_banner(r, 220, "Ready to start TLS", NULL);
    }


    if (rc != RECEIVE_OK) {
        return (RECEIVE_CLOSECONNECTION);
    }

    if (start_tls(r, ssl_ctx) != RECEIVE_OK) {
        /* RFC 3207 4.1 After the STARTTLS Command
         * If the SMTP server decides that the level of authentication or
         * privacy is not high enough for it to continue, it SHOULD reply to
         * every SMTP command from the client (other than a QUIT command) with
         * the 554 reply code (with a possible text string such as "Command
         * refused due to lack of security").
         */
        SSL_CTX_free(ssl_ctx);
        set_smtp_mode(r, "insecure", "TLS negotiation failed");
        return (RECEIVE_OK);
    }

    SSL_CTX_free(ssl_ctx);

    /* RFC 3207 4.2 Result of the STARTTLS Command
     * Upon completion of the TLS handshake, the SMTP protocol is reset to
     * the initial state (the state in SMTP after a server issues a 220
     * service ready greeting).  The server MUST discard any knowledge
     * obtained from the client, such as the argument to the EHLO command,
     * which was not obtained from the TLS negotiation itself.
     *
     * RFC 3207 6
     * Before the TLS handshake has begun, any protocol interactions are
     * performed in the clear and may be modified by an active attacker.
     * For this reason, clients and servers MUST discard any knowledge
     * obtained prior to the start of the TLS handshake upon completion of
     * the TLS handshake.
     */

    if (reset(r) != RECEIVE_OK) {
        return (RECEIVE_SYSERROR);
    }

    if (r->r_hello != NULL) {
        free(r->r_hello);
        r->r_hello = NULL;
    }

#ifdef HAVE_LIBSASL
    if (simta_config_bool("receive.auth.authn.enabled") &&
            !simta_config_bool("receive.auth.authn.honeypot")) {
        if (simta_sasl_reset(r->r_sasl, r->r_tls) != 0) {
            return (RECEIVE_SYSERROR);
        }
        update_sasl_extension(r);
    }
#endif /* HAVE_LIBSASL */

    return (RECEIVE_OK);
}

int
start_tls(struct receive_data *r, SSL_CTX *ssl_ctx) {
    int               rc;
    struct timeval    tv_wait;
    const SSL_CIPHER *ssl_cipher;

    simta_debuglog(3, "TLS: start_tls snet_starttls");

    simta_ucl_object_totimeval(
            simta_config_obj("receive.timeout.tls"), &tv_wait);
    snet_timeout(r->r_snet, SNET_SSL_ACCEPT_TIMEOUT, &tv_wait);

    if ((rc = snet_starttls(r->r_snet, ssl_ctx, 1)) != 1) {
        syslog(LOG_ERR, "Liberror: start_tls snet_starttls: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return (RECEIVE_SYSERROR);
    }

    if ((ssl_cipher = SSL_get_current_cipher(r->r_snet->sn_ssl)) != NULL) {
        syslog(LOG_INFO,
                "Receive [%s] %s: TLS established. Protocol: %s Cipher: %s",
                r->r_ip, r->r_remote_hostname,
                SSL_get_version(r->r_snet->sn_ssl),
                SSL_CIPHER_get_name(ssl_cipher));
        r->r_tls = SSL_CIPHER_get_bits(ssl_cipher, NULL);
    } else {
        return (RECEIVE_CLOSECONNECTION);
    }

    if (simta_config_bool("receive.tls.client_cert")) {
        simta_debuglog(3, "TLS: start_tls SSL_get_peer_certificate");
        if (tls_client_cert(r->r_remote_hostname, r->r_snet->sn_ssl) != 0) {
            return (RECEIVE_CLOSECONNECTION);
        }
    }

    /* RFC 3207 4.2 Result of the STARTTLS Command
     * A server MUST NOT return the STARTTLS extension in response to an
     * EHLO command received after a TLS handshake has completed.
     */
    ucl_object_delete_key(r->r_smtp_extensions, "STARTTLS");

    /* CVE-2011-0411: discard pending data from libsnet */
    snet_flush(r->r_snet);

    return (RECEIVE_OK);
}

#endif /* HAVE_LIBSSL */

int
f_auth(struct receive_data *r) {
    char *         clientin = NULL;
    struct timeval tv;
#ifdef HAVE_LIBSASL
    int                 rc;
    struct dnsl_result *authz_result;
#endif /* HAVE_LIBSASL */

    if (!simta_config_bool("receive.auth.authn.enabled")) {
        return (f_not_implemented(r));
    }

    tarpit_sleep(r);

    /* RFC 4954 4 The AUTH Command
     * Note that these BASE64 strings can be much longer than normal SMTP
     * commands. Clients and servers MUST be able to handle the maximum encoded
     * size of challenges and responses generated by their supported
     * authentication mechanisms. This requirement is independent of any line
     * length limitations the client or server may have in other parts of its
     * protocol implementation.
     */

    if ((r->r_ac != 2) && (r->r_ac != 3)) {
        log_bad_syntax(r);
        return (smtp_write_banner(r, 501, NULL,
                "RFC 4954 section 4 AUTH mechanism [initial-response]"));
    }

    if (simta_config_bool("receive.auth.authn.honeypot")) {
        if (strcasecmp(r->r_av[ 1 ], "PLAIN") == 0) {
            simta_debuglog(1, "Auth.fake [%s] %s: starting PLAIN auth", r->r_ip,
                    r->r_remote_hostname);
            if (r->r_ac == 3) {
                clientin = r->r_av[ 2 ];

            } else {
                if (smtp_write_banner(r, 334, NULL, NULL) != RECEIVE_OK) {
                    return (RECEIVE_CLOSECONNECTION);
                }
                simta_ucl_object_totimeval(
                        simta_config_obj("receive.timeout.command"), &tv);
                if ((clientin = snet_getline(r->r_snet, &tv)) == NULL) {
                    syslog(LOG_ERR, "Auth.fake [%s] %s: snet_getline failed",
                            r->r_ip, r->r_remote_hostname);
                    return (RECEIVE_CLOSECONNECTION);
                }
            }
        } else if (strcasecmp(r->r_av[ 1 ], "LOGIN") == 0) {
            simta_debuglog(1, "Auth.fake [%s] %s: starting LOGIN auth", r->r_ip,
                    r->r_remote_hostname);
            if (smtp_write_banner(r, 334, "VXNlciBOYW1lAA==", NULL) !=
                    RECEIVE_OK) {
                return (RECEIVE_CLOSECONNECTION);
            }
            simta_ucl_object_totimeval(
                    simta_config_obj("receive.timeout.command"), &tv);
            if ((clientin = snet_getline(r->r_snet, &tv)) == NULL) {
                syslog(LOG_ERR, "Auth.fake [%s] %s: snet_getline failed",
                        r->r_ip, r->r_remote_hostname);
                return (RECEIVE_CLOSECONNECTION);
            }
            syslog(LOG_INFO, "Auth.fake [%s] %s: %s", r->r_ip,
                    r->r_remote_hostname, clientin);
            if (smtp_write_banner(r, 334, "UGFzc3dvcmQA", NULL) != RECEIVE_OK) {
                return (RECEIVE_CLOSECONNECTION);
            }
            simta_ucl_object_totimeval(
                    simta_config_obj("receive.timeout.command"), &tv);
            if ((clientin = snet_getline(r->r_snet, &tv)) == NULL) {
                syslog(LOG_ERR, "Auth.fake [%s] %s: snet_getline failed",
                        r->r_ip, r->r_remote_hostname);
                return (RECEIVE_CLOSECONNECTION);
            }
        } else {
            syslog(LOG_NOTICE,
                    "Auth.fake [%s] %s: "
                    "unrecognized authentication type: %s",
                    r->r_ip, r->r_remote_hostname, r->r_smtp_command);
            if (smtp_write_banner(r, 504, NULL, NULL) != RECEIVE_OK) {
                return (RECEIVE_CLOSECONNECTION);
            }
        }

        if (clientin) {
            syslog(LOG_INFO, "Auth.fake [%s] %s: %s", r->r_ip,
                    r->r_remote_hostname, clientin);
            if (smtp_write_banner(r, 235, NULL, NULL) != RECEIVE_OK) {
                return (RECEIVE_CLOSECONNECTION);
            }
        }
        set_smtp_mode(
                r, simta_config_str("receive.punishment"), "Honeypot AUTH");
        return (RECEIVE_OK);
    }

#ifdef HAVE_LIBSASL
    /* RFC 4954 4 The AUTH Command
     * After an AUTH command has successfully completed, no more AUTH commands
     * may be issued in the same session. After a successful AUTH command
     * completes, a server MUST reject any further AUTH commands with a
     * 503 reply.
     */
    if (r->r_auth) {
        return (f_bad_sequence(r));
    }

    /* RFC 4954 4 The AUTH Command
     * The AUTH command is not permitted during a mail transaction. */
    if ((r->r_env != NULL) && (r->r_env->e_mail != NULL)) {
        return (f_bad_sequence(r));
    }

    rc = simta_sasl_server_auth(
            r->r_sasl, r->r_av[ 1 ], (r->r_ac == 3) ? r->r_av[ 2 ] : NULL);

    while (rc == 334) {
        if (smtp_write_banner(r, rc, r->r_sasl->s_response, NULL) !=
                RECEIVE_OK) {
            return (RECEIVE_CLOSECONNECTION);
        }

        /* Get response from the client */
        simta_ucl_object_totimeval(
                simta_config_obj("receive.timeout.command"), &tv);
        if ((clientin = snet_getline(r->r_snet, &tv)) == NULL) {
            if (snet_eof(r->r_snet)) {
                syslog(LOG_ERR, "Auth [%s] %s: %s: unexpected EOF", r->r_ip,
                        r->r_remote_hostname, r->r_sasl->s_auth_id);
            } else {
                syslog(LOG_ERR, "Liberror: f_auth snet_getline: %m");
            }
            return (RECEIVE_CLOSECONNECTION);
        }

        /* RFC 4954 4 The AUTH Command
         * If the client wishes to cancel the authentication exchange, it
         * issues a line with a single "*". If the server receives such a
         * response, it MUST reject the AUTH command by sending a 501 reply.
         */
        if (strcmp(clientin, "*") == 0) {
            syslog(LOG_ERR,
                    "Auth [%s] %s: %s: "
                    "client canceled authentication",
                    r->r_ip, r->r_remote_hostname, r->r_sasl->s_auth_id);

            simta_sasl_free(r->r_sasl);
            if ((r->r_sasl = simta_sasl_server_new(r->r_tls)) == NULL) {
                return (RECEIVE_CLOSECONNECTION);
            }
            update_sasl_extension(r);
            return (smtp_write_banner(
                    r, 501, NULL, "client canceled authentication"));
        }

        rc = simta_sasl_server_auth(r->r_sasl, NULL, clientin);
    }

    /* Handle failed authn */
    if (rc != 235) {
        syslog(LOG_INFO, "Auth [%s] %s: %s failed to authenticate", r->r_ip,
                r->r_remote_hostname, r->r_sasl->s_auth_id);

        if (rc == 535) {
            r->r_failedauth++;
        }
        rc = smtp_write_banner(r, rc,
                yasllen(r->r_sasl->s_response) ? r->r_sasl->s_response : NULL,
                NULL);
        return ((r->r_failedauth < 3) ? rc : RECEIVE_CLOSECONNECTION);
    }

    r->r_auth_id = r->r_sasl->s_auth_id;

    /* authn was successful, now we need to check authz */
    if ((authz_result = dnsl_check(
                 "receive.auth.authz.dns_list", NULL, r->r_auth_id)) == NULL) {
        syslog(LOG_INFO, "Auth [%s] %s: %s allowed by default", r->r_ip,
                r->r_remote_hostname, r->r_auth_id);
    } else {
        if (strcmp(authz_result->dnsl_action, "block") == 0) {
            r->r_failedauth++;
            syslog(LOG_INFO, "Auth [%s] %s: %s denied by DNS list %s: %s (%s)",
                    r->r_ip, r->r_remote_hostname, r->r_auth_id,
                    authz_result->dnsl_list, authz_result->dnsl_result,
                    authz_result->dnsl_reason);
            rc = smtp_write_banner(r, 535, NULL, NULL);
            return ((r->r_failedauth < 3) ? rc : RECEIVE_CLOSECONNECTION);
        } else {
            syslog(LOG_INFO, "Auth [%s] %s: %s allowed by DNS list %s: %s (%s)",
                    r->r_ip, r->r_remote_hostname, r->r_auth_id,
                    authz_result->dnsl_list, authz_result->dnsl_result,
                    authz_result->dnsl_reason);
        }
    }

    syslog(LOG_INFO, "Auth [%s] %s: %s authenticated via %s%s", r->r_ip,
            r->r_remote_hostname, r->r_auth_id, r->r_sasl->s_mech,
            r->r_tls ? "+TLS" : "");

    if (smtp_write_banner(r, 235, NULL, NULL) != RECEIVE_OK) {
        return (RECEIVE_CLOSECONNECTION);
    }

    r->r_auth = 1;

    set_smtp_mode(r, simta_config_str("receive.mode"), "Default");
#endif /* HAVE_LIBSASL */
    return (RECEIVE_OK);
}

int
smtp_receive(int fd, struct connection_info *c, struct simta_socket *ss) {
    struct receive_data r;
    ACAV *              acav = NULL;
    fd_set              fdset;
    int                 i = 0;
    int                 ret;
    int                 calculate_timers;
    const char *        timer_type = NULL;
    const char *        fallback_type = NULL;
    char *              line;
    char                hostname[ DNSR_MAX_NAME + 1 ];
    struct timeval      tv_start = {0, 0};
    struct timeval      tv_stop = {0, 0};
    struct timeval      tv_now;
    struct timeval      tv_wait;
    struct timeval      tv_line;
    struct timeval      tv_add;
    struct timeval      tv_command_start;
    struct timeval      tv_command_now;
    struct timeval *    tv_timeout = NULL;
    struct timeval *    tv_fallback = NULL;
#ifdef HAVE_LIBWRAP
    char *ctl_hostname;
#endif /* HAVE_LIBWRAP */

    /*
     * global connections max
     * auth init
     * check DNS reverse
     * TCP wrappers
     * DNS lists
     * if not DNSL_ACCEPT, local connections max
     * write before banner check
     * opening banner * command line loop
     */

    /*
     * local variable init
     * build snet connection
     * dynamic memory init
     * global connections max
     * if SIMTA_MODE_REFUSE, give 554 banner and go to command line loop
     * auth init
     * check DNS reverse
     * TCP wrappers
     * DNS lists
     * if not DNSL_ACCEPT, local connections max
     * write before banner check
     * tarpit sleep
     * opening banner
     * command line loop
     */

    memset(&r, 0, sizeof(struct receive_data));
    r.r_sa = (struct sockaddr *)&c->c_sa;
    r.r_ip = c->c_ip;
    r.r_dns_match = REVERSE_UNRESOLVED;
    r.r_remote_hostname = S_UNRESOLVED;
#ifdef HAVE_LIBSSL
    md_init(&r.r_md);
    md_init(&r.r_md_body);
#endif /* HAVE_LIBSSL */
    set_smtp_mode(&r, simta_config_str("receive.mode"), "Default");

    if (simta_config_bool("receive.dmarc.enabled")) {
        dmarc_init(&r.r_dmarc);
    }

    if (simta_gettimeofday(&tv_start) == SIMTA_ERR) {
        tv_start.tv_sec = 0;
        tv_start.tv_usec = 0;
    }

    if ((r.r_snet = snet_attach(fd, 1024 * 1024)) == NULL) {
        syslog(LOG_ERR, "Liberror: smtp_receive snet_attach: %m");
        return (0);
    }

    if (simta_config_bool("receive.connection.proxy.enabled")) {
        if (proxy_accept(&r) != RECEIVE_OK) {
            goto syserror;
        }
    }

    simta_ucl_object_totimeval(
            simta_config_obj("receive.timeout.command"), &tv_wait);
    snet_timeout(r.r_snet, SNET_READ_TIMEOUT, &tv_wait);
    simta_ucl_object_totimeval(
            simta_config_obj("receive.timeout.write"), &tv_wait);
    snet_timeout(r.r_snet, SNET_WRITE_TIMEOUT, &tv_wait);

    if (reset(&r) != RECEIVE_OK) {
        goto syserror;
    }

    acav = acav_alloc();

    if (simta_global_connections >
            simta_config_int("receive.connection.limits.global")) {
        syslog(LOG_WARNING,
                "Connect.in [%s] %s: connection refused: "
                "global maximum exceeded: %d",
                r.r_ip, r.r_remote_hostname, simta_global_connections);
        smtp_write_banner(&r, 421, S_MAXCONNECT, S_CLOSING);
        goto closeconnection;
    }

    if (simta_global_throttle_connections >
            simta_config_int("receive.connection.limits.throttle")) {
        syslog(LOG_WARNING,
                "Connect.in [%s] %s: connection refused: "
                "global throttle exceeded: %d",
                r.r_ip, r.r_remote_hostname, simta_global_throttle_connections);
        smtp_write_banner(&r, 421, S_MAXCONNECT, S_CLOSING);
        goto closeconnection;
    }

    if (r.r_smtp_mode == SMTP_MODE_DISABLED) {
        /* RFC 5321 3.1 Session Initiation
         * The SMTP protocol allows a server to formally reject a transaction
         * while still allowing the initial connection as follows: a 554
         * response MAY be given in the initial connection opening message
         * instead of the 220.  A server taking this approach MUST still wait
         * for the client to send a QUIT (see section 4.1.1.10) before closing
         * the connection and SHOULD respond to any intervening commands with
         * "503 bad sequence of commands".  Since an attempt to make an SMTP
         * connection to such a system is probably in error, a server returning
         * a 554 response on connection opening SHOULD provide enough
         * information in the reply text to facilitate debugging of the sending
         * system.
         */
        syslog(LOG_INFO,
                "Connect.in [%s] %s: connection refused: inbound smtp disabled",
                r.r_ip, r.r_remote_hostname);
        if (smtp_write_banner(&r, 554, "No SMTP service here", NULL) !=
                RECEIVE_OK) {
            goto closeconnection;
        }

    } else {
        if (auth_init(&r, ss) != 0) {
            goto syserror;
        }

        if (!simta_dnsr_init()) {
            goto syserror;
        }

        simta_debuglog(3, "Connect.in [%s]: checking reverse", r.r_ip);

        *hostname = '\0';
        switch (r.r_dns_match = check_reverse(hostname, r.r_sa)) {

        default:
            syslog(LOG_ERR, "Connect.in [%s]: check_reverse out of range",
                    r.r_ip);
            /* fall through to REVERSE_ERROR */
        case REVERSE_ERROR:
            r.r_remote_hostname = S_UNKNOWN;
            syslog(LOG_INFO, "Connect.in [%s] %s: reverse address error: %s",
                    r.r_ip, r.r_remote_hostname,
                    dnsr_err2string(dnsr_errno(simta_dnsr)));
            if (strcmp(simta_config_str("receive.connection.rdns.check"),
                        "chillaxed") != 0) {
                smtp_write_banner(&r, 421, S_421_DECLINE,
                        simta_config_str("receive.connection.rdns.message"));
                goto closeconnection;
            }
            break;

        case REVERSE_MATCH:
            r.r_remote_hostname = hostname;
            break;

        case REVERSE_UNKNOWN:
        case REVERSE_MISMATCH:
            /* invalid reverse */
            if (r.r_dns_match == REVERSE_MISMATCH) {
                r.r_remote_hostname = S_MISMATCH;
            } else {
                r.r_remote_hostname = S_UNKNOWN;
            }

            syslog(LOG_INFO, "Connect.in [%s] %s: invalid reverse", r.r_ip,
                    r.r_remote_hostname);
            if (strcmp(simta_config_str("receive.connection.rdns.check"),
                        "strict") == 0) {
                smtp_write_banner(&r, 421, S_421_DECLINE,
                        simta_config_str("receive.connection.rdns.message"));
                goto closeconnection;
            }
            break;
        } /* end of switch */

#ifdef HAVE_LIBWRAP
        simta_debuglog(3, "Connect.in [%s] %s: tcp_wrappers lookup", r.r_ip,
                r.r_remote_hostname);

        if (*hostname == '\0') {
            ctl_hostname = simta_strdup(STRING_UNKNOWN);
        } else {
            ctl_hostname = simta_strdup(hostname);
        }

        /* first STRING_UNKNOWN should be domain name of incoming host */
        if (hosts_ctl("simta", ctl_hostname, r.r_ip, STRING_UNKNOWN) == 0) {
            syslog(LOG_INFO, "Connect.in [%s] %s: Failed: access denied",
                    r.r_ip, r.r_remote_hostname);
            smtp_write_banner(&r, 421, S_421_DECLINE,
                    simta_config_str("receive.connection.libwrap.message"));
            free(ctl_hostname);
            goto closeconnection;
        }

        free(ctl_hostname);
#endif /* HAVE_LIBWRAP */

        simta_debuglog(3, "Connect.in [%s] %s: checking DNS lists", r.r_ip,
                r.r_remote_hostname);

        r.r_dnsl_result =
                dnsl_check("receive.connection.dns_list", r.r_sa, NULL);

        if (r.r_dnsl_result) {
            r.r_dnsl_checked = 1;
            if (strcmp((r.r_dnsl_result)->dnsl_action, "block") == 0) {
                syslog(LOG_INFO,
                        "Connect.in [%s] %s: DNS list %s: Blocked: %s (%s)",
                        r.r_ip, r.r_remote_hostname,
                        (r.r_dnsl_result)->dnsl_list,
                        (r.r_dnsl_result)->dnsl_result,
                        (r.r_dnsl_result)->dnsl_reason);
                set_smtp_mode(&r, "refuse", (r.r_dnsl_result)->dnsl_reason);
            }
        }

        if ((r.r_dnsl_result == NULL) ||
                ((strcmp((r.r_dnsl_result)->dnsl_action, "accept") != 0) &&
                        (strcmp((r.r_dnsl_result)->dnsl_action, "trust") !=
                                0))) {
            if (c->c_proc_total >
                    simta_config_int("receive.connection.limits.per_host")) {
                syslog(LOG_WARNING,
                        "Connect.in [%s] %s: connection refused: "
                        "local maximum exceeded: %d",
                        r.r_ip, r.r_remote_hostname, c->c_proc_total);
                smtp_write_banner(&r, 421, S_MAXCONNECT, S_CLOSING);
                goto closeconnection;
            }

            if (c->c_proc_throttle >
                    simta_config_int(
                            "receive.connection.limits.per_host_throttle")) {
                syslog(LOG_WARNING,
                        "Connect.in [%s] %s: connection refused: "
                        "connection per interval exceeded %d",
                        r.r_ip, r.r_remote_hostname, c->c_proc_throttle);
                smtp_write_banner(&r, 421, S_MAXCONNECT, S_CLOSING);
                goto closeconnection;
            }
        }

        simta_debuglog(3, "Connect.in [%s] %s: write before banner check",
                r.r_ip, r.r_remote_hostname);

        /* Write before Banner check */
        FD_ZERO(&fdset);
        FD_SET(snet_fd(r.r_snet), &fdset);
        if ((r.r_dnsl_result == NULL) ||
                (strcmp((r.r_dnsl_result)->dnsl_action, "trust") != 0)) {
            simta_ucl_object_totimeval(
                    simta_config_obj("receive.connection.banner.delay"),
                    &tv_wait);

            if ((ret = select(snet_fd(r.r_snet) + 1, &fdset, NULL, NULL,
                         &tv_wait)) < 0) {
                syslog(LOG_ERR, "Syserror: smtp_receive select: %m");
                goto syserror;
            } else if (ret > 0) {
                r.r_write_before_banner = 1;
                syslog(LOG_INFO, "Connect.in [%s] %s: Write before banner",
                        r.r_ip, r.r_remote_hostname);
                if (simta_config_bool(
                            "receive.connection.banner.punish_writes")) {
                    set_smtp_mode(&r, simta_config_str("receive.punishment"),
                            "Write before banner");
                    sleep(1);
                }
            }
        }

        tarpit_sleep(&r);

        simta_debuglog(3, "Connect.in [%s] %s: sending banner", r.r_ip,
                r.r_remote_hostname);

        if (r.r_smtp_mode == SMTP_MODE_REFUSE) {
            if (snet_writef(r.r_snet, "554 <%s> %s %s: %s\r\n", simta_hostname,
                        S_DENIED, r.r_ip,
                        r.r_dnsl_result ? (r.r_dnsl_result)->dnsl_reason
                                        : "denied by local policy") < 0) {
                syslog(LOG_ERR, "Receive [%s] %s: smtp_receive snet_writef: %m",
                        r.r_ip, r.r_remote_hostname);
                goto closeconnection;
            }

        } else {
            if (smtp_write_banner(&r, 220, NULL, NULL) != RECEIVE_OK) {
                goto closeconnection;
            }
        }

        syslog(LOG_INFO, "Connect.in [%s] %s: Accepted", r.r_ip,
                r.r_remote_hostname);
    }

    /* Set up extensions */
    r.r_smtp_extensions = ucl_object_new();
    ucl_object_insert_key(
            r.r_smtp_extensions, ucl_object_new(), "8BITMIME", 0, false);
    ucl_object_insert_key(r.r_smtp_extensions,
            ucl_object_copy(
                    simta_config_obj("receive.data.limits.message_size")),
            "SIZE", 0, false);

    if (simta_config_bool("receive.auth.authn.enabled") &&
            simta_config_bool("receive.auth.authn.honeypot")) {
        ucl_object_insert_key(r.r_smtp_extensions,
                ucl_object_fromstring("LOGIN PLAIN"), "AUTH", 0, false);
    }

#ifdef HAVE_LIBSSL
    if (simta_config_bool("receive.tls.enabled")) {
        ucl_object_insert_key(
                r.r_smtp_extensions, ucl_object_new(), "STARTTLS", 0, false);
    }
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBOPENARC
    if (simta_config_bool("receive.arc.enabled")) {
        if ((r.r_arc = arc_init()) == NULL) {
            syslog(LOG_ERR, "Liberror: smtp_receive arc_init: failed");
            goto syserror;
        }
#ifdef HAVE_LIBOPENDKIM
        /* Only sign the headers recommended by RFC 6376 plus the headers
             * required by draft-ietf-dmarc-arc-protocol.
             */
        if (arc_options(r.r_arc, ARC_OP_SETOPT, ARC_OPTS_SIGNHDRS,
                    dkim_should_signhdrs,
                    sizeof(unsigned char **)) != ARC_STAT_OK) {
            syslog(LOG_ERR, "Liberror: smtp_receive arc_options");
            goto syserror;
        }
#endif /* HAVE_LIBOPENDKIM */
    }
#endif /* HAVE_LIBOPENARC */

#ifdef HAVE_LIBOPENDKIM
    if ((r.r_dkim = dkim_init(NULL, NULL)) == NULL) {
        syslog(LOG_ERR, "Liberror: smtp_receive dkim_init: failed");
        goto syserror;
    }
#endif /* HAVE_LIBOPENDKIM */

    tv_add.tv_usec = 0;
    calculate_timers = 1;

    for (;;) {
        if (simta_child_signal != 0) {
            if (simta_waitpid(0, NULL, WNOHANG) != 0) {
                goto syserror;
            }
        }

        if (simta_gettimeofday(&tv_now) == SIMTA_ERR) {
            goto syserror;
        }

        /* see if we need to calculate the timers */
        if (calculate_timers == 1) {
            /* command line timer */
            simta_ucl_object_totimeval(
                    simta_config_obj("receive.timeout.command"), &tv_add);
            timeradd(&tv_add, &tv_now, &tv_line);
            tv_timeout = &tv_line;
            timer_type = S_COMMAND_LINE;

            /* global session timer */
            if (r.r_tv_session.tv_sec == 0) {
                simta_ucl_object_totimeval(
                        simta_config_obj("receive.timeout.session"), &tv_add);
                timeradd(&tv_add, &tv_now, &r.r_tv_session);
            }
            if (timercmp(tv_timeout, &(r.r_tv_session), >)) {
                tv_timeout = &r.r_tv_session;
                timer_type = S_GLOBAL_SESSION;
            }

            /* inactivity timer */
            if (r.r_tv_inactivity.tv_sec == 0) {
                simta_ucl_object_totimeval(
                        simta_config_obj("receive.timeout.inactivity"),
                        &tv_add);
                timeradd(&tv_add, &tv_now, &r.r_tv_inactivity);
            }
            if (timercmp(tv_timeout, &r.r_tv_inactivity, >)) {
                tv_timeout = &r.r_tv_inactivity;
                timer_type = S_INACTIVITY;
            }

            /* message send timer - must calculate last */
            if ((r.r_tv_accepted.tv_sec != 0) &&
                    timercmp(tv_timeout, &r.r_tv_accepted, >)) {
                tv_fallback = tv_timeout;
                tv_timeout = &r.r_tv_accepted;
                fallback_type = timer_type;
                timer_type = S_ACCEPTED_MESSAGE;
            }
        }

        if (timercmp(&tv_now, tv_timeout, >)) {
            syslog(LOG_INFO, "Receive [%s] %s: Command: Timeout %s", r.r_ip,
                    r.r_remote_hostname, timer_type);

            if (strcmp(timer_type, S_ACCEPTED_MESSAGE) == 0) {
                if (deliver_accepted(&r, 1) != RECEIVE_OK) {
                    goto syserror;
                }
                tv_timeout = tv_fallback;
                timer_type = fallback_type;
                calculate_timers = 0;
                continue;
            }

            /* timeout */
            smtp_write_banner(&r, 421, S_TIMEOUT, S_CLOSING);
            goto closeconnection;
        }

        timersub(tv_timeout, &tv_now, &tv_wait);

        if ((line = snet_getline(r.r_snet, &tv_wait)) == NULL) {
            if (snet_eof(r.r_snet)) {
                syslog(LOG_ERR,
                        "Receive [%s] %s: Command: "
                        "unexpected EOF",
                        r.r_ip, r.r_remote_hostname);
            } else if ((errno == ETIMEDOUT) || (errno == EINTR)) {
                calculate_timers = 0;
                continue;
            } else {
                syslog(LOG_ERR, "Liberror: smtp_receive snet_getline: %m");
            }
            goto closeconnection;
        }

        calculate_timers = 1;

        if (r.r_smtp_command != NULL) {
            free(r.r_smtp_command);
            r.r_smtp_command = NULL;
        }

        r.r_smtp_command = simta_strdup(line);
        statsd_counter("receive.smtp_command", "total", 1);

        if ((r.r_ac = acav_parse2821(acav, line, &(r.r_av))) < 0) {
            syslog(LOG_ERR, "Receive [%s] %s: acav_parse2821 failed: %m",
                    r.r_ip, r.r_remote_hostname);
            goto syserror;
        }

        /* RFC 5321 2.4 General Syntax Principles and Transaction Model
         * In the absence of a server-offered extension explicitly permitting
         * it, a sending SMTP system is not permitted to send envelope commands
         * in any character set other than US-ASCII. Receiving systems
         * SHOULD reject such commands, normally using "500 syntax error
         * - invalid character" replies.
         */
        if (r.r_ac != 0) {
            for (i = 0; i < r.r_ncommands; i++) {
                if (strcasecmp(r.r_av[ 0 ], r.r_commands[ i ].c_name) == 0) {
                    break;
                }
            }
        }

        if ((r.r_ac == 0) || (i >= r.r_ncommands)) {
            if (r.r_smtp_mode == SMTP_MODE_DISABLED) {
                f_disabled(&r);
                goto closeconnection;
            }

            if (r.r_ac == 0) {
                syslog(LOG_NOTICE, "Receive [%s] %s: No Command", r.r_ip,
                        r.r_remote_hostname);
                statsd_counter("receive.smtp_command", "null", 1);
            } else {
                syslog(LOG_NOTICE, "Receive [%s] %s: Command unrecognized: %s",
                        r.r_ip, r.r_remote_hostname, r.r_smtp_command);
                statsd_counter("receive.smtp_command", "unknown", 1);
            }

            tarpit_sleep(&r);

            if (smtp_write_banner(&r, 500, NULL, NULL) != RECEIVE_OK) {
                goto closeconnection;
            }
            continue;
        }

        if (simta_gettimeofday(&tv_command_start) == SIMTA_ERR) {
            goto syserror;
        }

        ret = (*(r.r_commands[ i ].c_func))(&r);

        if (simta_gettimeofday(&tv_command_now) == SIMTA_ERR) {
            goto syserror;
        }

        statsd_timer("receive.smtp_command", r.r_commands[ i ].c_name,
                SIMTA_ELAPSED_MSEC(tv_command_start, tv_command_now));

        switch (ret) {
        case RECEIVE_OK:
            break;

        case RECEIVE_CLOSECONNECTION:
            goto closeconnection;

        default:
        /* fallthrough */
        case RECEIVE_SYSERROR:
            goto syserror;
        }

        if (deliver_accepted(&r, 0) != RECEIVE_OK) {
            goto syserror;
        }

        if ((r.r_smtp_mode == SMTP_MODE_NORMAL) &&
                ((r.r_dnsl_result == NULL) ||
                        (strcmp((r.r_dnsl_result)->dnsl_action, "trust") !=
                                0))) {
            if ((simta_config_int("receive.rcpt_to.max_failures") > 0) &&
                    ((r.r_rcpt_attempt - r.r_rcpt_success) >=
                            simta_config_int("receive.rcpt_to.max_failures"))) {
                syslog(LOG_NOTICE,
                        "Receive [%s] %s: Too many failed recipients", r.r_ip,
                        r.r_remote_hostname);
                set_smtp_mode(&r, simta_config_str("receive.punishment"),
                        "Failed recipients");
            }
            if ((simta_config_int("receive.mail_from.max_failures") > 0) &&
                    ((r.r_mail_attempt - r.r_mail_success) >=
                            simta_config_int(
                                    "receive.mail_from.max_failures"))) {
                syslog(LOG_NOTICE, "Receive [%s] %s: Too many failed senders",
                        r.r_ip, r.r_remote_hostname);
                set_smtp_mode(&r, simta_config_str("receive.punishment"),
                        "failed senders");
            }
        }
    }

syserror:
    smtp_write_banner(&r, 421, NULL, NULL);

closeconnection:
    if (snet_close(r.r_snet) != 0) {
        syslog(LOG_ERR, "Liberror: smtp_receive snet_close: %m");
    }
    r.r_snet = NULL;

    if (acav != NULL) {
        acav_free(acav);
    }

    if (r.r_smtp_command != NULL) {
        free(r.r_smtp_command);
        r.r_smtp_command = NULL;
    }

    if (r.r_hello != NULL) {
        free(r.r_hello);
    }

    if (tv_start.tv_sec != 0) {
        if (simta_gettimeofday(&tv_stop) == SIMTA_ERR) {
            tv_start.tv_sec = 0;
            tv_stop.tv_sec = 0;
        }
    }

    if (r.r_auth) {
        simta_debuglog(1,
                "Connect.stat [%s] %s: Metrics: "
                "milliseconds %ld, mail from %d/%d, rcpt to %d/%d, data %d/%d: "
                "Authuser %s",
                r.r_ip, r.r_remote_hostname,
                SIMTA_ELAPSED_MSEC(tv_start, tv_stop), r.r_mail_success,
                r.r_mail_attempt, r.r_rcpt_success, r.r_rcpt_attempt,
                r.r_data_success, r.r_data_attempt, r.r_auth_id);
    } else {
        simta_debuglog(1,
                "Connect.stat [%s] %s: Metrics: "
                "milliseconds %ld, mail from %d/%d, rcpt to %d/%d, data %d/%d",
                r.r_ip, r.r_remote_hostname,
                SIMTA_ELAPSED_MSEC(tv_start, tv_stop), r.r_mail_success,
                r.r_mail_attempt, r.r_rcpt_success, r.r_rcpt_attempt,
                r.r_data_success, r.r_data_attempt);
    }

    if (reset(&r) != 0) {
        return (RECEIVE_SYSERROR);
    }

    while ((simta_fast_files > 0) || (simta_proc_stab != NULL)) {
        if (simta_fast_files > 0) {
            /* if we have mail, try to deliver it */
            if (deliver_accepted(&r, 1) != RECEIVE_OK) {
                return (RECEIVE_SYSERROR);
            }
        }

        if (simta_proc_stab != NULL) {
            /* If we still have children, wait for at least one of them to
             * change state before looping again.
             */
            if (simta_waitpid(0, NULL, 0) != 0) {
                syslog(LOG_ERR, "Syserror: smtp_receive simta_waitpid: %m");
            }
        }
    }

#ifdef HAVE_LIBSSL
    md_cleanup(&r.r_md);
    md_cleanup(&r.r_md_body);
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBOPENARC
    if (r.r_arc) {
        arc_close(r.r_arc);
    }
#endif /* HAVE_LIBOPENARC */

#ifdef HAVE_LIBOPENDKIM
    if (r.r_dkim != NULL) {
        dkim_close(r.r_dkim);
    }
#endif /* HAVE_LIBOPENDKIM */

    if (r.r_dmarc) {
        dmarc_free(r.r_dmarc);
    }

    spf_free(r.r_spf);

    return (simta_fast_files);
}

static int
proxy_accept(struct receive_data *r) {
    /* Implements the PROXY protocol as specified in
     * proxy-protocol.txt (revised 2015-05-02) from HAProxy 1.6
     *
     * The PROXY protocol provides a convenient way to safely transport
     * connection information such as a client's address across multiple layers
     * of NAT or TCP proxies.
     */
    union {
        struct {
            char line[ SIMTA_PROXY_HEADERLEN ];
        } v1;
        struct {
            uint8_t  signature[ 12 ];
            uint8_t  command;
            uint8_t  family;
            uint16_t len;
            union {
                struct {
                    uint32_t src;
                    uint32_t dest;
                    uint16_t src_port;
                    uint16_t dest_port;
                } ipv4;
                struct {
                    uint8_t  src[ 16 ];
                    uint8_t  dest[ 16 ];
                    uint16_t src_port;
                    uint16_t dest_port;
                } ipv6;
            } addr;
        } v2;
    } header;
    struct timeval   tv_wait;
    ssize_t          rlen;
    int              rc;
    yastr *          split = NULL;
    size_t           tok_count = 0;
    char *           p;
    struct addrinfo  hints;
    struct addrinfo *ai;

    /* proxy-protocol.txt 2 The PROXY protocol header
     * The receiver may apply a short timeout and decide to abort the
     * connection if the protocol header is not seen within a few seconds
     * (at least 3 seconds to cover a TCP retransmit).
     */
    simta_ucl_object_totimeval(
            simta_config_obj("receive.connection.proxy.timeout"), &tv_wait);
    do {
        rlen = snet_read(
                r->r_snet, header.v1.line, SIMTA_PROXY_HEADERLEN, &tv_wait);
    } while ((rlen == -1) && (errno == EINTR));

    /* proxy-protocol.txt 2.2 Binary header format (version 2)
     * Identifying the protocol version is easy:
     * if the incoming byte count is 16 or above and the 13 first bytes match
     * the protocol signature block followed by the protocol [is] version 2
     */
    if ((rlen >= 16) &&
            (memcmp(header.v2.signature,
                     "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a",
                     12) == 0) &&
            ((header.v2.command & 0xf0) == 0x20)) {
        simta_debuglog(1, "Receive.PROXY [%s] %s: found v2 header", r->r_ip,
                r->r_remote_hostname);
        if (rlen < (header.v2.len + 16)) {
            syslog(LOG_ERR, "Receive.PROXY [%s] %s: truncated v2 header",
                    r->r_ip, r->r_remote_hostname);
            return (RECEIVE_CLOSECONNECTION);
        }

        switch (header.v2.command & 0x0f) {
        case 0x00:
            /* LOCAL */
            simta_debuglog(1,
                    "Receive.PROXY [%s] %s: LOCAL, keeping socket address",
                    r->r_ip, r->r_remote_hostname);
            return (RECEIVE_OK);
        case 0x01:
            /* PROXY */
            break;
        default:
            syslog(LOG_ERR, "Receive.PROXY [%s] %s: unknown command: %u",
                    r->r_ip, r->r_remote_hostname, header.v2.command & 0x0f);
            return (RECEIVE_CLOSECONNECTION);
        }

        switch (header.v2.family) {
        case 0x11: /* IPv4 */
            r->r_sa->sa_family = AF_INET;
            ((struct sockaddr_in *)r->r_sa)->sin_addr.s_addr =
                    header.v2.addr.ipv4.src;
            ((struct sockaddr_in *)r->r_sa)->sin_port =
                    header.v2.addr.ipv4.src_port;
            break;

        case 0x21: /* IPv6 */
            r->r_sa->sa_family = AF_INET6;
            memcpy(&((struct sockaddr_in6 *)r->r_sa)->sin6_addr,
                    header.v2.addr.ipv6.src, 16);
            ((struct sockaddr_in6 *)r->r_sa)->sin6_port =
                    header.v2.addr.ipv6.src_port;
            break;

        default:
            syslog(LOG_ERR,
                    "Receive.PROXY [%s] %s: unsupported address family: %u",
                    r->r_ip, r->r_remote_hostname, header.v2.family);
            return (RECEIVE_CLOSECONNECTION);
        }

        /* proxy-protocol.txt 2.2 Binary header format (version 2)
     * if the incoming byte count is 8 or above, and the 5 first characters
     * match the ASCII representation of "PROXY" then the protocol must be
     * parsed as version 1
     */
    } else if ((rlen >= 8) && (memcmp(header.v1.line, "PROXY", 5) == 0)) {
        simta_debuglog(1, "Receive.PROXY [%s] %s: found v1 header", r->r_ip,
                r->r_remote_hostname);

        p = memchr(header.v1.line, '\r', rlen - 1);
        if ((p == NULL) || (p[ 1 ] != '\n')) {
            syslog(LOG_ERR,
                    "Receive.PROXY [%s] %s: missing v1 header delimiter",
                    r->r_ip, r->r_remote_hostname);
            return (RECEIVE_CLOSECONNECTION);
        }
        *p = '\0';
        split = yaslsplitlen(
                header.v1.line, p - header.v1.line, " ", 1, &tok_count);

        /* This is a very rough ABNF representation, since the original docs
          * are overly verbose.
          *
          * v1-header   = "PROXY" SP ( v1-tcp / v1-unknown ) CRLF
          * v1-tcp      = ( "TCP4" / "TCP6" ) SP source-addr SP dest-addr SP source-port SP dest-port
          * v1-unknown  = "UNKNOWN" *( %d0-9 / %d11-12 / %d14-127 )
         */
        if ((tok_count > 1) && (strcmp(split[ 1 ], "UNKNOWN") == 0)) {
            syslog(LOG_NOTICE,
                    "Receive.PROXY [%s] %s: v1 UNKNOWN, keeping socket address",
                    r->r_ip, r->r_remote_hostname);
            yaslfreesplitres(split, tok_count);
            return (RECEIVE_OK);
        }

        if (tok_count != 6) {
            syslog(LOG_ERR, "Receive.PROXY [%s] %s: malformed v1 header: %s",
                    r->r_ip, r->r_remote_hostname, header.v1.line);
            yaslfreesplitres(split, tok_count);
            return (RECEIVE_CLOSECONNECTION);
        }

        memset(&hints, 0, sizeof(struct addrinfo));

        if (strcmp(split[ 1 ], "TCP4") == 0) {
            hints.ai_family = AF_INET;
        } else if (strcmp(split[ 1 ], "TCP6") == 0) {
            hints.ai_family = AF_INET6;
        } else {
            syslog(LOG_ERR,
                    "Receive.PROXY [%s] %s: unsupported address family: %s",
                    r->r_ip, r->r_remote_hostname, split[ 1 ]);
            yaslfreesplitres(split, tok_count);
            return (RECEIVE_CLOSECONNECTION);
        }

        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        if ((rc = getaddrinfo(split[ 2 ], split[ 4 ], &hints, &ai)) != 0) {
            syslog(LOG_ERR, "Syserror: proxy_accept getaddrinfo: %s",
                    gai_strerror(rc));
            yaslfreesplitres(split, tok_count);
            return (RECEIVE_SYSERROR);
        }

        memcpy(r->r_sa, ai->ai_addr,
                ((ai->ai_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                             : sizeof(struct sockaddr_in)));

        yaslfreesplitres(split, tok_count);
        split = NULL;

        /* proxy-protocol.txt 2.2 Binary header format (version 2)
     * otherwise the protocol is not covered by this specification and the
     * connection must be dropped.
     */
    } else {
        syslog(LOG_ERR, "Receive.PROXY [%s] %s: no header", r->r_ip,
                r->r_remote_hostname);
        return (RECEIVE_CLOSECONNECTION);
    }

    if ((rc = getnameinfo(r->r_sa,
                 ((r->r_sa->sa_family == AF_INET6)
                                 ? sizeof(struct sockaddr_in6)
                                 : sizeof(struct sockaddr_in)),
                 r->r_ip, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST)) != 0) {
        syslog(LOG_ERR, "Syserror: proxy_accept getnameinfo: %s",
                gai_strerror(rc));
        return (RECEIVE_SYSERROR);
    }

    syslog(LOG_INFO, "Receive.PROXY [%s] %s: connection info updated", r->r_ip,
            r->r_remote_hostname);

    return (RECEIVE_OK);
}


int
auth_init(struct receive_data *r, struct simta_socket *ss) {
#ifdef HAVE_LIBSSL
    SSL_CTX *ssl_ctx;
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSSL
    if (ss->ss_flags & SIMTA_SOCKET_TLS) {
        if ((ssl_ctx = tls_server_setup()) == NULL) {
            syslog(LOG_ERR, "Liberror: auth_init tls_server_setup: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            smtp_write_banner(r, 554, NULL, "SSL didn't work!");
            return (-1);
        }

        if (start_tls(r, ssl_ctx) != RECEIVE_OK) {
            smtp_write_banner(r, 554, NULL, "SSL didn't work!");
            SSL_CTX_free(ssl_ctx);
            return (-1);
        }

        SSL_CTX_free(ssl_ctx);

        syslog(LOG_INFO, "Connect.in [%s] %s: SMTS", r->r_ip,
                r->r_remote_hostname);
    }
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    if (simta_config_bool("receive.auth.authn.enabled") &&
            !simta_config_bool("receive.auth.authn.honeypot")) {
        set_smtp_mode(r, "unauthenticated", "Authentication");
        if ((r->r_sasl = simta_sasl_server_new(r->r_tls)) == NULL) {
            return (-1);
        }
        update_sasl_extension(r);
    }
#endif /* HAVE_LIBSASL */

    simta_debuglog(3, "Auth: init finished");

    return (0);
}


#ifdef HAVE_LIBSASL
static void
update_sasl_extension(struct receive_data *r) {
    const char *mechlist;
    if (simta_sasl_mechlist(r->r_sasl, &mechlist) != 0) {
        return;
    }
    ucl_object_replace_key(r->r_smtp_extensions,
            ucl_object_fromstring(mechlist), "AUTH", 0, false);
}
#endif /* HAVE_LIBSASL */


static simta_address_status
local_address(char *addr, char *domain, const ucl_object_t *red) {
    int                 n_required_found = 0;
    int                 rc;
    char *              at;
    struct passwd *     passwd;
    ucl_object_iter_t   iter = NULL;
    const ucl_object_t *rule = NULL;
    const char *        type = NULL;
#ifdef HAVE_LMDB
    yastr             key;
    yastr             value = NULL;
    struct simta_dbh *dbh = NULL;
    yastr             fname = NULL;
#endif /* HAVE_LMDB */

    if ((at = strchr(addr, '@')) == NULL) {
        return ADDRESS_NOT_FOUND;
    }

    /* RFC 5321 4.5.1 Minimum Implementation
     *
     * Any system that includes an SMTP server supporting mail relaying or
     * delivery MUST support the reserved mailbox "postmaster" as a case-
     * insensitive local name.  This postmaster address is not strictly
     * necessary if the server always returns 554 on connection opening (as
     * described in Section 3.1).  The requirement to accept mail for
     * postmaster implies that RCPT commands that specify a mailbox for
     * postmaster at any of the domains for which the SMTP server provides
     * mail service, as well as the special case of "RCPT TO:<Postmaster>"
     * (with no domain specification), MUST be supported.
     */
    if (strncasecmp(addr, "postmaster@", strlen("postmaster@")) == 0) {
        return ADDRESS_OK;
    }

    /* Search for user using expansion table */
    iter = ucl_object_iterate_new(ucl_object_lookup(red, "rule"));
    while ((rule = ucl_object_iterate_safe(iter, false)) != NULL) {
        if (!ucl_object_toboolean(
                    ucl_object_lookup_path(rule, "receive.enabled"))) {
            continue;
        }

        type = ucl_object_tostring(ucl_object_lookup(rule, "type"));

        if (strcasecmp(type, "accept") == 0) {
            return ADDRESS_OK;

#ifdef HAVE_LMDB
        } else if (strcasecmp(type, "alias") == 0) {
            fname = yaslauto(ucl_object_tostring(
                    ucl_object_lookup_path(rule, "alias.path")));
            fname = yaslcat(fname, ".db");
            if ((rc = simta_db_open_r(&dbh, fname)) != 0) {
                dbh = NULL;
                syslog(LOG_ERR,
                        "Liberror: local_address simta_db_open_r %s: %s", fname,
                        simta_db_strerror(rc));
                yaslfree(fname);
                break;
            }
            yaslfree(fname);

            if ((key = yaslnew(addr, (size_t)(at - addr))) == NULL) {
                return ADDRESS_SYSERROR;
            }
            rc = simta_db_get(dbh, key, &value);
            yaslfree(key);
            yaslfree(value);
            value = NULL;
            simta_db_close(dbh);

            if (rc == 0) {
                if (ucl_object_toboolean(ucl_object_lookup_path(
                            rule, "receive.sufficient"))) {
                    return ADDRESS_OK;
                } else {
                    n_required_found++;
                }
            } else if (rc == 1) {
                return ADDRESS_SYSERROR;
            } else if (ucl_object_toboolean(ucl_object_lookup_path(
                               rule, "receive.required"))) {
                return ADDRESS_OK;
            }
#endif /* HAVE_LMDB */

        } else if (strcasecmp(type, "password") == 0) {
            /* Check password file */
            *at = '\0';
            passwd = simta_getpwnam(ucl_object_tostring(ucl_object_lookup_path(
                                            rule, "password.path")),
                    addr);
            *at = '@';

            if (passwd != NULL) {
                if (ucl_object_toboolean(ucl_object_lookup_path(
                            rule, "receive.sufficient"))) {
                    return ADDRESS_OK;
                } else {
                    n_required_found++;
                }
            } else if (ucl_object_toboolean(ucl_object_lookup_path(
                               rule, "receive.required"))) {
                return ADDRESS_NOT_FOUND;
            }

        } else if (strcasecmp(type, "srs") == 0) {
            if ((rc = srs_valid(addr, ucl_object_tostring(ucl_object_lookup(
                                              rule, "secret")))) ==
                    ADDRESS_OK) {
                if (ucl_object_toboolean(ucl_object_lookup_path(
                            rule, "receive.sufficient"))) {
                    return ADDRESS_OK;
                } else {
                    n_required_found++;
                }
            } else if (rc == ADDRESS_SYSERROR) {
                return ADDRESS_SYSERROR;
            } else if (ucl_object_toboolean(ucl_object_lookup_path(
                               rule, "receive.required"))) {
                return ADDRESS_NOT_FOUND;
            }

#ifdef HAVE_LDAP
        } else if (strcasecmp(type, "ldap") == 0) {
            /* Check LDAP */
            *at = '\0';
            rc = simta_ldap_address_local(rule, addr, domain);
            *at = '@';

            switch (rc) {
            case ADDRESS_SYSERROR:
                return ADDRESS_SYSERROR;

            case ADDRESS_NOT_FOUND:
                if (ucl_object_toboolean(
                            ucl_object_lookup_path(rule, "receive.required"))) {
                    return ADDRESS_NOT_FOUND;
                }
                continue;

            default:
                if (ucl_object_toboolean(ucl_object_lookup_path(
                            rule, "receive.sufficient"))) {
                    return rc;
                } else {
                    n_required_found++;
                }
                break;
            }
#endif /* HAVE_LDAP */

        } else {
            syslog(LOG_ERR, "local_address: unknown expansion type %s", type);
            return ADDRESS_SYSERROR;
        }
    }

    if (n_required_found != 0) {
        return ADDRESS_OK;
    }

    return ADDRESS_NOT_FOUND;
}

#ifdef HAVE_LIBOPENDKIM
static const char *
simta_dkim_authresult_str(DKIM_SIGERROR dkim_error) {
    switch (dkim_error) {
    case DKIM_SIGERROR_EXPIRED:
    case DKIM_SIGERROR_BADSIG:
        return ("fail");
    case DKIM_SIGERROR_DNSSYNTAX:
    case DKIM_SIGERROR_KEYFAIL:
    case DKIM_SIGERROR_MULTIREPLY:
    case DKIM_SIGERROR_FUTURE:
        return ("temperror");
    case DKIM_SIGERROR_NOKEY:
        return ("permerror");
    }
    return ("neutral");
}
#endif /* HAVE_LIBOPENDKIM */

static const char *
iprev_authresult_str(struct receive_data *r) {
    /* RFC 7601 2.7.3 "iprev"
     * The result values used by the "iprev" method, defined in Section 3,
     * are as follows:
     */
    switch (r->r_dns_match) {
    /* pass: The DNS evaluation succeeded, i.e., the "reverse" and
     * "forward" lookup results were returned and were in agreement.
     */
    case REVERSE_MATCH:
        return ("pass");
    /* fail: The DNS evaluation failed. In particular, the "reverse" and
     * "forward" lookups each produced results, but they were not in agreement,
     * or the "forward" query completed but produced no result, e.g., a DNS
     * RCODE of 3, commonly known as NXDOMAIN, or an RCODE of 0 (NOERROR) in a
     * reply containing no answers, was returned.
     */
    case REVERSE_MISMATCH:
        return ("fail");
    /* temperror: The DNS evaluation could not be completed due to some error
     * that is likely transient in nature, such as a temporary DNS error, e.g.,
     * a DNS RCODE of 2, commonly known as SERVFAIL, or other error condition
     * resulted. A later attempt may produce a final result.
     */
    case REVERSE_ERROR:
        return ("temperror");
    /* permerror: The DNS evaluation could not be completed because no PTR data
     * are published for the connecting IP address, e.g., a DNS RCODE of 3,
     * commonly known as NXDOMAIN, or an RCODE of 0 (NOERROR) in a reply
     * containing no answers, was returned. This prevented completion of the
     * evaluation. A later attempt is unlikely to produce a final result.
     */
    case REVERSE_UNKNOWN:
        return ("permerror");
    }
    return ("INVALID");
}

yastr
env_string(const char *left, const char *right) {
    yastr buf;

    buf = yaslauto(left);
    buf = yaslcatlen(buf, "=", 1);
    if (right && (*right != '\0')) {
        buf = yaslcat(buf, right);
    }

    return (buf);
}

static int
content_filter(
        struct receive_data *r, char **smtp_message, struct timeval *tv) {
    int retval = MESSAGE_ACCEPT;

    if (!simta_config_bool("receive.data.content_filter.enabled")) {
        return MESSAGE_ACCEPT;
    }

    if (r->r_dnsl_result &&
            (strcmp(r->r_dnsl_result->dnsl_action, "trust") == 0)) {
        if (strcmp(simta_config_str("receive.data.content_filter.when"),
                    "untrusted") == 0) {
            syslog(LOG_INFO,
                    "Receive [%s] %s: env <%s>: "
                    "content filter skipped for trusted host",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id);
            return MESSAGE_ACCEPT;
        }
    }

    if (r->r_env->e_flags & ENV_FLAG_DFILE) {
        if (env_tfile(r->r_env) != SIMTA_OK) {
            return MESSAGE_TEMPFAIL;
        }

        if (simta_gettimeofday(tv) == SIMTA_ERR) {
            return MESSAGE_TEMPFAIL;
        }

        retval = run_content_filter(r, smtp_message);

        /* Filter out bad combinations */
        if (retval & MESSAGE_TEMPFAIL) {
            if (retval & MESSAGE_REJECT) {
                simta_debuglog(2,
                        "content_filter: "
                        "overriding TEMPFAIL && REJECT to just TEMPFAIL");
                /* Tempfail has priority */
                retval &= ~MESSAGE_REJECT;
            }
        }

        /* Set the default message */
        if ((retval != MESSAGE_ACCEPT) && (*smtp_message == NULL)) {
            *smtp_message = simta_strdup(
                    simta_config_str("receive.data.content_filter.message"));
        }
    }

    return retval;
}

static int
run_content_filter(struct receive_data *r, char **smtp_message) {
    int             fd[ 2 ];
    pid_t           pid;
    int             status;
    pid_t           rc;
    int             filter_envc = 0;
    SNET *          snet;
    const char *    mail_filter = NULL;
    char *          line;
    char *          filter_argv[] = {0, 0};
    char *          filter_envp[ 22 ];
    char            fname[ MAXPATHLEN + 1 ];
    char            buf[ 256 ];
    struct timespec log_ts;
#ifdef HAVE_LIBOPENDKIM
    struct dll_entry *dkim_domain;
    yastr             dkim_domains;
#endif /* HAVE_LIBOPENDKIM */

    if (pipe(fd) < 0) {
        syslog(LOG_ERR, "Syserror: content_filter pipe: %m");
        return (MESSAGE_TEMPFAIL);
    }

    mail_filter = simta_config_str("receive.data.content_filter.path");

    simta_gettimeofday(NULL);

    switch (pid = fork()) {
    case -1:
        close(fd[ 0 ]);
        close(fd[ 1 ]);
        syslog(LOG_ERR, "Syserror: content_filter fork: %m");
        return (MESSAGE_TEMPFAIL);

    case 0:
        log_ts = simta_log_ts;
        simta_openlog(true, 0);
        /* use fd[ 1 ] to communicate with parent, parent uses fd[ 0 ] */
        if (close(fd[ 0 ]) < 0) {
            syslog(LOG_ERR, "Syserror: content_filter close 1: %m");
            exit(MESSAGE_TEMPFAIL);
        }

        /* stdout -> fd[ 1 ] */
        if (dup2(fd[ 1 ], 1) < 0) {
            syslog(LOG_ERR, "Syserror: content_filter dup2 1: %m");
            exit(MESSAGE_TEMPFAIL);
        }

        /* stderr -> fd[ 1 ] */
        if (dup2(fd[ 1 ], 2) < 0) {
            syslog(LOG_ERR, "Syserror: content_filter dup2 2: %m");
            exit(MESSAGE_TEMPFAIL);
        }

        if (close(fd[ 1 ]) < 0) {
            syslog(LOG_ERR, "Syserror: content_filter close 2: %m");
            exit(MESSAGE_TEMPFAIL);
        }

        /* no stdin */
        if (close(0) < 0) {
            syslog(LOG_ERR, "Syserror: content_filter close 3: %m");
            exit(MESSAGE_TEMPFAIL);
        }

        filter_argv[ 0 ] = simta_strdup(mail_filter);
        if (strrchr(mail_filter, '/')) {
            filter_argv[ 0 ] = strrchr(filter_argv[ 0 ], '/') + 1;
        }

        if (r->r_env->e_flags & ENV_FLAG_DFILE) {
            snprintf(fname, MAXPATHLEN, "%s/D%s", r->r_env->e_dir,
                    r->r_env->e_id);
        } else {
            *fname = '\0';
        }

        filter_envp[ filter_envc++ ] = env_string("SIMTA_DFILE", fname);

        if (r->r_env->e_flags & ENV_FLAG_TFILE) {
            snprintf(fname, MAXPATHLEN, "%s/t%s", r->r_env->e_dir,
                    r->r_env->e_id);
        } else {
            *fname = '\0';
        }

        filter_envp[ filter_envc++ ] = env_string("SIMTA_TFILE", fname);

        filter_envp[ filter_envc++ ] = env_string("SIMTA_REMOTE_IP", r->r_ip);

        filter_envp[ filter_envc++ ] =
                env_string("SIMTA_REMOTE_HOSTNAME", r->r_remote_hostname);

        sprintf(buf, "%d", r->r_dns_match);
        filter_envp[ filter_envc++ ] = env_string("SIMTA_REVERSE_LOOKUP", buf);

        if (r->r_dnsl_result) {
            filter_envp[ filter_envc++ ] = env_string(
                    "SIMTA_DNSL_RESULT", r->r_dnsl_result->dnsl_action);
        }

        if (r->r_env->e_mail_orig) {
            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_SMTP_MAIL_FROM", r->r_env->e_mail_orig);
        } else {
            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_SMTP_MAIL_FROM", r->r_env->e_mail);
        }

        filter_envp[ filter_envc++ ] =
                env_string("SIMTA_SMTP_HELO", r->r_hello);

        filter_envp[ filter_envc++ ] =
                env_string("SIMTA_HEADER_FROM", r->r_env->e_header_from);

        filter_envp[ filter_envc++ ] = env_string("SIMTA_MID", r->r_env->e_mid);

        filter_envp[ filter_envc++ ] = env_string("SIMTA_UID", r->r_env->e_id);

        if (r->r_write_before_banner != 0) {
            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_WRITE_BEFORE_BANNER", "1");
        } else {
            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_WRITE_BEFORE_BANNER", "0");
        }

        filter_envp[ filter_envc++ ] =
                env_string("SIMTA_BAD_HEADERS", r->r_bad_headers ? "1" : "0");

        filter_envp[ filter_envc++ ] =
                env_string("SIMTA_AUTH_ID", r->r_auth_id);

        sprintf(buf, "%d", getpid());
        filter_envp[ filter_envc++ ] = env_string("SIMTA_PID", buf);

        sprintf(buf, "%ld", log_ts.tv_sec);
        filter_envp[ filter_envc++ ] = env_string("SIMTA_CID", buf);

#ifdef HAVE_LIBOPENDKIM
        if (r->r_dmarc) {
            dkim_domains = yaslempty();
            for (dkim_domain = r->r_dmarc->dkim_domain_list;
                    dkim_domain != NULL; dkim_domain = dkim_domain->dll_next) {
                dkim_domains = yaslcat(dkim_domains, dkim_domain->dll_key);
                if (dkim_domain->dll_next) {
                    dkim_domains = yaslcat(dkim_domains, " ");
                }
            }
            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_DKIM_DOMAINS", dkim_domains);
            yaslfree(dkim_domains);
        }
#endif /* HAVE_LIBOPENDKIM */

        if (r->r_spf) {
            filter_envp[ filter_envc++ ] = env_string(
                    "SIMTA_SPF_RESULT", spf_result_str(r->r_spf->spf_result));

            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_SPF_DOMAIN", r->r_spf->spf_domain);
        }

        if (r->r_dmarc) {
            filter_envp[ filter_envc++ ] = env_string(
                    "SIMTA_DMARC_RESULT", dmarc_result_str(r->r_dmarc_result));

            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_DMARC_DOMAIN", r->r_dmarc->domain);
        }

#ifdef HAVE_LIBSSL
        if (simta_config_bool("receive.data.checksum.enabled")) {
            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_CHECKSUM_SIZE", r->r_md.md_bytes);

            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_CHECKSUM", r->r_md.md_b16);

            filter_envp[ filter_envc++ ] = env_string(
                    "SIMTA_BODY_CHECKSUM_SIZE", r->r_md_body.md_bytes);

            filter_envp[ filter_envc++ ] =
                    env_string("SIMTA_BODY_CHECKSUM", r->r_md_body.md_b16);
        }
#endif /* HAVE_LIBSSL */

        filter_envp[ filter_envc ] = NULL;

        execve(mail_filter, filter_argv, filter_envp);
        /* if we are here, there is an error */
        syslog(LOG_ERR, "Syserror: content_filter execve: %m");
        exit(MESSAGE_TEMPFAIL);

    default:
        /* use fd[ 0 ] to communicate with child, child uses fd[ 1 ] */
        if (close(fd[ 1 ]) < 0) {
            syslog(LOG_ERR, "Syserror: content_filter close 4: %m");
            return (MESSAGE_TEMPFAIL);
        }

        if ((snet = snet_attach(fd[ 0 ], 1024 * 1024)) == NULL) {
            syslog(LOG_ERR, "Liberror: content_filter snet_attach: %m");
            close(fd[ 0 ]);
            return (MESSAGE_TEMPFAIL);
        }

        for (;;) {
            errno = 0;
            if ((line = snet_getline(snet, NULL)) != NULL) {
                syslog(LOG_INFO, "Filter [%s] %s: %s: %s", r->r_ip,
                        r->r_remote_hostname, r->r_env->e_id, line);
                if (*smtp_message == NULL) {
                    *smtp_message = simta_strdup(line);
                }
                continue;
            }

            if (errno == EINTR) {
                if (simta_child_signal != 0) {
                    errno = 0;
                    if ((simta_waitpid(pid, &status, WNOHANG) != 0) &&
                            (errno != EINTR)) {
                        syslog(LOG_ERR,
                                "Syserror: content_filter simta_waitpid: %m");
                        close(fd[ 0 ]);
                        return (MESSAGE_TEMPFAIL);
                    }
                }
                continue;
            }
            break;
        }

        if (snet_close(snet) < 0) {
            syslog(LOG_ERR, "Liberror: content_filter snet_close: %m");
            return (MESSAGE_TEMPFAIL);
        }

        errno = 0;
        while ((rc = simta_waitpid(pid, &status, 0)) != pid) {
            if ((rc < 0) && (errno != EINTR)) {
                syslog(LOG_ERR, "Syserror: content_filter simta_waitpid: %m");
                return (MESSAGE_TEMPFAIL);
            }
        }

        if (WIFEXITED(status)) {
            syslog(LOG_INFO,
                    "Receive [%s] %s: env <%s>: "
                    "content filter %s exited %d: %s",
                    r->r_ip, r->r_remote_hostname, r->r_env->e_id, mail_filter,
                    WEXITSTATUS(status),
                    *smtp_message ? *smtp_message : "no filter message");

            return (WEXITSTATUS(status));

        } else if (WIFSIGNALED(status)) {
            syslog(LOG_ERR, "Child: filter %d died with signal %d", pid,
                    WTERMSIG(status));
            return (MESSAGE_TEMPFAIL);

        } else {
            syslog(LOG_ERR, "Child: filter %d died", pid);
            return (MESSAGE_TEMPFAIL);
        }
    }
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
