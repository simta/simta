#ifndef SIMTA_SIMTA_H
#define SIMTA_SIMTA_H

#include <dirent.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/types.h>

#include <denser.h>
#include <snet.h>
#include <ucl.h>
#include <yasl.h>

#include "ll.h"
#include "simta_ucl.h"

#define EMAIL_ADDRESS_NORMAL 0x0000
#define RFC_821_MAIL_FROM 0x0001
#define RFC_821_RCPT_TO 0x0010

/* These codes are for mail filter return values */
#define MESSAGE_ACCEPT 0
#define MESSAGE_TEMPFAIL (1 << 0)
#define MESSAGE_REJECT (1 << 1)
#define MESSAGE_DELETE (1 << 2)
#define MESSAGE_DISCONNECT (1 << 3)
#define MESSAGE_TARPIT (1 << 4)
#define MESSAGE_JAIL (1 << 5)
#define MESSAGE_BOUNCE (1 << 6)

#define STRING_POSTMASTER "postmaster"
#define S_UNEXPANDED "unexpanded"
#define S_UNKNOWN_HOST "Unknown host"

#define SIMTA_LOG_ID_LEN 80
#define SIMTA_FILE_CONFIG "/etc/simta.conf"
#define SIMTA_FILE_PID "/var/run/simta.pid"
#define SIMTA_BASE_DIR "/var/spool/simta"
#define SIMTA_EFILE_VERSION 5
#define SIMTA_EXPANSION_FAILED 0
#define SIMTA_EXPANSION_SUCCESS 1
#define SIMTA_MAX_HOST_NAME_LEN 256

#define EXIT_OK 0
#define SIMTA_EXIT_OK 0
#define SIMTA_EXIT_ERROR 1
#define SIMTA_EXIT_OK_LEAKY 2

#define SIMTA_ERROR_NONE 0
#define SIMTA_ERROR_DNSR 1
#define SIMTA_ERROR_SYSTEM -1

#define PROCESS_DEFAULT 0
#define PROCESS_Q_LOCAL 1
#define PROCESS_Q_SLOW 2
#define PROCESS_RECEIVE 3
#define PROCESS_CLEANUP 4
#define PROCESS_SERVER 5

#define SERVICE_SUBMISSION_OFF 0
#define SERVICE_SUBMISSION_ON 1

#define TEXT_WARNING 0
#define TEXT_ERROR 1

#define SMTP_MODE_NORMAL 0
#define SMTP_MODE_OFF 1
#define SMTP_MODE_REFUSE 2
#define SMTP_MODE_GLOBAL_RELAY 3
#define SMTP_MODE_TEMPFAIL 4
#define SMTP_MODE_TARPIT 5
#define SMTP_MODE_NOAUTH 6
#define SMTP_MODE_INSECURE 7

#define SIMTA_SASL_OFF 0
#define SIMTA_SASL_ON 1
#define SIMTA_SASL_HONEYPOT 2

#ifdef HAVE_LIBSSL
#define SERVICE_SMTPS_OFF 0
#define SERVICE_SMTPS_SERVER 1
#define SERVICE_SMTPS_CLIENT_SERVER 2
#endif /* HAVE_LIBSSL */

/* TLS Policy */
#define TLS_POLICY_DEFAULT 0
#define TLS_POLICY_OPTIONAL 1
#define TLS_POLICY_REQUIRED 2
#define TLS_POLICY_DISABLED 3

/* Punting Policy */
#define PUNT_POLICY_NORMAL 0
#define PUNT_POLICY_ALL 1

#define DKIMSIGN_POLICY_OFF 0
#define DKIMSIGN_POLICY_ALWAYS 1
#define DKIMSIGN_POLICY_LOCAL 2
#define DKIMSIGN_POLICY_BOUNCES 3

#define DMARC_POLICY_OFF 0
#define DMARC_POLICY_ON 1
#define DMARC_POLICY_STRICT 2

/* Queue Policy */
#define QUEUE_POLICY_FIFO 0
#define QUEUE_POLICY_SHUFFLE 1

#define RQUEUE_POLICY_FAST 0
#define RQUEUE_POLICY_SLOW 1
#define RQUEUE_POLICY_JAIL 2

#define SPF_POLICY_OFF 0
#define SPF_POLICY_ON 1
#define SPF_POLICY_STRICT 2

/* SRS policy */
#define SRS_POLICY_OFF 0
#define SRS_POLICY_ALWAYS 1
#define SRS_POLICY_FOREIGN 2
#define SRS_POLICY_SMART 3

/* Message checking */
#define SUBMISSION_MODE_MTA 0
#define SUBMISSION_MODE_MSA 1
#define SUBMISSION_MODE_SIMSEND 2
#define SUBMISSION_MODE_MTA_STRICT 3

#ifdef HAVE_LIBSSL
#define SIMTA_SOCKET_TLS (1 << 0)
#endif /* HAVE_LIBSSL */

#define SIMTA_CHARSET_ASCII 0
#define SIMTA_CHARSET_UTF8 1
#define SIMTA_CHARSET_INVALID 2

#define S_ACCEPTED_MESSAGE "Accepted Message"
#define S_COMMAND_LINE "Command Line"
#define S_DATA_LINE "Data Line"
#define S_DATA_SESSION "Data Session"
#define S_DEBUG "Debug"
#define S_DISK "Disk"
#define S_GLOBAL_SESSION "Global Session"
#define S_INACTIVITY "Command Inactivity"
#define S_LIMITER "Limiter"
#define S_MESSAGE "Message"
#define S_QUEUE "queue"
#define S_SENDER "sender"
#define S_UNSET "Unset"

struct simta_dirp {
    DIR *          sd_dirp;
    char *         sd_dir;
    int            sd_cycle;
    int            sd_entries;
    struct timeval sd_tv_start;
    struct timeval sd_tv_next;
};

struct proc_type {
    struct proc_type *      p_next;
    struct timeval          p_tv;
    struct simta_socket *   p_ss;
    struct connection_info *p_cinfo;
    pid_t                   p_id;
    int                     p_type;
    char *                  p_host;
    int *                   p_limit;
};

struct connection_info {
    struct connection_info *c_next;
    struct sockaddr_storage c_sa;
    int                     c_proc_total;
    int                     c_proc_throttle;
    struct timeval          c_tv;
    char                    c_ip[ INET6_ADDRSTRLEN ];
};

struct simta_socket {
    struct simta_socket *ss_next;
    char *               ss_service;
    int                  ss_socket;
    int                  ss_flags;
    int                  ss_count;
};

/* global variables */

extern const char *      simta_progname;
extern ucl_object_t *    simta_config;
extern struct dll_entry *simta_env_list;
extern struct dll_entry *simta_sender_list;
extern struct timeval    simta_global_throttle_tv;
extern struct timeval    simta_tv_now;
extern struct timeval    simta_log_tv;
extern struct host_q *   simta_deliver_q;
extern struct host_q *   simta_unexpanded_q;
extern struct host_q *   simta_punt_q;
extern struct host_q *   simta_host_q;
extern struct envelope * simta_env_queue;
extern struct proc_type *simta_proc_stab;
extern int               simta_proxy;
extern int               simta_proxy_timeout;
extern int               simta_submission_mode;
extern int               simta_policy_tls;
extern int               simta_policy_tls_cert;
extern int               simta_wait_min;
extern int               simta_wait_max;
extern int               simta_bounce_jail;
extern int               simta_local_jail;
extern int               simta_sender_list_enable;
extern int               simta_mid_list_enable;
extern int               simta_command_read_entries;
extern int               simta_disk_read_entries;
extern int               simta_bitbucket;
extern int               simta_aggressive_delivery;
extern int               simta_aggressive_expansion;
extern int               simta_aggressive_receipt_max;
extern int               simta_queue_policy;
extern int               simta_rqueue_policy;
extern int               simta_punt_policy;
extern int               simta_smtp_rcvbuf_min;
extern int               simta_smtp_rcvbuf_max;
extern int               simta_leaky_queue;
extern int               simta_listen_backlog;
extern int               simta_disk_cycle;
extern int               simta_launch_limit;
extern int               simta_min_work_time;
extern int               simta_unexpanded_time;
extern int               simta_global_connections_max;
extern int               simta_global_connections;
extern int               simta_global_throttle_max;
extern int               simta_global_throttle_connections;
extern int               simta_global_throttle_sec;
extern int               simta_local_connections_max;
extern int               simta_local_throttle_max;
extern int               simta_local_throttle_sec;
extern int               simta_q_runner_local;
extern int               simta_q_runner_local_max;
extern int               simta_q_runner_slow;
extern int               simta_q_runner_slow_max;
extern int               simta_q_runner_receive_max;
extern int               simta_bounce_seconds;
extern int               simta_jail_seconds;
extern int               simta_exp_level_max;
extern int               simta_process_type;
extern int               simta_umich_imap_letters;
extern int               simta_filesystem_cleanup;
extern int               sitma_smtp_extension;
extern int               simta_strict_smtp_syntax;
extern int               simta_sync;
extern int               simta_ignore_reverse;
extern int               simta_ignore_connect_in_reverse_errors;
extern int               simta_message_count;
extern int               simta_max_received_headers;
extern int               simta_max_bounce_size;
extern int               simta_smtp_outbound_attempts;
extern int               simta_smtp_outbound_delivered;
extern int               simta_read_before_banner;
extern int               simta_banner_delay;
extern int               simta_banner_punishment;
extern int               simta_max_failed_rcpts;
extern int               simta_max_failed_senders;
extern int               simta_dns_auto_config;
extern int               simta_smtp_default_mode;
extern int               simta_smtp_punishment_mode;
extern int               simta_from_checking;
extern int               simta_smtp_tarpit_default;
extern int               simta_smtp_tarpit_connect;
extern int               simta_smtp_tarpit_mail;
extern int               simta_smtp_tarpit_rcpt;
extern int               simta_smtp_tarpit_data;
extern int               simta_smtp_tarpit_data_eof;
extern int               simta_debug;
extern int               simta_expand_debug;
extern int               simta_verbose;
extern int               simta_child_signal;
extern int               simta_fast_files;
extern int               simta_tls;
extern int               simta_sasl;
#ifdef HAVE_LIBSASL
extern yastr simta_sasl_domain;
#endif /* HAVE_LIBSASL */
#ifdef HAVE_LIBSSL
extern char *simta_port_smtps;
extern int   simta_service_smtps;
extern char *simta_checksum_algorithm;
extern int   simta_checksum_body;
#endif /* HAVE_LIBSSL */
extern char *            simta_port_smtp;
extern char *            simta_port_submission;
extern int               simta_service_smtp;
extern int               simta_service_submission;
extern int               simta_smtp_extension;
extern int               simta_max_message_size;
extern int               simta_outbound_connection_msg_max;
extern char *            simta_dir_fast;
extern char *            simta_dir_slow;
extern char *            simta_dir_dead;
extern char *            simta_dir_local;
extern char *            simta_dir_command;
extern char *            simta_data_url;
extern char *            simta_libwrap_url;
extern char *            simta_reverse_url;
extern yastr             simta_domain;
extern char *            simta_mail_filter;
extern int               simta_filter_trusted;
extern int               simta_spf;
extern int               simta_dmarc;
extern int               simta_auth_results;
extern char *            simta_base_dir;
extern char *            simta_file_pid;
extern yastr             simta_hostname;
extern yastr             simta_punt_host;
extern yastr             simta_jail_host;
extern char *            simta_jail_bounce_address;
extern struct dll_entry *simta_dnsl_chains;
extern int               simta_authz_default;
extern char *            simta_queue_filter;
extern char *            simta_default_alias_db;
extern char *            simta_default_alias_file;
extern char *            simta_default_passwd_file;
extern char *            simta_tls_ciphers;
extern char *            simta_tls_ciphers_outbound;
extern char *            simta_file_ca;
extern char *            simta_dir_ca;
extern char *            simta_file_cert;
extern char *            simta_file_private_key;
extern char              simta_log_id[];
extern yastr             simta_postmaster;
extern char              simta_subaddr_separator;
extern DNSR *            simta_dnsr;
extern yastr             simta_seen_before_domain;
extern struct dll_entry *simta_publicsuffix_list;
extern char *            simta_file_publicsuffix;

/* SMTP INBOUND & OUTBOUND TIMERS */
extern int simta_inbound_accepted_message_timer;
extern int simta_inbound_global_session_timer;
extern int simta_inbound_command_line_timer;
extern int simta_inbound_command_inactivity_timer;
extern int simta_inbound_data_line_timer;
extern int simta_inbound_data_session_timer;
extern int simta_inbound_ssl_accept_timer;

extern int simta_outbound_command_line_timer;
extern int simta_outbound_data_line_timer;
extern int simta_outbound_data_session_timer;
extern int simta_outbound_ssl_connect_timer;

extern int   simta_arc;
extern yastr simta_authres_domain;
#ifdef HAVE_LIBOPENARC
extern char *simta_arc_key;
extern char *simta_arc_selector;
extern yastr simta_arc_domain;
#endif /* HAVE_LIBOPENARC */

extern int simta_dkim_verify;
#ifdef HAVE_LIBOPENDKIM
extern int   simta_dkim_sign;
extern char *simta_dkim_key;
extern char *simta_dkim_selector;
extern yastr simta_dkim_domain;
#endif /* HAVE_LIBOPENDKIM */

extern int   simta_srs;
extern int   simta_srs_maxage;
extern yastr simta_srs_domain;
extern yastr simta_srs_secret;

int   q_cleanup(void);
int   smtp_receive(int, struct connection_info *, struct simta_socket *);
void  panic(const char *);
char *simta_sender(void);
char *simta_resolvconf(void);
int   simta_init_hosts(void);
int   simta_read_config(const char *);
void  simta_openlog(int, int);
void  simta_debuglog(int, const char *, ...);
int   simta_gettimeofday(struct timeval *);
int   simta_check_charset(const char *);
pid_t simta_waitpid(pid_t, int *, int);
yastr simta_slurp(char *);
int   simta_child_q_runner(struct host_q *);

#define SIMTA_ELAPSED_MSEC(a, b)                                               \
    (((((b).tv_sec * 1000)) + ((b).tv_usec / 1000)) -                          \
            ((((a).tv_sec * 1000)) + ((a).tv_usec / 1000)))

/*****     bounce.c     *****/

int bounce_yastr(struct envelope *, int, const yastr);
int bounce_text(
        struct envelope *, int, const char *, const char *, const char *);
void             bounce_stdout(struct envelope *);
ino_t            bounce_dfile_out(struct envelope *, SNET *);
struct envelope *bounce(struct envelope *, int, const char *);
struct envelope *bounce_snet(
        struct envelope *, SNET *, struct host_q *, const char *);

#endif /* SIMTA_SIMTA_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
