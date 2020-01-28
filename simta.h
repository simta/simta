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

#define S_UNEXPANDED "unexpanded"
#define S_UNKNOWN_HOST "Unknown host"

#define SIMTA_LOG_ID_LEN 80
#define SIMTA_EFILE_VERSION 5
#define SIMTA_MAX_HOST_NAME_LEN 256

#define EXIT_OK 0

enum simta_exit_codes {
    SIMTA_EXIT_OK,
    SIMTA_EXIT_ERROR,
    SIMTA_EXIT_OK_LEAKY, /* FIXME: can we do better IPC (e.g. structured
                             * output from the child) instead of non-zero "OK"
                             * statuses?
                             */
};

typedef enum {
    SIMTA_OK,
    SIMTA_ERR,
} simta_result;

enum simta_proc_type {
    PROCESS_DEFAULT,
    PROCESS_Q_LOCAL,
    PROCESS_Q_SLOW,
    PROCESS_RECEIVE,
    PROCESS_CLEANUP,
    PROCESS_SERVER,
};

#define TEXT_WARNING 0
#define TEXT_ERROR 1

/* Message checking */
#define SUBMISSION_MODE_MTA 0
#define SUBMISSION_MODE_MSA 1
#define SUBMISSION_MODE_SIMSEND 2
#define SUBMISSION_MODE_MTA_STRICT 3

#ifdef HAVE_LIBSSL
#define SIMTA_SOCKET_TLS (1 << 0)
#endif /* HAVE_LIBSSL */

enum simta_charset {
    SIMTA_CHARSET_ASCII,
    SIMTA_CHARSET_UTF8,
    SIMTA_CHARSET_INVALID,
};

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

extern const char *         simta_progname;
extern ucl_object_t *       simta_config;
extern struct dll_entry *   simta_env_list;
extern struct dll_entry *   simta_sender_list;
extern struct timeval       simta_global_throttle_tv;
extern struct timeval       simta_tv_now;
extern struct timeval       simta_log_tv;
extern struct host_q *      simta_deliver_q;
extern struct host_q *      simta_unexpanded_q;
extern struct host_q *      simta_punt_q;
extern ucl_object_t *       simta_host_q;
extern struct envelope *    simta_env_queue;
extern struct proc_type *   simta_proc_stab;
extern int                  simta_submission_mode;
extern int                  simta_command_read_entries;
extern int                  simta_disk_read_entries;
extern int                  simta_aggressive_expansion;
extern int                  simta_aggressive_receipt_max;
extern int                  simta_punt_policy;
extern int                  simta_smtp_rcvbuf_min;
extern int                  simta_smtp_rcvbuf_max;
extern int                  simta_leaky_queue;
extern int                  simta_listen_backlog;
extern int                  simta_disk_cycle;
extern int                  simta_launch_limit;
extern int                  simta_min_work_time;
extern int                  simta_unexpanded_time;
extern int                  simta_global_connections_max;
extern int                  simta_global_connections;
extern int                  simta_global_throttle_max;
extern int                  simta_global_throttle_connections;
extern int                  simta_global_throttle_sec;
extern int                  simta_local_connections_max;
extern int                  simta_local_throttle_max;
extern int                  simta_local_throttle_sec;
extern int                  simta_q_runner_local;
extern int                  simta_q_runner_local_max;
extern int                  simta_q_runner_slow;
extern int                  simta_q_runner_slow_max;
extern int                  simta_q_runner_receive_max;
extern int                  simta_bounce_seconds;
extern int                  simta_jail_seconds;
extern int                  simta_exp_level_max;
extern enum simta_proc_type simta_process_type;
extern int                  simta_umich_imap_letters;
extern int                  simta_filesystem_cleanup;
extern int                  simta_sync;
extern int                  simta_message_count;
extern int                  simta_max_received_headers;
extern int                  simta_max_bounce_size;
extern int                  simta_smtp_outbound_attempts;
extern int                  simta_smtp_outbound_delivered;
extern int                  simta_read_before_banner;
extern int                  simta_from_checking;
extern int                  simta_smtp_tarpit_default;
extern int                  simta_smtp_tarpit_connect;
extern int                  simta_smtp_tarpit_mail;
extern int                  simta_smtp_tarpit_rcpt;
extern int                  simta_smtp_tarpit_data;
extern int                  simta_smtp_tarpit_data_eof;
extern int                  simta_debug;
extern int                  simta_expand_debug;
extern int                  simta_child_signal;
extern int                  simta_fast_files;
extern int                  simta_tls;
#ifdef HAVE_LIBSASL
extern yastr simta_sasl_domain;
#endif /* HAVE_LIBSASL */
#ifdef HAVE_LIBSSL
extern char *simta_checksum_algorithm;
extern int   simta_checksum_body;
#endif /* HAVE_LIBSSL */
extern int               simta_smtp_extension;
extern int               simta_max_message_size;
extern int               simta_outbound_connection_msg_max;
extern yastr             simta_dir_fast;
extern yastr             simta_dir_slow;
extern yastr             simta_dir_dead;
extern yastr             simta_dir_local;
extern yastr             simta_dir_command;
extern char *            simta_data_url;
extern char *            simta_libwrap_url;
extern yastr             simta_hostname;
extern yastr             simta_punt_host;
extern yastr             simta_jail_host;
extern char *            simta_jail_bounce_address;
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
extern DNSR *            simta_dnsr;
extern yastr             simta_seen_before_domain;
extern ucl_object_t *    simta_publicsuffix_list;

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

int   q_cleanup(void);
int   smtp_receive(int, struct connection_info *, struct simta_socket *);
void  panic(const char *);
char *simta_resolvconf(void);
int   simta_init_hosts(void);
int   simta_read_config(const char *, const char *);
const ucl_object_t *simta_config_obj(const char *);
bool                simta_config_bool(const char *);
int64_t             simta_config_int(const char *);
const char *        simta_config_str(const char *);
void                simta_dump_config(void);
void                simta_openlog(int, int);
void                simta_debuglog(int, const char *, ...);
simta_result        simta_gettimeofday(struct timeval *);
enum simta_charset  simta_check_charset(const char *);
pid_t               simta_waitpid(pid_t, int *, int);
int                 simta_signal_server(int);
yastr               simta_slurp(const char *);
int                 simta_child_q_runner(struct host_q *);

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
