/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     simta.h     *****/

#define	EMAIL_ADDRESS_NORMAL		0x0000
#define	RFC_2821_MAIL_FROM		0x0001
#define	RFC_2821_RCPT_TO		0x0010

/* These codes are for mail filter return values */
#define	MESSAGE_ACCEPT			0
#define	MESSAGE_TEMPFAIL		(1<<0)
#define	MESSAGE_REJECT			(1<<1)
#define	MESSAGE_DELETE			(1<<2)
#define	MESSAGE_DISCONNECT		(1<<3)
#define	MESSAGE_TARPIT			(1<<4)
#define	MESSAGE_JAIL			(1<<5)
#define	MESSAGE_BOUNCE			(1<<6)

#define	STRING_POSTMASTER		"postmaster"

#define SIMTA_LOG_ID_LEN		80
#define	SIMTA_FILE_CONFIG		"/etc/simta.conf"
#define	SIMTA_FILE_PID			"/var/run/simta.pid"
#define	SIMTA_BASE_DIR			"/var/spool/simta"
#define	SIMTA_BOUNCE_LINES		100
#define	SIMTA_EFILE_VERSION		3
#define SIMTA_MAX_RUNNERS_SLOW		250
#define SIMTA_MAX_RUNNERS_LOCAL		25
#define	SIMTA_EXPANSION_FAILED		0
#define	SIMTA_EXPANSION_SUCCESS		1
#define	SIMTA_LAUNCH_LIMIT		10
#define	SIMTA_MIN_WORK_TIME		300
#define	SIMTA_MAX_HOST_NAME_LEN	256

#define	EXIT_OK				0
#define	SIMTA_EXIT_OK			0
#define	SIMTA_EXIT_ERROR		1
#define	SIMTA_EXIT_OK_LEAKY		2

#define SIMTA_ERROR_NONE		0
#define SIMTA_ERROR_DNSR		1
#define SIMTA_ERROR_SYSTEM		-1

#define	PROCESS_DEFAULT			0
#define	PROCESS_Q_LOCAL			1
#define	PROCESS_Q_SLOW			2
#define	PROCESS_RECEIVE			3
#define	PROCESS_CLEANUP			4
#define	PROCESS_SMTP_SERVER		5
#define	PROCESS_Q_SCHEDULER		6

#define SERVICE_SUBMISSION_OFF		0
#define SERVICE_SUBMISSION_ON		1

#define	TEXT_WARNING	0
#define	TEXT_ERROR	1

#define SMTP_MODE_NORMAL		0
#define SMTP_MODE_OFF			1
#define SMTP_MODE_REFUSE		2
#define SMTP_MODE_GLOBAL_RELAY		3
#define SMTP_MODE_TEMPFAIL		4
#define SMTP_MODE_TARPIT		5
#define SMTP_MODE_NOAUTH		6

#ifdef HAVE_LIBSSL
#define SERVICE_SMTPS_OFF		0
#define SERVICE_SMTPS_SERVER		1
#define SERVICE_SMTPS_CLIENT_SERVER	2
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSSL
#define SIMTA_SOCKET_TLS	(1<<0)
#endif /* HAVE_LIBSSL */

struct proc_type {
    struct proc_type		*p_next;
    struct timeval		p_tv;
    struct simta_socket		*p_ss;
    struct connection_info	*p_cinfo;
    int				p_id;
    int				p_type;
    char			*p_host;
    int				*p_limit;
};

struct connection_info {
    struct connection_info	*c_next;
    struct sockaddr_in		c_sin;
    int				c_proc_total;
    int				c_proc_throttle;
    struct timeval		c_tv;
};

struct simta_socket {
    struct simta_socket		*ss_next;
    int				ss_socket;
    int				ss_port;
    char			*ss_service;
    int				ss_flags;
    int				ss_count;
};

/* global variables */

extern struct timeval			simta_global_throttle_tv;
extern struct timeval			simta_tv_now;
extern struct timeval			simta_log_tv;
extern struct timeval			simta_tv_mid;
extern struct host_q			*simta_deliver_q;
extern struct host_q			*simta_unexpanded_q;
extern struct host_q			*simta_punt_q;
extern struct host_q			*simta_host_q;
extern struct envelope			*simta_env_queue;
extern unsigned short			simta_smtp_port;
extern int				simta_bitbucket;
extern int				simta_aggressive_delivery;
extern int				simta_smtp_rcvbuf_min;
extern int				simta_smtp_rcvbuf_max;
extern int				simta_smtp_port_defined;
extern int				simta_rbl_verbose_logging;
extern int				simta_queue_incoming_smtp_mail;
extern int				simta_deliver_after_accept;
extern int				simta_leaky_queue;
extern int				simta_use_randfile;
extern int				simta_listen_backlog;
extern int				simta_disk_cycle;
extern int				simta_launch_limit;
extern int				simta_min_work_time;
extern int				simta_global_connections_max;
extern int				simta_global_connections;
extern int				simta_global_throttle_max;
extern int				simta_global_throttle_connections;
extern int				simta_global_throttle_sec;
extern int				simta_local_connections_max;
extern int				simta_local_throttle_max;
extern int				simta_local_throttle_sec;
extern int				simta_q_runner_local;
extern int				simta_q_runner_local_max;
extern int				simta_q_runner_slow;
extern int				simta_q_runner_slow_max;
extern unsigned int			simta_bounce_seconds;
extern int				simta_simsend_strict_from;
extern int				simta_exp_level_max;
extern int				simta_process_type;
extern int				simta_umich_imap_letters;
extern int				simta_filesystem_cleanup;
extern int				sitma_smtp_extension;
extern int				simta_strict_smtp_syntax;
extern int				simta_no_sync;
extern int				simta_ignore_reverse;
extern int				simta_ignore_connect_in_reverse_errors;
extern int				simta_inactivity_timer;
extern int				simta_receive_session_wait;
extern int				simta_receive_line_wait;
extern int				simta_data_transaction_wait;
extern int				simta_data_line_wait;
extern int				simta_message_count;
extern int				simta_max_received_headers;
extern int				simta_max_bounce_lines;
extern int				simta_smtp_outbound_attempts;
extern int				simta_smtp_outbound_delivered;
extern int				simta_read_before_banner;
extern int				simta_banner_delay;
extern int				simta_banner_punishment;
extern int				simta_max_failed_rcpts;
extern int				simta_dns_config;
extern int				simta_smtp_default_mode;
extern int				simta_smtp_punishment_mode;
extern int				simta_smtp_tarpit_default;
extern int				simta_smtp_tarpit_connect;
extern int				simta_smtp_tarpit_mail;
extern int				simta_smtp_tarpit_rcpt;
extern int				simta_smtp_tarpit_data;
extern int				simta_smtp_tarpit_data_eof;
extern int				simta_debug;
extern int				simta_expand_debug;
extern int				simta_verbose;
extern int				simta_fast_files;
extern int				simta_tls;
#ifdef HAVE_LIBSASL
extern int				simta_sasl;
#endif /* HAVE_LIBSASL */
#ifdef HAVE_LIBSSL
extern int				simta_service_smtps;
extern const EVP_MD				*simta_checksum_md;
extern char				*simta_checksum_algorithm;
#endif /* HAVE_LIBSSL */
extern int				simta_service_submission;
extern int				simta_smtp_extension;
extern long int				simta_max_message_size;
extern unsigned int			simta_max_message_size_value;
extern char				*simta_dir_fast;
extern char				*simta_dir_slow;
extern char				*simta_dir_dead;
extern char				*simta_dir_local;
extern char				*simta_data_url;
extern char				*simta_libwrap_url;
extern char				*simta_reverse_url;
extern char				*simta_domain;
extern char				*simta_mail_filter;
extern char				*simta_base_dir;
extern char				simta_hostname[];
extern char				*simta_punt_host;
extern char				*simta_jail_host;
extern struct rbl		        *simta_rbls;
extern struct rbl	         	*simta_user_rbls;
extern char				*simta_queue_filter;
extern char				*simta_default_alias_db;
extern char				*simta_default_passwd_file;
extern char				*simta_file_ca;
extern char				*simta_dir_ca;
extern char				*simta_file_cert;
extern char				*simta_file_private_key;
extern char				simta_log_id[];
char					*simta_postmaster;
extern DNSR				*simta_dnsr;
extern char				**simta_deliver_default_argv;
extern int				simta_deliver_default_argc;

int	q_cleanup( void );
int	smtp_receive( int, struct connection_info *, struct simta_socket * );
void	panic( char * );
char	*simta_sender( void );
char	*simta_resolvconf( void );
int	simta_init_hosts( void );
int	simta_config( char * );
int     simta_read_config( char * );
void	simta_openlog( int );
int	simta_gettimenow( void );

/*****     bounce.c     *****/

int bounce_text( struct envelope *, int, char *, char *, char * );
void bounce_stdout( struct envelope * );
ino_t bounce_dfile_out( struct envelope *, SNET * );
struct envelope *bounce( struct envelope *, struct host_q *, char * );
struct envelope *bounce_snet( struct envelope *, SNET *, struct host_q *,
	char *err );
