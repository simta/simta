/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     simta.h     *****/

#define SIMTA_OLD_EFILE_VERSION_1	0

#define	EMAIL_ADDRESS_NORMAL		0x0000
#define	RFC_2821_MAIL_FROM		0x0001
#define	RFC_2821_RCPT_TO		0x0010

/* These codes are for mail filter return values */
#define	MESSAGE_ACCEPT			0
#define	MESSAGE_ACCEPT_AND_DELETE	1
#define	MESSAGE_REJECT			2
#define	MESSAGE_TEMPFAIL		3

#define	STRING_POSTMASTER		"postmaster"

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
#define	SIMTA_MIN_WORK_TIME		60

#define	EXIT_OK				0

#define SIMTA_ERROR_NONE		0
#define SIMTA_ERROR_DNSR		1
#define SIMTA_ERROR_SYSTEM		-1

#define	PROCESS_DEFAULT			0
#define	PROCESS_Q_LOCAL			1
#define	PROCESS_Q_SLOW			2
#define	PROCESS_RECEIVE_SMTP		3
#define	PROCESS_RECEIVE_SMTPS		4
#define	PROCESS_RECEIVE_SUBMISSION	5
#define	PROCESS_CLEANUP			6
#define	PROCESS_SMTP_SERVER		7
#define	PROCESS_Q_SCHEDULER		8

#define SERVICE_SMTP_OFF		0
#define SERVICE_SMTP_ON			1
#define SERVICE_SMTP_REFUSE		2

#define SERVICE_SUBMISSION_OFF		0
#define SERVICE_SUBMISSION_ON		1

#define	TEXT_WARNING	0
#define	TEXT_ERROR	1

#ifdef HAVE_LIBSSL
#define SERVICE_SMTPS_OFF		0
#define SERVICE_SMTPS_SERVER		1
#define SERVICE_SMTPS_CLIENT_SERVER	2
#endif /* HAVE_LIBSSL */

/* global variables */

extern struct host_q			*simta_deliver_q;
extern struct host_q			*simta_unexpanded_q;
extern struct host_q			*simta_punt_q;
extern struct host_q			*simta_host_q;
extern struct envelope			*simta_env_queue;
extern int				simta_disk_cycle;
extern int				simta_disk_period;
extern int				simta_launch_limit;
extern int				simta_min_work_time;
extern int				simta_receive_connections_max;
extern int				simta_receive_connections;
extern int				simta_q_runner_local;
extern int				simta_q_runner_local_max;
extern int				simta_q_runner_slow;
extern int				simta_q_runner_slow_max;
extern unsigned int			simta_bounce_seconds;
extern int				simta_simsend_strict_from;
extern int				simta_exp_level_max;
extern int				simta_process_type;
extern int				simta_use_alias_db;
extern int				simta_umich_imap_letters;
extern int				simta_filesystem_cleanup;
extern int				sitma_smtp_extension;
extern int				simta_strict_smtp_syntax;
extern int				simta_no_sync;
extern int				simta_ignore_reverse;
extern int				simta_ignore_connect_in_reverse_errors;
extern int				simta_receive_wait;
extern int				simta_message_count;
extern int				simta_max_received_headers;
extern int				simta_max_bounce_lines;
extern int				simta_smtp_outbound_attempts;
extern int				simta_smtp_outbound_delivered;
extern int				simta_max_failed_rcpts;
extern int				simta_dns_config;
extern int				simta_global_relay;
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
#endif /* HAVE_LIBSSL */
extern int				simta_service_smtp;
extern int				simta_service_submission;
extern int				simta_smtp_extension;
extern long int				simta_max_message_size;
extern unsigned int			simta_max_message_size_value;
extern char				*simta_dir_fast;
extern char				*simta_dir_slow;
extern char				*simta_dir_dead;
extern char				*simta_dir_local;
extern char				*simta_reverse_url;
extern char				*simta_domain;
extern char				*simta_mail_filter;
extern char				*simta_base_dir;
extern char				simta_hostname[];
extern char				*simta_punt_host;
extern char				*simta_rbl_domain;
extern char				*simta_rbl_url;
extern char				*simta_user_rbl_domain;
extern char				*simta_user_rbl_url;
extern char				*simta_queue_filter;
char					*simta_postmaster;
extern DNSR				*simta_dnsr;
extern int				(*simta_local_mailer)(int, char *,
						struct recipient *);

int	q_cleanup( void );
int	smtp_receive ( int, struct sockaddr_in * );
void	panic ( char * );
char	*simta_sender ( void );
char	*simta_resolvconf ( void );
int	simta_init_hosts ( void );
int	simta_config( char * );
int     simta_read_config( char * );

/*****     bounce.c     *****/

int bounce_text( struct envelope *, int, char *, char *, char * );
void bounce_stdout( struct envelope * );
ino_t bounce_dfile_out( struct envelope *, SNET * );
struct envelope *bounce( struct host_q *, struct envelope *, SNET * );
