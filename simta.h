/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     simta.h     *****/

/* These codes are for mail filter return values */
#define	MESSAGE_ACCEPT			0
#define	MESSAGE_ACCEPT_AND_DELETE	1
#define	MESSAGE_REJECT			2
#define	MESSAGE_TEMPFAIL		4

#define	SIMTA_FILE_CONFIG		"/etc/simta.conf"
#define	SIMTA_FILE_PID			"/var/run/simta.pid"
#define	SIMTA_BASE_DIR			"/var/spool/simta"
#define	SIMTA_BOUNCE_LINES		100
#define	SIMTA_VERSION_STRING		"V0.1"
#define SIMTA_MAX_RUNNERS_SLOW		200
#define SIMTA_MAX_RUNNERS_LOCAL		25
#define SIMTA_MAX_LINE_LEN		1024
#define	SIMTA_EXPANSION_FAILED		0
#define	SIMTA_EXPANSION_SUCCESS		1

#define	EXIT_OK				1
#define	EXIT_FAST_FILE			2

#define SIMTA_ERROR_NONE		0
#define SIMTA_ERROR_DNSR		1
#define SIMTA_ERROR_SYSTEM		-1

/* global variables */

extern unsigned int			simta_bounce_seconds;
extern int				simta_no_sync;
extern int				simta_ignore_reverse;
extern int				simta_receive_wait;
extern int				simta_message_count;
extern int				simta_max_received_headers;
extern int				simta_max_bounce_lines;
extern int				simta_smtp_outbound_attempts;
extern int				simta_smtp_outbound_delivered;
extern int				simta_dns_config;
extern int				simta_global_relay;
extern int				simta_debug;
extern int				simta_expand_debug;
extern int				simta_verbose;
extern int				simta_fast_files;
extern char				*simta_dir_fast;
extern char				*simta_dir_slow;
extern char				*simta_dir_dead;
extern char				*simta_dir_local;
extern char				*simta_domain;
extern char				*simta_mail_filter;
extern char				simta_hostname[];
extern char				simta_dname[];
extern char				simta_dname_slow[];
extern char				simta_ename[];
extern char				simta_ename_slow[];
extern char				*simta_punt_host;
extern struct host_q			*simta_null_q;
extern struct stab_entry		*simta_hosts;
extern struct host			*simta_default_host;
char					*simta_postmaster;
extern DNSR				*simta_dnsr;
extern int				(*simta_local_mailer)(int, char *,
						struct recipient *);

void	smtp_receive ( int, struct sockaddr_in * );
void	panic ( char * );
char	*simta_sender ( void );
char	*simta_resolvconf ( void );
int	simta_init_hosts ( void );
int	simta_config( char *, char * );
int     simta_domain_config( char * );

/*****     bounce.c     *****/

int bounce_text( struct envelope *, char *, char *, char * );
void bounce_stdout( struct envelope * );
ino_t bounce_dfile_out( struct envelope *, SNET * );
struct envelope *bounce( struct host_q *, struct envelope *, SNET * );
