/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     simta.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */


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


/* global variables */
extern unsigned int			simta_bounce_seconds;
extern int				simta_ignore_reverse;
extern int				simta_receive_wait;
extern int				simta_message_count;
extern int				simta_smtp_outbound_attempts;
extern int				simta_smtp_outbound_delivered;
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
extern char				simta_hostname[];
extern char				simta_dname[];
extern char				simta_dname_slow[];
extern char				simta_ename[];
extern char				simta_ename_slow[];
extern char				*simta_punt_host;
extern struct host_q			*simta_null_q;
extern struct stab_entry		*simta_hosts;
char					*simta_postmaster;
extern DNSR				*simta_dnsr;

void	smtp_receive ___P(( int, struct sockaddr_in * ));
char	*simta_sender ___P(( void ));
char	*simta_resolvconf ___P(( void ));
int	simta_init_hosts ___P(( void ));
int	simta_config ___P(( char *, char * ));
