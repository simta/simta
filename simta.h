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


#define	SIMTA_EXPANSION_FAILED		0
#define	SIMTA_EXPANSION_SUCCESS		1
#define	SIMTA_FILE_CONFIG	"/etc/simta.conf"
#define	SIMTA_FILE_PID		"/var/run/simta.pid"
#define	SIMTA_DIR_LOCAL		"/var/spool/simta/local"
#define	SIMTA_DIR_FAST		"/var/spool/simta/fast"
#define	SIMTA_DIR_SLOW		"/var/spool/simta/slow"
#define SIMTA_DIR_LOG		"/var/simta/log"
#define	SIMTA_POSTMASTER	"postmaster"
#define	SIMTA_BOUNCE_LINES	100
#define	SIMTA_VERSION_STRING	"V0"
#define SIMTA_ALIAS_DB		"/etc/alias.db"
#define SIMTA_MAX_RUNNERS_SLOW	3
#define SIMTA_MAX_RUNNERS_LOCAL	3
#define SIMTA_MAX_LINE_LEN	1024


/* global variables */
extern int			simta_debug;
extern int			simta_verbose;
extern char			*simta_domain;
extern char			simta_hostname[];
extern char			*simta_punt_host;
extern struct host_q		*simta_null_q;
extern struct stab_entry	*simta_hosts;


char	*simta_sender ___P(( void ));
char	*simta_resolvconf ___P(( void ));
int	simta_init_hosts ___P(( void ));
int	simta_config ___P(( void ));
