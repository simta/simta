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

#define	SIMTA_PATH_PIDFILE	"/var/run/simta.pid"
#define	SIMTA_DIR_LOCAL		"/var/spool/simta/local"
#define	SIMTA_DIR_FAST		"/var/spool/simta/fast"
#define	SIMTA_DIR_SLOW		"/var/spool/simta/slow"
#define	SIMTA_POSTMASTER	"postmaster"
#define	SIMTA_BOUNCE_LINES	100
#define	SIMTA_VERSION_STRING	"V0"
#define SIMTA_ALIAS_DB		"/etc/alias.db"

char	*simta_gethostname ___P(( void ));
char	*simta_local_domain ___P(( void ));
char	*simta_sender ___P(( void ));
char	*simta_resolvconf ___P(( void ));
int	simta_config_host ___P(( struct stab_entry **hosts, char *hostname ));
