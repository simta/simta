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

char	*simta_local_domain ___P(( void ));
char	*simta_sender ___P(( void ));
