/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.h     *****/


#define SMTP_CONNECT    	"22"
#define SMTP_OK         	"250"
#define SMTP_DATAOK         	"354"
#define SMTP_USER_UNKNOWN	"55"
#define SMTP_TEMPFAIL		"45"
#define SMTP_FAILED		"554"
#define SMTP_DISCONNECT 	"221"
#define SMTP_EOF         	"."

#define	SMTP_ERR_SYSCALL	-1
#define	SMTP_ERR_NO_BOUNCE	1
#define	SMTP_ERR_BOUNCE_Q	2

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */


void	stdout_logger ___P(( char * ));
int	smtp_eval ___P(( char *, char * ));

int	smtp_connect ___P(( SNET **, char *, int, void (*)(char *)));
int	smtp_rset ___P(( SNET *, char *, void (*)(char *)));
int	smtp_quit ___P(( SNET *, char *, void (*)(char *)));
int	smtp_send ___P(( SNET *, char *, struct envelope *, SNET *,
		void (*)(char *)));
