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
#define SMTP_FAILED_FROM	"553"
#define SMTP_DISCONNECT 	"221"
#define SMTP_EOF         	"."

#define	SMTP_ERR_SYSCALL		-1
#define	SMTP_ERR_REMOTE			1
#define	SMTP_ERR_MESSAGE		2

#define	SMTP_ERR_NO_BOUNCE		1
#define	SMTP_ERR_BOUNCE_MESSAGE		2
#define	SMTP_ERR_BOUNCE_Q		3

#define	SMTP_TIME_CONNECT	60 * 5
#define	SMTP_TIME_HELO		60 * 5
#define	SMTP_TIME_MAIL		60 * 5
#define	SMTP_TIME_RCPT		60 * 5
#define	SMTP_TIME_DATA_INIT	60 * 2
#define	SMTP_TIME_DATA_EOF	60 * 10
#define	SMTP_TIME_RSET		60 * 5
#define	SMTP_TIME_QUIT		60 * 5

#define	SIMTA_SMTP_PORT		25

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */


void	stdout_logger ___P(( char * ));
int	smtp_eval ___P(( char *, char * ));

int	smtp_connect ___P(( SNET **, struct host_q * ));
int	smtp_rset ___P(( SNET *, struct host_q * ));
int	_smtp_send ___P(( SNET *, struct host_q *, struct envelope *, SNET * ));
int	_smtp_quit ___P(( SNET *, struct host_q * ));

int	smtp_quit ___P(( SNET *, char *, void (*)(char *)));
int	smtp_send ___P(( SNET *, char *, struct envelope *, SNET *,
		void (*)(char *)));
