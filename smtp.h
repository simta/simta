/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.h     *****/


#define SMTP_DISCONNECT 	"221"
#define SMTP_CONNECT    	"220"
#define SMTP_OK         	"250"
#define SMTP_DATAOK         	"354"
#define SMTP_EOF         	"."

#define	SMTP_ERR_SYSCALL	-1
#define	SMTP_NO_ERROR		0
#define	SMTP_ERR_SYNTAX		1
#define	SMTP_ERR_MAIL_LOOP	2

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */


void	stdout_logger ___P(( char * ));

int	smtp_send_message ___P(( SNET *, struct message *, void (*)(char *)));
int	smtp_send_single_message ___P(( char *, int, struct message *,
		void (*)(char *)));

SNET	*smtp_connect ___P(( char *, int ));
int	smtp_helo ___P(( SNET *, void (*)(char *)));
int	smtp_send ___P(( SNET *, struct envelope *, SNET *,  void (*)(char *)));
int	smtp_rset ___P(( SNET *, void (*)(char *)));
int	smtp_quit ___P(( SNET *, void (*)(char *)));
