/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     smtp.h     *****/


#define	SMTP_CONNECT		1
#define	SMTP_HELO		2
#define	SMTP_MAIL		3
#define	SMTP_RCPT		4
#define	SMTP_DATA		5
#define	SMTP_DATA_EOF		6
#define	SMTP_RSET		7
#define	SMTP_QUIT		8

#define	SMTP_OK			0
#define	SMTP_ERROR		1
#define	SMTP_BAD_CONNECTION	2

#define	SMTP_TIME_CONNECT	60 * 5
#define	SMTP_TIME_HELO		60 * 5
#define	SMTP_TIME_MAIL		60 * 5
#define	SMTP_TIME_RCPT		60 * 5
#define	SMTP_TIME_DATA		60 * 2
#define	SMTP_TIME_DATA_EOF	60 * 10
#define	SMTP_TIME_RSET		60 * 5
#define	SMTP_TIME_QUIT		60 * 5

#define	SIMTA_SMTP_PORT		25

void	stdout_logger ( char * );
int	smtp_reply( int, SNET*, struct host_q *, struct deliver * );
int	smtp_consume_banner ( struct line_file **, SNET *,
		struct timeval *, char *, char * );


int	smtp_connect ( SNET **, struct host_q * );
int	smtp_rset ( SNET *, struct host_q * );
int	smtp_send ( SNET *, struct host_q *, struct deliver * );
void	smtp_quit ( SNET *, struct host_q * );
SNET *  _smtp_connect_snet( struct sockaddr_in *sin, char *hostname );
SNET *  _smtp_connect_try( struct sockaddr_in *sin, struct host_q *hq );
