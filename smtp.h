#define	SMTP_CONNECT		1
#define	SMTP_HELO		2
#define	SMTP_EHLO		3
#define	SMTP_MAIL		4
#define	SMTP_RCPT		5
#define	SMTP_DATA		6
#define	SMTP_DATA_EOF		7
#define	SMTP_RSET		8
#define	SMTP_QUIT		9
#define	SMTP_STARTTLS		10

#define	SMTP_OK			0
#define	SMTP_ERROR		1
#define	SMTP_BAD_CONNECTION	2
#define	SMTP_BAD_TLS		3

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
int	smtp_reply( int, struct host_q *, struct deliver * );
int	smtp_consume_banner ( struct line_file **, struct deliver *,
		char *, char * );

int	smtp_connect( struct host_q *, struct deliver * );
int	smtp_parse_ehlo_banner( struct deliver *, char * );
int	smtp_rset( struct host_q *, struct deliver * );
int	smtp_send( struct host_q *, struct deliver * );
void	smtp_quit( struct host_q *, struct deliver * );
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
