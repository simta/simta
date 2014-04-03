/* Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <db.h>
#include <dirent.h>

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#ifndef LIBWRAP_ALLOW_FACILITY
# define LIBWRAP_ALLOW_FACILITY LOG_AUTH
#endif
#ifndef LIBWRAP_ALLOW_SEVERITY
# define LIBWRAP_ALLOW_SEVERITY LOG_INFO
#endif
#ifndef LIBWRAP_DENY_FACILITY
# define LIBWRAP_DENY_FACILITY LOG_AUTH
#endif
#ifndef LIBWRAP_DENY_SEVERITY
# define LIBWRAP_DENY_SEVERITY LOG_WARNING
#endif
int allow_severity = LIBWRAP_ALLOW_FACILITY|LIBWRAP_ALLOW_SEVERITY;
int deny_severity = LIBWRAP_DENY_FACILITY|LIBWRAP_DENY_SEVERITY;
#endif /* HAVE_LIBWRAP */

#ifdef HAVE_LIBSSL 
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#include <sasl/saslutil.h>	/* For sasl_decode64 and sasl_encode64 */
#include "base64.h"
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "bdb.h"
#include "denser.h"
#include "ll.h"
#include "envelope.h"
#include "expand.h"
#include "red.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "mx.h"
#include "simta.h"
#include "queue.h"
#include "line_file.h"
#include "header.h"

#ifdef HAVE_LIBSSL 
#include "tls.h"
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#endif /* HAVE_LDAP */

#define BYTE_LEN		10

#define	MDCTX_UNINITILIZED	0
#define	MDCTX_READY		1
#define	MDCTX_IN_USE		2
#define	MDCTX_FINAL		3

#define SIMTA_EXTENSION_SIZE    (1<<0)

extern char		*version;

struct receive_data {
    SNET			*r_snet;
    struct envelope		*r_env;
    int				r_ac;
    char			**r_av;
    struct sockaddr_in  	*r_sin;
    int				r_write_before_banner;
    int				r_data_success;
    int				r_data_attempt;
    int				r_mail_success;
    int				r_mail_attempt;
    int				r_rcpt_success;
    int				r_rcpt_attempt;
    int				r_failed_rcpts;
    int				r_tls;
    int				r_auth;
    int				r_dns_match;
    int				r_rbl_status;
    struct rbl			*r_rbl;
    char			*r_rbl_msg;
    char			*r_hello;
    char			*r_smtp_command;
    char			*r_remote_hostname;
    struct command 		*r_commands;
    int				r_ncommands;
    int				r_smtp_mode;
    char			*r_auth_id;
    struct timeval		r_tv_inactivity;
    struct timeval		r_tv_session;
    struct timeval		r_tv_accepted;

#ifdef HAVE_LIBSSL
    unsigned char		r_md_value[ EVP_MAX_MD_SIZE ];
    char			r_md_b64[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 ];
    EVP_MD_CTX			r_mdctx;
    int				r_mdctx_status;
    unsigned int		r_mdctx_bytes;
    unsigned int				r_md_len;
    char			r_md_bytes[ BYTE_LEN + 1 ];
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    sasl_conn_t			*r_conn;
    /* external security strength factor zero = NONE */
    sasl_ssf_t			r_ext_ssf;
    sasl_security_properties_t	r_secprops;
#endif /* HAVE_LIBSASL */
};

#ifdef HAVE_LIBSASL
#define BASE64_BUF_SIZE 21848 /* per RFC 2222bis: ((16k / 3 ) +1 ) * 4 */
#endif /* HAVE_LIBSASL */

#define	RECEIVE_OK		0x0000
#define	RECEIVE_SYSERROR	0x0001
#define	RECEIVE_CLOSECONNECTION	0x0010

#define S_421_DECLINE "Service not available: closing transmission channel"
#define S_451_DECLINE "Requested action aborted: "\
	"service temporarily unavailable"
#define S_451_MESSAGE "Message Tempfailed"
#define S_554_MESSAGE "Message Failed"
#define S_MAXCONNECT "Maximum connections exceeded"
#define S_TIMEOUT "Connection length exceeded"
#define S_CLOSING "closing transmission channel"
#define S_UNKNOWN_HOST "Unknown host"
#define S_UNKNOWN string_unknown	/* "unknown" */
#define S_UNRESOLVED "Unresolved"
#define S_DENIED "Access denied for IP"

#define S_DATA_LINE "Data Line"
#define S_COMMAND_LINE "Command Line"
#define S_INACTIVITY "Command Inactivity"
#define S_ACCEPTED_MESSAGE "Accepted Message"
#define S_GLOBAL_SESSION "Global Session"
#define S_DATA_SESSION "Data Session"

#define _S_SMTP "SMTP"
#define _S_DATA "Data"

/* return codes for address_expand */
#define	LOCAL_ADDRESS			1
#define	NOT_LOCAL			2
#define	LOCAL_ERROR			3
#define	LOCAL_ADDRESS_RBL		4

#define NO_ERROR		0
#define PROTOCOL_ERROR		1
#define SYSTEM_ERROR		2

struct command {
    char	*c_name;
    int		(*c_func)( struct receive_data * );
};

static char 	*env_string( char *, char * );
static int	auth_init( struct receive_data *, struct simta_socket * );
static int	content_filter( struct receive_data *, char ** );
static int	local_address( char *, char *, struct simta_red *);
static int	hello( struct receive_data *, char * );
static int	reset( struct receive_data * );
static int	deliver_accepted( struct receive_data * );
static int	f_helo( struct receive_data * );
static int	f_ehlo( struct receive_data * );
static int	f_mail( struct receive_data * );
static int	f_rcpt( struct receive_data * );
static int	f_data( struct receive_data * );
static int	f_rset( struct receive_data * );
static int	f_noop( struct receive_data * );
static int	f_quit( struct receive_data * );
static int	f_help( struct receive_data * );
static int	f_not_implemented( struct receive_data * );
static int	f_noauth( struct receive_data * );
static int	f_bad_sequence( struct receive_data * );
static void	set_smtp_mode( struct receive_data *, int, char* );
static void	tarpit_sleep( struct receive_data *, int );
static void	log_bad_syntax( struct receive_data* );
static int 	smtp_write_banner( struct receive_data *, int, char *,
			char * );

#ifdef HAVE_LIBSASL
static int	f_auth( struct receive_data * );
static int 	reset_sasl_conn( struct receive_data *r );
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
static int	f_starttls( struct receive_data * );
static int	_start_tls( struct receive_data * );
static int 	_post_tls( struct receive_data * );
#endif /* HAVE_LIBSSL */

struct command	smtp_commands[] = {
    { "HELO",		f_helo },
    { "EHLO",		f_ehlo },
    { "MAIL",		f_mail },
    { "RCPT",		f_rcpt },
    { "DATA",		f_data },
    { "RSET",		f_rset },
    { "NOOP",		f_noop },
    { "QUIT",		f_quit },
    { "HELP",		f_help },
    { "VRFY",		f_not_implemented },
    { "EXPN",		f_not_implemented },
#ifdef HAVE_LIBSSL
    { "STARTTLS",	f_starttls },
#endif /* HAVE_LIBSSL */
#ifdef HAVE_LIBSASL
    { "AUTH", 		f_auth },
#endif /* HAVE_LIBSASL */
};

struct command	refuse_commands[] = {
    { "HELO",		f_bad_sequence },
    { "EHLO",		f_bad_sequence },
    { "MAIL",		f_mail },
    { "RCPT",		f_rcpt },
    { "DATA",		f_data },
    { "RSET",		f_bad_sequence },
    { "NOOP",		f_bad_sequence },
    { "QUIT",		f_quit },
    { "HELP",		f_bad_sequence },
    { "VRFY",		f_bad_sequence },
    { "EXPN",		f_bad_sequence },
#ifdef HAVE_LIBSSL
    { "STARTTLS",	f_bad_sequence },
#endif /* HAVE_LIBSSL */
#ifdef HAVE_LIBSASL
    { "AUTH", 		f_bad_sequence },
#endif /* HAVE_LIBSASL */
};

struct command	off_commands[] = {
    { "MAIL",		f_mail },
    { "RCPT",		f_rcpt },
    { "DATA",		f_data },
    { "QUIT",		f_quit },
};


char *smtp_mode_str[] = {
    "Normal",
    "Off",
    "Refuse",
    "Global_Relay",
    "Tempfail",
    "Tarpit",
    "NoAuth",
    NULL
};

char string_unknown[] = STRING_UNKNOWN;        /* also S_UNKNOWN */

    static void
set_smtp_mode( struct receive_data *r, int mode, char *msg )
{
    if ( r->r_smtp_mode == mode ) {
	if ( msg != NULL ) {
	    syslog( LOG_DEBUG, "Receive [%s] %s: SMTP mode %s: %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    smtp_mode_str[ mode ], msg );
	} else {
	    syslog( LOG_DEBUG, "Receive [%s] %s: SMTP mode %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    smtp_mode_str[ mode ]);
	}
    } else {
	if ( msg != NULL ) {
	    syslog( LOG_DEBUG, "Receive [%s] %s: "
		    "switching SMTP mode from %s to %s: %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    smtp_mode_str[ r->r_smtp_mode ], smtp_mode_str[ mode ],
		    msg );
	} else {
	    syslog( LOG_DEBUG, "Receive [%s] %s: "
		    "switching SMTP mode from %s to %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    smtp_mode_str[ r->r_smtp_mode ], smtp_mode_str[ mode ]);
	}
    }

    r->r_smtp_mode = mode;

    switch ( mode ) {
    default:
	syslog( LOG_WARNING, "Syserror set_smtp_mode: mode out of range: %d",
		mode );
	r->r_smtp_mode = SMTP_MODE_OFF;
	/* fall through to case SMTP_MODE_OFF */
    case SMTP_MODE_OFF:
	r->r_commands = off_commands;
	r->r_ncommands = sizeof( off_commands ) /
		sizeof( off_commands[ 0 ] );
	return;

    case SMTP_MODE_TEMPFAIL:
    case SMTP_MODE_GLOBAL_RELAY:
    case SMTP_MODE_TARPIT:
    case SMTP_MODE_NORMAL:
    case SMTP_MODE_NOAUTH:
	r->r_commands = smtp_commands;
	r->r_ncommands = sizeof( smtp_commands ) /
		sizeof( smtp_commands[ 0 ] );
	return;

    case SMTP_MODE_REFUSE:
	r->r_commands = refuse_commands;
	r->r_ncommands = sizeof( refuse_commands ) /
		sizeof( refuse_commands[ 0 ] );
	return;
    }
}


    int
deliver_accepted( struct receive_data *r )
{
    if (( r->r_env ) && ( r->r_env->e_flags & ENV_FLAG_EFILE )) {
	queue_envelope( r->r_env );
	r->r_env = NULL;
    }

    if ( q_runner() != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    return( RECEIVE_OK );
}


    int
reset( struct receive_data *r )
{
    if ( deliver_accepted( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    if ( r->r_env != NULL ) {
	syslog( LOG_INFO, "Receive [%s] %s: %s: Message Failed: Abandoned",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id );
	env_free( r->r_env );
	r->r_env = NULL;
    }

    return( RECEIVE_OK );
}


    static int
hello( struct receive_data *r, char *hostname )
{
    /* If we get "HELO" twice, just toss the new one */
    if ( r->r_hello == NULL ) {
	/*
	 * rfc1123 5.2.5: We don't check that the "HELO" domain matches
	 * anything like the hostname.  When we create the data file, we'll
	 * reverse the source IP address and thus determine what the
	 * "Received:" header should say.  Since mail clients don't send well
	 * formed "HELO", we won't even do syntax checks on av[ 1 ].
	 */
	if (( r->r_hello = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "Syserror helo: strdup: %m" );
	    return( RECEIVE_SYSERROR );
	}
    }

    return( RECEIVE_OK );
}


    static void
tarpit_sleep( struct receive_data *r, int seconds )
{
    struct timespec			t;

    if ( r->r_smtp_mode != SMTP_MODE_TARPIT ) {
	return;
    }

    if ( seconds > 0 ) {
	t.tv_sec = seconds;
    } else {
	t.tv_sec = simta_smtp_tarpit_default;
    }
    t.tv_nsec = 0;

    if ( nanosleep( &t, NULL ) != 0 ) {
	syslog( LOG_DEBUG, "Syserror tarpit_sleep: nanosleep: %m" );
    }
}


/*
 * SMTP Extensions RFC.
 */

    static void
log_bad_syntax( struct receive_data *r )
{
    syslog( LOG_DEBUG, "Receive [%s] %s: Bad syntax: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );
    return;
}


    static int
smtp_write_banner( struct receive_data *r, int reply_code, char *msg,
	char *arg )
{
    char				*boilerplate;
    int					ret = RECEIVE_OK;
    int					hostname = 0;

    switch ( reply_code ) {
    case 211:
	hostname = 1;
	boilerplate = "simta";
	break;

    case 220:
	hostname = 1;
	boilerplate = "Simple Internet Message Transfer Agent ready";
	break;

    case 221:
	hostname = 1;
	ret = RECEIVE_CLOSECONNECTION;
	boilerplate = "Service closing transmission channel";
	break;

    case 235:
	boilerplate = "Authentication successful";
	break;

    case 250:
	boilerplate = "OK";
	break;

    case 334:
	boilerplate = "";
	break;

    case 354:
	boilerplate = "Start mail input; end with <CRLF>.<CRLF>";
	break;

    default:
	syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
		"smtp_banner_message: reply_code out of range: %d",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		reply_code );
	reply_code = 421;
	/* fall through to 421 */
    case 421:
	boilerplate = "Local error in processing: closing transmission channel";
	ret = RECEIVE_CLOSECONNECTION;
	hostname = 1;
	break;

    case 451:
	boilerplate = "Local error in processing: requested action aborted";
	break;

    case 500:
	boilerplate = "Command unrecognized";
	break;

    case 501:
	boilerplate = "Syntax error in parameters or arguments";
	break;

    case 502:
	boilerplate = "Command not implemented";
	break;

    case 503:
	boilerplate = "Bad sequence of commands";
	break;

    case 504:
	boilerplate = "Unrecognized authentication type";
	break;

    case 530:
	boilerplate = "Authentication required";
	break;

    case 534:
	boilerplate = "Authentication mechanism is too weak";
	break;

    case 535:
	boilerplate = "Invalid initial-response argument for mechanism";
	break;

    case 538:
	boilerplate = "Encryption required for requested authentication "
		"mechanism";
	break;

    case 550:
	boilerplate = "Requested action failed";
	break;

    case 552:
	boilerplate = "Message exceeds fixed maximum message size";
	break;

    case 554:
	boilerplate = "Transaction failed";
	break;
    }

    if ( hostname ) {
	if ( arg != NULL ) {
	    if ( snet_writef( r->r_snet, "%d %s %s: %s\r\n", reply_code,
		    simta_hostname, msg ? msg : boilerplate, arg ) < 0 ) {
		syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
			"smtp_banner_message: snet_writef: %m",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname );
		return( RECEIVE_CLOSECONNECTION );
	    }

	} else {
	    if ( snet_writef( r->r_snet, "%d %s %s\r\n", reply_code,
		    simta_hostname, msg ? msg : boilerplate ) < 0 ) {
		syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
			"smtp_banner_message: snet_writef: %m",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname );
		return( RECEIVE_CLOSECONNECTION );
	    }
	}

    } else {
	if ( arg != NULL ) {
	    if ( snet_writef( r->r_snet, "%d %s: %s\r\n", reply_code,
		    msg ? msg : boilerplate, arg ) < 0 ) {
		syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
			"smtp_banner_message: snet_writef: %m",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname );
		return( RECEIVE_CLOSECONNECTION );
	    }

	} else {
	    if ( snet_writef( r->r_snet, "%d %s\r\n", reply_code,
		    msg ? msg : boilerplate ) < 0 ) {
		syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
			"smtp_banner_message: snet_writef: %m",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname );
		return( RECEIVE_CLOSECONNECTION );
	    }
	}
    }

    return( ret );
}


    static int
f_helo( struct receive_data *r )
{
    tarpit_sleep( r, 0 );

    if ( r->r_ac != 2 ) {
	log_bad_syntax( r );
	return( smtp_write_banner( r, 501, NULL,
		"RFC 2821 section 4.1.1.1: \"HELO\" SP Domain CRLF" ));
    }

    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    if ( hello( r, r->r_av[ 1 ] ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    return( smtp_write_banner( r, 250, "Hello", r->r_av[ 1 ]));
}


    static int
f_ehlo( struct receive_data *r )
{
    extern int		simta_smtp_extension;
    int			extension_count;
    const char		*mechlist;

    extension_count = simta_smtp_extension;

    tarpit_sleep( r, 0 );

    /* rfc 2821 4.1.4
     * A session that will contain mail transactions MUST first be
     * initialized by the use of the EHLO command.  An SMTP server SHOULD
     * accept commands for non-mail transactions (e.g., VRFY or EXPN)
     * without this initialization.
     */
    if ( r->r_ac != 2 ) {
	log_bad_syntax( r );
	return( smtp_write_banner( r, 501, NULL,
		"RFC 2821 section 4.1.1.1: \"EHLO\" SP Domain CRLF" ));
    }

    /* rfc 2821 4.1.4
     * An EHLO command MAY be issued by a client later in the session.  If
     * it is issued after the session begins, the SMTP server MUST clear all
     * buffers and reset the state exactly as if a RSET command had been
     * issued.  In other words, the sequence of RSET followed immediately by
     * EHLO is redundant, but not harmful other than in the performance cost
     * of executing unnecessary commands.
     */
    if ( reset( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    /* rfc 2821 3.6
     * The domain name given in the EHLO command MUST BE either a primary
     * host name (a domain name that resolves to an A RR) or, if the host
     * has no name, an address literal as described in section 4.1.1.1.
     */

    if ( hello( r, r->r_av[ 1 ] ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    if ( snet_writef( r->r_snet, "%d%s%s Hello %s\r\n", 250,
	    extension_count-- ? "-" : " ",
	    simta_hostname, r->r_av[ 1 ]) < 0 ) {
	syslog( LOG_DEBUG, "Syserror f_ehlo: snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    if ( simta_max_message_size >= 0 ) {
	if ( snet_writef( r->r_snet, "%d%sSIZE=%d\r\n", 250,
		extension_count-- ? "-" : " ",
		simta_max_message_size ) < 0 ) {
	    syslog( LOG_DEBUG, "Syserror f_ehlo: snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
    }

#ifdef HAVE_LIBSASL
    if ( simta_sasl ) {
	if ( sasl_listmech( r->r_conn, NULL, "", " ", "", &mechlist, NULL,
		NULL ) != SASL_OK ) {
	    syslog( LOG_ERR, "Syserror f_ehlo: sasl_listmech: %s",
		    sasl_errdetail( r->r_conn ));
	    return( RECEIVE_SYSERROR );
	}
	if ( snet_writef( r->r_snet, "250%sAUTH %s\r\n", 
		    extension_count-- ? "-" : " ", mechlist ) < 0 ) {
	    syslog( LOG_DEBUG, "Syserror f_ehlo: snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
    }
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
    /* RFC 2487 4.2 
     * A server MUST NOT return the STARTTLS extension in response to an
     * EHLO command received after a TLS handshake has completed.
     */
    if ( simta_tls && !r->r_tls ) {
	if ( snet_writef( r->r_snet, "%d%sSTARTTLS\r\n", 250,
		    extension_count-- ? "-" : " " ) < 0 ) {
	    syslog( LOG_DEBUG, "Syserror f_ehlo: snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
    }
#endif /* HAVE_LIBSSL */

    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    return( RECEIVE_OK );
}


    static int
f_mail_usage( struct receive_data *r )
{
    log_bad_syntax( r );

    if ( snet_writef( r->r_snet,
	    "501-Syntax violates RFC 2821 section 4.1.1.2:\r\n"
	    "501-     \"MAIL FROM:\" (\"<>\" / Reverse-Path ) "
	    "[ SP Mail-parameters ] CRLF\r\n"
	    "501-         Reverse-path = Path\r\n"
	    "501          Path = \"<\" [ A-d-l \":\" ] Mailbox \">\"\r\n"
	    ) < 0 ) {
	syslog( LOG_DEBUG, "Syserror f_mail_usage: snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    if ( deliver_accepted( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    return( RECEIVE_OK );
}


    static int
f_mail( struct receive_data *r )
{
    int			rc;
    int			i;
    int			parameters;
    int			seen_extensions = 0;
    long int		message_size;
    char		*addr;
    char		*domain;
    char		*endptr;

    r->r_mail_attempt++;

    if ( r->r_smtp_mode == SMTP_MODE_OFF ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: SMTP_Off: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_smtp_command );
	return( smtp_write_banner( r, 421, S_421_DECLINE, NULL ));
    }

    tarpit_sleep( r, simta_smtp_tarpit_mail );

    if ( r->r_ac < 2 ) {
	return( f_mail_usage( r ));
    }

    if (( !simta_strict_smtp_syntax ) && ( r->r_ac >= 3 ) &&
	    ( strcasecmp( r->r_av[ 1 ], "FROM:" ) == 0 )) {
	/* r->r_av[ 1 ] = "FROM:", r->r_av[ 2 ] = "<ADDRESS>" */
	if ( parse_emailaddr( RFC_2821_MAIL_FROM, r->r_av[ 2 ], &addr,
		&domain ) != 0 ) {
	    return( f_mail_usage( r ));
	}
	parameters = 3;

    } else {
	if ( strncasecmp( r->r_av[ 1 ], "FROM:", strlen( "FROM:" )) != 0 ) {
	    return( f_mail_usage( r ));
	}

	/* r->r_av[ 1 ] = "FROM:<ADDRESS>" */
	if ( parse_emailaddr( RFC_2821_MAIL_FROM,
		r->r_av[ 1 ] + strlen( "FROM:" ), &addr, &domain ) != 0 ) {
	    return( f_mail_usage( r ));
	}
    	parameters = 2;
    }

    for ( i = parameters; i < r->r_ac; i++ ) {
	if ( strncasecmp( r->r_av[ i ], "SIZE", strlen( "SIZE" )) == 0 ) {
	    /* RFC 1870 Message Size Declaration */
	    if ( seen_extensions & SIMTA_EXTENSION_SIZE ) {
		syslog( LOG_DEBUG, "Receive [%s] %s: "
			"duplicate SIZE specified: %s",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_smtp_command );
		return( smtp_write_banner( r, 501, NULL,
			"duplicate SIZE specified" ));
	    } else {
		seen_extensions = seen_extensions | SIMTA_EXTENSION_SIZE;
	    }

	    if ( strncasecmp( r->r_av[ i ], "SIZE=", strlen( "SIZE=" )) != 0 ) {
		syslog( LOG_DEBUG, "Receive [%s] %s: "
			"invalid SIZE parameter: %s",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_smtp_command );
		return( smtp_write_banner( r, 501, NULL,
			"invalid SIZE command" ));
	    }

	    if ( simta_max_message_size > 0 ) {
		message_size = strtol( r->r_av[ i ] + strlen( "SIZE=" ),
			&endptr, 10 );

		if (( *(r->r_av[ i ] + strlen( "SIZE=" )) == '\0' )
			|| ( *endptr != '\0' )
			|| ( message_size == LONG_MIN )
			|| ( message_size == LONG_MAX ) 
			|| ( message_size < 0 )) {
		    syslog( LOG_DEBUG, "Receive [%s] %s: "
			    "invalid SIZE parameter: %s",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname, r->r_smtp_command );
		    return( smtp_write_banner( r, 501,
			    "Syntax Error: invalid SIZE parameter",
			    r->r_av[ i ] + strlen( "SIZE=" )));
		}

		if ( message_size > simta_max_message_size ) {
		    syslog( LOG_DEBUG, "Receive [%s] %s: "
			    "message SIZE too large: %s",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname, r->r_smtp_command );
		    return( smtp_write_banner( r, 552, NULL, NULL ));
		}
	    }

	} else {
	    syslog( LOG_DEBUG, "Receive [%s] %s: "
		    "unsupported SMTP extension: %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_smtp_command );

	    return( smtp_write_banner( r, 501, "Syntax Error: "
		    "unsupported SMPT service extension", r->r_av[ i ] ));
	}
    }

    /*
     * rfc1123 (5.3.2) Timeouts in SMTP.  We have a maximum of 5 minutes
     * before we must return something to a "MAIL" command.  Soft failures
     * can either be accepted (trusted) or the soft failures can be passed
     * along.  "451" is probably the correct error.
     */

    switch ( r->r_smtp_mode ) {
    default:
	syslog( LOG_ERR, "Syserror: Receive [%s] %s: From <%s>: "
		"smtp_mode out of range: %d",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		addr, r->r_smtp_mode );
	return( RECEIVE_SYSERROR );

    case SMTP_MODE_TEMPFAIL:
	syslog( LOG_DEBUG, "Receive [%s] %s: From <%s>: Tempfail",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, addr );
	return( smtp_write_banner( r, 451, S_451_DECLINE, NULL ));

    case SMTP_MODE_NOAUTH:
	syslog( LOG_DEBUG, "Receive [%s] %s: From <%s>: NoAuth",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, addr );
	return( smtp_write_banner( r, 530, NULL, NULL ));

    case SMTP_MODE_REFUSE:
	syslog( LOG_DEBUG, "Receive [%s] %s: From <%s>: Refused",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, addr );
	return( smtp_write_banner( r, 503, NULL, NULL ));

    case SMTP_MODE_TARPIT:
	break;

    case SMTP_MODE_GLOBAL_RELAY:
    case SMTP_MODE_NORMAL:
	if ( simta_from_checking == 0 ) {
	    break;
	}
	if ( domain == NULL ) {
	    break;
	}
	if (( rc = check_hostname( domain )) == 0 ) {
	    break;
	}
	if ( rc < 0 ) {
	    syslog( LOG_ERR, "Syserror f_mail: check_hostname %s: failed",
		    domain );
	    return( smtp_write_banner( r, 451, NULL, NULL ));
	}
	syslog( LOG_DEBUG, "Receive [%s] %s: From <%s>: Unknown host: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, addr,
		domain );
	return( smtp_write_banner( r, 550, S_UNKNOWN_HOST, domain ));
    }

    /*
     * Contrary to popular belief, it is not an error to give more than
     * one "MAIL FROM:" command.  According to rfc822, this is just like
     * "RSET".
     */
    if ( reset( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    if (( r->r_env = env_create( simta_dir_fast, NULL, addr, NULL )) == NULL ) {
	return( RECEIVE_SYSERROR );
    }

#ifdef HAVE_LIBSSL 
    if (( simta_mail_filter != NULL ) && ( simta_checksum_md != NULL )) {
	if ( r->r_mdctx_status != MDCTX_READY ) {
	    if ( r->r_mdctx_status == MDCTX_UNINITILIZED ) {
		EVP_MD_CTX_init( &r->r_mdctx );
	    } else if ( r->r_mdctx_status == MDCTX_IN_USE ) {
		EVP_DigestFinal_ex( &r->r_mdctx, r->r_md_value, &r->r_md_len );
	    }

	    EVP_DigestInit_ex( &r->r_mdctx, simta_checksum_md, NULL);
	    r->r_mdctx_status = MDCTX_READY;
	    r->r_mdctx_bytes = 0;
	}
    }
#endif /* HAVE_LIBSSL */

    if ( r->r_smtp_mode != SMTP_MODE_TARPIT ) {
	r->r_mail_success++;
	syslog( LOG_NOTICE, "Receive [%s] %s: %s: From <%s>: Accepted",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_mail );
    } else {
	syslog( LOG_NOTICE, "Receive [%s] %s: %s: From <%s>: Tarpit",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_mail );
    }

    r->r_tv_inactivity.tv_sec = 0;
    return( smtp_write_banner( r, 250, NULL, NULL ));
}


    static int
f_rcpt_usage( struct receive_data *r )
{
    log_bad_syntax( r );

    if ( snet_writef( r->r_snet,
	    "501-Syntax violates RFC 2821 section 4.1.1.3:\r\n"
	    "501-     \"RCPT TO:\" (\"<Postmaster@\" domain \">\" / "
	    "\"<Postmaster>\" / Forward-Path ) "
	    "[ SP Rcpt-parameters ] CRLF\r\n"
	    "501-         Forward-path = Path\r\n"
	    "501          Path = \"<\" [ A-d-l \":\" ] Mailbox \">\"\r\n"
	    ) < 0 ) {
	syslog( LOG_DEBUG, "Syserror f_rcpt_usage: snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}


    static int
f_rcpt( struct receive_data *r )
{
    int				addr_len;
    int				rc;
    char			*addr;
    char			*domain;
    struct simta_red		*red;

    r->r_rcpt_attempt++;

    if ( r->r_smtp_mode == SMTP_MODE_OFF ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: SMTP_Off: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_smtp_command );
	return( smtp_write_banner( r, 421, S_421_DECLINE, NULL ));
    }

    tarpit_sleep( r, simta_smtp_tarpit_rcpt );

    /* Must already have "MAIL FROM:", and no valid message */
    if (( r->r_env == NULL ) ||
	    (( r->r_env->e_flags & ENV_FLAG_EFILE ) != 0 )) {
	return( f_bad_sequence( r ));
    }

    if ( r->r_ac == 2 ) {
	if ( strncasecmp( r->r_av[ 1 ], "TO:", 3 ) != 0 ) {
	    return( f_rcpt_usage( r ));
	}

	if ( parse_emailaddr( RFC_2821_RCPT_TO, r->r_av[ 1 ] + 3, &addr,
		&domain ) != 0 ) {
	    return( f_rcpt_usage( r ));
	}

    } else if (( simta_strict_smtp_syntax == 0 ) && ( r->r_ac == 3 )) {
	if ( strcasecmp( r->r_av[ 1 ], "TO:" ) != 0 ) {
	    return( f_rcpt_usage( r ));
	}

	if ( parse_emailaddr( RFC_2821_RCPT_TO, r->r_av[ 2 ], &addr,
		&domain ) != 0 ) {
	    return( f_rcpt_usage( r ));
	}

    } else {
	return( f_rcpt_usage( r ));
    }

    /* rfc 2821 3.7
     * SMTP servers MAY decline to act as mail relays or to
     * accept addresses that specify source routes.  When route information
     * is encountered, SMTP servers are also permitted to ignore the route
     * information and simply send to the final destination specified as the
     * last element in the route and SHOULD do so.
     */

    /*
     * We're not currently going to parse for the "%-hack".  This sort
     * of relay is heavily discouraged due to SPAM abuses.
     */

    /*
     * Again, soft failures can either be accepted (trusted) or the soft
     * failures can be passed along.  "451" is probably the correct soft
     * error.
     *
     * If we're using DNS MX records to configure ourselves, then we should
     * probably preserve the results of our DNS check.
     */

    switch ( r->r_smtp_mode ) {
    default:
	syslog( LOG_ERR, "Syserror: Receive [%s] %s: %s: To <%s> From <%s>: "
		"smtp mode out of range: %d",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, addr, r->r_env->e_mail, r->r_smtp_mode );
	return( RECEIVE_SYSERROR );

    case SMTP_MODE_TEMPFAIL:
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: To <%s> From <%s>: Tempfail",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, addr, r->r_env->e_mail );
	return( smtp_write_banner( r, 451, S_451_DECLINE, NULL ));

    case SMTP_MODE_NOAUTH:
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: To <%s> From <%s>: NoAuth",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, addr, r->r_env->e_mail );
	return( smtp_write_banner( r, 530, NULL, NULL ));

    case SMTP_MODE_REFUSE:
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: To <%s> From <%s>: Refused",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, addr, r->r_env->e_mail );
	return( smtp_write_banner( r, 503, NULL, NULL ));

    case SMTP_MODE_TARPIT:
    case SMTP_MODE_GLOBAL_RELAY:
	break;

    case SMTP_MODE_NORMAL:
	if ( domain == NULL ) {
	    break;
	}

	/*
	 * Here we do an initial lookup in our domain table.  This is
	 * our best opportunity to decline recipients that are not
	 * local or unknown, since if we give an error the connecting
	 * client generates the bounce.
	 */
	if (( rc = check_hostname( domain )) != 0 ) {
	    r->r_failed_rcpts++;
	    if ( rc < 0 ) {
#ifdef HAVE_LIBSSL 
		if (( simta_mail_filter != NULL ) &&
			( simta_checksum_md != NULL )) {
		    addr_len = strlen( addr );
		    EVP_DigestUpdate( &r->r_mdctx, addr, addr_len );
		    r->r_mdctx_bytes += addr_len;
		    r->r_mdctx_status = MDCTX_IN_USE;
		}
#endif /* HAVE_LIBSSL */
		syslog( LOG_ERR, "Syserror f_rcpt: check_hostname: %s: failed",
			domain );
		return( smtp_write_banner( r, 451, NULL, NULL ));
	    }

	    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
		    "To <%s> From <%s>: Failed: Unknown domain",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id, addr, r->r_env->e_mail );

	    return( smtp_write_banner( r, 550, S_UNKNOWN_HOST, domain ));
	}

	if ((( red = host_local( domain )) == NULL ) ||
		( red->red_receive == NULL )) {
	    if ( r->r_smtp_mode == SMTP_MODE_NORMAL ) {
		r->r_failed_rcpts++;
		syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			"To <%s> From <%s>: Failed: Domain not local",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_env->e_id, addr, r->r_env->e_mail );
		if ( snet_writef( r->r_snet,
			"551 User not local to <%s>: please try <%s>\r\n",
			simta_hostname, domain ) < 0 ) {
		    syslog( LOG_DEBUG, "Syserror f_rcpt: snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		return( RECEIVE_OK );
	    }

	} else {
	    /*
	     * For local mail, we now have 5 minutes (rfc1123 5.3.2)
	     * to decline to receive the message.  If we're in the
	     * default configuration, we check the passwd and alias file.
	     * Other configurations use "mailer" specific checks.
	     */

	    /* rfc 2821 section 3.7
	     * A relay SMTP server is usually the target of a DNS MX record
	     * that designates it, rather than the final delivery system.
	     * The relay server may accept or reject the task of relaying
	     * the mail in the same way it accepts or rejects mail for
	     * a local user.  If it accepts the task, it then becomes an
	     * SMTP client, establishes a transmission channel to the next
	     * SMTP server specified in the DNS (according to the rules
	     * in section 5), and sends it the mail.  If it declines to 
	     * relay mail to a particular address for policy reasons, a 550
	     * response SHOULD be returned.
	     */

	    switch( local_address( addr, domain, red )) {
	    case NOT_LOCAL:
		r->r_failed_rcpts++;
		syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			"To <%s> From <%s>: Failed: User not local",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_env->e_id, addr, r->r_env->e_mail );
		return( smtp_write_banner( r, 550, NULL, "User not found" ));

	    case LOCAL_ERROR:
		syslog( LOG_ERR, "Syserror f_rcpt: local_address %s", addr );

#ifdef HAVE_LIBSSL 
		if (( simta_mail_filter != NULL ) &&
			( simta_checksum_md != NULL )) {
		    addr_len = strlen( addr );
		    EVP_DigestUpdate( &r->r_mdctx, addr, addr_len );
		    r->r_mdctx_bytes += addr_len;
		    r->r_mdctx_status = MDCTX_IN_USE;
		}
#endif /* HAVE_LIBSSL */

		return( smtp_write_banner( r, 451, NULL, NULL ));

	    case LOCAL_ADDRESS_RBL:
		if ( simta_user_rbls == NULL ) {
		    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			    "To <%s> From <%s>: No user RBLS",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id, addr, r->r_env->e_mail );
		    break;
		}

		if ( r->r_rbl_status == RBL_UNKNOWN ) {
		    r->r_rbl_status = rbl_check( simta_user_rbls,
			    &(r->r_sin->sin_addr), NULL, r->r_remote_hostname,
			    &(r->r_rbl), &(r->r_rbl_msg));
		}

		switch ( r->r_rbl_status ) {
		case RBL_ERROR:
		default:
		    r->r_rbl_status = RBL_UNKNOWN;
		    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			    "To <%s> From <%s>: RBL %s: error",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id, addr, r->r_env->e_mail,
			    r->r_rbl->rbl_domain );
		    if ( dnsr_errno( simta_dnsr ) !=
			    DNSR_ERROR_TIMEOUT ) {
			return( RECEIVE_CLOSECONNECTION );
		    }
		    dnsr_errclear( simta_dnsr );
		    break;

		case RBL_BLOCK:
		    r->r_failed_rcpts++;
		    r->r_rbl_status = RBL_BLOCK;
		    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			    "To <%s> From <%s>: RBL Blocked %s: %s",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname, r->r_env->e_id, addr,
			    r->r_env->e_mail, r->r_rbl->rbl_domain, 
			    r->r_rbl_msg );
		    if ( snet_writef( r->r_snet,
			    "550 <%s> %s %s: See %s\r\n", simta_hostname,
			    S_DENIED, inet_ntoa( r->r_sin->sin_addr ),
			    r->r_rbl->rbl_url ) < 0 ) {
			syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
				"f_rcpt: snet_writef: %m",
				inet_ntoa( r->r_sin->sin_addr ),
				r->r_remote_hostname );
			return( RECEIVE_CLOSECONNECTION );
		    }
		    return( RECEIVE_OK );

		case RBL_ACCEPT:
		    r->r_rbl_status = RBL_ACCEPT;
		    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			    "To <%s> From <%s>: RBL %s: Accepted: %s",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id, addr, r->r_env->e_mail,
			    r->r_rbl->rbl_domain, r->r_rbl_msg );
		    break;

		case RBL_NOT_FOUND:
		    r->r_rbl_status = RBL_NOT_FOUND;
		    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
			    "To <%s> From <%s>: RBL Unlisted",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname, r->r_env->e_id, addr,
			    r->r_env->e_mail );
		    break;
		}
		break; /* end case LOCAL_ADDRESS_RBL */

	    case LOCAL_ADDRESS:
		break;

	    default:
		panic( "f_rctp local_address return out of range" );
	    }
	}
    }

    if ( env_recipient( r->r_env, addr ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    if ( r->r_smtp_mode != SMTP_MODE_TARPIT ) {
	r->r_rcpt_success++;
	syslog( LOG_NOTICE, "Receive [%s] %s: %s: To <%s> From <%s>: Accepted",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_rcpt->r_rcpt, r->r_env->e_mail );
    } else {
	syslog( LOG_NOTICE, "Receive [%s] %s: %s: To <%s> From <%s>: Tarpit",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_rcpt->r_rcpt, r->r_env->e_mail );
    }

#ifdef HAVE_LIBSSL 
    if (( simta_mail_filter != NULL ) && ( simta_checksum_md != NULL )) {
	addr_len = strlen( addr );
	EVP_DigestUpdate( &r->r_mdctx, addr, addr_len );
	r->r_mdctx_bytes += addr_len;
	r->r_mdctx_status = MDCTX_IN_USE;
    }
#endif /* HAVE_LIBSSL */

    r->r_tv_inactivity.tv_sec = 0;
    return( smtp_write_banner( r, 250, NULL, NULL ));
}


    static int
f_data( struct receive_data *r )
{
    FILE				*dff = NULL;
    int					banner = 0;
    int					dfile_fd = -1;
    int					ret_code = RECEIVE_SYSERROR;
    int					header = 1;
    int					line_no = 0;
    int					message_banner = MESSAGE_TEMPFAIL;
    int					filter_result;
    int					f_result;
    int					read_err = NO_ERROR;
    unsigned int			line_len;
    char				*line;
    char				*msg;
    char				*failure_message;
    char				*filter_message = NULL;
    char				*system_message = NULL;
    char				*timer_type;
    char				*session_type = NULL;
    struct tm				*tm;
    struct timeval			tv_data_start;
    struct timeval			tv_wait;
    struct timeval			tv_session;
    struct timeval			tv_filter = { 0, 0 };
    struct timeval			tv_now;
    time_t				clock;
    struct stat				sbuf;
    char				daytime[ 60 ];
    char				dfile_fname[ MAXPATHLEN + 1 ];
    struct receive_headers		rh;
    unsigned int			data_wrote = 0;
    unsigned int			data_read = 0;
    struct envelope			*env_bounce;

    memset( &rh, 0, sizeof( struct receive_headers ));
    rh.r_env = r->r_env;

    r->r_data_attempt++;

    if ( r->r_smtp_mode == SMTP_MODE_OFF ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: SMTP_Off: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_smtp_command );
	return( smtp_write_banner( r, 421, S_421_DECLINE, NULL ));
    }

    tarpit_sleep( r, simta_smtp_tarpit_data );

    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */
    if ( r->r_ac != 1 ) {
	log_bad_syntax( r );
	return( smtp_write_banner( r, 501, NULL,
		"RFC 2821 section 4.1.1.1 \"DATA\" CRLF" ));
    }

    /* rfc 2821 3.3
     * If there was no MAIL, or no RCPT, command, or all such commands
     * were rejected, the server MAY return a "command out of sequence"
     * (503) or "no valid recipients" (554) reply in response to the DATA
     * command.
     *
     * Also note that having already accepted a message is bad.
     * A previous reset is also not a good thing.
     */
    if (( r->r_env == NULL ) ||
	    (( r->r_env->e_flags & ENV_FLAG_EFILE ) != 0 )) {
	return( f_bad_sequence( r ));
    }

    if ( r->r_env->e_rcpt == NULL ) {
	return( smtp_write_banner( r, 554, NULL, "No valid recipients" ));
    }

    switch ( r->r_smtp_mode ) {
    default:
	syslog( LOG_ERR, "Syserror: Receive [%s] %s: %s: Data: "
		"smtp mode out of range: %d",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_smtp_mode );
	return( RECEIVE_SYSERROR );

    case SMTP_MODE_TEMPFAIL:
	syslog( LOG_DEBUG, "Receive [%s] %s: Tempfail: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_smtp_command );
	return( smtp_write_banner( r, 451, S_451_DECLINE, NULL ));

    case SMTP_MODE_NOAUTH:
	return( f_noauth( r ));

    case SMTP_MODE_REFUSE:
	return( f_bad_sequence( r ));

    case SMTP_MODE_TARPIT:
	break;

    case SMTP_MODE_GLOBAL_RELAY:
    case SMTP_MODE_NORMAL:
	if (( dfile_fd = env_dfile_open( r->r_env )) < 0 ) {
	    return( -1 );
	}

	if (( dff = fdopen( dfile_fd, "w" )) == NULL ) {
	    syslog( LOG_ERR, "Syserror f_data: fdopen %s: %m", dfile_fname );
	    if ( close( dfile_fd ) != 0 ) {
		syslog( LOG_ERR, "Syserror f_data: close: %m" );
	    }
	    goto error;
	}

	clock = time( &clock );
	tm = localtime( &clock );
	strftime( daytime, sizeof( daytime ), "%e %b %Y %T %Z", tm );

	if ( simta_smtp_rcvbuf_min != 0 ) {
	    if ( setsockopt( snet_fd( r->r_snet ), SOL_SOCKET, SO_RCVBUF,
		    (void*)&simta_smtp_rcvbuf_max, sizeof( int )) < 0 ) {
		syslog( LOG_ERR, "Syserror f_data: setsockopt: %m" );
		goto error;
	    }
	    syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
		    "TCP window increased from %d to %d",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id, simta_smtp_rcvbuf_min,
		    simta_smtp_rcvbuf_max );
	}

	/*
	 * At this point, we must have decided what we'll put in the Received:
	 * header, since that is the first line in the file.  This is where
	 * we might want to put the sender's domain name, if we obtained one.
	 */
	/* RFC 2821 4.4 Trace Information:
	 *
	 * Time-stamp-line = "Received:" FWS Stamp <CRLF>
	 * Stamp = From-domain By-domain Opt-info ";"  FWS date-time
	 * From-domain = "FROM" FWS Extended-Domain CFWS
	 * By-domain = "BY" FWS Extended-Domain CFWS
	 * Extended-Domain = Domain /
	 *     ( Domain FWS "(" TCP-info ")" ) /
	 *     ( Address-literal FWS "(" TCP-info ")" )
	 * TCP-info = Address-literal / ( Domain FWS Address-literal )
	 *
	 */

	if ( simta_sasl ) {
	    if ( fprintf( dff,
		    "Received: FROM %s (%s [%s])\n"
		    "\tBy %s ID %s ;\n"
		    "\tAuthuser %s;\n"
		    "\t%s\n",
		    ( r->r_hello == NULL ) ? "NULL" : r->r_hello,
		    r->r_remote_hostname , inet_ntoa( r->r_sin->sin_addr ),
		    simta_hostname, r->r_env->e_id, r->r_auth_id,
		    daytime ) < 0 ) {
		syslog( LOG_ERR, "Syserror f_data: fprintf: %m" );
		goto error;
	    }

	} else {
	    if ( fprintf( dff,
		    "Received: FROM %s (%s [%s])\n"
		    "\tBy %s ID %s ;\n"
		    "\t%s\n",
		    ( r->r_hello == NULL ) ? "NULL" : r->r_hello,
		    r->r_remote_hostname , inet_ntoa( r->r_sin->sin_addr ),
		    simta_hostname, r->r_env->e_id, daytime ) < 0 ) {
		syslog( LOG_ERR, "Syserror f_data: fprintf: %m" );
		goto error;
	    }
	}
    }

    r->r_tv_inactivity.tv_sec = 0;

    if ( smtp_write_banner( r, 354, NULL, NULL ) != RECEIVE_OK ) {
	ret_code = RECEIVE_CLOSECONNECTION;
	goto error;
    }

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	goto error;
    }

    tv_data_start.tv_sec = tv_now.tv_sec;
    tv_data_start.tv_usec = tv_now.tv_usec;

    /* global smtp session timer */
    if ( r->r_tv_session.tv_sec != 0 ) {
	session_type = S_GLOBAL_SESSION;
	tv_session.tv_sec = r->r_tv_session.tv_sec;
	tv_session.tv_usec = 0;
    }

    /* smtp data session timer */
    if ( simta_inbound_data_session_timer != 0 ) {
	if ( session_type != NULL ) {
	    if (( tv_now.tv_sec + simta_inbound_data_session_timer ) <
		    tv_session.tv_sec ) {
		session_type = NULL;
	    }
	}

	if ( session_type == NULL ) {
	    session_type = S_DATA_SESSION;
	    tv_session.tv_sec = tv_now.tv_sec +
		    simta_inbound_data_session_timer;
	}
    }

    for ( ; ; ) {
	tv_wait.tv_sec = simta_inbound_data_line_timer;
	tv_wait.tv_usec = 0;
	timer_type = S_DATA_LINE;

	if ( session_type != NULL ) {
	    if ( tv_session.tv_sec <= tv_now.tv_sec ) {
		syslog( LOG_DEBUG,
			"Receive [%s] %s: %s: %s time limit exceeded",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_env->e_id, session_type );
		smtp_write_banner( r, 421, S_TIMEOUT, S_CLOSING );
		ret_code = RECEIVE_CLOSECONNECTION;
		goto error;
	    }

	    if ( tv_wait.tv_sec > ( tv_session.tv_sec - tv_now.tv_sec )) {
		tv_wait.tv_sec = tv_session.tv_sec - tv_now.tv_sec;
		timer_type = session_type;
	    }
	}

	if (( line = snet_getline( r->r_snet, &tv_wait )) == NULL ) {
	    if ( errno == ETIMEDOUT ) {
		ret_code = RECEIVE_CLOSECONNECTION;
		syslog( LOG_DEBUG,
			"Receive [%s] %s: %s: Data: Timeout %s",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_env->e_id, timer_type );
		smtp_write_banner( r, 421, S_TIMEOUT, S_CLOSING );
	    } else {
		syslog( LOG_DEBUG,
			"Receive [%s] %s: %s: Data: connection dropped",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
			r->r_env->e_id );
	    }
	    goto error;
	}

	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    read_err = SYSTEM_ERROR;
	}

	line_no++;
	line_len = strlen( line );
	data_read += line_len + 2;

	if ( *line == '.' ) {
	    if ( strcmp( line, "." ) == 0 ) {
		break;
	    }
	    line++;
	}

	if (( read_err == NO_ERROR ) && ( header == 1 )) {
	    msg = NULL;
	    if (( f_result = header_text( line_no, line, &rh, &msg )) == 0 ) {
		if ( msg != NULL ) {
		    syslog( LOG_DEBUG, "Receive [%s] %s: %s: %s",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname, r->r_env->e_id, msg );
		}
	    } else if ( f_result < 0 ) {
		read_err = SYSTEM_ERROR;
	    } else {
		header = 0;
	    }
	}

	if (( read_err == NO_ERROR ) && ( simta_max_message_size > 0 ) &&
		(( data_wrote + line_len + 1 ) > simta_max_message_size )) {
	    /* If we're going to reach max size, continue reading lines
	     * until the '.' otherwise, check message size.
	     */
	    syslog( LOG_DEBUG, "Receive [%s] %s: %s: Message Failed: "
		    "Message too large",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id );
	    system_message = "Message too large";
	    message_banner = MESSAGE_REJECT;
	    read_err = PROTOCOL_ERROR;
	}

	if (( read_err == NO_ERROR ) &&
		( rh.r_received_count > simta_max_received_headers )) {
	    syslog( LOG_DEBUG, "Receive [%s] %s: %s: Message Failed: "
		    "Too many Received headers",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id );
	    system_message = "Too many Received headers";
	    message_banner = MESSAGE_REJECT;
	    read_err = PROTOCOL_ERROR;
	}

	if ( rh.r_seen_before ) {
	    system_message = "Seen Before";
	    filter_message = strdup( rh.r_seen_before );
	    message_banner = MESSAGE_DELETE;
	    read_err = PROTOCOL_ERROR;
	}

	if ( read_err == NO_ERROR ) {
	    if (( dff != NULL ) && ( fprintf( dff, "%s\n", line ) < 0 )) {
		syslog( LOG_ERR, "Syserror f_data: fprintf: %m" );
		read_err = SYSTEM_ERROR;
	    } else {
		data_wrote += line_len + 1;
	    }
	}

	if (( read_err != NO_ERROR ) && ( dff != NULL )) {
	    if ( fclose( dff ) != 0 ) {
		syslog( LOG_ERR, "Syserror f_data: fclose1: %m" );
		read_err = SYSTEM_ERROR;
	    }
	    dff = NULL;
	    if ( env_dfile_unlink( r->r_env ) != 0 ) {
		read_err = SYSTEM_ERROR;
	    }
	}

#ifdef HAVE_LIBSSL 
	if (( dff != NULL ) && ( simta_mail_filter != NULL ) &&
		( simta_checksum_md != NULL )) {
	    EVP_DigestUpdate( &r->r_mdctx, line, line_len );
	    r->r_mdctx_bytes += line_len;
	}
#endif /* HAVE_LIBSSL */
    }

    if ( r->r_env->e_flags & ENV_FLAG_DFILE ) {
	/* get the Dfile's inode for the envelope structure */
	if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	    sprintf( dfile_fname, "%s/D%s", simta_dir_fast, r->r_env->e_id );
	    syslog( LOG_ERR, "Syserror f_data: fstat %s: %m", dfile_fname );
	    goto error;
	}
	r->r_env->e_dinode = sbuf.st_ino;

	if ( dff != NULL ) {
	    f_result = fclose( dff );
	    dff = NULL;
	    if ( f_result != 0 ) {
		syslog( LOG_ERR, "Syserror f_data: fclose2: %m" );
		goto error;
	    }
	}
	message_banner = MESSAGE_ACCEPT;
    }

    if ( simta_mail_filter == NULL ) {
	filter_result = MESSAGE_ACCEPT;
    } else if ( r->r_smtp_mode == SMTP_MODE_TARPIT ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
		"content filter %s not run because tarpit",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, simta_mail_filter);
	filter_result = MESSAGE_ACCEPT;
    } else if ( r->r_env->e_flags & ENV_FLAG_DFILE ) {
#ifdef HAVE_LIBSSL 
	if (( simta_mail_filter != NULL ) &&
		( simta_checksum_md != NULL )) {
	    EVP_DigestFinal_ex( &r->r_mdctx, r->r_md_value, &r->r_md_len );
	    r->r_mdctx_status = MDCTX_FINAL;
	    memset( r->r_md_b64, 0, SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 );
	    base64_e( r->r_md_value, r->r_md_len, r->r_md_b64 );
	    snprintf( r->r_md_bytes, BYTE_LEN, "%d", r->r_mdctx_bytes );
	}
#endif /* HAVE_LIBSSL */

	if ( simta_gettimeofday( &tv_filter ) != 0 ) {
	    goto error;
	}

	r->r_env->e_mid = rh.r_mid;
	rh.r_mid = 0;

	if ( env_tfile( r->r_env ) != 0 ) {
	    goto error;
	}

	filter_result = content_filter( r, &filter_message );

	syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
		"content filter %s exited %d: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, simta_mail_filter, filter_result,
		filter_message ? filter_message : "no filter message" );
	/* TEMPFAIL has precedence over REJECT */

	if ( message_banner == MESSAGE_TEMPFAIL ) {
	    if ( filter_result & MESSAGE_TEMPFAIL ) {
		if ( filter_result & MESSAGE_REJECT ) {
		syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			"Message Tempfail: Filter Error: Tempfail and Reject",
			inet_ntoa( r->r_sin->sin_addr ),
			r->r_remote_hostname,
			r->r_env->e_id );
		}
	    } else if ( filter_result & MESSAGE_REJECT ) {
		    syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			    "Message Tempfail: Filter Reject overridden",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id );
	    } else {
		    syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			    "Message Tempfail: Filter Accept overridden",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id );
	    }

	} else if ( message_banner == MESSAGE_REJECT ) {
	    if ( filter_result & MESSAGE_REJECT ) {
		if ( filter_result & MESSAGE_TEMPFAIL ) {
		    syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			    "Message Reject: Filter Error: Tempfail and Reject",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id );
		}
	    } else if ( filter_result & MESSAGE_TEMPFAIL ) {
		syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			"Message Reject: Filter Tempfail overridden",
			inet_ntoa( r->r_sin->sin_addr ),
			r->r_remote_hostname,
			r->r_env->e_id );
	    } else {
		syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			"Message Reject: Filter Accept overridden",
			inet_ntoa( r->r_sin->sin_addr ),
			r->r_remote_hostname,
			r->r_env->e_id );
	    }

	} else {
	    /* Message Accept, content filter can do whatever it wants */
	    if ( filter_result & MESSAGE_TEMPFAIL ) {
		if ( filter_result & MESSAGE_REJECT ) {
		    syslog( LOG_WARNING, "Receive [%s] %s: %s: "
			    "Message Tempfail: "
			    "Filter Error: Tempfail and Reject",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id );
		} else {
		    syslog( LOG_INFO, "Receive [%s] %s: %s: "
			    "Message Tempfail: Filter",
			    inet_ntoa( r->r_sin->sin_addr ),
			    r->r_remote_hostname,
			    r->r_env->e_id );
		}
		message_banner = MESSAGE_TEMPFAIL;
	    } else if ( filter_result & MESSAGE_REJECT ) {
		message_banner = MESSAGE_REJECT;
		syslog( LOG_INFO, "Receive [%s] %s: %s: "
			"Message Reject: Filter",
			inet_ntoa( r->r_sin->sin_addr ),
			r->r_remote_hostname,
			r->r_env->e_id );
	    }
	}
    }

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	goto error;
    }

    if ( tv_filter.tv_sec == 0 ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
		"Data Metric: Read %d write %d bytes in %d seconds",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, (int)data_read, (int)data_wrote,
		(int)(tv_now.tv_sec - tv_data_start.tv_sec));
    } else {
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: "
		"Data Metric: Read %d write %d bytes in %d seconds, "
		"filter %d seconds",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, (int)data_read, (int)data_wrote,
		(int)(tv_now.tv_sec - tv_data_start.tv_sec),
		(int)(tv_now.tv_sec - tv_filter.tv_sec));
    }

    if ( filter_result & MESSAGE_BOUNCE ) {
	if (( env_bounce = bounce( r->r_env,
		(( r->r_env->e_flags & ENV_FLAG_DFILE ) &&
		(( filter_result & MESSAGE_DELETE ) == 0 )),
		filter_message ? filter_message :
		"This message was rejected based on local content policies"
		)) == NULL ) {
	    goto error;
	}
	queue_envelope( env_bounce );
	syslog( LOG_NOTICE, "Receive [%s] %s: %s: Message Bounced: "
		"MID <%s> From <%s>: size %d: %s, %s: Bounce_ID: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id,
		r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		r->r_env->e_mail, data_read,
		system_message ? system_message : "no system message",
		filter_message ? filter_message : "no filter message",
		env_bounce->e_id );
	if ( simta_inbound_accepted_message_timer >= 0 ) {
	    r->r_tv_accepted.tv_sec = simta_inbound_accepted_message_timer +
		    tv_now.tv_sec;
	}
    }

    if ( filter_result & MESSAGE_JAIL ) {
	if (( r->r_env->e_flags & ENV_FLAG_DFILE ) == 0 ) {
	    syslog( LOG_WARNING, "Receive [%s] %s: %s: "
		    "no Dfile can't accept message:"
		    "MID <%s> size %d: %s, %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id, r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		    data_read,
		    system_message ? system_message : "no system message",
		    filter_message ? filter_message : "no filter message" );
	} else if ( simta_jail_host == NULL ) {
	    syslog( LOG_WARNING, "Receive [%s] %s: %s: "
		    "content filter returned MESSAGE_JAIL and "
		    "no JAIL_HOST is configured",
		    inet_ntoa( r->r_sin->sin_addr ),
		    r->r_remote_hostname,
		    r->r_env->e_id );
	} else {
	    /* remove tfile because we're going to change the hostname */
	    if ( env_tfile_unlink( r->r_env ) != 0 ) {
		goto error;
	    }
	    if ( env_hostname( r->r_env, simta_jail_host ) != 0 ) {
		goto error;
	    }
	    if (( simta_mail_jail != 0 ) && ( simta_bounce_jail == 0 )) {
		/* bounces must be able to get out of jail */
		env_jail_set( r->r_env, ENV_JAIL_NO_CHANGE );
	    }
	    syslog( LOG_NOTICE, "Receive [%s] %s: %s: "
		    "sending to JAIL_HOST %s",
		    inet_ntoa( r->r_sin->sin_addr ),
		    r->r_remote_hostname,
		    r->r_env->e_id, r->r_env->e_hostname );
	}

    /* see if we need to delete the message */
    } else if (( message_banner == MESSAGE_TEMPFAIL ) ||
	    ( message_banner == MESSAGE_REJECT ) ||
	    ( filter_result & MESSAGE_DELETE ) ||
	    ( filter_result & MESSAGE_BOUNCE )) {
	if (( filter_result & MESSAGE_DELETE ) &&
		(( filter_result & MESSAGE_BOUNCE ) == 0 )) {
	    syslog( LOG_NOTICE, "Receive [%s] %s: %s: "
		    "Message Deleted by content filter: "
		    "MID <%s> size %d: %s, %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id,
		    r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		    data_read,
		    system_message ? system_message : "no system message",
		    filter_message ? filter_message : "no filter message" );
	}

	if (( r->r_env->e_flags & ENV_FLAG_DFILE ) ) {
	     if ( env_dfile_unlink( r->r_env ) != 0 ) {
		 goto error;
	     }
	}
    }

    if ( r->r_env->e_flags & ENV_FLAG_DFILE ) {
	if ( env_outfile( r->r_env ) != 0 ) {
	    goto error;
	}

	if ( simta_inbound_accepted_message_timer >= 0 ) {
	    r->r_tv_accepted.tv_sec = simta_inbound_accepted_message_timer +
		    tv_now.tv_sec;
	}

	r->r_data_success++;

	syslog( LOG_NOTICE, "Receive [%s] %s: %s: Message Accepted: "
		"MID <%s> From <%s>: size %d: %s, %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id,
		r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		r->r_env->e_mail, data_read,
		system_message ? system_message : "no system message",
		filter_message ? filter_message : "no filter message" );
    }

    if ( filter_result & MESSAGE_DISCONNECT ) {
	set_smtp_mode( r, SMTP_MODE_OFF, simta_mail_filter );
    } else if ( filter_result & MESSAGE_TARPIT ) {
	set_smtp_mode( r, SMTP_MODE_TARPIT, simta_mail_filter );
    }

    tarpit_sleep( r, simta_smtp_tarpit_data_eof );

    if ( filter_message ) {
	failure_message = filter_message;
    } else if ( system_message ) {
	failure_message = system_message;
    } else if ( r->r_smtp_mode == SMTP_MODE_TARPIT ) {
	failure_message = NULL;
    } else if ( simta_data_url ) {
	failure_message = simta_data_url;
    } else {
	failure_message = NULL;
    }

    banner++;

    /* TEMPFAIL has precedence over REJECT */
    if ( message_banner == MESSAGE_TEMPFAIL ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: Tempfail Banner: "
		"MID <%s> size %d: %s, %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		data_read,
		system_message ? system_message : "no system message",
		filter_message ? filter_message : "no filter message" );
	if ( smtp_write_banner( r, 451, S_451_MESSAGE, failure_message )
		!= RECEIVE_OK ) {
	    ret_code = RECEIVE_CLOSECONNECTION;
	    goto error;
	}

    } else if ( message_banner == MESSAGE_REJECT ) {
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: Failed Banner: "
		"MID <%s> size %d: %s, %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		data_read,
		system_message ? system_message : "no system message",
		filter_message ? filter_message : "no filter message" );
	if ( smtp_write_banner( r, 554, S_554_MESSAGE, failure_message ) !=
		RECEIVE_OK ) {
	    ret_code = RECEIVE_CLOSECONNECTION;
	    goto error;
	}

    } else {
	syslog( LOG_DEBUG, "Receive [%s] %s: %s: Accept Banner: "
		"MID <%s> size %d: %s, %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id, r->r_env->e_mid ? r->r_env->e_mid : "NULL",
		data_read,
		system_message ? system_message : "no system message",
		filter_message ? filter_message : "no filter message" );
	if ( filter_message != NULL ) {
	    if ( snet_writef( r->r_snet, "250 Accepted: (%s): %s\r\n",
		    r->r_env->e_id, filter_message ) < 0 ) {
		syslog( LOG_DEBUG, "Syserror f_data: snet_writef: %m" );
		ret_code = RECEIVE_CLOSECONNECTION;
		goto error;
	    }
	} else {
	    if ( snet_writef( r->r_snet, "250 Accepted: (%s)\r\n",
		    r->r_env->e_id ) < 0 ) {
		syslog( LOG_DEBUG, "Syserror f_data: snet_writef: %m" );
		ret_code = RECEIVE_CLOSECONNECTION;
		goto error;
	    }
	}
    }

    /* if we just had a protocol error, we're OK */
    if ( read_err != SYSTEM_ERROR ) {
	ret_code = RECEIVE_OK;
    }

error:
    header_free( &rh );

    /* if dff is still open, there was an error and we need to close it */
    if (( dff != NULL ) && ( fclose( dff ) != 0 )) {
	syslog( LOG_ERR, "Syserror f_data: fclose3: %m" );
	if ( ret_code == RECEIVE_OK ) {
	    ret_code = RECEIVE_SYSERROR;
	}
    }

    /* if we didn't put a message on the disk, we need to clean up */
    if (( r->r_env->e_flags & ENV_FLAG_EFILE ) == 0 ) {
	/* Dfile no Efile */
	if ( r->r_env->e_flags & ENV_FLAG_DFILE ) {
	    if ( env_dfile_unlink( r->r_env ) != 0 ) {
		if ( ret_code == RECEIVE_OK ) {
		    ret_code = RECEIVE_SYSERROR;
		}
	    }
	}

	/* Tfile no Efile */
	if ( r->r_env->e_flags & ENV_FLAG_TFILE ) {
	    if ( env_tfile_unlink( r->r_env ) != 0 ) {
		if ( ret_code == RECEIVE_OK ) {
		    ret_code = RECEIVE_SYSERROR;
		}
	    }
	}

	syslog( LOG_INFO, "Receive [%s] %s: %s: Message Failed",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		r->r_env->e_id );
	env_free( r->r_env );
	r->r_env = NULL;
    }

    if ( filter_message != NULL ) {
	free( filter_message );
    }

    /* if we've already given a message result banner,
     * delay the syserror banner
     */
    if (( banner != 0 ) && ( ret_code == RECEIVE_SYSERROR )) {
	set_smtp_mode( r, SMTP_MODE_OFF, "Syserror" );
	return( RECEIVE_OK );
    }

    return( ret_code );
}


    static int
f_quit( struct receive_data *r )
{
    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    tarpit_sleep( r, 0 );

    return( smtp_write_banner( r, 221, NULL, NULL ));
}


    static int
f_rset( struct receive_data *r )
{
    /*
     * We could presume that this indicates another message.  However,
     * since some mailers send this just before "QUIT", and we're
     * checking "MAIL FROM:" as well, there's no need.
     */

    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    if ( reset( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    tarpit_sleep( r, 0 );

    return( smtp_write_banner( r, 250, NULL, NULL ));
}


    static int
f_noop( struct receive_data *r )
{
    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    if ( deliver_accepted( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    tarpit_sleep( r, 0 );

    return( smtp_write_banner( r, 250, "simta", version ));
}


    static int
f_help( struct receive_data *r )
{
    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    if ( deliver_accepted( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    tarpit_sleep( r, 0 );

    return( smtp_write_banner( r, 211, NULL, version ));
}


    /*
     * rfc 2821 section 3.5.3:
     * A server MUST NOT return a 250 code in response to a VRFY or EXPN
     * command unless it has actually verified the address.  In particular,
     * a server MUST NOT return 250 if all it has done is to verify that the
     * syntax given is valid.  In that case, 502 (Command not implemented)
     * or 500 (Syntax error, command unrecognized) SHOULD be returned.  As
     * stated elsewhere, implementation (in the sense of actually validating
     * addresses and returning information) of VRFY and EXPN are strongly
     * recommended.  Hence, implementations that return 500 or 502 for VRFY
     * are not in full compliance with this specification.
     *
     * rfc 2821 section 7.3:
     * As discussed in section 3.5, individual sites may want to disable
     * either or both of VRFY or EXPN for security reasons.  As a corollary
     * to the above, implementations that permit this MUST NOT appear to
     * have verified addresses that are not, in fact, verified.  If a site
     * disables these commands for security reasons, the SMTP server MUST
     * return a 252 response, rather than a code that could be confused with
     * successful or unsuccessful verification.
     */


    static int
f_not_implemented( struct receive_data *r )
{
    syslog( LOG_DEBUG, "Receive [%s] %s: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
	    r->r_smtp_command );

    if ( deliver_accepted( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    tarpit_sleep( r, 0 );

    return( smtp_write_banner( r, 502, NULL, NULL ));
}


    static int
f_bad_sequence( struct receive_data *r )
{
    syslog( LOG_DEBUG, "Receive [%s] %s: Bad Sequence: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
	    r->r_smtp_command );

    return( smtp_write_banner( r, 503, NULL, NULL ));
}


    static int
f_noauth( struct receive_data *r )
{
    tarpit_sleep( r, 0 );

    syslog( LOG_DEBUG, "Receive [%s] %s: NoAuth: %s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
	    r->r_smtp_command );
    return( smtp_write_banner( r, 530, NULL, NULL ));
}


#ifdef HAVE_LIBSSL
    static int
f_starttls( struct receive_data *r )
{
    int				rc;

    tarpit_sleep( r, 0 );

    if ( !simta_tls ) {
	return( smtp_write_banner( r, 502, NULL, NULL ));
    }

    /*
     * Client MUST NOT attempt to start a TLS session if a TLS
     * session is already active.  No mention of what to do if it does...
     */
    if ( r->r_tls ) {
	syslog( LOG_ERR, "Syserror f_starttls: called twice" );
	return( RECEIVE_SYSERROR );
    }

    if ( r->r_ac != 1 ) {
	log_bad_syntax( r );
	return( smtp_write_banner( r, 501, NULL, "no parameters allowed" ));
    }

    if ( smtp_write_banner( r, 220, "Ready to start TLS", NULL ) !=
	    RECEIVE_OK ) {
	return( RECEIVE_CLOSECONNECTION );
    }

    if ( _start_tls( r ) != RECEIVE_OK ) {
	return ( RECEIVE_OK );
    }

    /* RFC 3207 4.2 Result of the STARTTLS Command
     * Upon completion of the TLS handshake, the SMTP protocol is reset to
     * the initial state (the state in SMTP after a server issues a 220
     * service ready greeting).  The server MUST discard any knowledge
     * obtained from the client, such as the argument to the EHLO command,
     * which was not obtained from the TLS negotiation itself. 
     *
     * RFC 3207 6
     * Before the TLS handshake has begun, any protocol interactions are
     * performed in the clear and may be modified by an active attacker.
     * For this reason, clients and servers MUST discard any knowledge
     * obtained prior to the start of the TLS handshake upon completion of
     * the TLS handshake.
     */

    if ( reset( r ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    if ( r->r_hello != NULL ) {
	free( r->r_hello );
	r->r_hello = NULL;
    }

    if (( rc = _post_tls( r )) != RECEIVE_OK ) {
	return( rc );
    }

    syslog( LOG_DEBUG, "Receive [%s] %s: Start TLS",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname );

    return( RECEIVE_OK );
}

    int
_post_tls( struct receive_data *r )
{
#ifdef HAVE_LIBSASL
    int		rc; 

    if ( simta_sasl ) {
	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: _post_tls sasl_setprop 1" );
	}

	/* Get cipher_bits and set SSF_EXTERNAL */
	memset( &r->r_secprops, 0, sizeof( sasl_security_properties_t ));
	if (( rc = sasl_setprop( r->r_conn, SASL_SSF_EXTERNAL,
		&r->r_ext_ssf )) != SASL_OK ) {
	    syslog( LOG_ERR, "Syserror _post_tls: sasl_setprop1: %s",
		    sasl_errdetail( r->r_conn ));
	    return( RECEIVE_SYSERROR );
	}

	r->r_secprops.security_flags |= SASL_SEC_NOANONYMOUS;
	r->r_secprops.maxbufsize = 4096;
	r->r_secprops.min_ssf = 0;
	r->r_secprops.max_ssf = 256;

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: _post_tls sasl_setprop 2" );
	}

	if (( rc = sasl_setprop( r->r_conn, SASL_SEC_PROPS, &r->r_secprops))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "Syserror _post_tls: sasl_setprop2: %s",
		    sasl_errdetail( r->r_conn ));
	    return( RECEIVE_SYSERROR );
	}
    }
#endif /* HAVE_LIBSASL */
    return( RECEIVE_OK );
}

    int
_start_tls( struct receive_data *r )
{
    int				rc;
    X509			*peer;
    char			buf[ 1024 ];
    SSL_CTX			*ssl_ctx;
    struct timeval		tv_wait;

    if ( simta_debug != 0 ) {
	syslog( LOG_DEBUG, "Debug: _start_tls snet_starttls" );
    }

    if (( ssl_ctx = tls_server_setup( simta_use_randfile,
	    simta_service_smtps, simta_file_ca, simta_dir_ca,
	    simta_file_cert, simta_file_private_key )) == NULL ) {
	syslog( LOG_ERR, "Syserror: _start_tls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	return( smtp_write_banner( r, 554, NULL, "SSL didn't work!" ));
    }

    if ( simta_inbound_ssl_accept_timer != 0 ) {
	tv_wait.tv_usec = 0;
	tv_wait.tv_sec = simta_inbound_ssl_accept_timer;
	snet_timeout( r->r_snet, SNET_SSL_ACCEPT_TIMEOUT, &tv_wait );
    }

    if (( rc = snet_starttls( r->r_snet, ssl_ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "Syserror _start_tls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	return( smtp_write_banner( r, 554, NULL, "SSL didn't work!" ));
    }

    if ( simta_service_smtps == SERVICE_SMTPS_CLIENT_SERVER ) {
	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: _start_tls SSL_get_peer_certificate" );
	}

	if (( peer = SSL_get_peer_certificate( r->r_snet->sn_ssl )) == NULL ) {
	    syslog( LOG_ERR, "Syserror _start_tls: SSL_get_peer_certificate: "
		    "no peer certificate" );
	    return( smtp_write_banner( r, 554, NULL,  "SSL didn't work!" ));
	}
	syslog( LOG_DEBUG, "Receive [%s] %s: CERT Subject: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		X509_NAME_oneline( X509_get_subject_name( peer ), buf,
			sizeof( buf )));
	X509_free( peer );
    }

    r->r_tls = 1;
    simta_smtp_extension--;

    /* CVE-2011-0411: discard pending data from libsnet */
    while (snet_hasdata( r->r_snet )) {
	struct timeval temptv[1];
	char tempc[1];
	ssize_t rc;

	if (( rc = snet_read( r->r_snet, tempc, sizeof tempc, temptv )) != sizeof tempc) {
	    syslog( LOG_ERR, "Syserror _start_tls: read failed on %s %s: %d",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, (int)rc); 
	    break;
	}
    }

    return( RECEIVE_OK );
}

#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    int
f_auth( struct receive_data *r )
{
    int			rc;
    const char		*mechname;
    char		base64[ BASE64_BUF_SIZE + 1 ];
    char		*clientin = NULL;
    unsigned int	clientinlen = 0;
    const char		*serverout;
    unsigned int	serveroutlen;
    struct timeval	tv;

    tarpit_sleep( r, 0 );

    /* RFC 2554:
     * The BASE64 string may in general be arbitrarily long.  Clients
     * and servers MUST be able to support challenges and responses
     * that are as long as are generated by the authentication   
     * mechanisms they support, independent of any line length
     * limitations the client or server may have in other parts of its
     * protocol implementation.
     */

    if (( r->r_ac != 2 ) && ( r->r_ac != 3 )) {
	log_bad_syntax( r );
	return( smtp_write_banner( r, 501, NULL,
		"RFC 2554 section 4 AUTH mechanism [initial-response]" ));
    }

    /* RFC 2554 After an AUTH command has successfully completed, no more AUTH
     * commands may be issued in the same session.  After a successful
     * AUTH command completes, a server MUST reject any further AUTH
     * commands with a 503 reply.
     */
    if ( r->r_auth ) {
	return( f_bad_sequence( r ));
    }

    /* RFC 2554 The AUTH command is not permitted during a mail transaction. */
    if (( r->r_env != NULL ) && ( r->r_env->e_mail != NULL )) {
	return( f_bad_sequence( r ));
    }

    /* Initial response */
    if ( r->r_ac == 3 ) {
	clientin = base64;
	if ( strcmp( r->r_av[ 2 ], "=" ) == 0 ) {
	    /* Zero-length initial response */
	    base64[ 0 ] = '\0';
	} else {
	    if ( sasl_decode64( r->r_av[ 2 ], strlen( r->r_av[ 2 ]), clientin,
		    BASE64_BUF_SIZE, & clientinlen ) != SASL_OK ) {
		syslog( LOG_ERR, "Auth [%s] %s: %s: "
			"unable to BASE64 decode argument: %s",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
			r->r_auth_id, r->r_av[ 2 ]);
		return( smtp_write_banner( r, 501, NULL,
			"unable to BASE64 decode argument" ));
	    }
	}
    }

    rc = sasl_server_start( r->r_conn, r->r_av[ 1 ], clientin, clientinlen,
	&serverout, &serveroutlen );

    while ( rc == SASL_CONTINUE ) {
	/* send the challenge to the client */
	if ( serveroutlen ) {
	    if ( sasl_encode64( serverout, serveroutlen, base64,
		    BASE64_BUF_SIZE, NULL ) != SASL_OK ) {
		syslog( LOG_ERR, "Auth [%s] %s: %s: "
			"unable to BASE64 encode argument",
			inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
			r->r_auth_id );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    serverout = base64;
	} else {
	    serverout = "";
	}

	if ( smtp_write_banner( r, 334, (char*)serverout, NULL )
		!= RECEIVE_OK ) {
	    return( RECEIVE_CLOSECONNECTION );
	}

	/* Get response from the client */
	tv.tv_sec = simta_inbound_command_line_timer;
	tv.tv_usec = 0;
	if (( clientin = snet_getline( r->r_snet, &tv )) == NULL ) {
	    syslog( LOG_DEBUG, "Syserror f_auth: snet_getline: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	} 

	/* Check if client canceled authentication exchange */
	if ( clientin[ 0 ] == '*' && clientin[ 1 ] == '\0' ) {
	    syslog( LOG_ERR, "Auth [%s] %s: %s: "
		    "client canceled authentication",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		    r->r_auth_id );
	    if ( reset_sasl_conn( r ) != SASL_OK ) {
		return( RECEIVE_CLOSECONNECTION );
	    }
	    return( smtp_write_banner( r, 501, NULL,
		    "client canceled authentication" ));
	}

	/* decode response */
	if ( sasl_decode64( clientin, strlen( clientin ), clientin,
		BASE64_BUF_SIZE, &clientinlen ) != SASL_OK ) {
	    syslog( LOG_ERR, "Auth [%s] %s: %s: "
		    "sasl_decode64: unable to BASE64 decode argument: %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		    r->r_auth_id, clientin );
	    return( smtp_write_banner( r, 501, NULL,
		    "unable to BASE64 decode argument" ));
	}

	/* do next step */
	rc = sasl_server_step( r->r_conn, clientin, clientinlen, &serverout,
		&serveroutlen );
    }

    switch( rc ) {
    case SASL_OK:
	break;

    case SASL_NOMECH:
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"Unrecognized authentication type: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id, r->r_av[ 1 ] );
	return( smtp_write_banner( r, 504, NULL, NULL ));

    case SASL_BADPROT:
	/* RFC 2554:
 	 * If the client uses an initial-response argument to the AUTH    
	 * command with a mechanism that sends data in the initial
	 * challenge, the server rejects the AUTH command with a 535
	 * reply.
	 */
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"Invalid initial-response argument for mechanism %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id, r->r_av[ 1 ] );
	return( smtp_write_banner( r, 535, NULL, NULL ));

    /* Not sure what RC this is: RFC 2554 If the server rejects the
     * authentication data, it SHOULD reject the AUTH command with a
     * 535 reply unless a more specific error code, such as one listed
     * in section 6, is appropriate.
     */

    case SASL_TOOWEAK:
	/* RFC 2554
	 * 534 Authentication mechanism is too weak
	 * This response to the AUTH command indicates that the selected   
	 * authentication mechanism is weaker than server policy permits for
	 * that user.
	 */
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"Authentication mechanism is too weak",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id );
	return( smtp_write_banner( r, 534, NULL, NULL ));

    case SASL_ENCRYPT:
	/* RFC 2554
	 * 538 Encryption required for requested authentication mechanism
	 * This response to the AUTH command indicates that the selected   
	 * authentication mechanism may only be used when the underlying SMTP
	 * connection is encrypted.
	 */
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"Encryption required for mechanism %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id, r->r_av[ 1 ] );
	return( smtp_write_banner( r, 538, NULL, NULL ));

    default:
        sasl_getprop( r->r_conn, SASL_USERNAME, (const void **) &r->r_auth_id );
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"sasl_start_server: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id, sasl_errdetail( r->r_conn ));
	return( RECEIVE_SYSERROR );
    }

    if ( sasl_getprop( r->r_conn, SASL_USERNAME,
	    (const void **) &r->r_auth_id ) != SASL_OK ) {
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"sasl_getprop: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id, sasl_errdetail( r->r_conn ));
	return( RECEIVE_CLOSECONNECTION );
    }

    if ( sasl_getprop( r->r_conn, SASL_MECHNAME,
	    (const void **) &mechname ) != SASL_OK ) {
	syslog( LOG_ERR, "Auth [%s] %s: %s: "
		"sasl_getprop: %s",
		inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
		r->r_auth_id, sasl_errdetail( r->r_conn ));
	return( RECEIVE_CLOSECONNECTION );
    }

    syslog( LOG_INFO, "Auth [%s] %s: %s authenticated via %s%s",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname, 
	    r->r_auth_id, mechname, r->r_tls ? "+TLS" : "" );

    if ( smtp_write_banner( r, 235, NULL, NULL ) != RECEIVE_OK ) {
	return( RECEIVE_CLOSECONNECTION );
    }

    r->r_auth = 1;
    snet_setsasl( r->r_snet, r->r_conn );

    /* RFC 2554 If a security layer is negotiated through the SASL
     * authentication exchange, it takes effect immediately following
     * the CRLF that concludes the authentication exchange for the
     * client, and the CRLF of the success reply for the server.  Upon
     * a security layer's taking effect, the SMTP protocol is reset to
     * the initial state (the state in SMTP after a server issues a
     * 220 service ready greeting).  The server MUST discard any
     * knowledge obtained from the client, such as the argument to the
     * EHLO command, which was not obtained from the SASL negotiation
     * itself.
     */
     if ( snet_saslssf( r->r_snet )) {
	if ( r->r_hello ) {
	    free( r->r_hello );
	    r->r_hello = NULL;
	}
    }

    set_smtp_mode( r, simta_smtp_default_mode, "Default" );
    return( RECEIVE_OK );
}
#endif /* HAVE_LIBSASL */


    int
smtp_receive( int fd, struct connection_info *c, struct simta_socket *ss )
{
    struct receive_data			r;
    ACAV				*acav = NULL;
    fd_set				fdset;
    int					i;
    int					ret;
    int					continue_after_timeout = 0;
    int					time_remaining;
    char				*timer_type;
    char				*line;
    char				hostname[ DNSR_MAX_NAME + 1 ];
    struct timeval			tv;
    struct timeval			tv_start;
    struct timeval			tv_stop;
    struct timeval			tv_now;
    struct timeval			tv_wait;
#ifdef HAVE_LIBWRAP
    char				*ctl_hostname;
#endif /* HAVE_LIBWRAP */

    /*
     * global connections max 
     * auth init
     * check DNS reverse
     * TCP wrappers
     * RBLs
     * if not RBL_ACCEPT, local connections max
     * write before banner check
     * opening banner * command line loop
     */

    /*
     * local variable init
     * build snet connection
     * dynamic memory init
     * global connections max 
     * if SIMTA_MODE_REFUSE, give 554 banner and go to command line loop
     * auth init
     * check DNS reverse
     * TCP wrappers
     * RBLs
     * if not RBL_ACCEPT, local connections max
     * write before banner check
     * tarpit sleep
     * opening banner
     * command line loop
     */

    memset( &r, 0, sizeof( struct receive_data ));
    r.r_sin = &c->c_sin;
    r.r_dns_match = REVERSE_UNRESOLVED;
    r.r_remote_hostname = S_UNRESOLVED;
    r.r_rbl_status = RBL_UNKNOWN;
    r.r_mdctx_status = MDCTX_UNINITILIZED;
    set_smtp_mode( &r, simta_smtp_default_mode, "Default" );

    if ( simta_gettimeofday( &tv_start ) != 0 ) {
	tv_start.tv_sec = 0;
    }

    if ( simta_inbound_global_session_timer > 0 ) {
	r.r_tv_session.tv_sec = simta_inbound_global_session_timer +
		tv_start.tv_sec;
    }

    if (( r.r_snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "Syserror smtp_receive: snet_attach: %m" );
	return( 0 );
    }

    tv_wait.tv_sec = simta_inbound_command_line_timer;
    tv_wait.tv_usec = 0;
    snet_timeout( r.r_snet, SNET_WRITE_TIMEOUT | SNET_READ_TIMEOUT, &tv_wait );

    if ( reset( &r ) != RECEIVE_OK ) {
	goto syserror;
    }

    if (( acav = acav_alloc( )) == NULL ) {
	syslog( LOG_ERR, "Syserror smtp_receive: argcargv_alloc: %m" );
	goto syserror;
    }

    if (( simta_global_connections_max != 0 ) &&
	    ( simta_global_connections > simta_global_connections_max )) {
	syslog( LOG_WARNING, "Connect.in [%s] %s: connection refused: "
		"global maximum exceeded: %d",
		inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
		simta_global_connections );
	smtp_write_banner( &r, 421, S_MAXCONNECT, S_CLOSING );
	goto closeconnection;
    }

    if (( simta_global_throttle_max != 0 ) &&
	    ( simta_global_throttle_connections > simta_global_throttle_max )) {
	syslog( LOG_WARNING, "Connect.in [%s] %s: connection refused: "
		"global throttle exceeded: %d",
		inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
		simta_global_throttle_connections );
	smtp_write_banner( &r, 421, S_MAXCONNECT, S_CLOSING );
	goto closeconnection;
    }

    if ( r.r_smtp_mode == SMTP_MODE_REFUSE ) {
	/* rfc 2821 3.1 Session Initiation
	 * The SMTP protocol allows a server to formally reject a transaction   
	 * while still allowing the initial connection as follows: a 554
	 * response MAY be given in the initial connection opening message
	 * instead of the 220.  A server taking this approach MUST still wait
	 * for the client to send a QUIT (see section 4.1.1.10) before closing
	 * the connection and SHOULD respond to any intervening commands with
	 * "503 bad sequence of commands".  Since an attempt to make an SMTP
	 * connection to such a system is probably in error, a server returning
	 * a 554 response on connection opening SHOULD provide enough  
	 * information in the reply text to facilitate debugging of the sending
	 * system.
	 */
	syslog( LOG_INFO,
		"Connect.in [%s] %s: connection refused: inbound smtp disabled",
		inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
	if ( smtp_write_banner( &r, 554, "No SMTP Service here", NULL ) !=
		RECEIVE_OK ) {
	    goto closeconnection;
	}

    } else {
	if ( auth_init( &r, ss ) != 0 ) {
	    goto syserror;
	}

	if ( simta_dnsr == NULL ) {
	    if (( simta_dnsr = dnsr_new( )) == NULL ) {
		syslog( LOG_ERR, "Syserror smtp_receive: dnsr_new: NULL" );
		goto syserror;
	    }
	}

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: smtp_mail checking reverse" );
	}

	*hostname = '\0';
        switch ( r.r_dns_match =
		check_reverse( hostname, &(c->c_sin.sin_addr))) {

	default:
	    syslog( LOG_ERR, "Syserror smtp_receive check_reverse: "
		    "out of range" );
	    /* fall through to REVERSE_ERROR */
        case REVERSE_ERROR:
	    r.r_remote_hostname = S_UNKNOWN;
	    if ( simta_ignore_connect_in_reverse_errors ) {
		syslog( LOG_INFO, "Connect.in [%s] %s: "
			"Warning: reverse address error: %s",
			inet_ntoa( r.r_sin->sin_addr ),
			r.r_remote_hostname,
			dnsr_err2string( dnsr_errno( simta_dnsr )));

	    } else {
		syslog( LOG_INFO, "Connect.in [%s] %s: Failed: "
			"reverse address error: %s",
			inet_ntoa( r.r_sin->sin_addr ),
			r.r_remote_hostname,
			dnsr_err2string( dnsr_errno( simta_dnsr )));

		smtp_write_banner( &r, 421, S_421_DECLINE, NULL );
		goto closeconnection;
	    }
	    break;

        case REVERSE_MATCH:
	    r.r_remote_hostname = hostname;
	    break;

	case REVERSE_UNKNOWN:
        case REVERSE_MISMATCH:
	    /* invalid reverse */
	    if ( r.r_dns_match == REVERSE_MISMATCH ) {
		r.r_remote_hostname = S_MISMATCH;
	    } else {
		r.r_remote_hostname = S_UNKNOWN;
	    }

	    if ( simta_ignore_reverse == 0 ) {
		syslog( LOG_INFO, "Connect.in [%s] %s: Failed: "
			"invalid reverse", inet_ntoa( r.r_sin->sin_addr ),
			r.r_remote_hostname );
		smtp_write_banner( &r, 421, S_421_DECLINE,
			simta_reverse_url );
		goto closeconnection;

	    } else {
		syslog( LOG_INFO, "Connect.in [%s] %s: Warning: "
			"invalid reverse", inet_ntoa( r.r_sin->sin_addr ),
			r.r_remote_hostname );
	    }
	    break;
        } /* end of switch */

#ifdef HAVE_LIBWRAP
	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: smtp_mail host lookup" );
	}
	if ( *hostname == '\0' ) {
	    ctl_hostname = STRING_UNKNOWN;
	} else {
	    ctl_hostname = hostname;
	}

	/* first STRING_UNKNOWN should be domain name of incoming host */
	if ( hosts_ctl( "simta", ctl_hostname,
		inet_ntoa( r.r_sin->sin_addr ), STRING_UNKNOWN ) == 0 ) {
	    syslog( LOG_INFO, "Connect.in [%s] %s: Failed: access denied",
		    inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
	    smtp_write_banner( &r, 421, S_421_DECLINE, simta_libwrap_url );
	    goto closeconnection;
	}

	if ( r.r_remote_hostname == string_unknown ) {
	    r.r_remote_hostname = NULL;
	}
#endif /* HAVE_LIBWRAP */

        if ( simta_rbls != NULL ) {
	    if ( simta_debug != 0 ) {
		syslog( LOG_DEBUG, "Debug: smtp_mail checking rbls" );
	    }

            switch( rbl_check( simta_rbls, &(c->c_sin.sin_addr),
		    r.r_remote_hostname, NULL, &(r.r_rbl), &(r.r_rbl_msg))) {
            case RBL_BLOCK:
		r.r_rbl_status = RBL_BLOCK;
                syslog( LOG_INFO, "Connect.in [%s] %s: RBL Blocked %s: %s",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
                        (r.r_rbl)->rbl_domain, r.r_rbl_msg );
		set_smtp_mode( &r, SMTP_MODE_OFF, "RBL Blocked" );
		break;

            case RBL_ACCEPT:
		r.r_rbl_status = RBL_ACCEPT;
                syslog( LOG_INFO, "Connect.in [%s] %s: RBL Accepted: %s",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
                        (r.r_rbl)->rbl_domain );
                break;

            case RBL_NOT_FOUND:
		/* leave as RBL_UNKNOWN so user tests happen */
		r.r_rbl_status = RBL_UNKNOWN;
                syslog( LOG_DEBUG, "Connect.in [%s] %s: RBL Unlisted",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
                break;

	    case RBL_ERROR:
            default:
		r.r_rbl_status = RBL_UNKNOWN;
                syslog( LOG_INFO,
			"Connect.in [%s] %s: RBL Error: %s",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
                        (r.r_rbl)->rbl_domain );
                if ( dnsr_errno( simta_dnsr ) !=
                        DNSR_ERROR_TIMEOUT ) {
                    goto syserror;
                }
                dnsr_errclear( simta_dnsr );
                break;
            }
        }

	if ( r.r_rbl_status != RBL_ACCEPT ) {
	    if (( simta_local_connections_max != 0 ) &&
		    ( c->c_proc_total > simta_local_connections_max )) {
		syslog( LOG_WARNING, "Connect.in [%s] %s: connection refused: "
			"local maximum exceeded: %d",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
			c->c_proc_total );
		smtp_write_banner( &r, 421, S_MAXCONNECT, S_CLOSING );
		goto closeconnection;
	    }

	    if (( simta_local_throttle_max != 0 ) &&
		    ( c->c_proc_throttle > simta_local_throttle_max )) {
		syslog( LOG_WARNING, "Connect.in [%s] %s: connection refused: "
			"connection per interval exceeded %d",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
			c->c_proc_throttle );
		smtp_write_banner( &r, 421, S_MAXCONNECT, S_CLOSING );
		goto closeconnection;
	    }
	}

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: smtp_mail write before banner check" );
	}

	/* Write before Banner check */
	FD_ZERO( &fdset );
	FD_SET( snet_fd( r.r_snet ), &fdset );
	tv.tv_sec = simta_banner_delay;
	tv.tv_usec = 0;

	if (( ret = select( snet_fd( r.r_snet ) + 1, &fdset, NULL,
		NULL, &tv )) < 0 ) {
	    syslog( LOG_ERR, "Syserror smtp_receive select: %m (%d %d)",
		    snet_fd( r.r_snet ) + 1, simta_banner_delay );
	    goto syserror;
	} else if ( ret > 0 ) {
	    r.r_write_before_banner = 1;
	    syslog( LOG_INFO, "Connect.in [%s] %s: Write before banner",
		    inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
	    sleep( simta_banner_punishment );
	}

	tarpit_sleep( &r, simta_smtp_tarpit_connect );

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: smtp_mail opening banner" );
	}

	if ( r.r_smtp_mode == SMTP_MODE_OFF ) {
	    if ( snet_writef( r.r_snet,
		    "554 <%s> %s %s: See %s\r\n", simta_hostname, S_DENIED,
		    inet_ntoa( r.r_sin->sin_addr ), (r.r_rbl)->rbl_url ) < 0 ) {
		syslog( LOG_ERR, "Syserror: Receive [%s] %s: "
			"smtp_receive: snet_writef: %m",
			inet_ntoa( r.r_sin->sin_addr ),
			r.r_remote_hostname );
		goto closeconnection;
	    }

	} else {
	    if ( smtp_write_banner( &r, 220, NULL, NULL ) != RECEIVE_OK ) {
		goto closeconnection;
	    }
	}

	syslog( LOG_INFO, "Connect.in [%s] %s: Accepted",
		inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
    }

    for ( ; ; ) {
	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    goto syserror;
	}

	/* command line timer */
	tv_wait.tv_sec = simta_inbound_command_line_timer;
	tv_wait.tv_usec = 0;
	timer_type = S_COMMAND_LINE;

	/* global session timer */
	if ( r.r_tv_session.tv_sec != 0 ) {
	    if ( r.r_tv_session.tv_sec <= tv_now.tv_sec ) {
		timer_type = S_GLOBAL_SESSION;
		break;
	    }
	    time_remaining = r.r_tv_session.tv_sec - tv_now.tv_sec;
	    if ( tv_wait.tv_sec > time_remaining ) {
		tv_wait.tv_sec = time_remaining;
		timer_type = S_GLOBAL_SESSION;
	    }
	}

	/* inactivity timer */
	if ( simta_inbound_command_inactivity_timer > 0 ) {
	    if ( r.r_tv_inactivity.tv_sec != 0 ) {
		if ( r.r_tv_inactivity.tv_sec <= tv_now.tv_sec ) {
		    timer_type = S_INACTIVITY;
		    break;
		}
	    } else {
		r.r_tv_inactivity.tv_sec =
			simta_inbound_command_inactivity_timer + tv_now.tv_sec;
	    }

	    time_remaining = r.r_tv_inactivity.tv_sec - tv_now.tv_sec;
	    if ( tv_wait.tv_sec > time_remaining ) {
		tv_wait.tv_sec = time_remaining;
		timer_type = S_INACTIVITY;
	    }
	}

	/* message send timer */
	if ( r.r_tv_accepted.tv_sec != 0 ) {
	    if ( r.r_tv_accepted.tv_sec <= tv_now.tv_sec ) {
		r.r_tv_accepted.tv_sec = 0;
		if ( deliver_accepted( &r ) != RECEIVE_OK ) {
		    return( RECEIVE_SYSERROR );
		}
		continue;
	    }
	    time_remaining = r.r_tv_accepted.tv_sec - tv_now.tv_sec;
	    if ( tv_wait.tv_sec > time_remaining ) {
		tv_wait.tv_sec = time_remaining;
		continue_after_timeout = 1;
		timer_type = S_ACCEPTED_MESSAGE;
	    }
	}

	if (( line = snet_getline( r.r_snet, &tv_wait )) == NULL ) {
	    if ( errno == ETIMEDOUT ) {
		if ( continue_after_timeout != 0 ) {
		    continue_after_timeout = 0;
		    continue;
		}

		syslog( LOG_DEBUG, "Receive [%s] %s: Command: Timeout %s",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
			timer_type );
		smtp_write_banner( &r, 421, S_TIMEOUT, S_CLOSING );
		goto closeconnection;
	    }

	    syslog( LOG_DEBUG, "Receive [%s] %s: Command: connection dropped",
		    inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
	    goto syserror;
	}

	if ( r.r_smtp_command != NULL ) {
	    free( r.r_smtp_command );
	    r.r_smtp_command = NULL;
	}

	if (( r.r_smtp_command = strdup( line )) == NULL ) {
	    syslog( LOG_ERR, "Syserror smtp_receive: strdup: %m" );
	    goto syserror;
	}

	/*
	 * This routine needs to be revised to take rfc822 quoting into
	 * account.  E.g.  MAIL FROM:<"foo \: bar"@umich.edu>
	 */
	if (( r.r_ac = acav_parse2821( acav, line, &(r.r_av))) < 0 ) {
	    syslog( LOG_ERR, "Syserror smtp_receive: argcargv: %m" );
	    goto syserror;
	}

	/* rfc 2821 2.4
	 * No sending SMTP system is permitted to send envelope commands
	 * in any character set other than US-ASCII; receiving systems
	 * SHOULD reject such commands, normally using "500 syntax error
	 * - invalid character" replies.
	 */
	if ( r.r_ac != 0 ) {
	    for ( i = 0; i < r.r_ncommands; i++ ) {
		if ( strcasecmp( r.r_av[ 0 ],
			r.r_commands[ i ].c_name ) == 0 ) {
		    break;
		}
	    }
	}

	if (( r.r_ac == 0 ) || ( i >= r.r_ncommands )) {
	    if ( r.r_smtp_mode == SMTP_MODE_OFF ) {
		syslog( LOG_DEBUG, "Receive [%s] %s: SMTP_Off: %s",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
			r.r_smtp_command );
		smtp_write_banner( &r, 421, S_421_DECLINE, NULL );
		goto closeconnection;
	    }

	    if ( r.r_ac == 0 ) {
		syslog( LOG_DEBUG, "Receive [%s] %s: No Command",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname );
	    } else {
		syslog( LOG_DEBUG, "Receive [%s] %s: Command unrecognized: %s",
			inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
			r.r_smtp_command );
	    }

	    tarpit_sleep( &r, 0 );

	    if ( smtp_write_banner( &r, 500, NULL, NULL ) != RECEIVE_OK ) {
		goto closeconnection;
	    }
	    continue;
	}

	switch ((*(r.r_commands[ i ].c_func))( &r )) {
	case RECEIVE_OK:
	    break;

	case RECEIVE_CLOSECONNECTION:
	    goto closeconnection;

	default:
	/* fallthrough */
	case RECEIVE_SYSERROR:
	    goto syserror;
	}

	if (( r.r_smtp_mode == SMTP_MODE_NORMAL ) &&
		( simta_max_failed_rcpts > 0 ) &&
		( r.r_failed_rcpts >= simta_max_failed_rcpts )) {
	    syslog( LOG_INFO, "Receive [%s] %s: %s: Too many failed recipients",
		    inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
		    r.r_env->e_id );
	    set_smtp_mode( &r, simta_smtp_punishment_mode,
		    "Failed recipients" );
	}
    }

syserror:
    smtp_write_banner( &r, 421, NULL, NULL );

closeconnection:
    if ( snet_close( r.r_snet ) != 0 ) {
	syslog( LOG_ERR, "Syserror smtp_receive: snet_close: %m" );
    }

    if ( acav != NULL ) {
	acav_free( acav );
    }

    if ( r.r_smtp_command != NULL ) {
	free( r.r_smtp_command );
	r.r_smtp_command = NULL;
    }

    if ( r.r_hello != NULL ) {
	free( r.r_hello );
    }

    reset( &r );

#ifdef HAVE_LIBSSL 
    if ( r.r_mdctx_status != MDCTX_UNINITILIZED ) {
	EVP_MD_CTX_cleanup( &r.r_mdctx );
    }
#endif /* HAVE_LIBSSL */

    if ( tv_start.tv_sec != 0 ) {
	if ( simta_gettimeofday( &tv_stop ) != 0 ) {
	    tv_start.tv_sec = 0;
	    tv_stop.tv_sec = 0;
	}
    }

    if ( simta_sasl ) {
	syslog( LOG_DEBUG,
		"Connect.stat [%s] %s: Metrics: "
		"seconds %d, mail from %d/%d, rcpt to %d/%d, data %d/%d: "
		"Authuser %s",
		inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
		(int)(tv_stop.tv_sec - tv_start.tv_sec), r.r_mail_success,
		r.r_mail_attempt,
		r.r_rcpt_success, r.r_rcpt_attempt, r.r_data_success,
		r.r_data_attempt, r.r_auth_id );
    } else {
	syslog( LOG_DEBUG,
		"Connect.stat [%s] %s: Metrics: "
		"seconds %d, mail from %d/%d, rcpt to %d/%d, data %d/%d",
		inet_ntoa( r.r_sin->sin_addr ), r.r_remote_hostname,
		(int)(tv_stop.tv_sec - tv_start.tv_sec), r.r_mail_success,
		r.r_mail_attempt,
		r.r_rcpt_success, r.r_rcpt_attempt, r.r_data_success,
		r.r_data_attempt );
    }

    return( simta_fast_files );
}


    int
auth_init( struct receive_data *r, struct simta_socket *ss )
{
    int					ret;
#ifdef HAVE_LIBSASL
    sasl_security_properties_t		secprops;
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSASL
    if ( simta_sasl ) {
	set_smtp_mode( r, SMTP_MODE_NOAUTH, "Authentication" );
	if (( ret = sasl_server_new( "smtp", NULL, NULL, NULL, NULL, NULL,
		0, &(r->r_conn) )) != SASL_OK ) {
	    syslog( LOG_ERR, "Syserror auth_init: sasl_server_new: %s",
		    sasl_errstring( ret, NULL, NULL ));
	    return( -1 );
	}

	/* Init defaults... */
	memset( &secprops, 0, sizeof( secprops ));

	/* maxbufsize = maximum security layer receive buffer size.
	 * 0=security layer not supported
	 *
	 * security strength factor
	 * min_ssf      = minimum acceptable final level
	 * max_ssf      = maximum acceptable final level
	 *
	 * security_flags = bitfield for attacks to protect against
	 *
	 * NULL terminated array of additional property names, values
	 * const char **property_names;
	 * const char **property_values;
         */ 

	/* These are the various security flags apps can specify. */
	/* NOPLAINTEXT      -- don't permit mechanisms susceptible to simple 
	 *                     passive attack (e.g., PLAIN, LOGIN)           
	 * NOACTIVE         -- protection from active (non-dictionary) attacks
	 *                     during authentication exchange.
	 *                     Authenticates server.
	 * NODICTIONARY     -- don't permit mechanisms susceptible to passive
	 *                     dictionary attack
	 * FORWARD_SECRECY  -- require forward secrecy between sessions
	 *                     (breaking one won't help break next)
	 * NOANONYMOUS      -- don't permit mechanisms that allow anonymous
	 *		       login
	 * PASS_CREDENTIALS -- require mechanisms which pass client
	 *                     credentials, and allow mechanisms which can pass
	 *                     credentials to do so
	 * MUTUAL_AUTH      -- require mechanisms which provide mutual
	 *                     authentication
	 */ 

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: auth_init sasl_setprop 1" );
	}

	memset( &secprops, 0, sizeof( secprops ));
	secprops.maxbufsize = 4096;
	/* min_ssf set to zero with memset */
	secprops.max_ssf = 256;
	secprops.security_flags |= SASL_SEC_NOPLAINTEXT;
	secprops.security_flags |= SASL_SEC_NOANONYMOUS;
	if (( ret = sasl_setprop( r->r_conn, SASL_SEC_PROPS, &secprops))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "Syserror auth_init: sasl_setprop1: %s",
		    sasl_errdetail( r->r_conn ));
	    return( -1 );
	}

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: auth_init sasl_setprop 2" );
	}

	if (( ret = sasl_setprop( r->r_conn, SASL_SSF_EXTERNAL,
		&(r->r_ext_ssf))) != SASL_OK ) {
	    syslog( LOG_ERR, "Syserror auth_init: sasl_setprop2: %s",
		    sasl_errdetail( r->r_conn ));
	    return( -1 );
	}

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: auth_init sasl_setprop 3" );
	}

	if (( ret = sasl_setprop( r->r_conn, SASL_AUTH_EXTERNAL, r->r_auth_id ))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "Syserror auth_init: sasl_setprop3: %s",
		    sasl_errdetail( r->r_conn ));
	    return( -1 );
	}
    }
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
    if ( ss->ss_flags & SIMTA_SOCKET_TLS ) {

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: auth_init _start_tls" );
	}

	if ( _start_tls( r ) != RECEIVE_OK ) {
	    return( -1 );
	}

	if ( simta_debug != 0 ) {
	    syslog( LOG_DEBUG, "Debug: auth_init _post_tls" );
	}

	if (( ret = _post_tls( r )) != RECEIVE_OK ) {
	    return( -1 );
	}

	syslog( LOG_DEBUG, "Connect.in [%s] %s: SMTS",
	    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname );
    }
#endif /* HAVE_LIBSSL */

    if ( simta_debug != 0 ) {
	syslog( LOG_DEBUG, "Debug: auth_init finished" );
    }

    return( 0 );
}


    static int
local_address( char *addr, char *domain, struct simta_red *red )
{
    int			n_required_found = 0;
    int			rc;
    char		*at;
    struct passwd	*passwd;
    struct action	*action;
    DBT			value;

    if (( at = strchr( addr, '@' )) == NULL ) {
	return( NOT_LOCAL );
    }

    /* Search for user using expansion table */
    for ( action = red->red_receive; action != NULL; action = action->a_next ) {
	switch ( action->a_action ) {
	case EXPANSION_TYPE_GLOBAL_RELAY:
	    return( LOCAL_ADDRESS );

	case EXPANSION_TYPE_ALIAS:
	    if ( action->a_dbp == NULL ) {
		if (( rc = db_open_r( &(action->a_dbp), action->a_fname,
			NULL )) != 0 ) {
		    action->a_dbp = NULL;
		    syslog( LOG_ERR, "Syserror local_address: db_open_r %s: %s",
			    action->a_fname, db_strerror( rc ));
		    break;
		}
	    }

	    *at = '\0';
	    rc = db_get( action->a_dbp, addr, &value );
	    *at = '@';

	    if ( rc == 0 ) {
		if ( action->a_flags == ACTION_SUFFICIENT ) {
		    return( LOCAL_ADDRESS );
		} else {
		    n_required_found++;
		}
	    } else if ( action->a_flags == ACTION_REQUIRED ) {
		return( NOT_LOCAL );
	    }
	    break;

	case EXPANSION_TYPE_PASSWORD:
	    /* Check password file */
	    *at = '\0';
	    passwd = simta_getpwnam( action, addr );
	    *at = '@';

	    if ( passwd != NULL ) {
		if ( action->a_flags == ACTION_SUFFICIENT ) {
		    return( LOCAL_ADDRESS );
		} else {
		    n_required_found++;
		}
	    } else if ( action->a_flags == ACTION_REQUIRED ) {
		return( NOT_LOCAL );
	    }
	    break;

#ifdef HAVE_LDAP
	case EXPANSION_TYPE_LDAP:
	    /* Check LDAP */
	    *at = '\0';
	    rc = simta_ldap_address_local( action->a_ldap, addr, domain );
	    *at = '@';

	    switch ( rc ) {
	    default:
		syslog( LOG_ERR, "Syserror local_address: "
			"simta_ldap_address_local: bad value" );
	    case LDAP_SYSERROR:
		return( LOCAL_ERROR );

	    case LDAP_NOT_LOCAL:
		if ( action->a_flags == ACTION_REQUIRED ) {
		    return( NOT_LOCAL );
		}
		continue;

	    case LDAP_LOCAL:
		if ( action->a_flags == ACTION_SUFFICIENT ) {
		    return( LOCAL_ADDRESS );
		} else {
		    n_required_found++;
		}
		break;

	    case LDAP_LOCAL_RBL:
		return( LOCAL_ADDRESS_RBL );
	    }
	    break;
#endif /* HAVE_LDAP */

	default:
	    /* unknown lookup */
	    panic( "local_address: expansion type out of range" );
	}
    }

    if ( n_required_found != 0 ) {
	return( LOCAL_ADDRESS );
    }

    return( NOT_LOCAL );
}

 
    char *
env_string( char *left, char *right )
{
    char			*buf;

    if (( right == NULL ) || ( *right == '\0' )) {
	if (( buf = (char*)malloc( strlen( left ) + 2 )) == NULL ) {
	    syslog( LOG_ERR, "Syserror env_string: malloc: %m" );
	    return( NULL );
	}
	sprintf( buf, "%s=", left );

    } else {
	if (( buf = (char*)malloc( strlen( left ) +
		strlen( right ) + 2 )) == NULL ) {
	    syslog( LOG_ERR, "Syserror env_string: malloc: %m" );
	    return( NULL );
	}
	sprintf( buf, "%s=%s", left, right );
    }

    return( buf );
}


    int
content_filter( struct receive_data *r, char **smtp_message )
{
    int			fd[ 2 ];
    int			pid;
    int			status;
    SNET		*snet;
    char		*line;
    char		*filter_argv[] = { 0, 0 };
    char		*filter_envp[ 14 ];
    char		fname[ MAXPATHLEN + 1 ];
    char		buf[ 256 ];
    struct timeval	log_tv;

    if (( filter_argv[ 0 ] = strrchr( simta_mail_filter, '/' )) != NULL ) {
	filter_argv[ 0 ]++;
    } else {
	filter_argv[ 0 ] = simta_mail_filter;
    }

    if ( pipe( fd ) < 0 ) {
	syslog( LOG_ERR, "Syserror content_filter: pipe: %m" );
	return( MESSAGE_TEMPFAIL );
    }

    simta_gettimeofday( NULL );

    switch ( pid = fork()) {
    case -1 :
	close( fd[ 0 ]);
	close( fd[ 1 ]);
	syslog( LOG_ERR, "Syserror content_filter: fork: %m" );
	return( MESSAGE_TEMPFAIL );

    case 0 :
	log_tv = simta_log_tv;
	simta_openlog( 1 );
	/* use fd[ 1 ] to communicate with parent, parent uses fd[ 0 ] */
	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: close1: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	/* stdout -> fd[ 1 ] */
	if ( dup2( fd[ 1 ], 1 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: dup2: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	/* stderr -> fd[ 1 ] */
	if ( dup2( fd[ 1 ], 2 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: dup2: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: close2: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	/* no stdin */
	if ( close( 0 ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: close3: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( r->r_env->e_flags & ENV_FLAG_DFILE ) {
	    snprintf( fname, MAXPATHLEN, "%s/D%s", r->r_env->e_dir,
		    r->r_env->e_id );
	} else {
	    *fname = '\0';
	}

	if (( filter_envp[ 0 ] = env_string( "SIMTA_DFILE",
		fname )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( r->r_env->e_flags & ENV_FLAG_TFILE ) {
	    snprintf( fname, MAXPATHLEN, "%s/t%s", r->r_env->e_dir,
		    r->r_env->e_id );
	} else {
	    *fname = '\0';
	}

	if (( filter_envp[ 1 ] = env_string( "SIMTA_TFILE",
		fname )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 2 ] = env_string( "SIMTA_REMOTE_IP",
		inet_ntoa( r->r_sin->sin_addr ))) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 3 ] = env_string( "SIMTA_REMOTE_HOSTNAME",
		r->r_remote_hostname )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	sprintf( buf, "%d", r->r_dns_match );
	if (( filter_envp[ 4 ] = env_string( "SIMTA_REVERSE_LOOKUP",
		buf )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 5 ] = env_string( "SIMTA_SMTP_MAIL_FROM",
		r->r_env->e_mail )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 6 ] = env_string( "SIMTA_SMTP_HELO",
		r->r_hello )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 7 ] = env_string( "SIMTA_MID",
		r->r_env->e_mid )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 8 ] = env_string( "SIMTA_UID",
		r->r_env->e_id )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( r->r_write_before_banner != 0 ) {
	    if (( filter_envp[ 9 ] = env_string( "SIMTA_WRITE_BEFORE_BANNER",
		    "1" )) == NULL ) {
		exit( MESSAGE_TEMPFAIL );
	    }

	} else {
	    if (( filter_envp[ 9 ] = env_string( "SIMTA_WRITE_BEFORE_BANNER",
		    "0" )) == NULL ) {
		exit( MESSAGE_TEMPFAIL );
	    }
	}

	if (( filter_envp[ 10 ] = env_string( "SIMTA_AUTH_ID",
		r->r_auth_id )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}


	sprintf( buf, "%d", getpid() );
	if (( filter_envp[ 11 ] = env_string( "SIMTA_PID",
		buf )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}


	sprintf( buf, "%ld", log_tv.tv_sec );
	if (( filter_envp[ 12 ] = env_string( "SIMTA_CID",
		buf )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( simta_checksum_md != NULL ) {
	    if (( filter_envp[ 13 ] = env_string( "SIMTA_CHECKSUM_SIZE",
		    r->r_md_bytes )) == NULL ) {
		exit( MESSAGE_TEMPFAIL );
	    }

	    if (( filter_envp[ 14 ] = env_string( "SIMTA_CHECKSUM",
		    r->r_md_b64 )) == NULL ) {
		exit( MESSAGE_TEMPFAIL );
	    }

	    filter_envp[ 15 ] = NULL;
	} else {
	    filter_envp[ 13 ] = NULL;
	}


	execve( simta_mail_filter, filter_argv, filter_envp );
	/* if we are here, there is an error */
	syslog( LOG_ERR, "Syserror content_filter: execve: %m" );
	exit( MESSAGE_TEMPFAIL );

    default :
	/* use fd[ 0 ] to communicate with child, child uses fd[ 1 ] */
	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: close 4: %m" );
	    return( MESSAGE_TEMPFAIL );
	}

	if (( snet = snet_attach( fd[ 0 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "Syserror snet_attach: %m" );
	    close( fd[ 0 ] );
	    return( MESSAGE_TEMPFAIL );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    syslog( LOG_INFO, "Filter [%s] %s: %s: %s",
		    inet_ntoa( r->r_sin->sin_addr ), r->r_remote_hostname,
		    r->r_env->e_id, line );

	    if ( *smtp_message == NULL ) {
		if (( *smtp_message = strdup( line )) == NULL ) {
		    syslog( LOG_ERR, "Syserror content_filter: strdup: %m" );
		    snet_close( snet );
		    return( MESSAGE_TEMPFAIL );
		}
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "Syserror content_filter: snet_close: %m" );
	    return( MESSAGE_TEMPFAIL );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    syslog( LOG_ERR, "Syserror content_filter: waitpid: %m" );
	    return( MESSAGE_TEMPFAIL );
	}

	if ( WIFEXITED( status )) {
	    return( WEXITSTATUS( status ));

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Syserror content_filter: %d died on signal %d\n",
		    pid, WTERMSIG( status ));
	    return( MESSAGE_TEMPFAIL );

	} else {
	    syslog( LOG_ERR, "Syserror content_filter: %d died\n", pid );
	    return( MESSAGE_TEMPFAIL );
	}
    }
}

#ifdef HAVE_LIBSASL
    int
reset_sasl_conn( struct receive_data *r )
{

    int         rc;

    sasl_dispose( &r->r_conn );

    if (( rc = sasl_server_new( "smtp", NULL, NULL, NULL, NULL, NULL,
            0, &r->r_conn )) != SASL_OK ) {
	syslog( LOG_ERR, "Syserror reset_sasl_conn: sasl_server_new: %s",
		sasl_errdetail( r->r_conn ));
        return( rc );
    }

    if (( rc = sasl_setprop( r->r_conn, SASL_SSF_EXTERNAL,
	    &r->r_ext_ssf )) != SASL_OK) {
	syslog( LOG_ERR, "Syserror reset_sasl_conn: sasl_setprop1: %s",
		sasl_errdetail( r->r_conn ));
        return( rc );
    }

    if (( rc = sasl_setprop( r->r_conn, SASL_AUTH_EXTERNAL,
	    &r->r_ext_ssf )) != SASL_OK) {
	syslog( LOG_ERR, "Syserror reset_sasl_conn: sasl_setprop2: %s",
		sasl_errdetail( r->r_conn ));
        return( rc );
    }

    return( SASL_OK );
}

#else /* HAVE_LIBSASL */
    int
reset_sasl_conn( struct receive_data *r )
{
    return( -1 );
}

#endif /* HAVE_LIBSASL */
