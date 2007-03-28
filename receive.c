/* Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
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

extern SSL_CTX	*ctx;
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#include <sasl/saslutil.h>	/* For sasl_decode64 and sasl_encode64 */
#include "base64.h"
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "bdb.h"
#include "denser.h"
#include "queue.h"
#include "ll.h"
#include "envelope.h"
#include "expand.h"
#include "red.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "mx.h"
#include "simta.h"
#include "line_file.h"
#include "header.h"

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#endif

#define RECEIVE_RBL_UNKNOWN	0
#define RECEIVE_RBL_BLOCKED	1
#define RECEIVE_RBL_NOT_BLOCKED	2

#define BYTE_LEN		10

#define	MDCTX_UNINITILIZED	0
#define	MDCTX_READY		1
#define	MDCTX_IN_USE		2
#define	MDCTX_FINAL		3

#define SIMTA_EXTENSION_SIZE    (1<<0)

extern char		*version;
struct sockaddr_in  	*receive_sin;
int			data_success = 0;
int			data_attempt = 0;
int			mail_success = 0;
int			mail_attempt = 0;
int			rcpt_success = 0;
int			rcpt_attempt = 0;
int			receive_failed_rcpts = 0;
int			receive_tls = 0;
int			receive_auth = 0;
int			remote_rbl_status = RBL_UNKNOWN;
char			*receive_dns_match = "Unknown";
char			*receive_hello = NULL;
char			*receive_smtp_command = NULL;
char			*receive_remote_hostname = "Unknown";
struct command 		*receive_commands  = NULL;
int			receive_ncommands;
#ifdef HAVE_LIBSSL
int			_start_tls( SNET *snet );
int 			_post_tls( SNET *snet );
unsigned char		md_value[ EVP_MAX_MD_SIZE ];
char			md_b64[ SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 ];
EVP_MD_CTX		mdctx;
int			mdctx_status = MDCTX_UNINITILIZED;
unsigned int		mdctx_bytes;
int			md_len;
char			md_bytes[ BYTE_LEN + 1 ];
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#define BASE64_BUF_SIZE 21848 /* per RFC 2222bis: ((16k / 3 ) +1 ) * 4 */
sasl_conn_t			*receive_conn;
/* external security strength factor zero = NONE */
sasl_ssf_t			ext_ssf = 0;
sasl_security_properties_t	secprops;
char				*auth_id = NULL;
#endif /* HAVE_LIBSASL */

#define	RECEIVE_OK		0x0000
#define	RECEIVE_SYSERROR	0x0001
#define	RECEIVE_CLOSECONNECTION	0x0010
#define	RECEIVE_BADSEQUENCE	0x0100

/* return codes for address_expand */
#define	LOCAL_ADDRESS			1
#define	NOT_LOCAL			2
#define	LOCAL_ERROR			3
#define	MX_ADDRESS			4
#define	LOCAL_ADDRESS_RBL		5

struct command {
    char	*c_name;
    int		(*c_func)( SNET *, struct envelope *, int, char *[] );
};

static char 	*env_string( char *, char * );
static int	mail_filter( struct envelope *, int, char ** );
static int	local_address( char *, char *, struct simta_red *);
static int	hello( struct envelope *, char * );
static int	reset( struct envelope *env );
static int	f_helo( SNET *, struct envelope *, int, char *[] );
static int	f_ehlo( SNET *, struct envelope *, int, char *[] );
static int	f_mail( SNET *, struct envelope *, int, char *[] );
static int	f_rcpt( SNET *, struct envelope *, int, char *[] );
static int	f_data( SNET *, struct envelope *, int, char *[] );
static int	f_rset( SNET *, struct envelope *, int, char *[] );
static int	f_noop( SNET *, struct envelope *, int, char *[] );
static int	f_quit( SNET *, struct envelope *, int, char *[] );
static int	f_help( SNET *, struct envelope *, int, char *[] );
static int	f_vrfy( SNET *, struct envelope *, int, char *[] );
static int	f_expn( SNET *, struct envelope *, int, char *[] );
static int	f_noauth( SNET *, struct envelope *, int, char *[] );
#ifdef HAVE_LIBSSL
static int	f_starttls( SNET *, struct envelope *, int, char *[] );
#endif /* HAVE_LIBSSL */
#ifdef HAVE_LIBSASL
static int	f_auth( SNET *, struct envelope *, int, char *[] );
static int 	reset_sasl_conn( sasl_conn_t **conn );
#endif /* HAVE_LIBSASL */

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
    { "VRFY",		f_vrfy },
    { "EXPN",		f_expn },
#ifdef HAVE_LIBSSL
    { "STARTTLS",	f_starttls },
#endif /* HAVE_LIBSSL */
#ifdef HAVE_LIBSASL
    { "AUTH", 		f_auth },
#endif /* HAVE_LIBSASL */
};

struct command	noauth_commands[] = {
    { "HELO",		f_helo },
    { "EHLO",		f_ehlo },
    { "MAIL",		f_noauth },
    { "RCPT",		f_noauth },
    { "DATA",		f_noauth },
    { "RSET",		f_rset },
    { "NOOP",		f_noop },
    { "QUIT",		f_quit },
    { "HELP",		f_help },
    { "VRFY",		f_noauth },
    { "EXPN",		f_noauth },
#ifdef HAVE_LIBSSL
    { "STARTTLS",	f_starttls },
#endif /* HAVE_LIBSSL */
#ifdef HAVE_LIBSASL
    { "AUTH", 		f_auth },
#endif /* HAVE_LIBSASL */
};


    int
reset( struct envelope *env )
{
    int			r = 0;

    if ( env ) {
	if ( env->e_flags & ENV_FLAG_ON_DISK ) {
	    if ( expand_and_deliver( env ) != EXPAND_OK ) {
		r = RECEIVE_SYSERROR;
	    }

	} else if ( env->e_id != NULL ) {
	    syslog( LOG_INFO, "Receive %s: Message Failed: [%s] %s: Abandoned",
		    env->e_id, inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname );
	}

	env_reset( env );
    }

    return( r );
}

    static int
hello( struct envelope *env, char *hostname )
{
    /* If we get "HELO" twice, just toss the new one */
    if ( receive_hello == NULL ) {
	/*
	 * rfc1123 5.2.5: We don't check that the "HELO" domain matches
	 * anything like the hostname.  When we create the data file, we'll
	 * reverse the source IP address and thus determine what the
	 * "Received:" header should say.  Since mail clients don't send well
	 * formed "HELO", we won't even do syntax checks on av[ 1 ].
	 */
	if (( receive_hello = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "helo: strdup: %m" );
	    return( RECEIVE_SYSERROR );
	}
    }

    return( RECEIVE_OK );
}


    static int
f_helo( SNET *snet, struct envelope *env, int ac, char *av[])
{
    if ( ac != 2 ) {
	syslog( LOG_ERR, "Receive: Bad HELO syntax: %s", receive_smtp_command );

	if ( snet_writef( snet,
		"501 Syntax violates RFC 2821 section 4.1.1.1: "
		"\"HELO\" SP Domain CRLF\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_helo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( hello( env, av[ 1 ] ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    if ( snet_writef( snet, "%d %s Hello %s\r\n", 250, simta_hostname,
	    av[ 1 ]) < 0 ) {
	syslog( LOG_ERR, "f_helo snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    syslog( LOG_NOTICE, "f_helo %s", av[ 1 ]);
    return( RECEIVE_OK );
}


/*
 * SMTP Extensions RFC.
 */
    static int
f_ehlo( SNET *snet, struct envelope *env, int ac, char *av[])
{
    extern int		simta_smtp_extension;
    int			extension_count;
    const char		*mechlist;

    extension_count = simta_smtp_extension;

    /* rfc 2821 4.1.4
     * A session that will contain mail transactions MUST first be
     * initialized by the use of the EHLO command.  An SMTP server SHOULD
     * accept commands for non-mail transactions (e.g., VRFY or EXPN)
     * without this initialization.
     */
    if ( ac != 2 ) {
	syslog( LOG_ERR, "Receive: Bad EHLO syntax: %s", receive_smtp_command );

	if ( snet_writef( snet,
		"501 Syntax violates RFC 2821 section 4.1.1.1: "
		"\"EHLO\" SP Domain CRLF\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /* rfc 2821 4.1.4
     * An EHLO command MAY be issued by a client later in the session.  If
     * it is issued after the session begins, the SMTP server MUST clear all
     * buffers and reset the state exactly as if a RSET command had been
     * issued.  In other words, the sequence of RSET followed immediately by
     * EHLO is redundant, but not harmful other than in the performance cost
     * of executing unnecessary commands.
     */
    if ( reset( env ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    /* rfc 2821 3.6
     * The domain name given in the EHLO command MUST BE either a primary
     * host name (a domain name that resolves to an A RR) or, if the host
     * has no name, an address literal as described in section 4.1.1.1.
     */

    if ( hello( env, av[ 1 ] ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

    if ( snet_writef( snet, "%d%s%s Hello %s\r\n", 250,
	    extension_count-- ? "-" : " ",
	    simta_hostname, av[ 1 ]) < 0 ) {
	syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    if ( simta_max_message_size >= 0 ) {
	if ( snet_writef( snet, "%d%sSIZE=%d\r\n", 250,
		extension_count-- ? "-" : " ",
		simta_max_message_size ) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
    }

#ifdef HAVE_LIBSASL
    if ( simta_sasl ) {
	if ( sasl_listmech( receive_conn, NULL, "", " ", "", &mechlist, NULL,
		NULL ) != SASL_OK ) {
	    syslog( LOG_ERR, "f_ehlo sasl_listmech: %s",
		    sasl_errdetail( receive_conn ));
	    return( RECEIVE_SYSERROR );
	}
	if ( snet_writef( snet, "250%sAUTH %s\r\n", 
		    extension_count-- ? "-" : " ", mechlist ) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
    }
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
    /* RFC 2487 4.2 
     * A server MUST NOT return the STARTTLS extension in response to an
     * EHLO command received after a TLS handshake has completed.
     */
    if ( simta_tls && !receive_tls ) {
	if ( snet_writef( snet, "%d%sSTARTTLS\r\n", 250,
		    extension_count-- ? "-" : " " ) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
    }
#endif /* HAVE_LIBSSL */

    syslog( LOG_NOTICE, "f_ehlo %s", av[ 1 ]);

    return( RECEIVE_OK );
}


    static int
f_mail_usage( SNET *snet )
{
    syslog( LOG_ERR, "Receive: Bad MAIL FROM syntax: %s",
	    receive_smtp_command );

    if ( snet_writef( snet,
	    "501-Syntax violates RFC 2821 section 4.1.1.2:\r\n"
	    "501-     \"MAIL FROM:\" (\"<>\" / Reverse-Path ) "
	    "[ SP Mail-parameters ] CRLF\r\n"
	    "501-         Reverse-path = Path\r\n"
	    "501          Path = \"<\" [ A-d-l \":\" ] Mailbox \">\"\r\n"
	    ) < 0 ) {
	syslog( LOG_ERR, "f_mail_usage snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}


    static int
f_mail( SNET *snet, struct envelope *env, int ac, char *av[])
{
    int			rc, i;
    int			parameters;
    int			seen_extensions = 0;
    long int		message_size;
    char		*addr;
    char		*domain;
    char		*endptr;

    mail_attempt++;

    if ( ac < 2 ) {
	return( f_mail_usage( snet ));
    }

    if (( !simta_strict_smtp_syntax ) && ( ac >= 3 ) &&
	    ( strcasecmp( av[ 1 ], "FROM:" ) == 0 )) {
	/* av[ 1 ] = "FROM:", av[ 2 ] = "<ADDRESS>" */
	if ( parse_emailaddr( RFC_2821_MAIL_FROM, av[ 2 ], &addr,
		&domain ) != 0 ) {
	    return( f_mail_usage( snet ));
	}
	parameters = 3;

    } else {
	if ( strncasecmp( av[ 1 ], "FROM:", strlen( "FROM:" )) != 0 ) {
	    return( f_mail_usage( snet ));
	}

	/* av[ 1 ] = "FROM:<ADDRESS>" */
	if ( parse_emailaddr( RFC_2821_MAIL_FROM, av[ 1 ] + strlen( "FROM:" ),
		&addr, &domain ) != 0 ) {
	    return( f_mail_usage( snet ));
	}
    	parameters = 2;
    }

    for ( i = parameters; i < ac; i++ ) {
	if ( strncasecmp( av[ i ], "SIZE", strlen( "SIZE" )) == 0 ) {
	    /* RFC 1870 Message Size Declaration */
	    if ( seen_extensions & SIMTA_EXTENSION_SIZE ) {
		syslog( LOG_ERR,
			"Receive: duplicate size specified: %s",
			receive_smtp_command );
		if ( snet_writef( snet,
			"501 duplicate size specified\r\n" ) < 0 ) {
		    syslog( LOG_ERR, "f_mail snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		return( RECEIVE_OK );
	    } else {
		seen_extensions = seen_extensions | SIMTA_EXTENSION_SIZE;
	    }

	    if ( strncasecmp( av[ i ], "SIZE=", strlen( "SIZE=" )) != 0 ) {
		syslog( LOG_ERR,
			"Receive: invalid SIZE parameter: %s",
			receive_smtp_command );
		if ( snet_writef( snet,
			"501 invalid SIZE command\r\n" ) < 0 ) {
		    syslog( LOG_ERR, "f_mail snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		return( RECEIVE_OK );
	    }

	    if ( simta_max_message_size > 0 ) {
		message_size = strtol( av[ i ] + strlen( "SIZE=" ),
			&endptr, 10 );

		if (( *(av[ i ] + strlen( "SIZE=" )) == '\0' )
			|| ( *endptr != '\0' )
			|| ( message_size == LONG_MIN )
			|| ( message_size == LONG_MAX ) 
			|| ( message_size < 0 )) {
		    syslog( LOG_ERR,
			    "Receive: invalid SIZE parameter: %s",
			    receive_smtp_command );
		    if ( snet_writef( snet,
			    "501 invalid SIZE parameter: %s\r\n",
			    av[ i ] + strlen( "SIZE=" )) < 0 ) {
			syslog( LOG_ERR, "f_mail snet_writef: %m" );
			return( RECEIVE_CLOSECONNECTION );
		    }
		    return( RECEIVE_OK );
		}

		if ( message_size > simta_max_message_size ) {
		    syslog( LOG_ERR,
			    "Receive: message exceeds max message size: %s",
			    receive_smtp_command );
		    if ( snet_writef( snet,
	    "552 message exceeds fixed maximum message size\r\n" ) < 0 ) {
			syslog( LOG_ERR, "f_mail snet_writef: %m" );
			return( RECEIVE_CLOSECONNECTION );
		    }
		    return( RECEIVE_OK );
		}
	    }

	} else {
	    syslog( LOG_ERR, "Receive: unsupported SMTP service extension: %s",
		receive_smtp_command );

	    if ( snet_writef( snet,
		    "501 unsupported SMPT service extension: %s\r\n",
		    av[ i ] ) < 0 ) {
		syslog( LOG_ERR, "f_mail snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }

	    return( RECEIVE_OK );
	}
    }

    /*
     * rfc1123 (5.3.2) Timeouts in SMTP.  We have a maximum of 5 minutes
     * before we must return something to a "MAIL" command.  Soft failures
     * can either be accepted (trusted) or the soft failures can be passed
     * along.  "451" is probably the correct error.
     */
    if (( domain != NULL ) && ( simta_global_relay == 0 )) {
	if (( rc = check_hostname( domain )) != 0 ) {
	    if ( rc < 0 ) {
		syslog( LOG_ERR, "f_mail check_hostname: %s: failed", domain );
		if ( snet_writef( snet, "%d %s: temporary DNS error\r\n", 451,
			domain ) < 0 ) {
		    syslog( LOG_ERR, "f_mail snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
	    } else {
		syslog( LOG_ERR, "f_mail %s: unknown host", domain );
		if ( snet_writef( snet, "%d %s: unknown host\r\n", 550,
			domain ) < 0 ) {
		    syslog( LOG_ERR, "f_mail snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
	    }
	    return( RECEIVE_OK );
	}
    }

    /*
     * Contrary to popular belief, it is not an error to give more than
     * one "MAIL FROM:" command.  According to rfc822, this is just like
     * "RSET".
     */
    if ( reset( env ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    if ( env_id( env ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    if ( env_sender( env, addr ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

#ifdef HAVE_LIBSSL 
    if (( simta_mail_filter != NULL ) && ( simta_checksum_md != NULL )) {
	if ( mdctx_status != MDCTX_READY ) {
	    if ( mdctx_status == MDCTX_UNINITILIZED ) {
		EVP_MD_CTX_init( &mdctx );
	    } else if ( mdctx_status == MDCTX_IN_USE ) {
		EVP_DigestFinal_ex( &mdctx, md_value, &md_len );
	    }

	    EVP_DigestInit_ex( &mdctx, simta_checksum_md, NULL);
	    mdctx_status = MDCTX_READY;
	    mdctx_bytes = 0;
	}
    }
#endif /* HAVE_LIBSSL */

    mail_success++;

    syslog( LOG_INFO, "Receive %s: From <%s> Accepted", env->e_id,
	    env->e_mail );

    if ( snet_writef( snet, "%d OK\r\n", 250 ) < 0 ) {
	syslog( LOG_ERR, "f_mail snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    return( RECEIVE_OK );
}


    static int
f_rcpt_usage( SNET *snet )
{
    syslog( LOG_ERR, "Receive: Bad RCPT TO syntax: %s", receive_smtp_command );

    if ( snet_writef( snet,
	    "501-Syntax violates RFC 2821 section 4.1.1.3:\r\n"
	    "501-     \"RCPT TO:\" (\"<Postmaster@\" domain \">\" / "
	    "\"<Postmaster>\" / Forward-Path ) "
	    "[ SP Rcpt-parameters ] CRLF\r\n"
	    "501-         Forward-path = Path\r\n"
	    "501          Path = \"<\" [ A-d-l \":\" ] Mailbox \">\"\r\n"
	    ) < 0 ) {
	syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}


    static int
f_rcpt( SNET *snet, struct envelope *env, int ac, char *av[])
{
    int				addr_len;
    int				rc;
    char			*addr, *domain;
    struct simta_red		*red;
    struct rbl			*rbl_found;

    rcpt_attempt++;

    /* Must already have "MAIL FROM:", and no valid message */
    if (( env->e_mail == NULL ) ||
	    (( env->e_flags & ENV_FLAG_ON_DISK ) != 0 )) {
	return( RECEIVE_BADSEQUENCE );
    }

    if ( ac == 2 ) {
	if ( strncasecmp( av[ 1 ], "TO:", 3 ) != 0 ) {
	    return( f_rcpt_usage( snet ));
	}

	if ( parse_emailaddr( RFC_2821_RCPT_TO, av[ 1 ] + 3, &addr,
		&domain ) != 0 ) {
	    return( f_rcpt_usage( snet ));
	}

    } else if (( simta_strict_smtp_syntax == 0 ) && ( ac == 3 )) {
	if ( strcasecmp( av[ 1 ], "TO:" ) != 0 ) {
	    return( f_rcpt_usage( snet ));
	}

	if ( parse_emailaddr( RFC_2821_RCPT_TO, av[ 2 ], &addr,
		&domain ) != 0 ) {
	    return( f_rcpt_usage( snet ));
	}

    } else {
	return( f_rcpt_usage( snet ));
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

    /*
     * If this connection has too many not-local recipients, just answer
     * that we don't know.
     */
    if (( simta_max_failed_rcpts != 0 ) &&
	    ( receive_failed_rcpts >= simta_max_failed_rcpts )) {
	if ( receive_failed_rcpts == simta_max_failed_rcpts ) {
	    syslog( LOG_INFO, "Receive %s: Message Failed: [%s] %s: "
		    "451 Too many failed recipients", env->e_id,
		    inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname );
	    receive_failed_rcpts++;
	}
	if ( snet_writef( snet, "%d Requested action aborted: "
		"Too many failed recipients.\r\n", 451 ) < 0 ) {
	    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( domain != NULL ) {
	/*
	 * Here we do an initial lookup in our domain table.  This is
	 * our best opportunity to decline recipients that are not
	 * local or unknown, since if we give an error the connecting
	 * client generates the bounce.
	 */
	if (( rc = check_hostname( domain )) != 0 ) {
	    if ( rc < 0 ) {

#ifdef HAVE_LIBSSL 
		if (( simta_mail_filter != NULL ) &&
			( simta_checksum_md != NULL )) {
		    addr_len = strlen( addr );
		    EVP_DigestUpdate( &mdctx, addr, addr_len );
		    mdctx_bytes += addr_len;
		    mdctx_status = MDCTX_IN_USE;
		}
#endif /* HAVE_LIBSSL */

		syslog( LOG_ERR, "f_rcpt check_hostname: %s: failed", domain );
		if ( snet_writef( snet, "%d %s: temporary DNS error\r\n", 451,
			domain ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
	    } else {
		syslog( LOG_INFO,
			"Receive %s: To <%s> From <%s> Failed: "
			"Unknown domain", env->e_id, addr, env->e_mail );
		if ( snet_writef( snet, "%d %s: unknown host\r\n", 550,
			domain ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
	    }
	    return( RECEIVE_OK );
	}

	if ((( red = host_local( domain )) == NULL ) ||
		(( red->red_receive == NULL ) &&
		( red->red_host_type == RED_HOST_TYPE_LOCAL ))) {
	    if ( simta_global_relay == 0 ) {
		syslog( LOG_INFO,
			"Receive %s: To <%s> From <%s> Failed: "
			"Domain not local", env->e_id, addr, env->e_mail );
		if ( snet_writef( snet,
			"551 User not local to %s; please try <%s>\r\n",
			simta_hostname, domain ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
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
		syslog( LOG_INFO,
			"Receive %s: To <%s> From <%s> Failed: User not local",
			env->e_id, addr, env->e_mail );

		/* Count number of not-local recipients */
		receive_failed_rcpts++;
		if ( snet_writef( snet,
			"%d Requested action not taken: User not found.\r\n",
			550 ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		return( RECEIVE_OK );

	    case LOCAL_ERROR:
		syslog( LOG_ERR, "f_rcpt local_address %s: error", addr );
		if ( snet_writef( snet, "%d Requested action aborted: "
			"local error in processing.\r\n", 451 ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}

#ifdef HAVE_LIBSSL 
		if (( simta_mail_filter != NULL ) &&
			( simta_checksum_md != NULL )) {
		    addr_len = strlen( addr );
		    EVP_DigestUpdate( &mdctx, addr, addr_len );
		    mdctx_bytes += addr_len;
		    mdctx_status = MDCTX_IN_USE;
		}
#endif /* HAVE_LIBSSL */

		return( RECEIVE_OK );

	    case LOCAL_ADDRESS_RBL:
                if ( simta_user_rbls != NULL ) {
                    if ( remote_rbl_status == RBL_UNKNOWN ) {
                        /* Check and save RBL status */
                        switch ( rbl_check( simta_user_rbls,
				&(receive_sin->sin_addr),
                                &rbl_found )) {
                        case RBL_BLOCK:
                            remote_rbl_status = RBL_BLOCK;
			    syslog( LOG_INFO, "Receive %s: To <%s> From <%s> "
				    "RBL blocked: %s",
				    env->e_id, addr, env->e_mail,
                                    rbl_found->rbl_domain );
                            break;

			case RBL_ACCEPT:
			    remote_rbl_status = RBL_ACCEPT;
			    syslog( LOG_INFO, "Receive %s: To <%s> From <%s> "
				    "RBL accepted: %s",
				    env->e_id, addr, env->e_mail,
                                    rbl_found->rbl_domain );
			    break;

			case RBL_NOT_FOUND:
			    remote_rbl_status = RBL_NOT_FOUND;
			    syslog( LOG_INFO, "Receive %s: To <%s> From <%s> "
				    "RBL Not Found", env->e_id, addr,
				    env->e_mail );
			    break;

			case RBL_ERROR:
			default:
			    remote_rbl_status = RBL_UNKNOWN;
			    syslog( LOG_INFO, "Receive %s: To <%s> From <%s> "
				    "RBL error: %s",
				    env->e_id, addr, env->e_mail,
                                    rbl_found->rbl_domain );
			    if ( dnsr_errno( simta_dnsr ) !=
				    DNSR_ERROR_TIMEOUT ) {
				return( RECEIVE_CLOSECONNECTION );
			    }
			    dnsr_errclear( simta_dnsr );
			    break;
			}
		    }

		    if ( remote_rbl_status == RBL_BLOCK ) {
			receive_failed_rcpts++;
			syslog( LOG_INFO,
				"Receive %s: To <%s> From <%s> Failed: "
				"RBL %s ([%s] %s)", env->e_id, addr,
				env->e_mail, rbl_found->rbl_domain,
				inet_ntoa( receive_sin->sin_addr ),
				receive_remote_hostname );
			if ( snet_writef( snet,
				"550 No access from IP %s. See %s\r\n",
				inet_ntoa( receive_sin->sin_addr ),
				rbl_found->rbl_url ) != 0 ) {
			    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
			    return( RECEIVE_CLOSECONNECTION );
			}
			return( RECEIVE_OK );
		    }
		}
		break;

	    case LOCAL_ADDRESS:
	    case MX_ADDRESS:
		break;

	    default:
		panic( "f_rctp local_address return out of range" );
	    }
	}
    }

    if ( env_recipient( env, addr ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    rcpt_success++;

    syslog( LOG_INFO, "Receive %s: To <%s> From <%s> Accepted", env->e_id,
	    env->e_rcpt->r_rcpt, env->e_mail );

    if ( snet_writef( snet, "%d OK\r\n", 250 ) < 0 ) {
	syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

#ifdef HAVE_LIBSSL 
    if (( simta_mail_filter != NULL ) && ( simta_checksum_md != NULL )) {
	addr_len = strlen( addr );
	EVP_DigestUpdate( &mdctx, addr, addr_len );
	mdctx_bytes += addr_len;
	mdctx_status = MDCTX_IN_USE;
    }
#endif /* HAVE_LIBSSL */

    return( RECEIVE_OK );
}


    static int
f_data( SNET *snet, struct envelope *env, int ac, char *av[])
{
    FILE				*dff = NULL;
    int					dfile_fd = -1;
    int					dfile_on_disk = 0;
    int					tfile_on_disk = 0;
    int					ret_code = RECEIVE_SYSERROR;
    int					header = 1;
    int					line_no = 0;
    int					data_errors = 0;
    int					message_result;
    int					result;
    unsigned int			line_len;
    char				*line;
    char				*message = NULL;
    struct tm				*tm;
    struct timeval			tv_data_start;
    struct timeval			tv_line;
    struct timeval			tv_session;
    struct timeval			tv_filter = { 0, 0 };
    struct timeval			tv_now;
    struct timespec			req;
    time_t				clock;
    struct stat				sbuf;
    char				daytime[ 30 ];
    char				dfile_fname[ MAXPATHLEN + 1 ];
    off_t				data_size = 0;
    struct receive_headers		r;

    memset( &r, 0, sizeof( struct receive_headers ));
    r.r_env = env;

    data_attempt++;

    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */
    if ( ac != 1 ) {
	syslog( LOG_ERR, "Receive: Bad DATA syntax: %s", receive_smtp_command );

	if ( snet_writef( snet,
		"501 Syntax violates RFC 2821 section 4.1.1.4: "
		"\"DATA\" CRLF\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /*
     * If sending server has exceeded our bad recipient max, don't
     * take the mail.
     */
    if (( simta_max_failed_rcpts != 0 ) &&
	    ( receive_failed_rcpts >= simta_max_failed_rcpts )) {
	if ( receive_failed_rcpts == simta_max_failed_rcpts ) {
	    syslog( LOG_INFO, "Receive %s: Message Failed: [%s] %s: "
		    "451 Too many failed recipients", env->e_id,
		    inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname );
	    receive_failed_rcpts++;
	}
	if ( snet_writef( snet, "451 Requested action aborted:"
		" Too many failed recipients\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
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
    if (( env->e_mail == NULL ) ||
	    (( env->e_flags & ENV_FLAG_ON_DISK ) != 0 )) {
	return( RECEIVE_BADSEQUENCE );
    }

    if ( env->e_rcpt == NULL ) {
	if ( snet_writef( snet, "%d no valid recipients\r\n", 554 ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( simta_smtp_tarpit == 0 ) {
	sprintf( dfile_fname, "%s/D%s", simta_dir_fast, env->e_id );

	if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 ))
		< 0 ) {
	    syslog( LOG_ERR, "f_data open %s: %m", dfile_fname );
	    return( RECEIVE_SYSERROR );
	}
	dfile_on_disk++;

	if (( dff = fdopen( dfile_fd, "w" )) == NULL ) {
	    syslog( LOG_ERR, "f_data fdopen: %m" );
	    goto error;
	}

	clock = time( &clock );
	tm = localtime( &clock );
	strftime( daytime, sizeof( daytime ), "%e %b %Y %T", tm );

	/*
	 * At this point, we must have decided what we'll put in the Received:
	 * header, since that is the first line in the file.  This is where
	 * we might want to put the sender's domain name, if we obtained one.
	 */
	if ( fprintf( dff, "Received: FROM %s (%s [%s])\n\t"
		"BY %s ID %s ; \n\t%s %s\n",
		( receive_hello == NULL ) ? "NULL" : receive_hello,
		receive_remote_hostname , inet_ntoa( receive_sin->sin_addr ),
		simta_hostname, env->e_id, daytime, tz( tm )) < 0 ) {
	    syslog( LOG_ERR, "f_data fprintf: %m" );
	    goto error;
	}
    }

    if ( snet_writef( snet, "%d Start mail input; end with <CRLF>.<CRLF>\r\n",
	    354 ) < 0 ) {
	syslog( LOG_ERR, "f_data snet_writef: %m" );
	ret_code = RECEIVE_CLOSECONNECTION;
	goto error;
    }

    if ( gettimeofday( &tv_data_start, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: f_data gettimeofday: %m" );
	goto error;
    }

    /* start in header mode */
    header = 1;

    tv_line.tv_sec = simta_data_line_wait;
    tv_line.tv_usec = 0;

    tv_session.tv_sec = tv_data_start.tv_sec + simta_data_transaction_wait;
    tv_session.tv_usec = 0;

    while (( line = snet_getline( snet, &tv_line )) != NULL ) {
	line_no++;

	if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: f_data gettimeofday: %m" );
	    goto error;
	}

	if ( tv_now.tv_sec >= tv_session.tv_sec ) {
	    syslog( LOG_NOTICE, "Receive %s: DATA time limit exceeded",
		    env->e_id );
	    goto error;
	} else if ( simta_data_line_wait >
		( tv_session.tv_sec - tv_now.tv_sec )) {
	    tv_line.tv_sec = tv_session.tv_sec - tv_now.tv_sec;
	} else {
	    tv_line.tv_sec = simta_data_line_wait;
	}

	if ( *line == '.' ) {
	    if ( strcmp( line, "." ) == 0 ) {
		break;
	    }
	    line++;
	}

	line_len = strlen( line );
	/* Add strlen plus "\r\n" */
	data_size += line_len + 2;

	if (( simta_smtp_tarpit != 0 ) || ( data_errors != 0 )) {
	    if ( dfile_on_disk != 0 ) {
		if ( unlink( dfile_fname ) < 0 ) {
		    syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
		    goto error;
		}
		dfile_on_disk = 0;
	    }

	    if ( dff != NULL ) {
		if ( fclose( dff ) != 0 ) {
		    syslog( LOG_ERR, "f_data fclose: %m" );
		    dff = NULL;
		    goto error;
		}
		dff = NULL;
	    }
	    continue;
	}

#ifdef HAVE_LIBSSL 
	if (( simta_mail_filter != NULL ) && ( simta_checksum_md != NULL )) {
	    EVP_DigestUpdate( &mdctx, line, line_len );
	    mdctx_bytes += line_len;
	}
#endif /* HAVE_LIBSSL */

	if ( header == 1 ) {
	    if (( result = header_text( line_no, line, &r )) != 0 ) {
		if ( result < 0 ) {
		    goto error;
		}
		header = 0;
	    }
	}

	if (( simta_max_message_size != 0 ) &&
		( data_size > simta_max_message_size )) {
	    /* If we've already reached max size, continue reading lines
	     * until the '.' otherwise, check message size.
	     */
	    syslog( LOG_INFO, "Receive %s: Message Failed: [%s] %s: "
		    "Message too large", env->e_id, 
		    inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname );
	    data_errors++;
	    if (( message = strdup( "Message too large" )) == NULL ) {
		syslog( LOG_ERR, "f_data strdup: %m" );
		goto error;
	    }
	    continue;
	}

	if ( r.r_received_count > simta_max_received_headers ) {
	    syslog( LOG_INFO, "Receive %s: Message Failed: [%s] %s:"
		    "Too many received headers", env->e_id, 
		    inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname );
	    data_errors++;
	    if (( message = strdup( "Too many received headers" )) == NULL ) {
		syslog( LOG_ERR, "f_data strdup: %m" );
		goto error;
	    }
	    continue;
	}

	if ( fprintf( dff, "%s\n", line ) < 0 ) {
	    syslog( LOG_ERR, "f_data fprintf: %m" );
	    goto error;
	}
    }

    if ( line == NULL ) {	/* EOF */
	syslog( LOG_NOTICE, "f_data %s: connection dropped", env->e_id );
	ret_code = RECEIVE_CLOSECONNECTION;
	goto error;
    }

    if (( data_errors ) || ( simta_smtp_tarpit )) {
	message_result = MESSAGE_TEMPFAIL;
	if ( simta_smtp_tarpit ) {
	    if (( message = strdup( "Tarpit enabled" )) == NULL ) {
		syslog( LOG_ERR, "f_data strdup: %m" );
		goto error;
	    }
	}

    } else {
	/* get the Dfile's inode for the envelope structure */
	if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	    syslog( LOG_ERR, "f_data %s fstat %s: %m", env->e_id, dfile_fname );
	    goto error;
	}
	env->e_dinode = sbuf.st_ino;
	syslog( LOG_DEBUG, "f_data env %s dinode %d", env->e_id,
		(int)env->e_dinode );

	if ( fclose( dff ) != 0 ) {
	    syslog( LOG_ERR, "f_data fclose: %m" );
	    dff = NULL;
	    goto error;
	}
	dff = NULL;
	dfile_fd = -1;

	env->e_dir = simta_dir_fast;

	if ( env_tfile( env ) != 0 ) {
	    goto error;
	}
	tfile_on_disk++;

	if ( simta_mail_filter == NULL ) {
	    message_result = MESSAGE_ACCEPT;

	} else {
	    /* open Dfile to deliver */
	    if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
		syslog( LOG_ERR, "f_data open dfile %s: %m", dfile_fname );
		goto error;
	    }

#ifdef HAVE_LIBSSL 
	    if (( simta_mail_filter != NULL ) &&
		    ( simta_checksum_md != NULL )) {
		EVP_DigestFinal_ex( &mdctx, md_value, &md_len );
		mdctx_status = MDCTX_FINAL;
		memset( md_b64, 0, SZ_BASE64_E( EVP_MAX_MD_SIZE ) + 1 );
		base64_e( md_value, md_len, md_b64 );
		snprintf( md_bytes, BYTE_LEN, "%d", mdctx_bytes );
	    }
#endif /* HAVE_LIBSSL */

	    if ( gettimeofday( &tv_filter, NULL ) != 0 ) {
		syslog( LOG_ERR, "Syserror: f_data gettimeofday: %m" );
		goto error;
	    }

	    env->e_mid = r.r_mid;

	    syslog( LOG_DEBUG, "calling content filter %s", simta_mail_filter );
	    message_result = mail_filter( env, dfile_fd, &message );

	    if ( close( dfile_fd ) != 0 ) {
		syslog( LOG_ERR, "f_data close: %m" );
		dfile_fd = -1;
		goto error;
	    }
	    dfile_fd = -1;
	}
    }

    if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	syslog( LOG_ERR, "f_data gettimeofday: %m" );
	goto error;
    }

    if ( tv_filter.tv_sec == 0 ) {
	syslog( LOG_INFO, "Receive Data Metric: %d bytes in %d seconds",
		(int)data_size, (int)(tv_now.tv_sec - tv_data_start.tv_sec));
    } else {
	syslog( LOG_INFO, "Receive Data Metric: %d bytes in %d seconds, "
		" filter %d seconds", (int)data_size,
		(int)(tv_filter.tv_sec - tv_data_start.tv_sec),
		(int)(tv_now.tv_sec - tv_filter.tv_sec));
    }

    switch ( message_result ) {
    case MESSAGE_ACCEPT:
	/* env_efile() unlinks the tfile if a move is unsuccessful */
	tfile_on_disk = 0;
	if ( env_efile( env ) != 0 ) {
	    goto error;
	}

	/*
	 * We could perhaps 
	 * However, if we've already fully instanciated the message in the
	 * queue, a failure indication from snet_writef() may be false, the
	 * other end may have in reality recieved the "250 OK", and deleted
	 * the message.  Thus, it's safer to ignore the return value of
	 * snet_writef(), perhaps causing the sending-SMTP agent to transmit
	 * the message again.
	 */

	data_success++;

	if ( message != NULL ) {
	    syslog( LOG_INFO, "Receive %s: Message Accepted: "
		    "MID <%s> [%s] %s size %d: %s",
		    env->e_id, env->e_mid ? env->e_mid : "NULL",
		    inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname,
		    (int)sbuf.st_size,
		    message );
	} else {
	    syslog( LOG_INFO, "Receive %s: Message Accepted: "
		    "MID <%s> [%s] %s size %d",
		    env->e_id, env->e_mid ? env->e_mid : "NULL",
		    inet_ntoa( receive_sin->sin_addr ),
		    receive_remote_hostname,
		    (int)sbuf.st_size );
	}

	if ( snet_writef( snet, "250 (%s): Accepted\r\n", env->e_id ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    ret_code = RECEIVE_CLOSECONNECTION;
	    goto error;
	}

	break;

    case MESSAGE_ACCEPT_AND_DELETE:
	dfile_on_disk = 0;
	if ( unlink( dfile_fname ) < 0 ) {
	    syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
	    goto error;
	}

	tfile_on_disk = 0;
	if ( env_tfile_unlink( env ) != 0 ) {
	    goto error;
	}

	syslog( LOG_INFO, "Receive %s: Message Deleted after acceptance: "
		"MID <%s> [%s] %s size %d: %s",
		env->e_id, env->e_mid ? env->e_mid : "NULL",
		inet_ntoa( receive_sin->sin_addr ),
		receive_remote_hostname,
		(int)sbuf.st_size,
		message ? message : "no message" );

	if ( snet_writef( snet, "250 (%s): Accepted\r\n", env->e_id ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    ret_code = RECEIVE_CLOSECONNECTION;
	    goto error;
	}

	break;

    case MESSAGE_REJECT:
	dfile_on_disk = 0;
	if ( unlink( dfile_fname ) < 0 ) {
	    syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
	    goto error;
	}

	tfile_on_disk = 0;
	if ( env_tfile_unlink( env ) != 0 ) {
	    goto error;
	}

	syslog( LOG_INFO, "Receive %s: Message Failed: "
		"MID <%s> [%s] %s size %d: %s",
		env->e_id, env->e_mid ? env->e_mid : "NULL",
		inet_ntoa( receive_sin->sin_addr ),
		receive_remote_hostname,
		(int)sbuf.st_size,
		message ? message : "no message" );

	if ( simta_data_url != NULL ) {
	    if ( snet_writef( snet, "554 Transaction failed: %s\r\n",
		    simta_data_url ) < 0 ) {
		syslog( LOG_ERR, "f_data snet_writef: %m" );
		ret_code = RECEIVE_CLOSECONNECTION;
		goto error;
	    }
	} else {
	    if ( snet_writef( snet, "554 Transaction failed\r\n" ) < 0 ) {
		syslog( LOG_ERR, "f_data snet_writef: %m" );
		ret_code = RECEIVE_CLOSECONNECTION;
		goto error;
	    }
	}

	break;

    default:
	if (( message = strdup( "Bad CONTENT_FILTER return code" )) == NULL ) {
	    syslog( LOG_ERR, "f_data strdup: %m" );
	    goto error;
	}

    case MESSAGE_TEMPFAIL_TARPIT:
    case MESSAGE_TEMPFAIL:
	syslog( LOG_INFO, "Receive %s: Message Tempfailed: "
		"MID <%s> [%s] %s size %d: %s",
		env->e_id, env->e_mid ? env->e_mid : "NULL",
		inet_ntoa( receive_sin->sin_addr ),
		receive_remote_hostname,
		(int)sbuf.st_size,
		message ? message : "no message" );

	if ( dfile_on_disk ) {
	    dfile_on_disk = 0;
	    if ( unlink( dfile_fname ) < 0 ) {
		syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
		goto error;
	    }
	}

	if ( tfile_on_disk ) {
	    tfile_on_disk = 0;
	    if ( env_tfile_unlink( env ) != 0 ) {
		goto error;
	    }
	}

	if ( message_result == MESSAGE_TEMPFAIL_TARPIT ) {
	    simta_smtp_tarpit++;
	}

	if ( simta_smtp_tarpit ) {
	    req.tv_sec = simta_smtp_tarpit;
	    req.tv_nsec = 0;
	    if ( nanosleep( &req, NULL ) != 0 ) {
		syslog( LOG_DEBUG, "Tarpit: Error nanosleep %m" );
	    }
	}

	if ( snet_writef( snet, "451 Requested action aborted: %s\r\n",
		simta_data_url ? simta_data_url :
		"local error in processing" ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    ret_code = RECEIVE_CLOSECONNECTION;
	    goto error;
	}

	break;
    }

    if ( message != NULL ) {
	free( message );
    }

    return( RECEIVE_OK );

error:
    if ( dff != NULL ) {
	if ( fclose( dff ) != 0 ) {
	    syslog( LOG_ERR, "f_data fclose: %m" );
	}
    } else if ( dfile_fd >= 0 ) {
	if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "f_data close: %m" );
	}
    }
    if ( dfile_on_disk != 0 ) {
	if ( unlink( dfile_fname ) < 0 ) {
	    syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
	}
    }
    if ( tfile_on_disk != 0 ) {
	env_tfile_unlink( env );
    }
    if ( message != NULL ) {
	free( message );
    }
    return( ret_code );
}


    static int
f_quit( SNET *snet, struct envelope *env, int ac, char *av[])
{
    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */

    if ( ac != 1 ) {
	syslog( LOG_ERR, "Receive: Bad QUIT syntax: %s", receive_smtp_command );

	if ( snet_writef( snet,
		"501 Syntax violates RFC 2821 section 4.1.1.10: "
		"\"QUIT\" CRLF\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_quit snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( snet_writef( snet, "221 %s Service closing transmission channel\r\n",
	    simta_hostname ) < 0 ) {
	syslog( LOG_ERR, "f_quit snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    syslog( LOG_NOTICE, "f_quit OK" );
    return( RECEIVE_CLOSECONNECTION );
}


    static int
f_rset( SNET *snet, struct envelope *env, int ac, char *av[])
{
    /*
     * We could presume that this indicates another message.  However,
     * since some mailers send this just before "QUIT", and we're
     * checking "MAIL FROM:" as well, there's no need.
     */

    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */
    if ( ac != 1 ) {
	syslog( LOG_ERR, "Receive: Bad RSET syntax: %s", receive_smtp_command );

	if ( snet_writef( snet,
		"501 Syntax violates RFC 2821 section 4.1.1.5: "
		"\"RSET\" CRLF\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_rset snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( reset( env ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    if ( snet_writef( snet, "%d OK\r\n", 250 ) < 0 ) {
	syslog( LOG_ERR, "f_rset snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    syslog( LOG_NOTICE, "f_rset OK" );
    return( RECEIVE_OK );
}

    static int
f_noop( SNET *snet, struct envelope *env, int ac, char *av[])
{
    if ( snet_writef( snet, "%d simta v%s\r\n", 250, version ) < 0 ) {
	syslog( LOG_ERR, "f_noop snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    syslog( LOG_NOTICE, "f_noop OK" );
    return( RECEIVE_OK );
}


    static int
f_help( SNET *snet, struct envelope *env, int ac, char *av[])
{
    if ( snet_writef( snet, "%d simta v%s\r\n", 211, version ) < 0 ) {
	syslog( LOG_ERR, "f_help snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
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
f_vrfy( SNET *snet, struct envelope *env, int ac, char *av[])
{
    if ( snet_writef( snet, "%d Command not implemented\r\n", 502 ) < 0 ) {
	syslog( LOG_ERR, "f_vrfy snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}


    static int
f_expn( SNET *snet, struct envelope *env, int ac, char *av[])
{
    if ( snet_writef( snet, "%d Command not implemented\r\n", 502 ) < 0 ) {
	syslog( LOG_ERR, "f_expn snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}

    static int
f_noauth( SNET *snet, struct envelope *env, int ac, char *av[])
{
    syslog( LOG_NOTICE, "f_noauth: %s", av[ 0 ] );
    if ( snet_writef( snet, "530 Authentication required\r\n" ) < 0 ) {
	syslog( LOG_ERR, "f_expn snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}

#ifdef HAVE_LIBSSL
    static int
f_starttls( SNET *snet, struct envelope *env, int ac, char *av[])
{
    int				rc;

    if ( !simta_tls ) {
	if ( snet_writef( snet, "%d Command not implemented\r\n", 502 ) < 0 ) {
	    syslog( LOG_ERR, "f_expn snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /*
     * Client MUST NOT attempt to start a TLS session if a TLS
     * session is already active.  No mention of what to do if it does...
     */
    if ( receive_tls ) {
	syslog( LOG_ERR, "f_starttls: called twice" );
	return( RECEIVE_SYSERROR );
    }

    if ( ac != 1 ) {
	syslog( LOG_ERR, "Receive: Bad STARTTLS syntax: %s",
		receive_smtp_command );

	if ( snet_writef( snet, "%d Syntax error (no parameters allowed)\r\n",
		501 ) < 0 ) {
	    syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( snet_writef( snet, "%d Ready to start TLS\r\n", 220 ) < 0 ) {
	syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    if ( _start_tls( snet ) != RECEIVE_OK ) {
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

    if ( reset( env ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    if ( receive_hello != NULL ) {
	free( receive_hello );
	receive_hello = NULL;
    }

    if (( rc = _post_tls( snet )) != RECEIVE_OK ) {
	return( rc );
    }

    syslog( LOG_NOTICE, "f_starttls OK" );

    return( RECEIVE_OK );
}

    int
_post_tls( SNET *snet )
{
#ifdef HAVE_LIBSASL
    int		rc; 

    if ( simta_sasl ) {

	/* Get cipher_bits and set SSF_EXTERNAL */
	memset( &secprops, 0, sizeof( secprops ));
	if (( rc = sasl_setprop( receive_conn, SASL_SSF_EXTERNAL,
		&ext_ssf )) != SASL_OK ) {
	    syslog( LOG_ERR, "f_starttls sasl_setprop: %s",
		    sasl_errdetail( receive_conn ));
	    return( RECEIVE_SYSERROR );
	}

	secprops.security_flags |= SASL_SEC_NOANONYMOUS;
	secprops.maxbufsize = 4096;
	secprops.min_ssf = 0;
	secprops.max_ssf = 256;

	if (( rc = sasl_setprop( receive_conn, SASL_SEC_PROPS, &secprops))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "f_starttls sasl_setprop: %s",
		    sasl_errdetail( receive_conn ));
	    return( RECEIVE_SYSERROR );
	}
    }
#endif /* HAVE_LIBSASL */
    return( RECEIVE_OK );
}

    int
_start_tls( SNET *snet )
{
    int				rc;
    X509			*peer;
    char			buf[ 1024 ];

    if (( rc = snet_starttls( snet, ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "f_starttls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	if ( snet_writef( snet, "%d SSL didn't work!\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_SYSERROR );
    }

    if ( simta_service_smtps == SERVICE_SMTPS_CLIENT_SERVER ) {
	if (( peer = SSL_get_peer_certificate( snet->sn_ssl )) == NULL ) {
	    syslog( LOG_ERR,
		    "starttls SSL_get_peer_certificate: no peer certificate" );
	    if ( snet_writef( snet, "%d SSL didn't work!\r\n", 501 ) < 0 ) {
		syslog( LOG_ERR, "f_starttls snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    return( RECEIVE_SYSERROR );
	}
	syslog( LOG_NOTICE, "CERT Subject: %s\n",
		X509_NAME_oneline( X509_get_subject_name( peer ),
		buf, sizeof( buf )));
	X509_free( peer );
    }

    receive_tls = 1;
    simta_smtp_extension--;

    return( RECEIVE_OK );
}

#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    int
f_auth( SNET *snet, struct envelope *env, int ac, char *av[])
{
    int			rc;
    const char		*mechname;
    char		base64[ BASE64_BUF_SIZE + 1 ];
    char		*clientin = NULL;
    unsigned int	clientinlen = 0;
    const char		*serverout;
    unsigned int	serveroutlen;
    struct timeval	tv;

    /* RFC 2554:
     * The BASE64 string may in general be arbitrarily long.  Clients
     * and servers MUST be able to support challenges and responses
     * that are as long as are generated by the authentication   
     * mechanisms they support, independent of any line length
     * limitations the client or server may have in other parts of its
     * protocol implementation.
     */

    if (( ac != 2 ) && ( ac != 3 )) {
	if ( snet_writef( snet,
		"501 Syntax violates RFC 2554 section 4: "
		"AUTH mechanism [initial-response]\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /* RFC 2554 After an AUTH command has successfully completed, no more AUTH
     * commands may be issued in the same session.  After a successful
     * AUTH command completes, a server MUST reject any further AUTH
     * commands with a 503 reply.
     */
    if ( receive_auth ) {
	return( RECEIVE_BADSEQUENCE );
    }

    /* RFC 2554 The AUTH command is not permitted during a mail transaction. */
    if ( env->e_mail != NULL ) {
	return( RECEIVE_BADSEQUENCE );
    }

    /* Initial response */
    if ( ac == 3 ) {
	clientin = base64;
	if ( strcmp( av[ 2 ], "=" ) == 0 ) {
	    /* Zero-length initial response */
	    base64[ 0 ] = '\0';
	} else {
	    if ( sasl_decode64( av[ 2 ], strlen( av[ 2 ]), clientin,
		    BASE64_BUF_SIZE, & clientinlen ) != SASL_OK ) {
		if ( snet_writef( snet,
			"501 unable to BASE64 decode argument\r\n" ) < 0 ) {
		    syslog( LOG_ERR, "f_auth snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		syslog( LOG_ERR, "f_auth unable to BASE64 decode argument" );
		return( RECEIVE_OK );
	    }
	}
    }

    rc = sasl_server_start( receive_conn, av[ 1 ], clientin, clientinlen,
	&serverout, &serveroutlen );

    while ( rc == SASL_CONTINUE ) {
	/* send the challenge to the client */
	if ( serveroutlen ) {
	    if ( sasl_encode64( serverout, serveroutlen, base64,
		    BASE64_BUF_SIZE, NULL ) != SASL_OK ) {
		syslog( LOG_ERR, "f_auth unable to BASE64 encode argument" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    serverout = base64;
	} else {
	    serverout = "";
	}

	if ( snet_writef( snet, "334 %s\r\n", serverout ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}

	/* Get response from the client */
	tv.tv_sec = simta_receive_wait;
	tv.tv_usec = 0;
	if (( clientin = snet_getline( snet, &tv )) == NULL ) {
	    syslog( LOG_ERR, "f_auth snet_getline: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	} 

	/* Check if client canceled authentication exchange */
	if ( clientin[ 0 ] == '*' && clientin[ 1 ] == '\0' ) {
	    if ( snet_writef( snet,
		    "501 client canceled authentication\r\n" ) < 0 ) {
		syslog( LOG_ERR, "f_auth snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    syslog( LOG_INFO, "f_auth: client canceled authentication" );
	    if ( reset_sasl_conn( &receive_conn ) != SASL_OK ) {
		return( RECEIVE_CLOSECONNECTION );
	    }
	    return( RECEIVE_OK );
	}

	/* decode response */
	if ( sasl_decode64( clientin, strlen( clientin ), clientin,
		BASE64_BUF_SIZE, &clientinlen ) != SASL_OK ) {
	    if ( snet_writef( snet,
		    "501 unable to BASE64 decode argument\r\n" ) < 0 ) {
		syslog( LOG_ERR, "f_auth snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    syslog( LOG_ERR, "f_auth unable to BASE64 decode argument" );
	    return( RECEIVE_OK );
	}

	/* do next step */
	rc = sasl_server_step( receive_conn, clientin, clientinlen, &serverout,
		&serveroutlen );
    }

    switch( rc ) {
    case SASL_OK:
	if ( sasl_getprop( receive_conn, SASL_USERNAME,
		(const void **) &auth_id ) != SASL_OK ) {
	    syslog( LOG_ERR, "f_auth sasl_getprop: %s",
		    sasl_errdetail( receive_conn ));
	    return( RECEIVE_CLOSECONNECTION );
	}
	if ( sasl_getprop( receive_conn, SASL_MECHNAME,
		(const void **) &mechname ) != SASL_OK ) {
	    syslog( LOG_ERR, "f_auth sasl_getprop: %s",
		    sasl_errdetail( receive_conn ));
	    return( RECEIVE_CLOSECONNECTION );
	}

	syslog( LOG_NOTICE | LOG_INFO,
		"f_auth %s authenticated via %s%s [%s] %s:",
		auth_id, mechname, receive_tls ? "+TLS" : "",
		inet_ntoa( receive_sin->sin_addr ), receive_remote_hostname );

	if ( snet_writef( snet, "235 Authentication successful\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}

	receive_auth = 1;
	snet_setsasl( snet, receive_conn );

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
	 if ( snet_saslssf( snet )) {
	    if ( receive_hello ) {
		free( receive_hello );
		receive_hello = NULL;
	    }
	}

	receive_commands = smtp_commands;
	receive_ncommands = sizeof( smtp_commands ) /
	    sizeof( smtp_commands[ 0 ] );

	return( RECEIVE_OK );

    case SASL_NOMECH:
	if ( snet_writef( snet,
		"504 Unrecognized authentication type.\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	syslog( LOG_INFO, "Receive: Unrecognized authentication type: %s",
		av[ 1 ] );
	return( RECEIVE_OK );

    case SASL_BADPROT:
	/* RFC 2554:
 	 * If the client uses an initial-response argument to the AUTH    
	 * command with a mechanism that sends data in the initial
	 * challenge, the server rejects the AUTH command with a 535
	 * reply.
	 */
	if ( snet_writef( snet,
		"535 invalid initial-response arugment "
		"for mechanism\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	syslog( LOG_INFO,
		"Receive: Invaid initial-response argument for mechanism %s",
		av[ 1 ] );
	return( RECEIVE_OK );

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
	if ( snet_writef( snet,
		"534 Authentication mechanism is too weak\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	syslog( LOG_INFO, "Receive: Authentication mechanism is too weak" );
	return( RECEIVE_OK );

    case SASL_ENCRYPT:
	/* RFC 2554
	 * 538 Encryption required for requested authentication mechanism
	 * This response to the AUTH command indicates that the selected   
	 * authentication mechanism may only be used when the underlying SMTP
	 * connection is encrypted.
	 */
	if ( snet_writef( snet,
		"538 Encryption required for requested authentication "
		"mechanism\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_auth snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	syslog( LOG_INFO,
		"Receive: Encryption required for mechanism %s", av[ 1 ] );
	return( RECEIVE_OK );


    default:
	syslog( LOG_ERR, "f_auth sasl_start_server: %s",
		sasl_errdetail( receive_conn ));
	return( RECEIVE_SYSERROR );
    }
}
#endif /* HAVE_LIBSASL */

    int
smtp_receive( int fd, struct sockaddr_in *sin )
{
    SNET				*snet;
    struct envelope			*env = NULL;
    ACAV				*acav = NULL;
    fd_set				fdset;
    int					ac;
    int					i;
    int					r = 0;
    int					rc;
    char				**av = NULL;
    char				*line;
    char				hostname[ DNSR_MAX_NAME + 1 ];
    struct timeval			tv;
    struct timeval			tv_write;
    struct timeval			tv_start;
    struct timeval			tv_stop;
    struct timespec			req;
    struct rbl				*rbl_found;
#ifdef HAVE_LIBSASL
    sasl_security_properties_t		secprops;
#endif /* HAVE_LIBSASL */
#ifdef HAVE_LIBWRAP
    char				*ctl_hostname;
#endif /* HAVE_LIBWRAP */

    receive_commands = smtp_commands;
    receive_ncommands = sizeof( smtp_commands ) / sizeof( smtp_commands[ 0 ] );

    if ( gettimeofday( &tv_start, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: smtp_receive gettimeofday: %m" );
	tv_start.tv_sec = 0;
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "receive snet_attach: %m" );
	return( 0 );
    }

    memset( &tv_write, 0, sizeof( struct timeval ));
    tv_write.tv_sec = 5 * 60;
    snet_timeout( snet, SNET_WRITE_TIMEOUT, &tv_write );

#ifdef HAVE_LIBSASL
    if ( simta_sasl ) {
	receive_commands = noauth_commands;
	receive_ncommands = sizeof( noauth_commands ) /
		sizeof( noauth_commands[ 0 ] );
	if (( rc = sasl_server_new( "smtp", NULL, NULL, NULL, NULL, NULL,
		0, &receive_conn )) != SASL_OK ) {
	    syslog( LOG_ERR, "receive sasl_server_new: %s",
		    sasl_errstring( rc, NULL, NULL ));
	    goto syserror;
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

	memset( &secprops, 0, sizeof( secprops ));
	secprops.maxbufsize = 4096;
	/* min_ssf set to zero with memset */
	secprops.max_ssf = 256;
	secprops.security_flags |= SASL_SEC_NOPLAINTEXT;
	secprops.security_flags |= SASL_SEC_NOANONYMOUS;
	if (( rc = sasl_setprop( receive_conn, SASL_SEC_PROPS, &secprops))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "receive sasl_setprop: %s",
		    sasl_errdetail( receive_conn ));
	    goto syserror;
	}

	ext_ssf = 0;
	auth_id = NULL;
	if (( rc = sasl_setprop( receive_conn, SASL_SSF_EXTERNAL, &ext_ssf ))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "receive sasl_setprop: %s",
		    sasl_errdetail( receive_conn ));
	    goto syserror;
	}
	if (( rc = sasl_setprop( receive_conn, SASL_AUTH_EXTERNAL, auth_id ))
		!= SASL_OK ) {
	    syslog( LOG_ERR, "receive sasl_setprop: %s",
		    sasl_errdetail( receive_conn ));
	    goto syserror;
	}


    }
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
    if (( simta_service_smtps > 0 ) &&
	    ( simta_process_type == PROCESS_RECEIVE_SMTPS )) {
	if ( _start_tls( snet ) != RECEIVE_OK ) {
	    goto syserror;
	}
	if (( rc = _post_tls( snet )) != RECEIVE_OK ) {
	    goto syserror;
	}

	syslog( LOG_NOTICE, "Connect.in [%s] %s: SMTS",
		inet_ntoa( sin->sin_addr ), receive_remote_hostname );

    }
#endif /* HAVE_LIBSSL */

    /* Read before Banner punishment */
    if ( simta_read_before_banner > 0 ) {
	FD_ZERO( &fdset );
	FD_SET( snet_fd( snet ), &fdset );

	tv.tv_sec = simta_read_before_banner;
	tv.tv_usec = 0;

	if (( r = select( snet_fd( snet ) + 1, &fdset, NULL, NULL, &tv ))
		< 0 ) {
	    syslog( LOG_ERR, "receive select: %m" );
	    goto syserror;
	} else if ( r > 0 ) {
	    receive_failed_rcpts = simta_max_failed_rcpts + 1;
	}
    }

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

    if ( simta_service_smtp == SERVICE_SMTP_REFUSE ) {
	syslog( LOG_NOTICE,
		"receive connection refused: inbound smtp disabled" );
	if ( snet_writef( snet, "554 No SMTP service here\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "receive snet_writef: %m" );
	    goto closeconnection;
	}
    } else {
	if ( simta_receive_connections_max != 0 ) {
	    if ( simta_receive_connections >= simta_receive_connections_max ) {
		syslog( LOG_NOTICE, "receive connection refused: "
			"max connections exceeded" );
		if ( snet_writef( snet, "421 Maximum connections exceeded, "
			"closing transmission channel\r\n" ) < 0 ) {
		    syslog( LOG_ERR, "receive snet_writef: %m" );
		}
		goto closeconnection;
	    }
	}

	if ( simta_dnsr == NULL ) {
	    if (( simta_dnsr = dnsr_new( )) == NULL ) {
		syslog( LOG_ERR, "receive dnsr_new: returned NULL" );
		goto syserror;
	    }
	}

	*hostname = '\0';

        if (( rc = check_reverse( hostname, &(sin->sin_addr))) == 0 ) {  
            receive_dns_match = "PASSED";
        } else {
            receive_dns_match = "FAILED";
            if ( rc < 0 ) {                     /* DNS error */
                if ( simta_ignore_connect_in_reverse_errors ) {
                    syslog( LOG_NOTICE,
                        "Connect.in [%s]: Warning: reverse address error: %s",
                        inet_ntoa( sin->sin_addr ),
                        dnsr_err2string( dnsr_errno( simta_dnsr )));
                } else {
                    syslog( LOG_NOTICE,
                        "Connect.in [%s]: Failed: reverse address error: %s",
                        inet_ntoa( sin->sin_addr ),
                        dnsr_err2string( dnsr_errno( simta_dnsr )));
                    snet_writef( snet,
                        "421 Error checking reverse address: %s %s\r\n",
                        inet_ntoa( sin->sin_addr ),
                        dnsr_err2string( dnsr_errno( simta_dnsr )));
                    goto closeconnection;
                }
            } else {                            /* invalid reverse */
                if ( simta_ignore_reverse == 0 ) {
                    syslog( LOG_NOTICE, "Connect.in [%s]: Failed: "
                            "invalid reverse", inet_ntoa( sin->sin_addr ));
		    if ( simta_reverse_url ) {
			snet_writef( snet,
				"421 No access from IP %s.  See %s\r\n",
				inet_ntoa( sin->sin_addr ),
				simta_reverse_url );
		    } else {
			snet_writef( snet,
				"421 No access from IP %s.\r\n",
				inet_ntoa( sin->sin_addr ));
		    }
                    goto closeconnection;
                } else {
                    syslog( LOG_NOTICE, "Connect.in [%s]: Warning: "
                            "invalid reverse", inet_ntoa( sin->sin_addr ));
                }
            }
        }

	if ( *hostname != '\0' ) {
	    receive_remote_hostname = hostname;
	}

        if ( simta_rbls != NULL ) {
            switch( rbl_check( simta_rbls, &(sin->sin_addr), &rbl_found )) {
            case RBL_BLOCK:
		remote_rbl_status = RBL_BLOCK;
                syslog( LOG_NOTICE, "Connect.in [%s] %s: RBL Blocked: %s",
                        inet_ntoa( sin->sin_addr ), receive_remote_hostname,
                        rbl_found->rbl_domain );
                snet_writef( snet, "550 No access from IP %s.  See %s\r\n",
                        inet_ntoa( sin->sin_addr ), rbl_found->rbl_url );
                goto closeconnection;

            case RBL_ACCEPT:
		remote_rbl_status = RBL_ACCEPT;
                syslog( LOG_NOTICE, "Connect.in [%s] %s: RBL Accepted: %s",
                        inet_ntoa( sin->sin_addr ), receive_remote_hostname,
                        rbl_found->rbl_domain );
                break;

            case RBL_NOT_FOUND:
		/* leave as RBL_UNKNOWN so user tests happen */
		remote_rbl_status = RBL_UNKNOWN;
                syslog( LOG_NOTICE, "Connect.in [%s] %s: RBL Not Found",
                        inet_ntoa( sin->sin_addr ), receive_remote_hostname );
                break;

	    case RBL_ERROR:
            default:
		remote_rbl_status = RBL_UNKNOWN;
                syslog( LOG_NOTICE,
			"Connect.in [%s] %s: RBL Error: %s",
                        inet_ntoa( sin->sin_addr ), receive_remote_hostname,
                        rbl_found->rbl_domain );
                if ( dnsr_errno( simta_dnsr ) !=
                        DNSR_ERROR_TIMEOUT ) {
                    goto syserror;
                }
                dnsr_errclear( simta_dnsr );
                break;
            }
        }

#ifdef HAVE_LIBWRAP
	if ( *hostname == '\0' ) {
	    ctl_hostname = STRING_UNKNOWN;
	} else {
	    ctl_hostname = hostname;
	}

	/* first STRING_UNKNOWN should be domain name of incoming host */
	if ( hosts_ctl( "simta", ctl_hostname,
		inet_ntoa( sin->sin_addr ), STRING_UNKNOWN ) == 0 ) {
	    syslog( LOG_NOTICE, "Connect.in [%s] %s: Failed: access denied",
		    inet_ntoa( sin->sin_addr ), receive_remote_hostname );
	    goto syserror;
	}

	if ( receive_remote_hostname == STRING_UNKNOWN ) {
	    receive_remote_hostname = NULL;
	}
#endif /* HAVE_LIBWRAP */

	if (( env = env_create( NULL, NULL )) == NULL ) {
	    goto syserror;
	}
	receive_sin = sin;

	if (( acav = acav_alloc( )) == NULL ) {
	    syslog( LOG_ERR, "receive argcargv_alloc: %m" );
	    goto syserror;
	}

	if ( snet_writef( snet, "%d %s Simple Internet Message Transfer Agent "
		"ready\r\n", 220, simta_hostname ) < 0 ) {
	    syslog( LOG_ERR, "receive snet_writef: %m" );
	    goto closeconnection;
	}

	syslog( LOG_NOTICE, "Connect.in [%s] %s: Accepted",
		inet_ntoa( sin->sin_addr ), receive_remote_hostname );
    }

    tv.tv_sec = simta_receive_wait;
    tv.tv_usec = 0;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = simta_receive_wait;
	tv.tv_usec = 0;

	if ( receive_smtp_command != NULL ) {
	    free( receive_smtp_command );
	    receive_smtp_command = NULL;
	}

	if (( receive_smtp_command = strdup( line )) == NULL ) {
	    syslog( LOG_ERR, "receive strdup: %m" );
	    goto syserror;
	}

	/*
	 * This routine needs to be revised to take rfc822 quoting into
	 * account.  E.g.  MAIL FROM:<"foo \: bar"@umich.edu>
	 */
	if (( ac = acav_parse2821( acav, line, &av )) < 0 ) {
	    syslog( LOG_ERR, "receive argcargv: %m" );
	    goto syserror;
	}

	if ( ac == 0 ) {
	    if ( snet_writef( snet, "500 Command unrecognized\r\n" ) < 0 ) {
		goto closeconnection;
	    }
	    continue;
	}

	/* rfc 2821 2.4
	 * No sending SMTP system is permitted to send envelope commands
	 * in any character set other than US-ASCII; receiving systems
	 * SHOULD reject such commands, normally using "500 syntax error
	 * - invalid character" replies.
	 */

	for ( i = 0; i < receive_ncommands; i++ ) {
	    if ( strcasecmp( av[ 0 ], receive_commands[ i ].c_name ) == 0 ) {
		break;
	    }
	}

	/* tarpitting */
	if ( simta_smtp_tarpit != 0 ) {
	    req.tv_sec = simta_smtp_tarpit;
	    req.tv_nsec = 0;
	    if ( nanosleep( &req, NULL ) != 0 ) {
		syslog( LOG_DEBUG, "Tarpit: Error nanosleep %m" );
	    }
	}

	if (( simta_service_smtp == SERVICE_SMTP_REFUSE ) &&
		( strcasecmp( av[ 0 ], "QUIT" ) != 0 )) {
	    if ( snet_writef( snet, "503 bad sequence of commands\r\n" ) < 0 ) {
		goto closeconnection;
	    }
	    continue;
	}

	if ( i >= receive_ncommands ) {
	    if ( snet_writef( snet, "500 Command unrecognized\r\n" ) < 0 ) {
		goto closeconnection;
	    }
	    continue;
	}

	switch ((*(receive_commands[ i ].c_func))( snet, env, ac, av )) {

	case RECEIVE_OK:
	    break;

	case RECEIVE_CLOSECONNECTION:
	    goto closeconnection;

	case RECEIVE_BADSEQUENCE:
	    if ( snet_writef( snet, "503 Bad sequence of commands\r\n" ) < 0 ) {
		syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		goto syserror;
	    }
	    break;

	default:
	/* fallthrough */
	case RECEIVE_SYSERROR:
	    goto syserror;
	}
    }

    if ( errno == ETIMEDOUT ) {
	if ( snet_writef( snet, "421 closing transmission channel: "
		"command timeout\r\n", simta_hostname ) < 0 ) {
	    syslog( LOG_ERR, "receive snet_writef: %m" );
	}
	goto closeconnection;
    }

syserror:
    if ( snet_writef( snet, "421 %s Service not available, "
	    "closing transmission channel\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_ERR, "receive snet_writef: %m" );
    }

closeconnection:
    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_ERR, "receive snet_close: %m" );
    }

    if ( acav != NULL ) {
	acav_free( acav );
    }

    if ( receive_smtp_command != NULL ) {
	free( receive_smtp_command );
	receive_smtp_command = NULL;
    }

    if ( receive_hello != NULL ) {
	free( receive_hello );
    }

    reset( env );

#ifdef HAVE_LIBSSL 
    if ( mdctx_status != MDCTX_UNINITILIZED ) {
	EVP_MD_CTX_cleanup( &mdctx );
    }
#endif /* HAVE_LIBSSL */

    if (( tv_start.tv_sec != 0 ) &&
	    (( r = gettimeofday( &tv_stop, NULL )) != 0 )) {
	if ( r != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_read_dir gettimeofday: %m" );
	}
	tv_start.tv_sec = 1;
	tv_stop.tv_sec = 0;
    }

    syslog( LOG_NOTICE,
	    "Connect.in [%s] %s: Metrics: "
	    "seconds %d, mail from %d/%d, rcpt to %d/%d, data %d/%d",
	    inet_ntoa( sin->sin_addr ), receive_remote_hostname,
	    (int)(tv_stop.tv_sec - tv_start.tv_sec), mail_success, mail_attempt,
	    rcpt_success, rcpt_attempt, data_success, data_attempt );

    return( simta_fast_files );
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

    /* If host is configured to be a high pref mx ( done by hand ),
     * do not check for local address.
     */
    if ( red->red_host_type == RED_HOST_TYPE_SECONDARY_MX ) {
	return( MX_ADDRESS );
    }

    /* Search for user using expansion table */
    for ( action = red->red_receive; action != NULL; action = action->a_next ) {
	switch ( action->a_action ) {
	case EXPANSION_TYPE_ALIAS:
	    if ( action->a_dbp == NULL ) {
		if (( rc = db_open_r( &(action->a_dbp), action->a_fname,
			NULL )) != 0 ) {
		    action->a_dbp = NULL;
		    syslog( LOG_ERR, "local_address: db_open_r %s: %s",
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
	    rc = simta_ldap_address_local( addr, domain );
	    *at = '@';

	    switch ( rc ) {
	    default:
		syslog( LOG_ERR,
			"local_address simta_ldap_address_local: bad value" );
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
	    syslog( LOG_ERR, "env_string malloc: %m" );
	    return( NULL );
	}
	sprintf( buf, "%s=", left );

    } else {
	if (( buf = (char*)malloc( strlen( left ) +
		strlen( right ) + 2 )) == NULL ) {
	    syslog( LOG_ERR, "env_string malloc: %m" );
	    return( NULL );
	}
	sprintf( buf, "%s=%s", left, right );
    }

    return( buf );
}


    int
mail_filter( struct envelope *env, int f, char **smtp_message )
{
    int			fd[ 2 ];
    int			pid;
    int			status;
    SNET		*snet;
    char		*line;
    char		*filter_argv[] = { 0, 0 };
    char		*filter_envp[ 11 ];
    char		fname[ MAXPATHLEN + 1 ];

    if (( filter_argv[ 0 ] = strrchr( simta_mail_filter, '/' )) != NULL ) {
	filter_argv[ 0 ]++;
    } else {
	filter_argv[ 0 ] = simta_mail_filter;
    }

    if ( pipe( fd ) < 0 ) {
	syslog( LOG_ERR, "mail_filter pipe: %m" );
	return( MESSAGE_TEMPFAIL );
    }

    switch ( pid = fork()) {
    case -1 :
	close( fd[ 0 ]);
	close( fd[ 1 ]);
	syslog( LOG_ERR, "mail_filter fork: %m" );
	return( MESSAGE_TEMPFAIL );

    case 0 :
	/* use fd[ 1 ] to communicate with parent, parent uses fd[ 0 ] */
	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter close: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	/* stdout -> fd[ 1 ] */
	if ( dup2( fd[ 1 ], 1 ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter dup2: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	/* stderr -> fd[ 1 ] */
	if ( dup2( fd[ 1 ], 2 ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter dup2: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter close: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	/* f -> stdin */
	if ( dup2( f, 0 ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter dup2: %m" );
	    exit( MESSAGE_TEMPFAIL );
	}

	snprintf( fname, MAXPATHLEN, "%s/D%s", simta_dir_fast, env->e_id );
	if (( filter_envp[ 0 ] = env_string( "SIMTA_DFILE",
		fname )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	snprintf( fname, MAXPATHLEN, "%s/t%s", simta_dir_fast, env->e_id );
	if (( filter_envp[ 1 ] = env_string( "SIMTA_TFILE",
		fname )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 2 ] = env_string( "SIMTA_REMOTE_IP",
		inet_ntoa( receive_sin->sin_addr ))) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 3 ] = env_string( "SIMTA_REMOTE_HOSTNAME",
		receive_remote_hostname )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 4 ] = env_string( "SIMTA_REVERSE_LOOKUP",
		receive_dns_match )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 5 ] = env_string( "SIMTA_SMTP_MAIL_FROM",
		env->e_mail )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 6 ] = env_string( "SIMTA_SMTP_HELO",
		receive_hello )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if (( filter_envp[ 7 ] = env_string( "SIMTA_MID",
		env->e_mid )) == NULL ) {
	    exit( MESSAGE_TEMPFAIL );
	}

	if ( simta_checksum_md != NULL ) {
	    if (( filter_envp[ 8 ] = env_string( "SIMTA_CHECKSUM_SIZE",
		    md_bytes )) == NULL ) {
		exit( MESSAGE_TEMPFAIL );
	    }

	    if (( filter_envp[ 9 ] = env_string( "SIMTA_CHECKSUM",
		    md_b64 )) == NULL ) {
		exit( MESSAGE_TEMPFAIL );
	    }

	    filter_envp[ 10 ] = NULL;
	} else {
	    filter_envp[ 8 ] = NULL;
	}


	execve( simta_mail_filter, filter_argv, filter_envp );
	/* if we are here, there is an error */
	syslog( LOG_ERR, "mail_filter execve: %m" );
	exit( MESSAGE_TEMPFAIL );

    default :
	/* use fd[ 0 ] to communicate with child, child uses fd[ 1 ] */
	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter close: %m" );
	    return( MESSAGE_TEMPFAIL );
	}

	if (( snet = snet_attach( fd[ 0 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    close( fd[ 0 ] );
	    return( MESSAGE_TEMPFAIL );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    syslog( LOG_INFO, "Filter %s: %s", env->e_id, line );

	    if ( *smtp_message == NULL ) {
		if (( *smtp_message = strdup( line )) == NULL ) {
		    syslog( LOG_ERR, "strdup: %m" );
		    snet_close( snet );
		    return( MESSAGE_TEMPFAIL );
		}
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "mail_filter snet_close: %m" );
	    return( MESSAGE_TEMPFAIL );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    syslog( LOG_ERR, "mail_filter waitpid: %m" );
	    return( MESSAGE_TEMPFAIL );
	}

	if ( WIFEXITED( status )) {
	    switch ( WEXITSTATUS( status )) {
	    case MESSAGE_ACCEPT:
		return( MESSAGE_ACCEPT );

	    case MESSAGE_ACCEPT_AND_DELETE:
		return( MESSAGE_ACCEPT_AND_DELETE );

	    case MESSAGE_REJECT:
		return( MESSAGE_REJECT );

	    case MESSAGE_TEMPFAIL:
		return( MESSAGE_TEMPFAIL );

	    default:
		syslog( LOG_WARNING, "mail_filter %d return out of range (%d)",
			pid, WEXITSTATUS( status ));
		return( MESSAGE_TEMPFAIL );
	    }

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "mail_filter %d died on signal %d\n", pid, 
		    WTERMSIG( status ));
	    return( MESSAGE_TEMPFAIL );

	} else {
	    syslog( LOG_ERR, "mail_filter %d died\n", pid );
	    return( MESSAGE_TEMPFAIL );
	}
    }
}

#ifdef HAVE_LIBSASL
    int
reset_sasl_conn( sasl_conn_t **conn )
{

    int         rc;

    sasl_dispose( conn );

    if (( rc = sasl_server_new( "smtp", NULL, NULL, NULL, NULL, NULL,
            0, conn )) != SASL_OK ) {
	syslog( LOG_ERR, "reset_sasl_conn sasl_server_new: %s",
		sasl_errdetail( *conn ));
        return( rc );
    }

    if (( rc = sasl_setprop( *conn, SASL_SSF_EXTERNAL, &ext_ssf )) != SASL_OK) {
	syslog( LOG_ERR, "reset_sasl_conn sasl_setprop: %s",
		sasl_errdetail( *conn ));
        return( rc );
    }

    if (( rc = sasl_setprop( *conn, SASL_AUTH_EXTERNAL,
	    &ext_ssf )) != SASL_OK) {
	syslog( LOG_ERR, "reset_sasl_conn sasl_setprop: %s",
		sasl_errdetail( *conn ));
        return( rc );
    }

    return( SASL_OK );
}

#else /* HAVE_LIBSASL */
    int
reset_sasl_conn( sasl_conn_t **conn )
{
    return( -1 );
}

#endif /* HAVE_LIBSASL */
