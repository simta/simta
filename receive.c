/*
* Copyright (c) 1998 Regents of The University of Michigan.
* All Rights Reserved.  See COPYRIGHT.
*/

#include "config.h"

#include <sys/types.h>
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
#endif /* HAVE_LIBWRAP */

#ifdef HAVE_LIBSSL 
#include <openssl/ssl.h>
#include <openssl/err.h>

extern SSL_CTX	*ctx;
#endif /* HAVE_LIBSSL */

#include <snet.h>

#include "bdb.h"
#include "denser.h"
#include "queue.h"
#include "ll.h"
#include "simta.h"
#include "envelope.h"
#include "expand.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "mx.h"
#include "simta.h"
#include "line_file.h"
#include "header.h"

extern char		*version;
struct host_q		*hq_receive = NULL;
struct sockaddr_in  	*receive_sin;
int			receive_global_relay = 0;
char			*receive_hello = NULL;

#define	RECEIVE_OK		0x0000
#define	RECEIVE_SYSERROR	0x0001
#define	RECEIVE_CLOSECONNECTION	0x0010
#define	RECEIVE_LINE_LENGTH	0x0100

/* return codes for address_expand */
#define	LOCAL_ADDRESS			1
#define	NOT_LOCAL			2
#define	LOCAL_ERROR			3

struct command {
    char	*c_name;
    int		(*c_func) ___P(( SNET *, struct envelope *, int, char *[] ));
};

static int	local_address ___P(( char * ));
static int	f_helo ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_ehlo ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_mail ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_rcpt ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_data ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_rset ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_noop ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_quit ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_help ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_vrfy ___P(( SNET *, struct envelope *, int, char *[] ));
static int	f_expn ___P(( SNET *, struct envelope *, int, char *[] ));
#ifdef HAVE_LIBSSL
static int	f_starttls ___P(( SNET *, struct envelope *, int, char *[] ));
#endif /* HAVE_LIBSSL */

static int	hello ___P(( struct envelope *, char * ));
static char	*smtp_trimaddr ___P(( char *, char * ));


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


    int
f_helo( SNET *snet, struct envelope *env, int ac, char *av[])
{
    if ( ac != 2 ) {
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
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

    syslog( LOG_INFO, "f_helo %s", av[ 1 ]);
    return( RECEIVE_OK );
}


/*
 * SMTP Extensions RFC.
 */
    int
f_ehlo( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    /* rfc 2821 4.1.4
     * A session that will contain mail transactions MUST first be
     * initialized by the use of the EHLO command.  An SMTP server SHOULD
     * accept commands for non-mail transactions (e.g., VRFY or EXPN)
     * without this initialization.
     */
    if ( ac != 2 ) {
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
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
    if (( env->e_flags & E_READY ) == 0 ) {
	if ( *(env->e_id) != '\0' ) {
	    syslog( LOG_INFO, "f_mail %s: abandoned", env->e_id );
	}
	env_reset( env );
    }

    /* rfc 2821 3.6
     * The domain name given in the EHLO command MUST BE either a primary
     * host name (a domain name that resolves to an A RR) or, if the host
     * has no name, an address literal as described in section 4.1.1.1.
     */

    if ( hello( env, av[ 1 ] ) != RECEIVE_OK ) {
	return( RECEIVE_SYSERROR );
    }

#ifdef HAVE_LIBSSL
    /* RFC 2487 SMTP TLS */
    if (( env->e_flags & E_TLS ) == 0 ) {
	if ( snet_writef( snet, "%d-%s Hello %s\r\n", 250, simta_hostname,
		av[ 1 ]) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}

	if ( snet_writef( snet, "%d STARTTLS\r\n", 250 ) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	syslog( LOG_INFO, "f_ehlo %s start_tls", av[ 1 ]);

    } else {
	if ( snet_writef( snet, "%d %s Hello %s\r\n", 250, simta_hostname,
		av[ 1 ]) < 0 ) {
	    syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	syslog( LOG_INFO, "f_ehlo %s", av[ 1 ]);
    }
#else /* HAVE_LIBSSL */

    if ( snet_writef( snet, "%d %s Hello %s\r\n", 250, simta_hostname,
	    av[ 1 ]) < 0 ) {
	syslog( LOG_ERR, "f_ehlo snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    syslog( LOG_INFO, "f_ehlo %s", av[ 1 ]);
#endif /* HAVE_LIBSSL */

    return( RECEIVE_OK );
}


    static char *
smtp_trimaddr( addr, leader )
    char	*addr;
    char	*leader;
{
    char	*p, *q;

    if (( addr == NULL ) || ( leader == NULL )) {
	return( NULL );
    }

    if ( strncasecmp( addr, leader, strlen( leader )) != 0 ) {
	return( NULL );
    }
    p = addr + strlen( leader );
    q = p + strlen( p ) - 1;
    if (( *p != '<' ) || ( *q != '>' )) {
	return( NULL );
    }
    *q = '\0';
    p++;	/* p points to the address */

    return( p );
}


    int
f_mail( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    int			rc;
    char		*addr;
    char		*domain;

    /* XXX handle MAIL FROM:<foo> AUTH=bar */
    if ( ac != 2 ) {
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_mail snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /* RFC 2821 Section 4.1.1.2
     * "MAIL FROM:" ("<>" / Reverse-Path ) CRLF
     */
    if (( addr = smtp_trimaddr( av[ 1 ], "FROM:" )) == NULL ) {
	/* not a correct address */
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_mail snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /*
     * rfc1123 (5.3.2) Timeouts in SMTP.  We have a maximum of 5 minutes
     * before we must return something to a "MAIL" command.  Soft failures
     * can either be accepted (trusted) or the soft failures can be passed
     * along.  "451" is probably the correct error.
     */
    if ( *addr != '\0' ) {
	if ((( domain = strchr( addr, '@' )) == NULL ) || ( domain == addr )) {
	    if ( snet_writef( snet, "%d Requested action not taken: "
		    "bad address syntax\r\n", 553 ) < 0 ) {
		syslog( LOG_ERR, "f_mail snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    return( RECEIVE_OK );
	}
	domain++;

	if (( rc = check_hostname( &simta_dnsr, domain )) != 0 ) {
	    if ( rc < 0 ) {
		syslog( LOG_ERR, "f_mail check_host: %s: failed", domain );
		env_reset( env );
		return( RECEIVE_SYSERROR );
	    } else {
		if ( snet_writef( snet, "%d %s: unknown host\r\n", 550,
			domain ) < 0 ) {
		    syslog( LOG_ERR, "f_mail snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		syslog( LOG_ERR, "f_mail check_host %s: unknown host", domain );
		return( RECEIVE_OK );
	    }
	}
    }

    /*
     * Contrary to popular belief, it is not an error to give more than
     * one "MAIL FROM:" command.  According to rfc822, this is just like
     * "RSET".
     */
    if (( env->e_flags & E_READY ) != 0 ) {
	switch ( expand_and_deliver( &hq_receive, env )) {
	    default:
	    case EXPAND_SYSERROR:
	    case EXPAND_FATAL:
		env_reset( env );
		return( RECEIVE_SYSERROR );

	    case EXPAND_OK:
		break;
	}
    }

    env_reset( env );

    if ( env_gettimeofday_id( env ) != 0 ) {
	syslog( LOG_ERR, "f_mail env_gettimeofday_id: %m" );
	return( RECEIVE_SYSERROR );
    }

    if (( env->e_mail = strdup( addr )) == NULL ) {
	syslog( LOG_ERR, "f_mail: strdup: %m" );
	return( RECEIVE_SYSERROR );
    }

    syslog( LOG_INFO, "f_mail %s: mail: <%s>", env->e_id, env->e_mail );

    if ( snet_writef( snet, "%d OK\r\n", 250 ) < 0 ) {
	syslog( LOG_ERR, "f_mail snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    return( RECEIVE_OK );
}


    int
f_rcpt( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    int			high_mx_pref, rc;
    char		*addr, *domain;
    struct dnsr_result	*result;

    if ( ac != 2 ) {
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /* Must already have "MAIL FROM:", and no valid message */
    if (( env->e_mail == NULL ) || (( env->e_flags & E_READY ) != 0 )) {
	if ( snet_writef( snet, "%d Bad sequence of commands\r\n", 503 ) < 0 ) {
	    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if (( addr = smtp_trimaddr( av[ 1 ], "TO:" )) == NULL ) {
	syslog( LOG_ERR, "f_rcpt smtp_trimaddr error" );
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    /* XXX check address for validity here */

    /* rfc 2821 3.7
     * SMTP servers MAY decline to act as mail relays or to
     * accept addresses that specify source routes.  When route information
     * is encountered, SMTP servers are also permitted to ignore the route
     * information and simply send to the final destination specified as the
     * last element in the route and SHOULD do so.
     */
    /* short-circuit route-addrs */
    if ( *addr == '@' ) {
	if (( addr = strchr( addr, ':' )) == NULL ) {
	    syslog( LOG_ERR, "f_rcpt strchr error addr" );
	    if ( snet_writef( snet, "%d Requested action not taken\r\n",
		    553 ) < 0 ) {
		syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    return( RECEIVE_OK );
	}
	addr++;
    }

    /*
     * We're not currently going to parse for the "%-hack".  This sort
     * of relay is heavily discouraged due to SPAM abuses.
     */
    if ((( domain = strchr( addr, '@' )) == NULL ) || ( domain == addr )) {
	syslog( LOG_ERR, "f_rcpt strchr error domain" );
	if ( snet_writef( snet, "%d Requested action not taken\r\n",
		553 ) < 0 ) {
	    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }
    domain++;

    /*
     * Again, soft failures can either be accepted (trusted) or the soft
     * failures can be passed along.  "451" is probably the correct soft
     * error.
     *
     * If we're using DNS MX records to configure ourselves, then we should
     * probably preserve the results of our DNS check.
     */

    /* rfc 2821 3.6
     * The reserved mailbox name "postmaster" may be used in a RCPT
     * command without domain qualification (see section 4.1.1.3) and
     * MUST be accepted if so used.
     */

    if ( strncasecmp( addr, "postmaster", strlen( "postmaster" )) != 0 ) {
	if (( rc = check_hostname( &simta_dnsr, domain )) != 0 ) {
	    if ( rc < 0 ) {
		syslog( LOG_ERR, "f_mail check_host: %s: failed", domain );
		env_reset( env );
		return( RECEIVE_SYSERROR );
	    } else {
		if ( snet_writef( snet, "%d %s: unknown host\r\n", 550,
			domain ) < 0 ) {
		    syslog( LOG_ERR, "f_mail snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		syslog( LOG_ERR, "f_mail check_host %s: unknown host", domain );
		return( RECEIVE_OK );
	    }
	}
    }

    if ( simta_global_relay == 0 ) {
	/*
	 * Here we do an initial lookup in our domain table.  This is our
	 * best opportunity to decline recipients that are not local or
	 * unknown, since if we give an error the connecting client generates
	 * the bounce.
	 */
	/* XXX check config file, check MXes */

	switch ( mx_local( env, result, domain )) {
	case 1:
	    high_mx_pref = 1;
	    break;

	case 2:
	    high_mx_pref = 0;
	    break;

	default:
	    dnsr_free_result( result );
	    if ( snet_writef( snet, "551 User not local; please try <%s>\r\n",
		    addr ) < 0 ) {
		syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		return( RECEIVE_CLOSECONNECTION );
	    }
	    return( RECEIVE_OK );
	}

	dnsr_free_result( result );

	/*
	 * For local mail, we now have 5 minutes (rfc1123 5.3.2) to decline
	 * to receive the message.  If we're in the default configuration, we
	 * check the passwd and alias file.  Other configurations use "mailer"
	 * specific checks.
	 */

	/* rfc 2821 section 3.7
	 * A relay SMTP server is usually the target of a DNS MX record that
	 * designates it, rather than the final delivery system.  The relay
	 * server may accept or reject the task of relaying the mail in the same
	 * way it accepts or rejects mail for a local user.  If it accepts the
	 * task, it then becomes an SMTP client, establishes a transmission
	 * channel to the next SMTP server specified in the DNS (according to
	 * the rules in section 5), and sends it the mail.  If it declines to
	 * relay mail to a particular address for policy reasons, a 550 response
	 * SHOULD be returned.
	 */

	if ( high_mx_pref != 0 ) {
	    switch( local_address( addr )) {
	    case NOT_LOCAL:
		syslog( LOG_INFO, "f_rcpt %s: address not local", addr );
		if ( snet_writef( snet,
			"%d Requested action not taken: User not found.\r\n",
			550 ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		return( RECEIVE_OK );

	    case LOCAL_ERROR:
	    default:
		syslog( LOG_ERR, "f_rcpt local_address %s: error", addr );
		if ( snet_writef( snet,
			"%d Requested action aborted: "
			"local error in processing.\r\n", 451 ) < 0 ) {
		    syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
		    return( RECEIVE_CLOSECONNECTION );
		}
		return( RECEIVE_SYSERROR );

	    case LOCAL_ADDRESS:
		break;
	    }
	}
    }

    if ( env_recipient( env, addr ) != 0 ) {
	return( RECEIVE_SYSERROR );
    }

    if ( snet_writef( snet, "%d OK\r\n", 250 ) < 0 ) {
	syslog( LOG_ERR, "f_rcpt snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    syslog( LOG_INFO, "%s: rcpt: <%s>", env->e_id, env->e_rcpt->r_rcpt );
    return( RECEIVE_OK );
}


    int
f_data( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    struct timeval			tv;
    char				*line;
    int					err = RECEIVE_OK;
    int					dfile_fd;
    time_t				clock;
    struct tm				*tm;
    FILE				*dff;
    char				dfile_fname[ MAXPATHLEN + 1 ];
    char				daytime[ 30 ];
    struct line_file			*lf = NULL;
    struct line				*l;
    int					header = 1;
    int					line_no = 0;
    struct stat				sbuf;

    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */
    if ( ac != 1 ) {
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
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
    if (( env->e_mail == NULL ) || (( env->e_flags & E_READY ) != 0 )) {
	if ( snet_writef( snet, "%d Bad sequence of commands\r\n", 503 ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( env->e_rcpt == NULL ) {
	if ( snet_writef( snet, "%d no valid recipients\r\n", 554 ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    sprintf( dfile_fname, "%s/D%s", simta_dir_fast, env->e_id );

    if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 ))
	    < 0 ) {
	syslog( LOG_ERR, "f_data open %s: %m", dfile_fname );
	return( RECEIVE_SYSERROR );
    }

    if (( dff = fdopen( dfile_fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "f_data fdopen: %m" );
	err = RECEIVE_SYSERROR;
	if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "f_data close: %m" );
	}

	if ( unlink( dfile_fname ) < 0 ) {
	    syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
	}

	return( RECEIVE_SYSERROR );
    }

    clock = time( &clock );
    tm = localtime( &clock );
    strftime( daytime, sizeof( daytime ), "%e %b %Y %T", tm );

    /*
     * At this point, we must have decided what we'll put in the Received:
     * header, since that is the first line in the file.  This is where
     * we might want to put the sender's domain name, if we obtained one.
     */
    if ( fprintf( dff, "Received: FROM %s ([%s])\n\tBY %s ID %s ; \n\t%s %s\n",
	    ( receive_hello == NULL ) ? "NULL" : receive_hello,
	    inet_ntoa( receive_sin->sin_addr ), simta_hostname, env->e_id,
	    daytime, tz( tm )) < 0 ) {
	syslog( LOG_ERR, "f_data fprintf: %m" );
	err = RECEIVE_SYSERROR;
	goto cleanup;
    }

    if (( lf = line_file_create()) == NULL ) {
	err = RECEIVE_SYSERROR;
	goto cleanup;
    }

    if ( snet_writef( snet, "%d Start mail input; end with <CRLF>.<CRLF>\r\n",
	    354 ) < 0 ) {
	syslog( LOG_ERR, "f_data snet_writef: %m" );
	err = RECEIVE_CLOSECONNECTION;
	goto cleanup;
    }

    header = 1;

    /* XXX should implement a byte count to limit DofS attacks */
    tv.tv_sec = simta_receive_wait;
    tv.tv_usec = 0;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = simta_receive_wait;
	tv.tv_usec = 0;
	line_no++;

	if ( *line == '.' ) {
	    if ( strcmp( line, "." ) == 0 ) {
		break;
	    }
	    line++;
	}

	/*
	 * RFC 2821 4.5.3:
	 * 
	 * text line
	 *     The maximum total length of a text line including the <CRLF> is
	 *     1000 characters (not counting the leading dot duplicated for
	 *     transparency).  This number may be increased by the use of SMTP
	 *     Service Extensions.
	 */

	if ( strlen( line ) > 1000 ) {
	    err = RECEIVE_LINE_LENGTH;
	}

	if ( header == 1 ) {
	    if ( header_end( lf, line ) != 0 ) {
		/* XXX reject message based on headers here */

		if ( err == RECEIVE_OK ) {
		    if ( header_file_out( lf, dff ) != 0 ) {
			syslog( LOG_ERR, "f_data header_file_out: %m" );
			err = RECEIVE_SYSERROR;
		    } else {
			if ( fprintf( dff, "%s\n", line ) < 0 ) {
			    syslog( LOG_ERR, "f_data fprintf: %m" );
			    err = RECEIVE_SYSERROR;
			}
		    }
		}

		header = 0;

	    } else {
		/* append line to headers */
		if ( err == RECEIVE_OK ) {
		    if (( l = line_append( lf, line )) == NULL ) {
			syslog( LOG_ERR, "f_data line_append: %m" );
			err = RECEIVE_SYSERROR;
		    } else {
			l->line_no = line_no;
		    }
		}
	    }

	} else {
	    if ( err == RECEIVE_OK ) {
		if ( fprintf( dff, "%s\n", line ) < 0 ) {
		    syslog( LOG_ERR, "f_data fprintf: %m" );
		    err = RECEIVE_SYSERROR;
		}
	    }
	}
    }

    if ( header == 1 ) {
	/* XXX reject message based on headers here */

	if ( err == RECEIVE_OK ) {
	    if ( header_file_out( lf, dff ) != 0 ) {
		syslog( LOG_ERR, "f_data header_file_out: %m" );
		err = RECEIVE_SYSERROR;
	    }
	}
    }

    line_file_free( lf );
    lf = NULL;

    if ( line == NULL ) {	/* EOF */
	syslog( LOG_INFO, "f_data %s: connection dropped", env->e_id );
	err = RECEIVE_CLOSECONNECTION;
    }

    if ( err != 0 ) {
	goto cleanup;
    }

    if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	syslog( LOG_ERR, "f_data %s fstat %s: %m", env->e_id, dfile_fname );
        goto cleanup;
    }
    env->e_dinode = sbuf.st_ino;

    if ( fclose( dff ) != 0 ) {
	syslog( LOG_ERR, "f_data fclose: %m" );
	err = RECEIVE_SYSERROR;
	goto cleanup;
    }

    /* make E (t) file */
    /* XXX make sure this is accounted for in fast file db */
    env->e_dir = simta_dir_fast;
    if ( env_outfile( env ) != 0 ) {
	err = RECEIVE_SYSERROR;
	goto cleanup;
    }

    /*
     * We could perhaps check that snet_writef() gets a good return.
     * However, if we've already fully instanciated the message in the
     * queue, a failure indication from snet_writef() may be false, the
     * other end may have in reality recieved the "250 OK", and deleted
     * the message.  Thus, it's safer to ignore the return value of
     * snet_writef(), perhaps causing the sending-SMTP agent to transmit
     * the message again.
     */
    if ( snet_writef( snet, "%d OK (%s)\r\n", 250, env->e_id ) < 0 ) {
	syslog( LOG_ERR, "f_data snet_writef: %m" );
	err = RECEIVE_CLOSECONNECTION;
	goto cleanup;
    }

    /* mark message as ready to roll */
    env->e_flags = env->e_flags | E_READY;
    syslog( LOG_INFO, "f_data %s: accepted", env->e_id );
    return( RECEIVE_OK );

cleanup:
    if ( fclose( dff ) != 0 ) {
	syslog( LOG_ERR, "f_data fclose: %m" );
    }

    if ( lf != NULL ) {
	line_file_free( lf );
    }

    if ( unlink( dfile_fname ) < 0 ) {
	syslog( LOG_ERR, "f_data unlink %s: %m", dfile_fname );
    }

    switch ( err ) {
    default:
	return( err );

    case RECEIVE_LINE_LENGTH:
	if ( snet_writef( snet, "554 line too long\r\n" ) < 0 ) {
	    syslog( LOG_ERR, "f_data snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }
}

    int
f_quit( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */

    if ( ac != 1 ) {
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
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

    syslog( LOG_INFO, "f_quit OK" );
    return( RECEIVE_CLOSECONNECTION );
}


    int
f_rset( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
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
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_rset snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if (( env->e_flags & E_READY ) == 0 ) {
	if ( *(env->e_id) != '\0' ) {
	    syslog( LOG_INFO, "f_rset %s: abandoned", env->e_id );
	}
	env_reset( env );
    }

    if ( snet_writef( snet, "%d OK\r\n", 250 ) < 0 ) {
	syslog( LOG_ERR, "f_rset snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    syslog( LOG_INFO, "f_rset OK" );
    return( RECEIVE_OK );
}


    int
f_noop( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    if ( snet_writef( snet, "%d simta v%s\r\n", 250, version ) < 0 ) {
	syslog( LOG_ERR, "f_noop snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    syslog( LOG_INFO, "f_noop OK" );
    return( RECEIVE_OK );
}


    int
f_help( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
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

    int
f_vrfy( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    if ( snet_writef( snet, "%d Command not implemented\r\n", 502 ) < 0 ) {
	syslog( LOG_ERR, "f_vrfy snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}


    int
f_expn( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    if ( snet_writef( snet, "%d Command not implemented\r\n", 502 ) < 0 ) {
	syslog( LOG_ERR, "f_expn snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }
    return( RECEIVE_OK );
}


#ifdef HAVE_LIBSSL
    int
f_starttls( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    int				rc;
    X509			*peer;
    char			buf[ 1024 ];

    /*
     * Client MUST NOT attempt to start a TLS session if a TLS
     * session is already active.  No mention of what to do if it does...
     */
    if (( env->e_flags & E_TLS ) != 0 ) {
	syslog( LOG_ERR, "f_starttls: called twice" );
	return( RECEIVE_SYSERROR );
    }

    if ( ac != 1 ) {
	syslog( LOG_ERR, "f_starttls: syntax_error" );
	if ( snet_writef( snet, "%d Syntax error\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_OK );
    }

    if ( snet_writef( snet, "%d Ready to start TLS\r\n", 220 ) < 0 ) {
	syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	return( RECEIVE_CLOSECONNECTION );
    }

    /* XXX Begin TLS - hope this works */
    if (( rc = snet_starttls( snet, ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "f_starttls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ));
	if ( snet_writef( snet, "%d SSL didn't work!\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_SYSERROR );
    }

    if (( peer = SSL_get_peer_certificate( snet->sn_ssl )) == NULL ) {
	syslog( LOG_ERR,
		"starttls SSL_get_peer_certificate: no peer certificate" );
	if ( snet_writef( snet, "%d SSL didn't work!\r\n", 501 ) < 0 ) {
	    syslog( LOG_ERR, "f_starttls snet_writef: %m" );
	    return( RECEIVE_CLOSECONNECTION );
	}
	return( RECEIVE_SYSERROR );
    }

    syslog( LOG_INFO, "CERT Subject: %s\n",
	    X509_NAME_oneline( X509_get_subject_name( peer ),
	    buf, sizeof( buf )));
    X509_free( peer );

    env_reset( env );
    env->e_flags = env->e_flags | E_TLS;

    return( 0 );
}
#endif /* HAVE_LIBSSL */

struct command	commands[] = {
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
};
int		ncommands = sizeof( commands ) / sizeof( commands[ 0 ] );


    void
smtp_receive( fd, sin )
    int			fd;
    struct sockaddr_in	*sin;
{
    SNET				*snet;
    struct envelope			*env = NULL;
    ACAV				*acav;
    int					ac;
    int					i;
    int					rc;
    char				**av = NULL;
    char				*line;
    char				*ctl_domain;
    char				hostname[ DNSR_MAX_NAME + 1 ];
    struct timeval			tv;
    extern int				connections;
    extern int				maxconnections;

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "receive snet_attach: %m" );
	return;
    }

    if ( maxconnections != 0 ) {
	if ( connections >= maxconnections ) {
	    syslog( LOG_INFO,
		    "receive connection refused: max connections exceeded" );
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

    ctl_domain = hostname;
    *ctl_domain = '\0';

    if (( rc = check_reverse( &simta_dnsr, ctl_domain,
	    &(sin->sin_addr))) != 0 ) {
	if ( rc < 0 ) {
	    syslog( LOG_INFO, "receive %s: connection rejected: %s",
		dnsr_err2string( dnsr_errno( simta_dnsr )),
		inet_ntoa( sin->sin_addr ));
	    snet_writef( snet, "421 Error checking reverse address: %s\r\n",
		    dnsr_err2string( dnsr_errno( simta_dnsr )));
	    goto closeconnection;

	} else {
	    if ( simta_ignore_reverse == 0 ) {
		syslog( LOG_INFO, "receive %s: connection rejected: "
		    "invalid reverse", inet_ntoa( sin->sin_addr ));
		snet_writef( snet,
			"421 Access Denied - Invalid reverse address\r\n" );
		goto closeconnection;

	    } else {
		syslog( LOG_INFO, "receive %s: invalid reverse",
			inet_ntoa( sin->sin_addr ));
	    }
	}
    }

    if ( *ctl_domain == '\0' ) {
	ctl_domain = STRING_UNKNOWN;
    }

#ifdef HAVE_LIBWRAP
    /* first STRING_UNKNOWN should be domain name of incoming host */
    if ( hosts_ctl( "simta", ctl_domain, inet_ntoa( sin->sin_addr ),
	    STRING_UNKNOWN ) == 0 ) {
	syslog( LOG_INFO, "receive connection refused %s: access denied",
		inet_ntoa( sin->sin_addr ));
	snet_writef( snet, "421 Access Denied - remote access restricted\r\n" );
	goto closeconnection;
    }
#endif /* HAVE_LIBWRAP */

    if (( env = env_create( NULL )) == NULL ) {
	goto syserror;
    }
    receive_sin = sin;

    if (( acav = acav_alloc( )) == NULL ) {
	syslog( LOG_ERR, "receive argcargv_alloc: %m" );
	goto syserror;
    }

    if ( snet_writef( snet, "%d %s Simple Internet Message Transfer Agent "
	    "ready\r\n", 220, simta_hostname ) < 0 ) {
	goto closeconnection;
    }

    tv.tv_sec = simta_receive_wait;
    tv.tv_usec = 0;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = simta_receive_wait;
	tv.tv_usec = 0;

	/*
	 * This routine needs to be revised to take rfc822 quoting into
	 * account.  E.g.  MAIL FROM:<"foo \: bar"@umich.edu>
	 */
	if (( ac = acav_parse2821( acav, line, &av )) < 0 ) {
	    syslog( LOG_ERR, "receive argcargv: %m" );
	    goto syserror;
	}

	if ( ac == 0 ) {
	    if ( snet_writef( snet, "%d Command unrecognized\r\n", 501 ) < 0 ) {
		goto closeconnection;
	    }
	    continue;
	}

	/* XXX - Do we want to check this? */
	/* rfc 2821 2.4
	 * No sending SMTP system is permitted to send envelope commands
	 * in any character set other than US-ASCII; receiving systems
	 * SHOULD reject such commands, normally using "500 syntax error
	 * - invalid character" replies.
	 */

	for ( i = 0; i < ncommands; i++ ) {
	    if ( strcasecmp( av[ 0 ], commands[ i ].c_name ) == 0 ) {
		break;
	    }
	}

	if ( i >= ncommands ) {
	    if ( snet_writef( snet, "%d Command %s unregcognized\r\n",
		    500, av[ 0 ]) < 0 ) {
		goto closeconnection;
	    }
	    continue;
	}

	switch ((*(commands[ i ].c_func))( snet, env, ac, av )) {
	case RECEIVE_OK:
	    break;

	case RECEIVE_CLOSECONNECTION:
	    goto closeconnection;

	default:
	/* fallthrough */
	case RECEIVE_SYSERROR:
	    goto syserror;
	}
    }

syserror:
    if ( snet_writef( snet, "421 %s Service not available, local error, "
	    "closing transmission channel\r\n", simta_hostname ) < 0 ) {
	syslog( LOG_ERR, "receive snet_writef: %m" );
    }

closeconnection:
    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_ERR, "receive snet_close: %m" );
    }

    if ( av != NULL ) {
	acav_free( acav );
    }

    if ( receive_hello != NULL ) {
	free( receive_hello );
    }

    if ( env != NULL ) {
	if (( env->e_flags & E_READY ) != 0 ) {
	    expand_and_deliver( &hq_receive, env );
	}

	env_free( env );
    }
}


    int
local_address( char *addr )
{
    int			rc;
    char		*domain;
    char		*at;
    struct host		*host;
    struct passwd	*passwd;
    struct stab_entry	*i;
    DBT			value;

    /* Check for domain in domain table */
    if (( at = strchr( addr, '@' )) == NULL ) {
	return( NOT_LOCAL );
    }

    /* always accept mail for the local postmaster */
    /* XXX accept mail for all local postmasters? */
    if ( strcasecmp( simta_postmaster, addr ) == 0 ) {
	return( LOCAL_ADDRESS );
    }

    domain = at + 1;

    if (( host = (struct host*)ll_lookup( simta_hosts, domain )) == NULL ) {
	return( NOT_LOCAL );
    }

    /* Search for user using expansion table */
    for ( i = host->h_expansion; i != NULL; i = i->st_next ) {
	if ( strcmp( i->st_key, "alias" ) == 0 ) {
	    /* check alias file */
	    if ( simta_dbp == NULL ) {
		if (( rc = db_open_r( &simta_dbp, SIMTA_ALIAS_DB, NULL ))
			!= 0 ) {
		    syslog( LOG_ERR, "local_address: db_open_r: %s",
			    db_strerror( rc ));
		    return( LOCAL_ERROR );
		}
	    }

	    *at = '\0';
	    rc = db_get( simta_dbp, addr, &value );
	    *at = '@';

	    if ( rc == 0 ) {
		return( LOCAL_ADDRESS );
	    }

	} else if ( strcmp( i->st_key, "password" ) == 0 ) {
	    /* Check password file */
	    *at = '\0';
	    passwd = getpwnam( addr );
	    *at = '@';

	    if ( passwd != NULL ) {
		return( LOCAL_ADDRESS );
	    }

#ifdef HAVE_LDAP
	} else if ( strcmp( i->st_key, "ldap" ) == 0 ) {
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
		continue;

	    case LDAP_LOCAL:
		return( LOCAL_ADDRESS );
	    }
#endif /* HAVE_LDAP */

	} else {
	    /* unknown lookup */
	    syslog( LOG_ERR, "local_address: %s: unknown expansion",
		    i->st_key );
	    return( LOCAL_ERROR );
	}
    }

    return( NOT_LOCAL );
}



    /*
     * Path = "<" [ A-d-l ":" ] Mailbox ">"
     * A-d-l = At-domain *( "," A-d-l )
     *     ; Note that this form, the so-called "source route",
     *     ; MUST BE accepted, SHOULD NOT be generated, and SHOULD be
     *     ; ignored.
     * At-domain = "@" domain
     * Mailbox = Local-part "@" Domain
     * Local-part = Dot-string / Quoted-string
     *     ; MAY be case-sensitive
     * Dot-string = Atom *("." Atom)
     * Atom = 1*atext
     * Quoted-string = DQUOTE *qcontent DQUOTE
     * String = Atom / Quoted-string
 
 
 
     * address-literal = "[" IPv4-address-literal /
     * IPv6-address-literal /
     * General-address-literal "]"
     *     ; See section 4.1.3
     * 
 
     * Mail-parameters = esmtp-param *(SP esmtp-param)
     * Rcpt-parameters = esmtp-param *(SP esmtp-param)
     * 
     * esmtp-param     = esmtp-keyword ["=" esmtp-value]
     * esmtp-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
     * esmtp-value     = 1*(%d33-60 / %d62-127)
     *     ; any CHAR excluding "=", SP, and control characters
     * Keyword  = Ldh-str
     * Argument = Atom
 
     * Domain = (sub-domain 1*("." sub-domain)) / address-literal
     * sub-domain = Let-dig [Ldh-str]
     */
