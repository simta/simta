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
#include <inttypes.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#ifdef HAVE_LIBSSL 
#include <openssl/ssl.h>
#include <openssl/err.h>

extern SSL_CTX	*ctx;
#endif /* HAVE_LIBSSL */

#include <snet.h>

#include "queue.h"
#include "ll.h"
#include "simta.h"
#include "envelope.h"
#include "expand.h"
#include "receive.h"
#include "denser.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"
#include "mx.h"
#include "simta.h"
#include "line_file.h"
#include "header.h"

extern char		*version;
struct host_q		*hq_receive = NULL;

struct command {
    char	*c_name;
    int		(*c_func) ___P(( SNET *, struct envelope *, int, char *[] ));
};

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
hello( env, hostname )
    struct envelope		*env;
    char			*hostname;
{
    /* If we get "HELO" twice, just toss the new one */
    if ( env->e_helo == NULL ) {
	/*
	 * rfc1123 5.2.5: We don't check that the "HELO" domain matches
	 * anything like the hostname.  When we create the data file, we'll
	 * reverse the source IP address and thus determine what the
	 * "Received:" header should say.  Since mail clients don't send well
	 * formed "HELO", we won't even do syntax checks on av[ 1 ].
	 */
	if (( env->e_helo = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "f_helo: strdup: %m" );
	    return( -1 );
	}

	syslog( LOG_INFO, "helo: %s", env->e_helo );
    } else {
	syslog( LOG_INFO, "helo: %s (again)", hostname );
    }

    return( 0 );
}

    int
f_helo( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    if ( ac != 2 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    if ( hello( env, av[ 1 ] ) < 0 ) {
	return( -1 );
    }

    snet_writef( snet, "%d %s Hello %s\r\n", 250, simta_hostname, av[ 1 ]);
    if ( simta_debug ) fprintf( stderr, ">>> %d %s Hello %s\r\n",
	250, simta_hostname, av[ 1 ] );
    return( 0 );
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

    /* XXX - rfc 2821 4.1.4
     * A session that will contain mail transactions MUST first be
     * initialized by the use of the EHLO command.  An SMTP server SHOULD
     * accept commands for non-mail transactions (e.g., VRFY or EXPN)
     * without this initialization.
     */

    if ( ac != 2 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    /* rfc 2821 4.1.4
     * An EHLO command MAY be issued by a client later in the session.  If
     * it is issued after the session begins, the SMTP server MUST clear all
     * buffers and reset the state exactly as if a RSET command had been
     * issued.  In other words, the sequence of RSET followed immediately by
     * EHLO is redundant, but not harmful other than in the performance cost
     * of executing unnecessary commands.
     */

    if ( env->e_helo != NULL ) {
	env_reset( env );
    }

    if ( hello( env, av[ 1 ] ) < 0 ) {
	return( -1 );
    }

    /* rfc 2821 3.6
     * The domain name given in the EHLO command MUST BE either a primary
     * host name (a domain name that resolves to an A RR) or, if the host
     * has no name, an address literal as described in section 4.1.1.1.
     */

    snet_writef( snet, "%d-%s Hello %s\r\n", 250, simta_hostname, av[ 1 ]);
    if ( simta_debug ) fprintf( stderr, ">>> %d-%s Hello %s\r\n",
	250, simta_hostname, av[ 1 ] );

#ifdef HAVE_LIBSSL
    /* RFC 2487 SMTP TLS */
    /*
     * Note that this must be last, as it has '250 ' instead of
     * '250-' as above.
     */
    if (( env->e_flags & E_TLS ) == 0 ) {
	snet_writef( snet, "%d STARTTLS\r\n", 250 );
	if ( simta_debug ) fprintf( stderr, ">>> %d STARTTLS\r\n", 250 );
    }
#endif /* HAVE_LIBSSL */

#ifdef notdef
    /*
     * RFC 2554 SMTP SASL
     */
    snet_writef( snet, "%d AUTH", 250 );
    if ( simta_debug ) fprintf( stderr, ">>> %d AUTH", 250 );
    for ( s = sasl; s->s_name; s++ ) {
	snet_writef( snet, " %s", s->s_name );
	if ( simta_debug ) fprintf( stderr, " %s", s->s_name );
    }
    snet_writef( snet, "\r\n" );
    if ( simta_debug ) fprintf( stderr, "\r\n", 501 );
#endif /* notdef */

    /*
     * Should put something here that isn't a compile-time option, so
     * we can have something that ends with '250 ' instead of '250-' .
     */

    return( 0 );
}

    static char *
smtp_trimaddr( addr, leader )
    char	*addr;
    char	*leader;
{
    char	*p, *q;

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
    struct timeval	tv;
    char		*addr, *domain;
    DNSR		*dnsr;
    struct dnsr_result	*result;

    /*
     * Contrary to popular belief, it is not an error to give more than
     * one "MAIL FROM:" command.  According to rfc822, this is just like
     * "RSET".
     */

    if (( env->e_flags & E_READY ) != 0 ) {
	switch ( expand_and_deliver( &hq_receive, env )) {
	    case EXPAND_OK:
		break;

	    /* XXX fix these cases */
	    default:
	    case EXPAND_SYSERROR:
	    case EXPAND_FATAL:
		return( -1 );
	}

	env_reset( env );
    }

    if ( ac != 2 ) {
    	/* XXX handle MAIL FROM:<foo> AUTH=bar */
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    /* RFC 2821 Section 4.1.1.2
     * "MAIL FROM:" ("<>" / Reverse-Path ) CRLF
     */
    if (( addr = smtp_trimaddr( av[ 1 ], "FROM:" )) == NULL ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    if ((( domain = strchr( addr, '@' )) == NULL ) || ( domain == addr )) {
	snet_writef( snet, "%d Requested action not taken\r\n", 553 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Requested action not taken\r\n", 553 );
	return( 1 );
    }
    domain++;

    /*
     * rfc1123 (5.3.2) Timeouts in SMTP.  We have a maximum of 5 minutes
     * before we must return something to a "MAIL" command.  Soft failures
     * can either be accepted (trusted) or the soft failures can be passed
     * along.  "451" is probably the correct error.
     */
    if ( *addr != '\0' ) {

	/* XXX - Should this return? */
	if (( dnsr = dnsr_new( )) == NULL ) {
	    syslog( LOG_ERR, "dnsr_new: %s",
		dnsr_err2string( dnsr_errno( dnsr )));
	    snet_writef( snet,
		"%d Requested action aborted: local error in processing.\r\n",
		451 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Requested action aborted: local error in processing.\r\n", 451 );
	    return( -1 );
	}

	if (( result = get_mx( dnsr, domain )) == NULL ) {
	    if ( simta_debug ) fprintf( stderr, "get_mx: %s\n",
		dnsr_err2string( dnsr_errno( dnsr )));
	    switch ( dnsr_errno( dnsr )) {
	    case DNSR_ERROR_NAME:
	    case DNSR_ERROR_NO_ANSWER:
		snet_writef( snet, "%d %s: unknown host\r\n", 550, domain );
		if ( simta_debug ) fprintf( stderr,
		    ">>> %d %s: unknown host\r\n", 550, domain );
		return( 1 );
	    default:
		snet_writef( snet,
		    "%d Requested action aborted: local error "
		    "in processing\r\n", 451 );
		if ( simta_debug ) fprintf( stderr,
		    ">>> %d Requested action aborted: local error "
		    "in processing\r\n", 451 );
		return( -1 );
	    }
	}

	if (( dnsr_errno( dnsr ) == DNSR_ERROR_NAME )
		|| ( dnsr_errno( dnsr ) == DNSR_ERROR_NO_ANSWER )) {
	    /* No valid DNS */
	    snet_writef( snet, "%d Can't verify address\r\n", 451 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Can't verify address\r\n", 451 );
	    return( 1 );
	}
    }

    if ( env->e_mail != NULL ) {
	/* XXX check for an accepted message */
	syslog( LOG_INFO, "%s: abandoned", env->e_id );
	env_reset( env );
    }

    if ( gettimeofday( &tv, NULL ) < 0 ) {
	syslog( LOG_ERR, "f_mail: gettimeofday: %m" );
	return( -1 );
    }
    sprintf( env->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec );

    if (( env->e_mail = strdup( addr )) == NULL ) {
	syslog( LOG_ERR, "f_mail: strdup: %m" );
	return( -1 );
    }

    /* check for authorized relay */
    if ( simta_global_relay != 0 ) {
	syslog( LOG_INFO, "relay to %s for %s", addr, env->e_mail );
	env->e_relay = 1;

    } else if ( strncmp( env->e_mail, "mcneal@umich.edu",
	    strlen( "mcneal@umich.edu" )) == 0 ) {
	/* everyone likes mcneal */
	syslog( LOG_INFO, "relay to %s for %s", addr, env->e_mail );
	env->e_relay = 1;
    }

    syslog( LOG_INFO, "%s: mail: <%s>", env->e_id, env->e_mail );

    snet_writef( snet, "%d OK\r\n", 250 );
    if ( simta_debug ) fprintf( stderr, ">>> %d OK\r\n", 250 );
    return( 0 );
}

    int
f_rcpt( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    int			high_mx_pref;
    char		*addr, *domain;
    struct recipient	*r;
    DNSR		*dnsr;
    struct dnsr_result	*result;

    if ( ac != 2 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    /*
     * Must already have "MAIL FROM:"
     */
    if ( env->e_mail == NULL ) {
	snet_writef( snet, "%d Bad sequence of commands\r\n", 503 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Bad sequence of commands\r\n", 503 );
	return( 1 );
    }

    if (( addr = smtp_trimaddr( av[ 1 ], "TO:" )) == NULL ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    /* rfc 2821 3.7
     * SMTP servers MAY decline to act as mail relays or to
     * accept addresses that specify source routes.  When route information
     * is encountered, SMTP servers are also permitted to ignore the route
     * information and simply send to the final destination specified as the
     * last element in the route and SHOULD do so.
     */

    if ( *addr == '@' ) {		/* short-circuit route-addrs */
	if (( addr = strchr( addr, ':' )) == NULL ) {
	    snet_writef( snet, "%d Requested action not taken\r\n", 553 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Requested action not taken\r\n", 553 );
	    return( 1 );
	}
	addr++;
    }

    /*
     * We're not currently going to parse for the "%-hack".  This sort
     * of relay is heavily discouraged due to SPAM abuses.
     */
    if ((( domain = strchr( addr, '@' )) == NULL ) || ( domain == addr )) {
	snet_writef( snet, "%d Requested action not taken\r\n", 553 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Requested action not taken\r\n", 553 );
	return( 1 );
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
	/* DNS check for invalid domain */
	/* XXX - this should be an optional check */
	if (( dnsr = dnsr_new( )) == NULL ) {
	    syslog( LOG_ERR, "dnsr_new: %s",
		dnsr_err2string( (int)dnsr_errno( dnsr )));
	    snet_writef( snet,
		"%d Requested action aborted: local error in processing.\r\n",
		451 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Requested action aborted: "
		"local error in processing.\r\n",
		451 );
	    return( -1 );
	}

	if (( result = get_mx( dnsr, domain )) == NULL ) {
	    if ( simta_debug ) fprintf( stderr, "get_mx: %s: %s\n",
		domain, dnsr_err2string( dnsr_errno( dnsr )));
	    if ((( dnsr_errno( dnsr ) == DNSR_ERROR_NAME )) ||
		    ( dnsr_errno( dnsr ) == DNSR_ERROR_NO_ANSWER )) {
		snet_writef( snet, "%d %s: unknown host\r\n", 550, domain );
		if ( simta_debug ) fprintf( stderr,
		    ">>> %d %s: unknown host\r\n", 550, domain );
		return( 1 );
	    } else {
		snet_writef( snet,
		    "%d Requested action aborted: local error "
		    "in processing\r\n", 451 );
		if ( simta_debug ) fprintf( stderr,
		    ">>> %d Requested action aborted: local error "
		    "in processing\r\n", 451 );
		return( -1 );
	    }
	}

	if (( dnsr_errno( dnsr ) == DNSR_ERROR_NAME )
		|| ( dnsr_errno( dnsr ) == DNSR_ERROR_NO_ANSWER )) {
	    /* No valid DNS */
	    snet_writef( snet, "%d Can't verify address\r\n", 451 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Can't verify address\r\n", 451 );
	    return( 1 );
	}
    }

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
	/* XXX Is 551 correct?  550 is for policy */
	if ( env->e_relay ) {
	    break;
	}
	snet_writef( snet, "%d User not local; please try <%s>\r\n",
	    551, addr );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d User not local; please try <%s>\r\n", 551, addr );
	return( 1 );
    }

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

    if ( high_mx_pref ) {
	switch( address_local( addr )) {

	case ADDRESS_NOT_LOCAL:
	    if ( env->e_relay ) {
		break;
	    }
	    snet_writef( snet,
		"%d Requested action not taken: User not found.\r\n", 550 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Requested action not taken: User not found.\r\n", 550 );
	    return( 1 );

	case ADDRESS_SYSERROR:
	default:
	    snet_writef( snet,
		"%d 3 Requested action aborted: local error in processing.\r\n",
		451 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d 3 Requested action aborted: "
		"local error in processing.\r\n", 451 );
	    return( 1 );

	case ADDRESS_LOCAL:
	    break;
	}
    }

    if (( r = (struct recipient *)malloc( sizeof(struct recipient)))
	    == NULL ) {
	syslog( LOG_ERR, "f_rcpt: malloc: %m" );
	return( -1 );
    }
    if (( r->r_rcpt = strdup( addr )) == NULL ) {
	syslog( LOG_ERR, "f_rcpt: strdup: %m" );
	return( -1 );
    }
    r->r_next = env->e_rcpt;
    env->e_rcpt = r;

    syslog( LOG_INFO, "%s: rcpt: <%s>", env->e_id, env->e_rcpt->r_rcpt );

    snet_writef( snet, "%d OK\r\n", 250 );
    if ( simta_debug ) fprintf( stderr, ">>> %d OK\r\n", 250 );
    return( 0 );
}

    int
f_data( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    char		*line;
    int			err = 0;
    int			fd;
    time_t		clock;
    struct tm		*tm;
    FILE		*dff;
    char		df[ 25 ];
    char		daytime[ 30 ];
    struct line_file	*lf;
    struct line		*l;
    int			header = 1;
    int			line_no = 0;

    /* rfc 2821 4.1.1
     * Several commands (RSET, DATA, QUIT) are specified as not permitting
     * parameters.  In the absence of specific extensions offered by the
     * server and accepted by the client, clients MUST NOT send such
     * parameters and servers SHOULD reject commands containing them as
     * having invalid syntax.
     */
    if ( ac != 1 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    /* rfc 2821 3.3
     * If there was no MAIL, or no RCPT, command, or all such commands
     * were rejected, the server MAY return a "command out of sequence"
     * (503) or "no valid recipients" (554) reply in response to the DATA
     * command.
     */
    if ( env->e_mail == NULL ) {
	snet_writef( snet, "%d Bad sequence of commands\r\n", 503 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Bad sequence of commands\r\n", 503 );
	return( 1 );
    }
    if ( env->e_rcpt == NULL ) {
	snet_writef( snet, "%d no valid recipients\r\n", 554 );
	if ( simta_debug ) fprintf( stderr, ">>> %d no valid recipients\r\n",
	    554 );
	return( 1 );
    }

    /* XXX - do we want to write D file into tmp? */
    sprintf( df, "%s/D%s", simta_dir_fast, env->e_id );

    if (( fd = open( df, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	syslog( LOG_ERR, "f_data: open %s: %m", df );
	return( -1 );
    }

    if (( dff = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "f_data: fdopen: %m" );
	err = -1;
	close( fd );
	goto cleanup;
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
	    ( env->e_helo == NULL ) ? "NULL" : env->e_helo,
	    inet_ntoa( env->e_sin->sin_addr ), simta_hostname, env->e_id,
	    daytime, tz( tm )) < 0 ) {
	syslog( LOG_ERR, "f_data: fprintf \"Received\": %m" );
	err = 1;
	fclose( dff );
	snet_writef( snet,
	    "%d Requested action not taken: insufficient system storage\r\n",
	    452 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Requested action not taken: "
	    "insufficient system storage\r\n", 452 );
	goto cleanup;
    }

    snet_writef( snet, "%d Start mail input; end with <CRLF>.<CRLF>\r\n", 354 );
    if ( simta_debug ) fprintf( stderr,
	">>> %d Start mail input; end with <CRLF>.<CRLF>\r\n", 354 );

    if (( lf = line_file_create()) == NULL ) {
	syslog( LOG_ERR, "malloc: %m" );
	return( -1 );
    }

    header = 1;

    /* should implement a byte count to limit DofS attacks */
    /* XXX not to mention a timeout! */
    /* XXX not to mention line length limits! */
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	line_no++;

	if ( *line == '.' ) {
	    if ( strcmp( line, "." ) == 0 ) {
		break;
	    }
	    line++;
	}

	if ( header == 1 ) {
	    if ( header_end( lf, line ) != 0 ) {
		/* XXX reject message based on headers here */

		/* punt message based on headers */
		if ( simta_punt_host != NULL ) {
		    if ( header_punt( lf ) != 0 ) {
			env->e_punt = simta_punt_host;
		    }
		}

		if ( err == 0 ) {
		    if ( header_file_out( lf, dff ) != 0 ) {
			syslog( LOG_ERR, "f_data header_file_out: %m" );
			err = 1;
		    }
		}

		/* print line to dfile */
		if ( err == 0 ) {
		    if ( fprintf( dff, "%s\n", line ) < 0 ) {
			syslog( LOG_ERR, "f_data fprintf: %m" );
			err = 1;
		    }
		}

		header = 0;

	    } else {
		/* append line to headers */
		if ( err == 0 ) {
		    if (( l = line_append( lf, line )) == NULL ) {
			syslog( LOG_ERR, "f_data line_append: %m" );
			err = 1;
		    }

		    l->line_no = line_no;
		}
	    }

	} else {
	    if ( err == 0 ) {
		if ( fprintf( dff, "%s\n", line ) < 0 ) {
		    syslog( LOG_ERR, "f_data fprintf: %m" );
		    err = 1;
		}
	    }
	}
    }

    if ( header == 1 ) {
	/* XXX reject message based on headers here */

	/* punt message based on headers */
	if ( simta_punt_host != NULL ) {
	    if ( header_punt( lf ) != 0 ) {
		env->e_punt = simta_punt_host;
	    }
	}

	if ( err == 0 ) {
	    if ( header_file_out( lf, dff ) != 0 ) {
		syslog( LOG_ERR, "f_data header_file_out: %m" );
		err = 1;
	    }
	}
    }

    line_file_free( lf );

    if ( line == NULL ) {	/* EOF */
	syslog( LOG_INFO, "%s: connection dropped", env->e_id );
	err = -1;
	fclose( dff );
	goto cleanup;
    }

    /* sync? */
    if ( fclose( dff ) == EOF || err ) {
	err = 1;
	snet_writef( snet,
	    "%d Requested action not taken: insufficient system storage\r\n",
	    452 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Requested action not taken: insufficient system storage\r\n",
	    452 );
	goto cleanup;
    }

    /* make E (t) file */
    /* XXX make sure this is accounted for in fast file db */
    if ( env_outfile( env, simta_dir_fast ) != 0 ) {
	err = 1;
	snet_writef( snet,
	    "%d Requested action not taken: insufficient system storage\r\n",
	    452 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Requested action not taken: insufficient system storage\r\n",
	    452 );
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
    snet_writef( snet, "%d OK (%s)\r\n", 250, env->e_id );
    if ( simta_debug ) fprintf( stderr, ">>> %d OK (%s)\r\n", 250, env->e_id );

    syslog( LOG_INFO, "%s: accepted", env->e_id );

    /* mark message as ready to roll */
    env->e_flags = env->e_flags | E_READY;

    return( 0 );

cleanup:
    if ( unlink( df ) < 0 ) {
	syslog( LOG_ERR, "f_data unlink %s: %m", df );
    }
    return( err );
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
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    if (( env->e_flags & E_READY ) != 0 ) {
	switch ( expand_and_deliver( &hq_receive, env )) {
	    case EXPAND_OK:
		break;

	    /* XXX fix these cases */
	    default:
	    case EXPAND_SYSERROR:
	    case EXPAND_FATAL:
		return( -1 );
	}

	env_reset( env );
    }

    snet_writef( snet, "%d %s Service closing transmission channel\r\n",
	221, simta_hostname );
    if ( simta_debug ) fprintf( stderr,
	">>> %d %s Service closing transmission channel\r\n",
	221, simta_hostname );

    if ( snet_close( snet ) < 0 ) {
	syslog( LOG_ERR, "f_quit: snet_close: %m" );
	return( 1 );
    }
    return( 0 );
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
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    snet_writef( snet, "%d OK\r\n", 250 );
    if ( simta_debug ) fprintf( stderr, ">>> %d OK\r\n", 250 );
    return( 0 );
}

    int
f_noop( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    snet_writef( snet, "%d simta v%s\r\n", 250, version );
    if ( simta_debug ) fprintf( stderr, ">>> %d simta v%s\r\n", 250, version );
    return( 0 );
}

    int
f_help( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    snet_writef( snet, "%d simta v%s\r\n", 211, version );
    if ( simta_debug ) fprintf( stderr, ">>> %d simta v%s\r\n", 211, version );
    return( 0 );
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
    snet_writef( snet, "%d Command not implemented\r\n", 502 );
    if ( simta_debug ) fprintf( stderr, ">>> %d Command not implemented\r\n",
	502 );
    return( 0 );
}

    int
f_expn( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    snet_writef( snet, "%d Command not implemented\r\n", 502 );
    if ( simta_debug ) fprintf( stderr, ">>> %d Command not implemented\r\n",
	502 );
    return( 0 );
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
	return( -1 );
    }

    if ( ac != 1 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	if ( simta_debug ) fprintf( stderr, ">>> %d Syntax error\r\n", 501 );
	return( 1 );
    }

    snet_writef( snet, "%d Ready to start TLS\r\n", 220 );
    if ( simta_debug ) fprintf( stderr, ">>> %d Ready to start TLS\r\n", 220 );

    /*
     * Begin TLS
     */
    if (( rc = snet_starttls( snet, ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "f_starttls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ) );
	snet_writef( snet, "%d SSL didn't work error! XXX\r\n", 501 );
	return( 1 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d SSL didn't work error! XXX\r\n", 501 );
    }
    if (( peer = SSL_get_peer_certificate( snet->sn_ssl ))
	    == NULL ) {
	syslog( LOG_ERR, "no peer certificate" );
	return( -1 );
    }

    syslog( LOG_INFO, "CERT Subject: %s\n", X509_NAME_oneline( X509_get_subject_name( peer ), buf, sizeof( buf )));
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

    int
receive( fd, sin )
    int			fd;
    struct sockaddr_in	*sin;
{
    SNET				*snet;
    struct envelope			*env;
    ACAV				*acav;
    int					ac, i;
    char				**av, *line;
    struct timeval			tv;
    DNSR				*dnsr;
    struct dnsr_result			*result;
    extern int				connections;
    extern int				maxconnections;

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	return( 1 );
    }

    if ( maxconnections != 0 ) {
	if ( connections >= maxconnections ) {
	    syslog( LOG_INFO, "connections refused: server busy" );
	    snet_writef( snet,
		"%d Service busy, closing transmission channel\r\n", 421 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Service busy, closing transmission channel\r\n", 421 );
	    return( 1 );
	}
    }

    if (( dnsr = dnsr_new( )) == NULL ) {
	syslog( LOG_ERR, "dnsr_new: %s",
	    dnsr_err2string( dnsr_errno( dnsr )));
	snet_writef( snet,
	    "%d Requested action aborted: local error in processing.\r\n",
	    451 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Requested action aborted: local error in processing.\r\n",
	    451 );
	return( -1 );
    }

    /* Get PTR for connection */
    if ( dnsr_query( dnsr, DNSR_TYPE_PTR, DNSR_CLASS_IN,
	    inet_ntoa( sin->sin_addr )) < 0 ) {
	syslog( LOG_ERR, "dnsr_query failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Service not available, closing transmission channel\r\n",
	    421 );
	return( 1 );
    }
    if (( result = dnsr_result( dnsr, NULL )) == NULL ) {
	syslog( LOG_ERR, "dnsr_result failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Service not available, closing transmission channel\r\n",
	    421 );
	return( 1 );
    }

    /* Get A record on PTR result */
    if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN,
	    result->r_answer[ 0 ].rr_dn.dn_name )) < 0 ) {
	syslog( LOG_ERR, "dnsr_query failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Service not available, closing transmission channel\r\n",
	    421 );
	return( 1 );
    }
    if (( result = dnsr_result( dnsr, NULL )) == NULL ) {
	syslog( LOG_ERR, "dnsr_result failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Service not available, closing transmission channel\r\n",
	    421 );
	return( 1 );
    }

    /* Verify A record matches IP */
    {
	/* XXX - how should this be checked? */

	struct in_addr      addr;

	memcpy( &addr.s_addr, &(result->r_answer[ 0 ].rr_a), sizeof( int ));

	if ( strcmp( inet_ntoa( addr ), inet_ntoa( sin->sin_addr )) != 0 ) {
	    syslog( LOG_INFO, "%s: connection rejected: invalid A record",
		inet_ntoa( sin->sin_addr ));
	    snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	    return( 1 );
	}
    }

    /* Check bad guy list */

    if (( env = env_create( NULL )) == NULL ) {
	syslog( LOG_ERR, "env_create: %m" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	if ( simta_debug ) fprintf( stderr,
	    ">>> %d Service not available, closing transmission channel\r\n",
	    421 );
	return( 1 );
    }
    env->e_sin = sin;
    env->e_dir = simta_dir_fast;

    snet_writef( snet, "%d %s Simple Internet Message Transfer Agent ready\r\n",
	    220, simta_hostname );
    if ( simta_debug ) fprintf( stderr,
	">>> %d %s Simple Internet Message Transfer Agent ready\r\n",
	220, simta_hostname );

    tv.tv_sec = 60 * 10;	/* 10 minutes, should get this from config */
    tv.tv_usec = 0;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = 60 * 10;
	tv.tv_usec = 0;

	if ( simta_debug ) fprintf( stderr, "<<< %s\n", line );

	/*
	 * This routine needs to be revised to take rfc822 quoting into
	 * account.  E.g.  MAIL FROM:<"foo \: bar"@umich.edu>
	 */

	if (( acav = acav_alloc( )) == NULL ) {
	    syslog( LOG_ERR, "argcargv_alloc: %m" );
	    snet_writef( snet,
		"%d Requested action aborted: local error in processing.\r\n",
		451 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Requested action aborted: "
		"local error in processing.\r\n",
		451 );
	    return( -1 );
	}

	if (( ac = acav_parse( acav, line, &av )) < 0 ) {
	    syslog( LOG_ERR, "argcargv: %m" );
	    break;
	}

	if ( ac == 0 ) {
	    snet_writef( snet, "%d Command unrecognized\r\n", 501 );
	    if ( simta_debug ) fprintf( stderr,
		">>> %d Command unrecognized\r\n", 501 );
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
	    snet_writef( snet, "%d Command %s unregcognized\r\n", 500, av[ 0 ]);
	    continue;
	}

	if ( (*(commands[ i ].c_func))( snet, env, ac, av ) < 0 ) {
	    break;
	}
	acav_free( acav );
    }

    snet_writef( snet,
	    "%d %s Service not available, closing transmission channel\r\n",
	    421, simta_hostname );
    if ( simta_debug ) fprintf( stderr, 
	">>> %d %s Service not available, closing transmission channel\r\n",
	421, simta_hostname );

    if ( line == NULL ) {
	syslog( LOG_ERR, "snet_getline: %m" );
    }

    if (( env->e_flags & E_READY ) != 0 ) {
	switch ( expand_and_deliver( &hq_receive, env )) {
	    case EXPAND_OK:
		break;

	    /* XXX fix these cases */
	    default:
	    case EXPAND_SYSERROR:
	    case EXPAND_FATAL:
		return( -1 );
	}

	env_reset( env );
    }

    return( 1 );
}
