/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

extern SSL_CTX	*ctx;
#endif /* TLS */

#include <snet.h>

#include "ll.h"
#include "address.h"
#include "receive.h"
#include "envelope.h"
#include "auth.h"
#include "denser.h"
#include "bprint.h"
#include "argcargv.h"
#include "timeval.h"

extern char	*version;
extern int	debug;
struct stab_entry	*expansion = NULL;
struct stab_entry	*seen = NULL;

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
#ifdef TLS
static int	f_starttls ___P(( SNET *, struct envelope *, int, char *[] ));
#endif /* TLS */

static int	hello ___P(( struct envelope *, char * ));

static char	*smtp_trimaddr ___P(( char *, char * ));

int get_mx( DNSR *dnsr, char *host );

    int
get_mx( DNSR *dnsr, char *host )
{
    int			i;

    /* Check for MX of address */
    if (( dnsr_query( dnsr, DNSR_TYPE_MX, DNSR_CLASS_IN, host )) < 0 ) {
	syslog( LOG_ERR, "dnsr_query %s failed", host );
	return( -1 );
    }

    /* Check for vaild result */
    if ( dnsr_result( dnsr, NULL ) != 0 ) {

	/* No - Check for A of address */
	if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN, host )) < 0 ) {
	    syslog( LOG_ERR, "dnsr_query %s failed", host );
	    return( -1 );
	}
	if ( dnsr_result( dnsr, NULL ) != 0 ) {
	    syslog( LOG_ERR, "dnsr_query %s failed", host );
	    return( -1 );
	}

    } else {

	/* Check for valid A record in MX */
	/* XXX - Should we search for A if no A returned in MX? */
	for ( i = 0; i < dnsr->d_result->ancount; i++ ) {
	    if ( dnsr->d_result->answer[ i ].r_ip != NULL ) {
		break;
	    }
	}
	if ( i > dnsr->d_result->ancount ) {
	    syslog( LOG_ERR, "%s: no valid A record for MX", host );
	    return( -1 );
	}
    }

    return( 0 );
}

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
	return( 1 );
    }

    if ( hello( env, av[ 1 ] ) < 0 ) {
	return( -1 );
    }

    snet_writef( snet, "%d %s\r\n", 250, env->e_hostname );
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
    if ( ac != 2 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    if ( hello( env, av[ 1 ] ) < 0 ) {
	return( -1 );
    }

    snet_writef( snet, "%d-%s\r\n", 250, env->e_hostname );

#ifdef TLS
    /* RFC 2487 SMTP TLS */
    /*
     * Note that this must be last, as it has '250 ' instead of
     * '250-' as above.
     */
    if (( env->e_flags & E_TLS ) == 0 ) {
	snet_writef( snet, "%d STARTTLS\r\n", 250 );
    }
#endif /* TLS */

#ifdef notdef
    /*
     * RFC 2554 SMTP SASL
     */
    snet_writef( snet, "%d AUTH", 250 );
    for ( s = sasl; s->s_name; s++ ) {
	snet_writef( snet, " %s", s->s_name );
    }
    snet_writef( snet, "\r\n" );
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

    /*
     * Check if we have a message already ready to send.
     */

    /*
     * Contrary to popular belief, it is not an error to give more than
     * one "MAIL FROM:" command.  According to rfc822, this is just like
     * "RSET".
     */

    if ( ac != 2) {
    	/* XXX handle MAIL FROM:<foo> AUTH=bar */
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    /* RFC 2821 Section 4.1.1.2
     * "MAIL FROM:" ("<>" / Reverse-Path ) CRLF
     */
    if (( addr = smtp_trimaddr( av[ 1 ], "FROM:" )) == NULL ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    if ((( domain = strchr( addr, '@' )) == NULL ) || ( domain == addr )) {
	snet_writef( snet, "%d Requested action not taken\r\n", 553 );
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

	/* XXX - Should this exit? */
	if (( dnsr = dnsr_open( )) == NULL ) {
	    syslog( LOG_ERR, "dnsr_open failed" );
	    snet_writef( snet,
		"%d Requested action aborted: local error in processing.\r\n",
		451 );
	    return( -1 );
	}
	if ( get_mx( dnsr, domain ) != 0 ) {
	    snet_writef( snet,
		"%d Requested action aborted: local error in processing.\r\n",
		451 );
	    return( -1 );
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

    syslog( LOG_INFO, "%s: mail: <%s>", env->e_id, env->e_mail );

    snet_writef( snet, "%d OK\r\n", 250 );
    return( 0 );
}

    int
f_rcpt( snet, env, ac, av )
    SNET			*snet;
    struct envelope		*env;
    int				ac;
    char			*av[];
{
    char		*addr, *domain;
    struct recipient	*r;
    DNSR		*dnsr;
    struct stab_entry	*cur = NULL;

    if ( ac != 2 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    /*
     * Must already have "MAIL FROM:"
     */
    if ( env->e_mail == NULL ) {
	snet_writef( snet, "%d Bad sequence of commands\r\n", 503 );
	return( 1 );
    }

    if (( addr = smtp_trimaddr( av[ 1 ], "TO:" )) == NULL ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    if ( *addr == '@' ) {		/* short-circuit route-addrs */
	if (( addr = strchr( addr, ':' )) == NULL ) {
	    snet_writef( snet, "%d Requested action not taken\r\n", 553 );
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

    /*
     * rfc2821 3.6: The reserved mailbox name "postmaster" may be used in a RCPT
     * command without domain qualification (see section 4.1.1.3) and
     * MUST be accepted if so used.
     */

    if ( strncasecmp( addr, "postmaster", strlen( "postmaster" )) != 0 ) {
	/* DNS check for invalid domain */
	if (( dnsr = dnsr_open( )) == NULL ) {
	    syslog( LOG_ERR, "dnsr_open failed" );
	    snet_writef( snet,
		"%d-1 Requested action aborted: local error in processing.\r\n",
		451 );
	    return( -1 );
	}
	if ( get_mx( dnsr, domain ) != 0 ) {
	    snet_writef( snet,
		"%d-2 Requested action aborted: local error in processing.\r\n",
		451 );
	    return( -1 );
	}
    }

    /*
     * Here we do an initial lookup in our domain table.  This is our
     * best opportunity to decline recipients that are not local or
     * unknown, since if we give an error the connecting client generates
     * the bounce.
     */
    /* XXX check config file, check MXes */

    /* no config file, no DNS, use our hostname */
    if ( strcasecmp( domain, env->e_hostname ) != 0 ) {
	/* XXX Is 551 correct?  550 is for policy */
	snet_writef( snet, "%d User not local; please try <%s>\r\n",
	    551, addr );
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

    switch( address_local( addr )) {
    case 0:
	snet_writef( snet, "%d Requested action not taken: User not found.\r\n",
	    550 );
	return( 1 );
    case 1:
	break;
    default:
	snet_writef( snet,
	    "%d-3 Requested action aborted: local error in processing.\r\n",
	    451 );
	return( 1 );
    }

    if (( r = (struct recipient *)malloc( sizeof(struct recipient)))
	    == NULL ) {
	syslog( LOG_ERR, "f_rcpt: malloc: %m" );
	return( -1 );
    }
    if (( r->r_rcpt = strdup( (char*)cur->st_data )) == NULL ) {
	syslog( LOG_ERR, "f_rcpt: strdup: %m" );
	return( -1 );
    }
    r->r_next = env->e_rcpt;
    env->e_rcpt = r;

    syslog( LOG_INFO, "%s: rcpt: <%s>", env->e_id, env->e_rcpt->r_rcpt );

    snet_writef( snet, "%d OK\r\n", 250 );
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
    struct recipient	*r;
    FILE		*dff, *tff;
    char		df[ 25 ];
    char		tf[ 25 ];
    char		ef[ 25 ];
    char		daytime[ 30 ];

    if ( ac != 1 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    sprintf( df, "tmp/D%s", env->e_id );
    sprintf( tf, "tmp/t%s", env->e_id );
    sprintf( ef, "tmp/E%s", env->e_id );

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
	    inet_ntoa( env->e_sin->sin_addr ), env->e_hostname,
	    env->e_id, daytime, tz( tm )) < 0 ) {
	syslog( LOG_ERR, "f_data: fprintf \"Received\": %m" );
	err = 1;
	fclose( dff );
	snet_writef( snet,
	    "%d Requested action not taken: insufficient system storage\r\n",
	    452 );
	goto cleanup;
    }

    snet_writef( snet, "%d Start mail input; end with <CRLF>.<CRLF>\r\n", 354 );

    /* should implement a byte count to limit DofS attacks */
    /* XXX not to mention a timeout! */
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( *line == '.' ) {
	    if ( strcmp( line, "." ) == 0 ) {
		break;
	    }
	    line++;
	}

	if (( err == 0 ) && ( fprintf( dff, "%s\n", line ) < 0 )) {
	    syslog( LOG_ERR, "f_data: fprintf: %m" );
	    err = 1;
	}
    }
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
	goto cleanup;
    }

    /* make E (t) file */
    if (( fd = open( tf, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	syslog( LOG_ERR, "f_data: open %s: %m", tf );
	return( -1 );
    }
    if (( tff = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "f_data: fdopen: %m" );
	err = -1;
	close( fd );
	goto cleanup2;
    }
    if ( fprintf( tff, "%s\n", env->e_mail ) < 0 ) {
	syslog( LOG_ERR, "f_data: fprintf mail: %m" );
	err = 1;
	fclose( tff );
	snet_writef( snet,
	    "%d Requested action not taken: insufficient system storage\r\n",
	    452 );
	goto cleanup2;
    }
    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( fprintf( tff, "%s\n", r->r_rcpt ) < 0 ) {
	    syslog( LOG_ERR, "f_data: fprintf rcpt: %m" );
	    err = 1;
	    fclose( tff );
	    snet_writef( snet,
	       "%d Requested action not taken: insufficient system storage\r\n",
		452 );
	    goto cleanup2;
	}
    }
    /* sync? */
    if ( fclose( tff ) == EOF ) {
	err = 1;
	snet_writef( snet,
	    "%d Requested action not taken: insufficient system storage\r\n",
	    452 );
	goto cleanup2;
    }

    if ( rename( tf, ef ) < 0 ) {
	syslog( LOG_ERR, "f_data: rename %s %s: %m", tf, ef );
	err = -1;
	goto cleanup2;
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

    syslog( LOG_INFO, "%s: accepted", env->e_id );

    /* mark message as ready to roll */

    return( 0 );

cleanup2:
    if ( unlink( tf ) < 0 ) {
	syslog( LOG_ERR, "f_data unlink %s: %m", tf );
    }
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
    snet_writef( snet, "%d %s Service closing transmission channel\r\n",
	    221, env->e_hostname );

    /* XXX check for an accepted message */

    /*
     * Deliver a pending message without fork()ing.
     */
    exit( 0 );
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
    snet_writef( snet, "%d OK\r\n", 250 );
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
    return( 0 );
}

#ifdef TLS
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
    if ( env->e_flags & E_TLS ) {
	syslog( LOG_ERR, "f_starttls: called twice" );
	return( -1 );
    }

    if ( ac != 1 ) {
	snet_writef( snet, "%d Syntax error\r\n", 501 );
	return( 1 );
    }

    snet_writef( snet, "%d Ready to start TLS\r\n", 220 );

    /*
     * Begin TLS
     */
    if (( rc = snet_starttls( snet, ctx, 1 )) != 1 ) {
	syslog( LOG_ERR, "f_starttls: snet_starttls: %s",
		ERR_error_string( ERR_get_error(), NULL ) );
	snet_writef( snet, "%d SSL didn't work error! XXX\r\n", 501 );
	return( 1 );
    }
    if (( peer = SSL_get_peer_certificate( snet->sn_ssl ))
	    == NULL ) {
	syslog( LOG_ERR, "no peer certificate" );
	return( -1 );
    }

    syslog( LOG_INFO, "CERT Subject: %s\n", X509_NAME_oneline( X509_get_subject_name( peer ), buf, sizeof( buf )));
    X509_free( peer );

    env_reset( env );
    env->e_flags = E_TLS;

    return( 0 );
}
#endif /* TLS */

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
#ifdef TLS
    { "STARTTLS",	f_starttls },
#endif /* TLS */
};
int		ncommands = sizeof( commands ) / sizeof( commands[ 0 ] );

    int
receive( fd, sin )
    int			fd;
    struct sockaddr_in	*sin;
{
    SNET				*snet;
    struct envelope			*env;
    int					ac, i;
    char				**av, *line;
    struct timeval			tv;
    DNSR				*dnsr;
    extern int				denser_debug;
    extern int				connections;
    extern int				maxconnections;

    denser_debug = 0;

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_attach: %m" );
	/* We *could* use write(2) to report an error before we exit here */
	exit( 1 );
    }

    if ( maxconnections != 0 ) {
	if ( connections > maxconnections ) {
	    syslog( LOG_INFO, "connections refused: server busy" );
	    snet_writef( snet,
		"%d Service busy, closing transmission channel\r\n", 421 );
	    exit( 1 );
	}
    }

    if (( dnsr = dnsr_open( )) == NULL ) {
	syslog( LOG_ERR, "dnsr_open failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	exit( 1 );
    }

    /* Get PTR for connection */
    if (( dnsr_query( dnsr, DNSR_TYPE_PTR, DNSR_CLASS_IN,
	    inet_ntoa( sin->sin_addr ))) < 0 ) {
	syslog( LOG_ERR, "dnsr_query failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	exit( 1 );
    }
    if ( dnsr_result( dnsr, NULL ) != 0 ) {
	syslog( LOG_ERR, "dnsr_result failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	exit( 1 );
    }

    /* Get A record on PTR result */
    if (( dnsr_query( dnsr, DNSR_TYPE_A, DNSR_CLASS_IN,
	    dnsr->d_result->answer[ 0 ].r_dn.dn )) < 0 ) {
	syslog( LOG_ERR, "dnsr_query failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	exit( 1 );
    }
    if ( dnsr_result( dnsr, NULL ) != 0 ) {
	syslog( LOG_ERR, "dnsr_result failed" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	exit( 1 );
    }


    /* Verify A record matches IP */
    {
	/* XXX - how should this be checked? */

	struct in_addr      addr;

	memcpy( &addr.s_addr, &dnsr->d_result->answer[ 0 ].r_a, sizeof( int ));

	if ( strcmp( inet_ntoa( addr ), inet_ntoa( sin->sin_addr )) != 0 ) {
	    syslog( LOG_INFO, "%s: connection rejected: invalid A record",
		inet_ntoa( sin->sin_addr ));
	    snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );

	    exit( 1 );
	}
    }

    /* Check bad guy list */

    if (( env = env_create( NULL )) == NULL ) {
	syslog( LOG_ERR, "env_create: %m" );
	snet_writef( snet,
		"%d Service not available, closing transmission channel\r\n",
		421 );
	exit( 1 );
    }
    env->e_sin = sin;

    snet_writef( snet, "%d %s Simple Internet Message Transfer Agent ready\r\n",
	    220, env->e_hostname );

    tv.tv_sec = 60 * 10;	/* 10 minutes, should get this from config */
    tv.tv_usec = 0;
    while (( line = snet_getline( snet, &tv )) != NULL ) {
	tv.tv_sec = 60 * 10;
	tv.tv_usec = 0;

	/*
	 * This routine needs to be revised to take rfc822 quoting into
	 * account.  E.g.  MAIL FROM:<"foo \: bar"@umich.edu>
	 */
	if (( ac = argcargv( line, &av )) < 0 ) {
	    syslog( LOG_ERR, "argcargv: %m" );
	    break;
	}

	if ( ac == 0 ) {
	    snet_writef( snet, "%d Command unrecognized\r\n", 501 );
	    continue;
	}

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
    }

    snet_writef( snet,
	    "%d %s Service not available, closing transmission channel\r\n",
	    421, env->e_hostname );

    if ( line == NULL ) {
	syslog( LOG_ERR, "snet_getline: %m" );
    }

    /* XXX check for an accepted message */

    exit( 1 );

}
