/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <denser.h>
#include <snet.h>
#include <yasl.h>

#ifdef HAVE_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif /* HAVE_JEMALLOC */

#ifdef HAVE_LDAP
#include <ldap.h>
#endif /* HAVE_LDAP */

#ifdef HAVE_LIBIDN
#include <idna.h>
#endif /* HAVE_LIBIDN */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif /* HAVE_LIBSSL */

#include "ll.h"
#include "expand.h"
#include "red.h"
#include "envelope.h"
#include "simta.h"
#include "argcargv.h"
#include "dns.h"
#include "simta_ldap.h"
#include "queue.h"
#include "ml.h"

static int simta_config_bool( const char *, int *, int, char **, const char *,
	int );
static int simta_config_int( const char *, int *, int, int, char **,
	const char *, int );
static int simta_read_publicsuffix( void );


/* global variables */
#if defined(HAVE_JEMALLOC) || defined(__FreeBSD__)
const char		*malloc_conf = "xmalloc:true";
#endif /* HAVE_JEMALLOC */

struct dll_entry	*simta_sender_list = NULL;
struct dll_entry	*simta_env_list = NULL;
struct timeval		simta_tv_now = { 0, 0 };
struct timeval		simta_log_tv;
struct envelope		*simta_env_queue = NULL;
struct host_q		*simta_host_q = NULL;
struct host_q		*simta_deliver_q = NULL;
struct host_q		*simta_unexpanded_q = NULL;
struct host_q		*simta_punt_q = NULL;
struct simta_red	*simta_red_host_default = NULL;
struct simta_red	*simta_red_hosts = NULL;
struct action		*simta_red_action_secondary_mx = NULL;
struct proc_type	*simta_proc_stab = NULL;
int			simta_bounce_seconds = 259200;
int			simta_jail_seconds = 14400;
int			simta_ipv4 = -1;
int			simta_ipv6 = 0;
int			simta_proxy = 0;
int			simta_proxy_timeout = 10;
int			simta_submission_mode = SUBMISSION_MODE_MTA;
int			simta_policy_tls = TLS_POLICY_DEFAULT;
int			simta_policy_tls_cert = TLS_POLICY_DEFAULT;
int			simta_wait_max = 80 * 60;
int			simta_wait_min = 5 * 60;
int			simta_bounce_jail = 0;
int			simta_local_jail = 0;
int			simta_sender_list_enable = 0;
int			simta_mid_list_enable = 0;
int			simta_command_read_entries = 10;
int			simta_disk_read_entries = 10;
int			simta_domain_trailing_dot = 1;
int			simta_bitbucket = -1;
int			simta_aggressive_delivery = 1;
int			simta_aggressive_expansion = 1;
int			simta_aggressive_receipt_max = 50;
int			simta_queue_policy = QUEUE_POLICY_FIFO;
int			simta_rqueue_policy = RQUEUE_POLICY_FAST;
int			simta_leaky_queue = 0;
int			simta_listen_backlog = 64;
int			simta_disk_cycle = 0;
int			simta_global_connections_max = SIMTA_MAXCONNECTIONS;
int			simta_global_connections = 0;
int			simta_global_throttle_max = 0;
int			simta_global_throttle_connections = 0;
int			simta_global_throttle_sec = 1;
struct timeval		simta_global_throttle_tv = { 0, 0 };
int			simta_local_throttle_max = 0;
int			simta_local_throttle_sec = 1;
int			simta_local_connections_max = 0;
int			simta_launch_limit = 10;
int			simta_min_work_time = 60;
int			simta_unexpanded_time = 60;
int			simta_q_runner_local_max = 25;
int			simta_q_runner_local = 0;
int			simta_q_runner_slow_max = 250;
int			simta_q_runner_slow = 0;
int			simta_q_runner_receive_max = 0;
int			simta_exp_level_max = 5;
int			simta_process_type = 0;
int			simta_filesystem_cleanup = 0;
int			simta_smtp_extension = 0;
int			simta_smtp_rcvbuf_min = 0;
int			simta_smtp_rcvbuf_max;
int			simta_strict_smtp_syntax = 0;
int			simta_dns_auto_config = 0;
int			simta_sync = 0;
int			simta_max_received_headers = 100;
int			simta_max_bounce_size = 524288;
int			simta_banner_delay = 0;
int			simta_banner_punishment = 0;
int			simta_max_failed_rcpts = 0;
int			simta_ignore_reverse = 0;
int			simta_ignore_connect_in_reverse_errors = 0;
int			simta_message_count = 0;
int			simta_smtp_outbound_attempts = 0;
int			simta_smtp_outbound_delivered = 0;
int			simta_fast_files = 0;
int			simta_smtp_punishment_mode = SMTP_MODE_TEMPFAIL;
int			simta_smtp_default_mode = SMTP_MODE_NORMAL;
int			simta_from_checking = 1;
int			simta_smtp_tarpit_default = 120;
int			simta_smtp_tarpit_connect = 0;
int			simta_smtp_tarpit_mail = 0;
int			simta_smtp_tarpit_rcpt = 0;
int			simta_smtp_tarpit_data = 0;
int			simta_smtp_tarpit_data_eof = 0;
int			simta_debug = 1;
int			simta_verbose = 0;
int			simta_child_signal = 0;
#ifdef HAVE_LIBSSL
int			simta_tls = 0;
#endif /* HAVE_LIBSSL */
int			simta_sasl = SIMTA_SASL_OFF;
char			*simta_port_smtp = "25";
char			*simta_port_submission = "587";
int			simta_service_smtp = 1;
int			simta_service_submission = 0;
#ifdef HAVE_LIBSSL
char			*simta_port_smtps = "465";
int			simta_service_smtps = 0;
const EVP_MD		*simta_checksum_md = NULL;
char			*simta_checksum_algorithm;
int			simta_checksum_body = 1;
#endif /* HAVE_LIBSSL */
int			simta_max_message_size = -1;
int                     simta_outbound_connection_msg_max = 0;
char			*simta_mail_filter = NULL;
int			simta_filter_trusted = 1;
int			simta_spf = SPF_POLICY_ON;
int			simta_dmarc = DMARC_POLICY_ON;
int			simta_auth_results = 1;
char			*simta_data_url = NULL;
char			*simta_reverse_url = NULL;
char			*simta_libwrap_url = NULL;
yastr			simta_punt_host = NULL;
yastr			simta_jail_host = NULL;
char			*simta_jail_bounce_address = NULL;
yastr			simta_postmaster = NULL;
yastr			simta_domain = NULL;
char			simta_subaddr_separator = '\0';
struct rbl	     	*simta_rbls = NULL;
struct rbl     		*simta_user_rbls = NULL;
int			simta_authz_default = RBL_ACCEPT;
struct rbl		*simta_auth_rbls = NULL;
char			*simta_queue_filter = NULL;
char			*simta_dir_dead = NULL;
char			*simta_dir_local = NULL;
char			*simta_dir_slow = NULL;
char			*simta_dir_fast = NULL;
char			*simta_dir_command = NULL;
char			*simta_base_dir = SIMTA_BASE_DIR;
char                    *simta_file_pid = SIMTA_FILE_PID;
yastr			simta_hostname;
char			simta_log_id[ SIMTA_LOG_ID_LEN + 1 ] = "\0";
DNSR			*simta_dnsr = NULL;
char			*simta_default_alias_db = SIMTA_ALIAS_DB;
char			*simta_default_alias_file = "/etc/aliases";
char			*simta_default_passwd_file = "/etc/passwd";
#ifdef HAVE_LIBSSL
char			*simta_tls_ciphers = NULL;
char			*simta_tls_ciphers_outbound = NULL;
char			*simta_file_ca = NULL;
char			*simta_dir_ca = NULL;
char			*simta_file_cert = "cert/cert.pem";
char			*simta_file_private_key = "cert/cert.pem";
#endif /* HAVE_LIBSSL */
char			**simta_deliver_default_argv;
int			simta_deliver_default_argc;
yastr			simta_seen_before_domain = NULL;
struct dll_entry	*simta_publicsuffix_list = NULL;
char			*simta_file_publicsuffix = NULL;

/* SMTP RECEIVE & DELIVER TIMERS */
int			simta_inbound_accepted_message_timer = -1;
int			simta_inbound_global_session_timer = 0;
int			simta_inbound_command_inactivity_timer = 3600;
int			simta_inbound_command_line_timer = 600;
int			simta_inbound_data_line_timer = 300;
int			simta_inbound_data_session_timer = 3600;
#ifdef HAVE_LIBSSL
int			simta_inbound_ssl_accept_timer = 300;
#endif /* HAVE_LIBSSL */
int			simta_outbound_command_line_timer = 300;
int			simta_outbound_data_line_timer = 300;
int			simta_outbound_data_session_timer = 0;
#ifdef HAVE_LIBSSL
int			simta_outbound_ssl_connect_timer = 300;
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBOPENDKIM
int			simta_dkim_verify = 1;
int			simta_dkim_sign = DKIMSIGN_POLICY_OFF;
char			*simta_dkim_key = NULL;
char			*simta_dkim_selector = "simta";
yastr			simta_dkim_domain = NULL;
#endif /* HAVE_LIBOPENDKIM */

int			simta_srs = SRS_POLICY_OFF;
int			simta_srs_maxage = 10;
yastr			simta_srs_domain = NULL;
char			*simta_srs_secret = NULL;

    void
panic( const char *message )
{
    syslog( LOG_CRIT, "%s", message );
    abort();
}


    int
simta_gettimeofday( struct timeval *tv )
{
    struct timeval		tv_now;

    if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: simta_gettimeofday gettimeofday: %m" );
	return( 1 );
    }

    /* did gettimeofday() return a unique timestamp not in the past? */
    if (( tv_now.tv_sec < simta_tv_now.tv_sec ) ||
	    (( tv_now.tv_sec == simta_tv_now.tv_sec ) &&
	    ( tv_now.tv_usec <= simta_tv_now.tv_usec ))) {
	tv_now.tv_usec = simta_tv_now.tv_usec + 1;
	if ( tv_now.tv_usec <= simta_tv_now.tv_usec ) {
	    tv_now.tv_usec = 0;
	    tv_now.tv_sec = simta_tv_now.tv_sec + 1;
	} else {
	    tv_now.tv_sec = simta_tv_now.tv_sec;
	}
    }

    simta_tv_now.tv_usec = tv_now.tv_usec;
    simta_tv_now.tv_sec = tv_now.tv_sec;

    if ( tv != NULL ) {
	tv->tv_usec = tv_now.tv_usec;
	tv->tv_sec = tv_now.tv_sec;
    }

    return( 0 );
}

    void
simta_openlog( int cl, int options )
{
    if ( cl ) {
	closelog();
    }

    simta_log_tv = simta_tv_now;

    snprintf( simta_log_id, SIMTA_LOG_ID_LEN, "%s[%d.%ld]",
	    simta_progname, getpid( ), simta_log_tv.tv_sec );

    /* openlog now, as some support functions require it. */
    openlog( simta_log_id, LOG_NOWAIT | options, LOG_SIMTA );

    return;
}


    void
simta_debuglog( int level, const char *format, ... )
{
    va_list	vl;

    va_start( vl, format );
    if ( simta_debug >= level ) {
	vsyslog( LOG_DEBUG, format, vl );
    }
    va_end( vl );
}


    char *
simta_sender( void )
{
    static char			*sender = NULL;
    struct passwd		*pw;

    if ( sender == NULL ) {
	if (( pw = getpwuid( getuid())) == NULL ) {
	    perror( "getpwuid" );
	    return( NULL );
	}

	sender = malloc( strlen( pw->pw_name ) + yasllen( simta_domain ) + 2 );
	sprintf( sender, "%s@%s", pw->pw_name, simta_domain );
    }

    return( sender );
}


/* XXX - need to add support for:
 * include files/dirs
 *   in dirs, only read .conf files, have depth limit and exit on duplicate
 * virtual users - user@wcbn.org -> wcbn.user@domain
 */
    int
simta_read_config( const char *fname )
{
    int			red_code;
    int			lineno = 0;
    int			fd;
    int			ac;
    int			rc;
    int			x;
    yastr		buf;
    char		hostname[ DNSR_MAX_HOSTNAME + 1 ];
    char		*f_arg;
    char		*endptr;
    char		*line;
    char		*c;
    ACAV		*acav;
    char		**av;
    SNET		*snet;
    char		*domain;
    struct simta_red	*red;
    struct action	*a;
    struct simta_ldap	*ld;

    simta_debuglog( 2, "simta_config: %s", fname );

    /* Set up simta_hostname */
    if ( gethostname( hostname, DNSR_MAX_HOSTNAME ) != 0 ) {
	perror( "gethostname" );
	return( -1 );
    }
    simta_hostname = yaslauto( hostname );

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	if ( errno == ENOENT )  {
	    errno = 0;
	    simta_debuglog( 1, "simta config file %s not found", fname );
	    return( 1 );
	}
	perror( fname );
	return( -1 );
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	perror( "simta_read_config: snet_attach" );
	close( fd );
	return( -1 );
    }

    acav = acav_alloc( );

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	lineno++;

	while (( line[ 0 ] == ' ' ) || ( line[ 0 ] == '\t' )) {
	    /* Leading whitespace */
	    line++;
	}

	if (( line[ 0 ] == '\0' ) || ( line[ 0 ] == '#' )) {
	    /* blank line or comment */
	    continue;
	}

	if (( ac = acav_parse( acav, line, &av )) < 0 ) {
	    perror( "simta_read_config: acav_parse:" );
	    goto error;
	}

	if ( ac == 0 ) {
	    /* Not sure if this can happen, but if it does we would segfault.
	     * That's bad. */
	    fprintf( stderr,
		    "%s: line %d: not blank but parsing returned nothing\n",
		    fname, lineno );
	    goto error;
	}

	/* @hostname RED OPTION */
	if ( *av[ 0 ] == '@' ) {

	    domain = av[ 0 ] + 1;
	    if ( strlen( domain ) > DNSR_MAX_HOSTNAME ) {
		printf( "len: %zu\n", strlen( domain ));
		fprintf( stderr, "%s: line %d: domain name too long\n",
			fname, lineno );
		goto error;
	    }
	    /* XXX - need to lower-case domain */

	    if ( ac <= 2 ) {
		fprintf( stderr,
			"%s: line %d: expected 1 or more arguments\n",
			fname, lineno );
		goto error;
	    }

	    /* RED code parse */
	    red_code = 0;
	    for ( c = av[ 1 ]; *c != '\0'; c++ ) {
		switch ( *c ) {
		case 'R':
		    if ( red_code & RED_CODE_r ) {
			fprintf( stderr, "%s: line %d: R and r illegal\n",
				fname, lineno );
			goto error;
		    }
		    red_code |= RED_CODE_R;
		    break;

		case 'r':
		    if ( red_code & RED_CODE_R ) {
			fprintf( stderr, "%s: line %d: R and r illegal\n",
				fname, lineno );
			goto error;
		    }
		    red_code |= RED_CODE_r;
		    break;

		case 'E':
		    red_code |= RED_CODE_E;
		    break;

		case 'D':
		    red_code |= RED_CODE_D;
		    break;

		default:
		    fprintf( stderr, "%s: line %d: bad RED arg: %s\n",
			    fname, lineno, av[ 1 ]);
		    goto error;
		}
	    }

	    if ( strcasecmp( domain, "LOCALHOST" ) == 0 ) {
		domain = simta_hostname;
	    }

	    red = red_host_add( domain );

	    if ( strcasecmp( av[ 2 ], "ACCEPT" ) == 0 ) {
		/* @DOMAIN R ACCEPT */
		if (( ac != 3 ) || ( red_code != RED_CODE_R )) {
		    fprintf( stderr, "%s: line %d: usage: @domain R ACCEPT\n",
			    fname, lineno );
		    goto error;
		}

		red_action_add( red, RED_CODE_R, EXPANSION_TYPE_GLOBAL_RELAY,
			NULL );

#ifdef HAVE_LMDB
	    } else if ( strcasecmp( av[ 2 ], "ALIAS" ) == 0 ) {
		if ( ac == 3 ) {
		    if ( simta_default_alias_db == NULL ) {
			fprintf( stderr,
				"%s: line %d: no default alias DB set\n",
				fname, lineno );
			goto error;
		    }

		    f_arg = simta_default_alias_db;
		} else if ( ac == 4 ) {
		    f_arg = av[ 3 ];
		} else {
		    fprintf( stderr, "%s: line %d: usage: "
			    "@domain RE ALIAS [database file]\n",
			    fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    red_action_add( red, RED_CODE_r, EXPANSION_TYPE_ALIAS,
			    f_arg );
		} else if ( red_code & RED_CODE_R ) {
		    red_action_add( red, RED_CODE_R, EXPANSION_TYPE_ALIAS,
			    f_arg );
		}

		if ( red_code & RED_CODE_E ) {
		    red_action_add( red, RED_CODE_E, EXPANSION_TYPE_ALIAS,
			    f_arg );
		}
#endif /* HAVE_LMDB */

#ifdef HAVE_LDAP
	    } else if ( strcasecmp( av[ 2 ], "LDAP" ) == 0 ) {
		if ( ac != 4 ) {
		    fprintf( stderr, "%s: line %d: usage: "
			    "@domain RE LDAP <ldap config file>\n",
			    fname, lineno );
		    goto error;
		}
		if (( ld = simta_ldap_config( av[ 3 ], domain )) == NULL ) {
		    fprintf( stderr, "%s: line %d: Using %s to configure LDAP "
			    "failed, please check the logs\n",
			    fname, lineno, av[ 3 ]);
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    a = red_action_add( red, RED_CODE_r, EXPANSION_TYPE_LDAP,
			    NULL );
		    a->a_ldap = ld;
		} else if ( red_code & RED_CODE_R ) {
		    a = red_action_add( red, RED_CODE_R, EXPANSION_TYPE_LDAP,
			    NULL );
		    a->a_ldap = ld;
		}

		if ( red_code & RED_CODE_E ) {
		    a = red_action_add( red, RED_CODE_E, EXPANSION_TYPE_LDAP,
			    NULL );
		    a->a_ldap = ld;
		}
#endif /* HAVE_LDAP */

	    } else if ( strcasecmp( av[ 2 ], "MAILER" ) == 0 ) {
		/* @DOMAIN D MAILER <arg> [...] */
		if (( ac < 4 ) || ( red_code != RED_CODE_D )) {
		    fprintf( stderr, "%s: line %d: usage: "
			    "@domain D MAILER <arg> [arg ...]\n",
			    fname, lineno );
		    goto error;
		}

		if ( red->red_deliver_argc != 0 ) {
		    fprintf( stderr,
			    "%s: line %d: mailer already defined for %s\n",
			    fname, lineno, av[ 0 ]);
		    goto error;
		}

		if ( strcasecmp( av[ 3 ], "DEFAULT" ) != 0 ) {
		    /* store array */
		    red->red_deliver_argc = ac - 3;
		    red->red_deliver_argv = calloc( (size_t)( ac - 2 ),
			    sizeof( char * ));

		    for ( x = 0; x < red->red_deliver_argc; x++ ) {
			red->red_deliver_argv[ x ] = strdup( av[ x + 3 ] );
		    }

		    red->red_deliver_argv[ x ] = NULL;
		}

		red->red_deliver_type = RED_DELIVER_BINARY;

	    } else if ( strcasecmp( av[ 2 ], "PASSWORD" ) == 0 ) {
		if ( ac == 3 ) {
		    f_arg = simta_default_passwd_file;
		} else if ( ac == 4 ) {
		    f_arg = av[ 3 ];
		} else {
		    fprintf( stderr, "%s: line %d: usage: "
			    "@domain RE PASSWORD [passwd file]\n",
			    fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    red_action_add( red, RED_CODE_r, EXPANSION_TYPE_PASSWORD,
			    f_arg );
		} else if ( red_code & RED_CODE_R ) {
		    red_action_add( red, RED_CODE_R, EXPANSION_TYPE_PASSWORD,
			    f_arg );
		}

		if ( red_code & RED_CODE_E ) {
		    red_action_add( red, RED_CODE_E, EXPANSION_TYPE_PASSWORD,
			    f_arg );
		}

	    } else if ( strcasecmp( av[ 2 ], "PUNTING" ) == 0 ) {
		/* @DOMAIN D PUNTING <ENABLED|DISABLED> */
		if (( ac == 4 ) && ( red_code == RED_CODE_D )) {
		    if ( strcasecmp( av[ 3 ], "ENABLED" ) == 0 ) {
			red->red_policy_punting = RED_PUNTING_ENABLED;
			continue;
		    } else if ( strcasecmp( av[ 3 ], "DISABLED" ) == 0 ) {
			red->red_policy_punting = RED_PUNTING_DISABLED;
			continue;
		    }
		}
		fprintf( stderr, "%s: line %d: usage: "
			"@domain D PUNTING <ENABLED|DISABLED>\n",
			fname, lineno );
		goto error;

	    } else if ( strcasecmp( av[ 2 ], "QUEUE_WAIT" ) == 0 ) {
		/* @DOMAIN D QUEUE_WAIT min max */
		if (( ac == 5 ) && ( red_code == RED_CODE_D )) {
		    red->red_wait_set = 1;
		    errno = 0;
		    red->red_wait_min = strtol( av[ 3 ], &endptr, 10 );
		    if (( errno == 0 ) && ( red->red_wait_min > 0 ) &&
			    ( endptr != av[ 3 ] )) {
			red->red_wait_max = strtol( av[ 4 ], &endptr, 10 );
			if (( errno == 0 ) && ( red->red_wait_max > 0 ) &&
				( endptr != av[ 4 ] )) {
			    simta_debuglog( 2, "QUEUE WAITING for %s: %d %d",
				    domain, red->red_wait_min,
				    red->red_wait_max );
			    continue;
			}
		    }
		}

		fprintf( stderr, "%s: line %d: usage: "
			"@domain D QUEUE_WAIT <min> <max>\n",
			fname, lineno );
		goto error;

	    } else if ( strcasecmp( av[ 2 ], "SECONDARY_MX" ) == 0 ) {
		struct action			*a;

		/* @DOMAIN R SECONDARY_MX MX_EXCHANGE */
		if (( ac != 4 ) || ( red_code != RED_CODE_R )) {
		    fprintf( stderr, "%s: line %d: usage: %s\n",
			    fname, lineno,
			    "@domain R SECONDARY_MX <secondary MX name>" );
		    goto error;
		}

		if ( strcasecmp( simta_hostname, domain ) == 0 ) {
		    fprintf( stderr, "%s: line %d: "
			    "secondary MX name can't be local host\n",
			    fname, lineno );
		    goto error;
		}

		a = red_action_add( red, RED_CODE_R,
			EXPANSION_TYPE_GLOBAL_RELAY, av[ 3 ] );

		a->a_next_secondary_mx = simta_red_action_secondary_mx;
		simta_red_action_secondary_mx = a;

	    } else if ( strcasecmp( av[ 2 ], "SRS" ) == 0 ) {
		if ( ac == 3 ) {
		    f_arg = simta_srs_secret;
		} else if ( ac == 4 ) {
		    f_arg = av[ 3 ];
		} else {
		    fprintf( stderr, "%s: line %d: usage: "
			    "@domain RE SRS [secret]\n",
			    fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    red_action_add( red, RED_CODE_r, EXPANSION_TYPE_SRS,
			    f_arg );
		} else if ( red_code & RED_CODE_R ) {
		    red_action_add( red, RED_CODE_R, EXPANSION_TYPE_SRS,
			    f_arg );
		}
		if ( red_code & RED_CODE_E ) {
		    red_action_add( red, RED_CODE_E, EXPANSION_TYPE_SRS,
			    f_arg );
		}

#ifdef HAVE_LIBSSL
	    } else if ( strcasecmp( av[ 2 ], "TLS" ) == 0 ) {
		/* @DOMAIN D TLS <OPTIONAL|REQUIRED|DISABLED> */
		if (( ac == 4 ) && ( red_code == RED_CODE_D )) {
		    if ( strcasecmp( av[ 3 ], "OPTIONAL" ) == 0 ) {
			red->red_policy_tls = TLS_POLICY_OPTIONAL;
			continue;
		    } else if ( strcasecmp( av[ 3 ], "REQUIRED" ) == 0 ) {
			red->red_policy_tls = TLS_POLICY_REQUIRED;
			continue;
		    } else if ( strcasecmp( av[ 3 ], "DISABLED" ) == 0 ) {
			red->red_policy_tls = TLS_POLICY_DISABLED;
			continue;
		    }
		}
		fprintf( stderr, "%s: line %d: usage: %s\n",
			fname, lineno,
			"@domain D TLS <OPTIONAL|REQUIRED|DISABLED>" );
		goto error;

	    } else if ( strcasecmp( av[ 2 ], "TLS_CERT" ) == 0 ) {
		/* @DOMAIN D TLS_CERT <OPTIONAL|REQUIRED> */
		if (( ac == 4 ) && ( red_code == RED_CODE_D )) {
		    if ( strcasecmp( av[ 3 ], "OPTIONAL" ) == 0 ) {
			red->red_policy_tls_cert = TLS_POLICY_OPTIONAL;
			continue;
		    } else if ( strcasecmp( av[ 3 ], "REQUIRED" ) == 0 ) {
			red->red_policy_tls_cert = TLS_POLICY_REQUIRED;
			continue;
		    }
		}
		fprintf( stderr, "%s: line %d: usage: %s\n",
			fname, lineno,
			"@domain D TLS_CERT <OPTIONAL|REQUIRED>" );
		goto error;

	    } else if ( strcasecmp( av[ 2 ], "TLS_CIPHERS" ) == 0 ) {
		if (( ac == 4 ) && ( red_code == RED_CODE_D )) {
		    red->red_tls_ciphers = strdup( av[ 3 ] );
		    continue;
		}
		fprintf( stderr, "%s: line %d: usage: %s\n",
			fname, lineno,
			"@domain D TLS_CIPHERS <cipher string>" );
		goto error;
#endif /* HAVE_LIBSSL */

	    } else {
		fprintf( stderr, "%s: line %d: unknown RED keyword: %s\n",
			fname, lineno, av[ 2 ] );
		goto error;
	    }

	} else if (( rc = simta_config_bool( "AGGRESSIVE_DELIVERY",
		&simta_aggressive_delivery, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "AGGRESSIVE_EXPANSION",
		&simta_aggressive_expansion, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "AGGRESSIVE_RECEIPT",
		    &simta_aggressive_receipt_max, 0, ac, av, fname,
		    lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

#ifdef HAVE_LMDB
	} else if ( strcasecmp( av[ 0 ], "ALIAS_DB" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_default_alias_db = strdup( av[ 1 ] );
	    } else if ( ac == 1 ) {
		simta_default_alias_db = NULL;

	    } else {
		fprintf( stderr, "%s: line %d: usage: "
			"ALIAS_DB [database file]\n",
			fname, lineno );
		goto error;
	    }

	    simta_debuglog( 2, "ALIAS_DB: %s",
		    simta_default_alias_db
		    ? simta_default_alias_db
		    : "Disabled" );

	} else if ( strcasecmp( av[ 0 ], "ALIAS_FILE" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_default_alias_file = strdup( av[ 1 ] );
	    } else {
		fprintf( stderr, "%s: line %d: usage: "
			"ALIAS_FILE <alias file>\n",
			fname, lineno );
		goto error;
	    }
#endif /* HAVE_LMDB */

	} else if ( strcasecmp( av[ 0 ], "AUTHN" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		    simta_sasl = SIMTA_SASL_OFF;
		    simta_debuglog( 2, "AUTHN OFF" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "HONEYPOT" ) == 0 ) {
		    simta_sasl = SIMTA_SASL_HONEYPOT;
		    simta_debuglog( 2, "AUTHN HONEYPOT" );
		    continue;
#ifdef HAVE_LIBSASL
		} else if ( strcasecmp( av[ 1 ], "SASL" ) == 0 ) {
		    simta_sasl = SIMTA_SASL_ON;
		    simta_debuglog( 2, "AUTHN SASL" );
		    continue;
#endif /* HAVE_LIBSASL */
		}
	    }

	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno, "AUTHN <ON|OFF|HONEYPOT>" );
	    goto error;

	} else if (( rc = simta_config_bool( "AUTHN_RESULTS",
		&simta_auth_results, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

#ifdef HAVE_LIBSASL
	} else if ( strcasecmp( av[ 0 ], "AUTHZ_DEFAULT" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "ALLOW" ) == 0 ) {
		    simta_authz_default = RBL_ACCEPT;
		    simta_debuglog( 2, "AUTHZ_DEFAULT ALLOW" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "DENY" ) == 0 ) {
		    simta_authz_default = RBL_BLOCK;
		    simta_debuglog( 2, "AUTHZ_DEFAULT DENY" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "AUTHZ_DEFAULT <ALLOW|DENY>" );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "AUTHZ_DNS" ) == 0 ) {
	    if ( ac == 3 ) {
		if ( strcasecmp( av[ 1 ], "ALLOW" ) == 0 ) {
		    rbl_add( &simta_auth_rbls, RBL_ACCEPT, av[ 2 ], "" );
		    simta_debuglog( 2, "AUTHZ_DNS ALLOW: %s", av[ 2 ] );
		    continue;
		}
		else if ( strcasecmp( av[ 1 ], "DENY" ) == 0 ) {
		    rbl_add( &simta_auth_rbls, RBL_BLOCK, av[ 2 ], "" );
		    simta_debuglog( 2, "AUTHZ_DNS DENY: %s", av[ 2 ] );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: "
		    "AUTHZ_DNS <ALLOW|DENY> <dns zone>\n",
		    fname, lineno );
	    goto error;

#endif /* HAVE_LIBSASL */

	} else if (( rc = simta_config_int( "BANNER_DELAY",
		&simta_banner_delay, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_bool( "BANNER_PUNISH_WRITES",
		&simta_banner_punishment, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "BASE_DIR" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strlen( av[ 1 ]  ) > MAXPATHLEN ) {
		    fprintf( stderr,
			    "%s: line %d: path too long\n", fname, lineno );
		    goto error;
		}
		simta_base_dir = strdup( av[ 1 ] );
		simta_debuglog( 2, "BASE_DIR: %s", simta_base_dir );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: BASE_DIR <base directory>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_int( "BITBUCKET", &simta_bitbucket, 1,
		ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "BOUNCE_SIZE",
		&simta_max_bounce_size, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "BOUNCE_SECONDS",
		&simta_bounce_seconds, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

#ifdef HAVE_LIBSSL
	} else if ( strcasecmp( av[ 0 ], "CHECKSUM_ALGORITHM" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"CHECKSUM_ALGORITHM <algorithm>\n",
			fname, lineno );
		goto error;
	    }

	    /* OpenSSL 1.1.0 added auto-init */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	    OpenSSL_add_all_digests();
#endif /* OpenSSL < 1.1.0 */
	    simta_checksum_md = EVP_get_digestbyname( (const char*)(av[ 1 ]));
	    if ( simta_checksum_md == NULL ) {
		fprintf( stderr, "%s: line %d: Unknown message digest: %s\n",
			fname, lineno, av[ 1 ]);
		goto error;
	    }

	    simta_checksum_algorithm = strdup( av[ 1 ] );
	    simta_debuglog( 2, "CHECKSUM_ALGORITHM %s",
		    simta_checksum_algorithm );

	} else if (( rc = simta_config_bool( "CHECKSUM_BODY",
		&simta_checksum_body, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }
#endif /* HAVE_LIBSSL */

	} else if (( rc = simta_config_int( "COMMAND_READ_LIMIT",
		&simta_command_read_entries, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "CONNECTION_LIMIT",
		&simta_global_connections_max, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }


	} else if (( rc = simta_config_int( "CONNECTION_LIMIT_PER_HOST",
		&simta_local_connections_max, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "CONNECTION_THROTTLE",
		&simta_global_throttle_max, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "CONNECTION_THROTTLE_INTERVAL",
		&simta_global_throttle_sec, 1, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }
	    simta_local_throttle_sec = simta_global_throttle_sec;

	} else if (( rc = simta_config_int( "CONNECTION_THROTTLE_PER_HOST",
		&simta_local_throttle_max, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "CONTENT_FILTER" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_mail_filter = strdup( av[ 1 ] );
		simta_debuglog( 2, "CONTENT_FILTER: %s", simta_mail_filter );
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: "
		    "CONTENT_FILTER <filter path>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "CONTENT_FILTER_URL" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"CONTENT_FILTER_URL <url>\n",
			fname, lineno );
		goto error;
	    }
	    simta_data_url = strdup( av[ 1 ] );
	    simta_debuglog( 2, "CONTENT_FILTER_URL: %s", simta_data_url );

	} else if ( strcasecmp( av[ 0 ], "DEBUG_LOGGING" ) == 0 ) {
	    if ( ac == 1 ) {
		simta_debug++;
		simta_debuglog( 2, "DEBUG_LOGGING: %d", simta_debug );
		continue;
	    } else if ( ac == 2 ) {
		errno = 0;
		simta_debug = strtol( av[ 1 ], &endptr, 10 );
		if (( errno == 0 ) && simta_debug >= 0 &&
			( endptr != av[ 1 ] )) {
		    simta_debuglog( 2, "DEBUG_LOGGING: %d", simta_debug );
		    continue;
		}
	    }

	    fprintf( stderr, "%s: line %d: usage: DEBUG_LOGGING [n]\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "DEFAULT_LOCAL_MAILER" ) == 0 ) {
	    if ( ac < 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"DEFAULT_LOCAL_MAILER <arg> [arg ...]\n",
			fname, lineno );
		goto error;
	    }

	    /* store array */
	    simta_deliver_default_argc = ac - 1;
	    simta_deliver_default_argv = calloc( (size_t)ac, sizeof( char * ));

	    for ( x = 0; x < simta_deliver_default_argc; x++ ) {
		simta_deliver_default_argv[ x ] = strdup( av[ x + 1 ] );
	    }

	    simta_deliver_default_argv[ x ] = NULL;

	    if ( simta_debug > 1 ) {
		buf = yasljoin( simta_deliver_default_argv,
			simta_deliver_default_argc, " ", 1 );
		simta_debuglog( 2, "DEFAULT_LOCAL_MAILER: %s", buf );
		yaslfree( buf );
	    }

	} else if (( rc = simta_config_int( "DELIVER_COMMAND_LINE_TIMEOUT",
		&simta_outbound_command_line_timer, 1, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "DELIVER_DATA_LINE_TIMEOUT",
		&simta_outbound_data_line_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "DELIVER_DATA_SESSION_TIMEOUT",
		&simta_outbound_data_session_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "DELIVER_MESSAGES_PER_CONNECTION",
		&simta_outbound_connection_msg_max, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "DELIVER_QUEUE_STRATEGY" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "FIFO" ) == 0 ) {
		    simta_queue_policy = QUEUE_POLICY_FIFO;
		    simta_debuglog( 2, "DELIVER_QUEUE_STRATEGY FIFO" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "SHUFFLE" ) == 0 ) {
		    simta_queue_policy = QUEUE_POLICY_SHUFFLE;
		    simta_debuglog( 2, "DELIVER_QUEUE_STRATEGY SHUFFLE" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: "
		    "DELIVER_QUEUE_STRATEGY <FIFO|SHUFFLE>\n",
		    fname, lineno );
	    goto error;

#ifdef HAVE_LIBSSL
	} else if ( strcasecmp( av[ 0 ], "DELIVER_TLS" ) == 0 ) {
	    /* DELIVER_TLS <OPTIONAL|REQUIRED|DISABLED> */
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "OPTIONAL" ) == 0 ) {
		    simta_policy_tls = TLS_POLICY_OPTIONAL;
		    simta_debuglog( 2, "DELIVER_TLS OPTIONAL" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "REQUIRED" ) == 0 ) {
		    simta_policy_tls = TLS_POLICY_REQUIRED;
		    simta_debuglog( 2, "DELIVER_TLS REQUIRED" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "DISABLED" ) == 0 ) {
		    simta_policy_tls = TLS_POLICY_DISABLED;
		    simta_debuglog( 2, "DELIVER_TLS DISABLED" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "DELIVER_TLS <OPTIONAL|REQUIRED|DISABLED>" );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "DELIVER_TLS_CERT" ) == 0 ) {
	    /* DELIVER_TLS_CERT <OPTIONAL|REQUIRED> */
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "OPTIONAL" ) == 0 ) {
		    simta_policy_tls_cert = TLS_POLICY_OPTIONAL;
		    simta_debuglog( 2, "DELIVER_TLS_CERT OPTIONAL" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "REQUIRED" ) == 0 ) {
		    simta_policy_tls_cert= TLS_POLICY_REQUIRED;
		    simta_debuglog( 2, "DELIVER_TLS_CERT REQUIRED" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "DELIVER_TLS_CERT <OPTIONAL|REQUIRED>" );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "DELIVER_TLS_CIPHERS" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_tls_ciphers_outbound = strdup( av[ 1 ] );
		simta_debuglog( 2, "DELIVER_TLS_CIPHERS: %s",
			simta_tls_ciphers_outbound );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "DELIVER_TLS_CIPHERS <cipher string>" );
	    goto error;

	} else if (( rc = simta_config_int( "DELIVER_TLS_CONNECT_TIMEOUT",
		&simta_outbound_ssl_connect_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }
#endif /* HAVE_LIBSSL */

	} else if (( rc = simta_config_int( "DISK_READ_INTERVAL",
		&simta_min_work_time, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "DISK_READ_LIMIT",
		&simta_disk_read_entries, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

#ifdef HAVE_LIBOPENDKIM
	} else if ( strcasecmp( av[ 0 ], "DKIM_DOMAIN" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_dkim_domain = yaslauto( av[ 1 ] );
		yasltolower( simta_dkim_domain );
		simta_debuglog( 2, "DKIM_DOMAIN: %s", simta_dkim_domain );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: DKIM_DOMAIN <domain>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "DKIM_KEY" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_dkim_key = strdup( av[ 1 ] );
		simta_debuglog( 2, "DKIM_KEY: %s", simta_dkim_key );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: DKIM_KEY <path>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "DKIM_SIGN" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		    simta_dkim_sign = DKIMSIGN_POLICY_OFF;
		    simta_debuglog( 2, "DKIM_SIGN OFF" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "ALWAYS" ) == 0 ) {
		    simta_dkim_sign = DKIMSIGN_POLICY_ALWAYS;
		    simta_debuglog( 2, "DKIM_SIGN ALWAYS" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "LOCAL" ) == 0 ) {
		    simta_dkim_sign = DKIMSIGN_POLICY_LOCAL;
		    simta_debuglog( 2, "DKIM_SIGN LOCAL" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "BOUNCES" ) == 0 ) {
		     simta_dkim_sign = DKIMSIGN_POLICY_BOUNCES;
		     simta_debuglog( 2, "DKIM_SIGN BOUNCES" );
		     continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: "
		    "DKIM_SIGN <OFF|ALWAYS|LOCAL|BOUNCES>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "DKIM_SELECTOR" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_dkim_selector = strdup( av[ 1 ] );
		simta_debuglog( 2, "DKIM_SELECTOR: %s", simta_dkim_selector );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: DKIM_SELECTOR <selector>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_bool( "DKIM_VERIFY", &simta_dkim_verify,
		ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }
#endif /* HAVE_LIBOPENDKIM */

	} else if ( strcasecmp( av[ 0 ], "DMARC" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "ON" ) == 0 ) {
		    simta_dmarc = DMARC_POLICY_ON;
		    simta_debuglog( 2, "DMARC ON" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		    simta_dmarc = DMARC_POLICY_OFF;
		    simta_debuglog( 2, "DMARC OFF" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "STRICT" ) == 0 ) {
		    simta_dmarc = DMARC_POLICY_STRICT;
		    simta_debuglog( 2, "DMARC STRICT" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "DMARC <ON|OFF|STRICT>" );
	    goto error;

	} else if (( rc = simta_config_bool( "DNS_AUTO_CONFIG",
		&simta_dns_auto_config, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "SENDER_LIST",
		&simta_sender_list_enable, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "EXPAND_INTERVAL",
		&simta_unexpanded_time, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "FILTER_TRUSTED",
		&simta_filter_trusted, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "IPV4", &simta_ipv4, ac, av,
		fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "IPV6", &simta_ipv6, ac, av,
		fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "JAIL" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		    fprintf( stderr, "%s: line %d: domain name too long\n",
			    fname, lineno );
		    goto error;
		}
		simta_jail_host = yaslauto( av[ 1 ] );
		yasltolower( simta_jail_host );
		simta_debuglog( 2, "JAIL: %s", simta_jail_host );
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: JAIL <hostname>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "JAIL_BOUNCE_ADDRESS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( ac == 2 ) {
		simta_jail_bounce_address = strdup( av[ 1 ] );
		simta_debuglog( 2, "JAIL_BOUNCE_ADDRESS: %s",
			simta_jail_bounce_address );
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: "
		    "JAIL_BOUNCE_ADDRESS <address>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_bool( "JAIL_BOUNCES",
		&simta_bounce_jail, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "JAIL_CLEANUP_INTERVAL",
		&simta_jail_seconds, 1, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "JAIL_LOCAL", &simta_bounce_jail,
		ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "LIBWRAP_URL" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: LIBWRAP_URL <url>\n",
			fname, lineno );
		goto error;
	    }
	    simta_libwrap_url = strdup( av[ 1 ] );
	    simta_debuglog( 2, "LIBWRAP_URL: %s", simta_libwrap_url );

	} else if ( strcasecmp( av[ 0 ], "MASQUERADE" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		    fprintf( stderr, "%s: line %d: domain name too long\n",
			    fname, lineno );
		    goto error;
		}
		simta_domain = yaslauto( av[ 1 ] );
		yasltolower( simta_domain );
		simta_debuglog( 2, "MASQUERADE: %s", simta_domain );
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: MASQUERADE <hostname>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_int( "MAX_FAILED_RCPTS",
		&simta_max_failed_rcpts, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "MAX_MESSAGE_SIZE",
		&simta_max_message_size, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "MAX_Q_RUNNERS_LOCAL",
		&simta_q_runner_local_max, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "MAX_Q_RUNNERS_RECEIVE",
		&simta_q_runner_receive_max, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "MAX_Q_RUNNERS_SLOW",
		&simta_q_runner_slow_max, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "MAX_Q_RUNNERS_LAUNCH",
		&simta_launch_limit, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "MAX_RECEIVED_HEADERS",
		&simta_max_received_headers, 1, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "MID_LIST",
		&simta_mid_list_enable, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

        } else if ( strcasecmp( av[ 0 ], "PID_FILE" ) == 0 ) {
            if ( ac == 2 ) {
		if ( strlen( av[ 1 ]  ) > MAXPATHLEN ) {
		    fprintf( stderr,
			    "%s: line %d: path too long\n", fname, lineno );
		    goto error;
		}
		simta_file_pid = strdup( av[ 1 ] );
		simta_debuglog( 2, "PID_FILE: %s", simta_file_pid );
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: PID_FILE <path>\n", fname,
		    lineno );
	    goto error;

        } else if (( rc = simta_config_bool( "PROXY",
                &simta_proxy, ac, av, fname, lineno )) != 0 ) {
            if ( rc < 0 ) {
                goto error;
            }

	} else if (( rc = simta_config_int( "PROXY_TIMEOUT",
		&simta_proxy_timeout, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "PUBLICSUFFIX_FILE" ) == 0 ) {
	    if (( ac == 2 ) && ( strlen( av[ 1 ]  ) <= MAXPATHLEN )) {
		if (( simta_file_publicsuffix = strdup( av[ 1 ] )) == NULL ) {
		    perror( "strdup" );
		    goto error;
		}
		simta_debuglog( 2, "PUBLICSUFFIX_FILE: %s",
			simta_file_publicsuffix );
		if ( simta_read_publicsuffix( )) {
		    goto error;
		}
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: PUBLICSUFFIX_FILE <path>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "PUNISHMENT" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "TEMPFAIL" ) == 0 ) {
		    simta_smtp_punishment_mode = SMTP_MODE_TEMPFAIL;
		    simta_debuglog( 2, "PUNISHMENT: TEMPFAIL" );
		    continue;
		}
		if ( strcasecmp( av[ 1 ], "TARPIT" ) == 0 ) {
		    simta_smtp_punishment_mode = SMTP_MODE_TARPIT;
		    simta_debuglog( 2, "PUNISHMENT: TARPIT" );
		    continue;
		}
		if ( strcasecmp( av[ 1 ], "DISCONNECT" ) == 0 ) {
		    simta_smtp_punishment_mode = SMTP_MODE_OFF;
		    simta_debuglog( 2, "PUNISHMENT: DISCONNECT" );
		    continue;
		}
	    }

	    fprintf( stderr, "%s: line %d: usage: "
		    "PUNISHMENT <TEMPFAIL|TARPIT|DISCONNECT>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "PUNT" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		    fprintf( stderr, "%s: line %d: domain name too long\n",
			    fname, lineno );
		    goto error;
		}
		simta_punt_host = yaslauto( av[ 1 ] );
		yasltolower( simta_punt_host );
		simta_debuglog( 2, "PUNT: %s", simta_punt_host );
		continue;
	    }

	    fprintf( stderr, "%s: line %d: usage: PUNT <hostname>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_int( "QUEUE_WAIT_MAX", &simta_wait_max,
		0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "QUEUE_WAIT_MIN", &simta_wait_min,
		0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "RBL_ACCEPT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: RBL_ACCEPT <dns zone>\n",
		    fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_rbls, RBL_ACCEPT, av[ 1 ], "" );
	    simta_debuglog( 2, "RBL_ACCEPT: %s", av[ 1 ] );

	} else if ( strcasecmp( av[ 0 ], "RBL_BLOCK" ) == 0 ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"RBL_BLOCK <dns zone> <url>\n",
			fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_rbls, RBL_BLOCK, av[ 1 ], av[ 2 ] );
	    simta_debuglog( 2, "RBL_BLOCK: %s\tURL: %s", av[ 1 ], av[ 2 ] );

	} else if ( strcasecmp( av[ 0 ], "RBL_LOG_ONLY" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"RBL_LOG_ONLY <dns zone>\n",
			fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_rbls, RBL_LOG_ONLY, av[ 1 ], "" );
	    simta_debuglog( 2, "RBL_LOG_ONLY: %s", av[ 1 ] );

	} else if ( strcasecmp( av[ 0 ], "RBL_TRUST" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: RBL_TRUST <dns zone>\n",
		    fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_rbls, RBL_TRUST, av[ 1 ], "" );
	    simta_debuglog( 2, "RBL_TRUST: %s", av[ 1 ]);

	} else if ( strcasecmp( av[ 0 ], "RDNS_CHECK" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "STRICT" ) == 0 ) {
		    simta_ignore_reverse = 0;
		    simta_ignore_connect_in_reverse_errors = 0;
		    simta_debuglog( 2, "RDNS_CHECK: STRICT" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "RELAXED" ) == 0 ) {
		    simta_ignore_reverse = 1;
		    simta_ignore_connect_in_reverse_errors = 0;
		    simta_debuglog( 2, "RDNS_CHECK: RELAXED" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "CHILLAXED" ) == 0 ) {
		    simta_ignore_reverse = 1;
		    simta_ignore_connect_in_reverse_errors = 1;
		    simta_debuglog( 2, "RDNS_CHECK: CHILLAXED" );
		    continue;
		}
	    }

	    fprintf( stderr, "%s: line %d: usage: "
		    "RDNS_CHECK <STRICT|RELAXED|CHILLAXED>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "RDNS_URL" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: RDNS_URL <url>\n",
			fname, lineno );
		goto error;
	    }
	    simta_reverse_url = strdup( av[ 1 ] );
	    simta_debuglog( 2, "RDNS_URL: %s", simta_reverse_url );

	} else if (( rc = simta_config_int( "RECEIVE_ACCEPTED_MESSAGE_TIMER",
		&simta_inbound_accepted_message_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int(
		"RECEIVE_COMMAND_INACTIVITY_TIMEOUT",
		&simta_inbound_command_inactivity_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "RECEIVE_COMMAND_LINE_TIMEOUT",
		&simta_inbound_command_line_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "RECEIVE_DATA_LINE_TIMEOUT",
		&simta_inbound_data_line_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "RECEIVE_DATA_SESSION_TIMEOUT",
		&simta_inbound_data_session_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "RECEIVE_GLOBAL_SESSION_TIMEOUT",
		&simta_inbound_global_session_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "RECEIVE_QUEUE_STRATEGY" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "FAST" ) == 0 ) {
		    simta_rqueue_policy = RQUEUE_POLICY_FAST;
		    simta_debuglog( 2, "RECEIVE_QUEUE_STRATEGY FAST" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "JAIL" ) == 0 ) {
		    simta_rqueue_policy = RQUEUE_POLICY_JAIL;
		    simta_debuglog( 2, "RECEIVE_QUEUE_STRATEGY JAIL" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "SLOW" ) == 0 ) {
		    simta_rqueue_policy = RQUEUE_POLICY_SLOW;
		    simta_debuglog( 2, "RECEIVE_QUEUE_STRATEGY SLOW" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "PUNT" ) == 0 ) {
		    simta_rqueue_policy = RQUEUE_POLICY_PUNT;
		    simta_debuglog( 2, "RECEIVE_QUEUE_STRATEGY PUNT" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: "
		    "RECEIVE_QUEUE_STRATEGY <FAST|SLOW|PUNT|JAIL>\n",
		    fname, lineno );
	    goto error;

#ifdef HAVE_LIBSSL
	} else if (( rc = simta_config_int( "RECEIVE_TLS_ACCEPT_TIMEOUT",
		&simta_inbound_ssl_accept_timer, 0, ac, av, fname,
		lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }
#endif /* HAVE_LIBSSL */

	} else if ( strcasecmp( av[ 0 ], "SEEN_BEFORE_DOMAIN" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"SEEN_BEFORE_DOMAIN <hostname>\n",
			fname, lineno );
		goto error;
	    }
	    if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		fprintf( stderr,
			"%s: line %d: domain name too long\n", fname, lineno );
		goto error;
	    }
	    simta_seen_before_domain = yaslauto( av[ 1 ] );
	    yasltolower( simta_seen_before_domain );
	    simta_debuglog( 2, "SEEN_BEFORE_DOMAIN: %s",
		    simta_seen_before_domain );

	} else if (( rc = simta_config_bool( "SENDER_CHECKING",
		&simta_from_checking, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "SENDER_LIST",
		&simta_sender_list_enable, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_LISTEN_BACKLOG",
		&simta_listen_backlog, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "SMTP_MODE" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "NORMAL" ) == 0 ) {
		    simta_smtp_default_mode = SMTP_MODE_NORMAL;
		    continue;
		} else if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		    simta_smtp_default_mode = SMTP_MODE_OFF;
		    continue;
		} else if ( strcasecmp( av[ 1 ], "REFUSE" ) == 0 ) {
		    simta_smtp_default_mode = SMTP_MODE_REFUSE;
		    continue;
		} else if ( strcasecmp( av[ 1 ], "GLOBAL_RELAY" ) == 0 ) {
		    simta_smtp_default_mode = SMTP_MODE_GLOBAL_RELAY;
		    continue;
		} else if ( strcasecmp( av[ 1 ], "TEMPFAIL" ) == 0 ) {
		    simta_smtp_default_mode = SMTP_MODE_TEMPFAIL;
		    continue;
		} else if ( strcasecmp( av[ 1 ], "TARPIT" ) == 0 ) {
		    simta_smtp_default_mode = SMTP_MODE_TARPIT;
		    continue;
		}
	    }

	    fprintf( stderr, "%s: line %d: "
		    "usage: SMTP_MODE "
		    "<NORMAL|OFF|REFUSE|GLOBAL_RELAY|TEMPFAIL|TARPIT>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_bool( "SMTP_PORT", &simta_service_smtp,
		ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_bool( "SMTP_STRICT_SYNTAX",
		&simta_strict_smtp_syntax, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_TARPIT_CONNECT",
		&simta_smtp_tarpit_connect, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_TARPIT_DATA",
		&simta_smtp_tarpit_data, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_TARPIT_DATA_EOF",
		&simta_smtp_tarpit_data_eof, 0, ac, av,
		fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_TARPIT_DEFAULT",
		&simta_smtp_tarpit_default, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_TARPIT_MAIL",
		&simta_smtp_tarpit_mail, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if (( rc = simta_config_int( "SMTP_TARPIT_RCPT",
		&simta_smtp_tarpit_rcpt, 0, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "SPF" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "ON" ) == 0 ) {
		    simta_spf = SPF_POLICY_ON;
		    simta_debuglog( 2, "SPF ON" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		    simta_spf = SPF_POLICY_OFF;
		    simta_debuglog( 2, "SPF OFF" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "STRICT" ) == 0 ) {
		    simta_spf = SPF_POLICY_STRICT;
		    simta_debuglog( 2, "SPF STRICT" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: SPF <ON|OFF|STRICT>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "SRS" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		    simta_srs = SRS_POLICY_OFF;
		    simta_debuglog( 2, "SRS OFF" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "ALWAYS" ) == 0 ) {
		    simta_srs = SRS_POLICY_ALWAYS;
		    simta_debuglog( 2, "SRS ALWAYS" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "FOREIGN" ) == 0 ) {
		    simta_srs = SRS_POLICY_FOREIGN;
		    simta_debuglog( 2, "SRS FOREIGN" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "SMART" ) == 0 ) {
		    simta_srs = SRS_POLICY_SMART;
		    simta_debuglog( 2, "SRS SMART" );
		    continue;
		}
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "SRS <OFF|ALWAYS|FOREIGN|SMART>" );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "SRS_DOMAIN" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_srs_domain = yaslauto( av[ 1 ] );
		yasltolower( simta_srs_domain );
		simta_debuglog( 2, "SRS_DOMAIN: %s", simta_srs_domain );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: SRS_DOMAIN <domain>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "SRS_SECRET" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_srs_secret = yaslauto( av[ 1 ] );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: %s\n",
		    fname, lineno,
		    "SRS_SECRET <secret>" );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "SUBADDRESS_SEPARATOR" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_subaddr_separator = *av[ 1 ];
		simta_debuglog( 2, "SUBADDRESS_SEPARATOR: %c",
			simta_subaddr_separator );
		continue;
	    }
	    fprintf( stderr,
		    "%s: line %d: usage: SUBADDRESS_SEPARATOR <char>\n",
		    fname, lineno );
	    goto error;

	} else if ( strcasecmp( av[ 0 ], "SUBMISSION_MODE" ) == 0 ) {
	    if ( ac == 2 ) {
		if ( strcasecmp( av[ 1 ], "MSA" ) == 0 ) {
		    simta_submission_mode = SUBMISSION_MODE_MSA;
		    simta_debuglog( 2, "SUBMISSION_MODE MSA" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "MTA" ) == 0 ) {
		    simta_submission_mode = SUBMISSION_MODE_MTA;
		    simta_debuglog( 2, "SUBMISSION_MODE MTA" );
		    continue;
		} else if ( strcasecmp( av[ 1 ], "MTA_STRICT" ) == 0 ) {
		    simta_submission_mode = SUBMISSION_MODE_MTA_STRICT;
		    simta_debuglog( 2, "SUBMISSION_MODE MTA_STRICT" );
		    continue;
		}
	    }

	    fprintf( stderr, "%s: line %d: usage: "
		    "SUBMISSION_MODE <MSA|MTA|MTA_STRICT>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_bool( "SUBMISSION_PORT",
		&simta_service_submission, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if (( rc = simta_config_bool( "SYNC", &simta_sync, ac, av,
		fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

#ifdef HAVE_LIBSSL
	} else if (( rc = simta_config_bool( "TLS", &simta_tls, ac, av,
		fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "TLS_CA_DIRECTORY" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"TLS_CA_DIRECTORY <path>\n",
			fname, lineno );
		goto error;
	    }
	    simta_dir_ca = strdup( av[ 1 ] );
	    simta_debuglog( 2, "TLS_CA_DIRECTORY: %s", simta_dir_ca );

	} else if ( strcasecmp( av[ 0 ], "TLS_CA_FILE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: TLS_CA_FILE <path>\n",
			fname, lineno );
		goto error;
	    }
	    simta_file_ca = strdup( av[ 1 ] );
	    simta_debuglog( 2, "TLS_CA_FILE: %s", simta_file_ca );

	} else if ( strcasecmp( av[ 0 ], "TLS_CERT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: TLS_CERT <path>\n",
			fname, lineno );
		goto error;
	    }
	    simta_file_cert = strdup( av[ 1 ] );
	    simta_debuglog( 2, "TLS_CERT: %s", simta_file_cert );

	} else if ( strcasecmp( av[ 0 ], "TLS_CERT_KEY" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: TLS_CERT_KEY <path>\n",
			fname, lineno );
		goto error;
	    }
	    simta_file_private_key = strdup( av[ 1 ] );
	    simta_debuglog( 2, "TLS_CERT_KEY: %s", simta_file_private_key );

	} else if ( strcasecmp( av[ 0 ], "TLS_CIPHERS" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_tls_ciphers = strdup( av[ 1 ] );
		simta_debuglog( 2, "TLS_CIPHERS: %s", simta_tls_ciphers );
		continue;
	    }
	    fprintf( stderr, "%s: line %d: usage: "
		    "TLS_CIPHERS <cipher string>\n",
		    fname, lineno );
	    goto error;

	} else if (( rc = simta_config_bool( "TLS_LEGACY_PORT",
		&simta_service_smtps, ac, av, fname, lineno )) != 0 ) {
	    if ( rc < 0 ) {
	        goto error;
	    }

#endif /* HAVE_LIBSSL */

	} else if ( strcasecmp( av[ 0 ], "USER_RBL_ACCEPT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"USER_RBL_ACCEPT <dns zone>\n",
			fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_user_rbls, RBL_ACCEPT, av[ 1 ], "" );

	    simta_debuglog( 2, "USER_RBL_ACCEPT: %s\n", av[ 1 ]);

	} else if ( strcasecmp( av[ 0 ], "USER_RBL_BLOCK" ) == 0 ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"USER_RBL_BLOCK <dns zone> <url>\n",
			fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_user_rbls, RBL_BLOCK, av[ 1 ], av[ 2 ] );

	    simta_debuglog( 2, "USER_RBL_BLOCK: %s\tURL: %s", av[ 1 ], av[ 2 ]);

	} else if ( strcasecmp( av[ 0 ], "USER_RBL_LOG_ONLY" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"USER_RBL_LOG_ONLY <dns zone>\n",
			fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_user_rbls, RBL_LOG_ONLY, av[ 1 ], "" );

	    simta_debuglog( 2, "USER_RBL_LOG_ONLY: %s", av[ 1 ]);

        } else if ( strcasecmp( av[ 0 ], "USER_RBL_TRUST" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: usage: "
			"USER_RBL_TRUST <dns zone>\n",
			fname, lineno );
		goto error;
	    }

	    rbl_add( &simta_user_rbls, RBL_TRUST, av[ 1 ], "" );

	    simta_debuglog( 2, "USER_RBL_TRUST: %s", av[ 1 ]);

	} else {
	    fprintf( stderr, "%s: line %d: unknown keyword: %s\n",
		    fname, lineno, av[ 0 ] );
	    goto error;
	}
    }
    acav_free( acav );

    if ( snet_close( snet ) != 0 ) {
	perror( "simta_domain_config: snet_close" );
	return( -1 );
    }

    return( 0 );

error:
    snet_close( snet );
    acav_free( acav );
    return( -1 );
}


    int
simta_host_is_jailhost( char *host )
{
    if ( simta_jail_host != NULL ) {
	if ( strcasecmp( simta_jail_host, host ) == 0 ) {
	    return( 1 );
	}
    }
    return 0;
}


    int
simta_config( void )
{
    char		path[ MAXPATHLEN + 1 ];
    struct timeval	tv_now;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
        return( -1 );
    }

    srandom( tv_now.tv_usec * tv_now.tv_sec * getpid( ) );

    if ( simta_host_is_jailhost( simta_hostname )) {
	fprintf( stderr, "punt host can't be localhost\n" );
	return( -1 );
    }

    if ( simta_punt_host != NULL ) {
	if ( yaslcmp( simta_punt_host, simta_hostname ) == 0 ) {
	    fprintf( stderr, "punt host can't be localhost\n" );
	    return( -1 );
	}
    }

    if ( !simta_domain ) {
	/* simta_domain defaults to simta_hostname */
	simta_domain = simta_hostname;
    }

    if ( !simta_seen_before_domain ) {
	/* simta_seen_before_domain defaults to simta_domain */
	simta_seen_before_domain = simta_domain;
    }

    if ( !simta_srs_domain ) {
	simta_srs_domain = simta_domain;
    }

#ifdef HAVE_LIBOPENDKIM
    if ( !simta_dkim_domain ) {
	simta_dkim_domain = simta_domain;
    }
#endif /* HAVE_LIBOPENDKIM */

    simta_postmaster = yaslcatyasl( yaslauto( "postmaster@" ), simta_hostname );

    /* set our local mailer */
    if ( set_local_mailer() != 0 ) {
	fprintf( stderr, "simta_config: set_local_mailer failed!\n" );
	return( -1 );
    }

    simta_red_host_default = red_host_add( simta_hostname );
    red_action_default( simta_red_host_default );

    /* check base_dir before using it */
    if ( simta_base_dir == NULL ) {
	fprintf( stderr, "No base directory defined.\n" );
	return( -1 );
    }

    /* set up data dir pathnames */
    sprintf( path, "%s/%s", simta_base_dir, "fast" );
    simta_dir_fast = strdup( path );

    sprintf( path, "%s/%s", simta_base_dir, "slow" );
    simta_dir_slow = strdup( path );

    sprintf( path, "%s/%s", simta_base_dir, "dead" );
    simta_dir_dead = strdup( path );

    sprintf( path, "%s/%s", simta_base_dir, "local" );
    simta_dir_local = strdup( path );

    sprintf( path, "%s/%s", simta_base_dir, "command" );
    simta_dir_command = strdup( path );

    return( 0 );
}

    int
simta_check_charset( const char *str )
{
    const unsigned char	    *c;
    size_t		    charlen;
    int			    i;
    uint32_t		    u;
    uint8_t		    mask;
    int			    ret = SIMTA_CHARSET_ASCII;

    for ( c = (unsigned char *)str; *c != '\0'; c++ ) {
	if ( *c < 0x80 ) {
	    continue;
	}
	ret = SIMTA_CHARSET_UTF8;
	if (( *c & 0xe0 ) == 0xc0 ) {
	    charlen = 2;
	    mask = 0x1f;
	} else if (( *c & 0xf0 ) == 0xe0 ) {
	    charlen = 3;
	    mask = 0x0f;
	} else if (( *c & 0xf8 ) == 0xf0 ) {
	    charlen = 4;
	    mask = 0x07;
	} else {
	    /* RFC 3629 limits UTF-8 to 21 bits (4 bytes), so
	     * anything else that has the high bit set is either an
	     * out-of-order continuation octet or completely invalid.
	     */
	    return( SIMTA_CHARSET_INVALID );
	}

	u = *c & mask;
	for ( i = 1; i < charlen; i++ ) {
	    c++;
	    if (( *c & 0xc0 ) != 0x80 ) {
		return( SIMTA_CHARSET_INVALID );
	    }
	    u <<= 6;
	    u |= ( *c & 0x3f );
	}

	/* Check that the codepoint used the shortest representation */
	if (( u < 0x80 ) || (( u < 0x800 ) && ( charlen > 2 )) ||
		(( u < 0x10000 ) && ( charlen > 4 ))) {
	    return( SIMTA_CHARSET_INVALID );
	}

	/* Check for invalid codepoints */
    }

    return( ret );
}

    static int
simta_config_bool( const char *key, int *value, int ac, char **av,
	const char *fname, int lineno )
{
    if ( strcasecmp( av[ 0 ], key ) != 0 ) {
	return( 0 );
    }

    if ( ac == 2 ) {
	if ( strcasecmp( av[ 1 ], "ON" ) == 0 ) {
	    *value = 1;
	    simta_debuglog( 2, "%s ON", key );
	    return( 1 );
	} else if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
	    *value = 0;
	    simta_debuglog( 2, "%s OFF", key );
	    return( 1 );
	}
    }

    fprintf( stderr, "%s: line %d: usage: %s <ON|OFF>\n", fname, lineno, key );
    return( -1 );
}

    static int
simta_config_int( const char *key, int *value, int min, int ac, char **av,
	const char *fname, int lineno )
{
    char    *endptr;

    if ( strcasecmp( av[ 0 ], key ) != 0 ) {
	return( 0 );
    }

    if ( ac == 2 ) {
	errno = 0;
	*value = strtol( av[ 1 ], &endptr, 10 );
	if (( errno == 0 ) && ( *value >= min ) && ( endptr != av[ 1 ] )) {
	    simta_debuglog( 2, "%s: %d", key, *value );
	    return( 1 );
	}
    }

    fprintf( stderr, "%s: line %d: usage: %s <value>\n", fname, lineno, key );
    if ( *value < min ) {
	fprintf( stderr, "%s must be greater than or equal to %d\n", key, min );
    }
    return( -1 );
}

    static int
simta_read_publicsuffix ( void )
{
    SNET		*snet = NULL;
    char		*line, *p;
    struct dll_entry	*leaf;
#ifdef HAVE_LIBIDN
    char		*idna = NULL;
#endif /* HAVE_LIBIDN */

    /* Set up public suffix list */
    if ( simta_file_publicsuffix != NULL ) {
	if (( snet = snet_open( simta_file_publicsuffix,
		O_RDONLY, 0, 1024 * 1024 )) == NULL ) {
	    fprintf( stderr, "simta_read_publicsuffix: open %s: %m",
		    simta_file_publicsuffix );
	    return( 1 );
	}
	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    /* Each line is only read up to the first whitespace; entire
	     * lines can also be commented using //.
	     */
	    if (( *line == '\0' ) || ( *line == ' ' ) || ( *line == '\t' ) ||
		    ( strncmp( line, "//", 2 ) == 0 )) {
		continue;
	    }
	    for ( p = line; ((*p != '\0' ) && (!isspace(*p))) ; p++ );
	    *p = '\0';
	    leaf = NULL;


#ifdef HAVE_LIBIDN
	    if ( simta_check_charset( line ) == SIMTA_CHARSET_UTF8 ) {
		if ( idna_to_ascii_8z( line, &idna, 0 ) == IDNA_SUCCESS ) {
		    line = idna;
		}
	    }
#endif /* HAVE_LIBIDN */

	    while ( *line != '\0' ) {
		if (( p = strrchr( line, '.' )) == NULL ) {
		    p = line;
		} else {
		    *p = '\0';
		    p++;
		}

		if ( leaf == NULL ) {
		    leaf = dll_lookup_or_create( &simta_publicsuffix_list,
			    p, 1 );
		} else {
		    leaf = dll_lookup_or_create(
			    (struct dll_entry **)&leaf->dll_data, p, 1 );
		}

		*p = '\0';
	    }

#ifdef HAVE_LIBIDN
	    if ( idna ) {
		free( idna );
		idna = NULL;
	    }
#endif /* HAVE_LIBIDN */
	}
	if ( snet_close( snet ) != 0 ) {
	    perror( "snet_close" );
	    return( 1 );
	}
    }

    return( 0 );
}

    pid_t
simta_waitpid( pid_t child, int *childstatus, int options )
{
    pid_t		retval = 0;
    int			ll;
    pid_t		pid;
    int			status;
    int			exitstatus;
    long		milliseconds;
    struct proc_type	**p_search;
    struct proc_type	*p_remove;
    struct timeval	tv_now;
    struct host_q	*hq;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return( -1 );
    }

    for ( ; ; ) {
	simta_child_signal = 0;

	if (( pid = waitpid( 0, &status, options )) <= 0 ) {
	    break;
	}

	for ( p_search = &simta_proc_stab; *p_search != NULL;
		p_search = &((*p_search)->p_next)) {
	    if ((*p_search)->p_id == pid ) {
		break;
	    }
	}

	if ( *p_search == NULL ) {
	    if ( pid == child ) {
		if ( childstatus ) {
		    *childstatus = status;
		}
		return( pid );
	    }
	    syslog( LOG_ERR, "Child: %d: unknown child process", pid );
	    retval--;
	    continue;
	}

	p_remove = *p_search;
	*p_search = p_remove->p_next;

	if ( p_remove->p_limit != NULL ) {
	    (*p_remove->p_limit)--;
	}

	milliseconds = SIMTA_ELAPSED_MSEC( p_remove->p_tv, tv_now );
	ll = LOG_INFO;

	if ( WIFEXITED( status )) {
	    if (( exitstatus = WEXITSTATUS( status )) != EXIT_OK ) {
		if (( p_remove->p_type == PROCESS_Q_SLOW ) &&
			( exitstatus == SIMTA_EXIT_OK_LEAKY )) {

		    /* remote host activity, requeue to encourage it */
		    if (( hq = host_q_lookup( p_remove->p_host )) != NULL ) {
			hq->hq_leaky = 1;
			hq_deliver_pop( hq );

			if ( hq_deliver_push( hq, &tv_now, NULL ) != 0 ) {
			    retval--;
			}

		    } else {
			simta_debuglog( 1, "Queue %s: Not Found",
				p_remove->p_host );
		    }

		} else {
		    retval--;
		    ll = LOG_ERR;
		}
	    }

	    switch ( p_remove->p_type ) {
	    case PROCESS_Q_LOCAL:
		syslog( ll, "Child: local runner %d.%ld exited %d "
			"(%ld milliseconds, %d siblings remaining)",
			pid, p_remove->p_tv.tv_sec, exitstatus, milliseconds,
			*p_remove->p_limit );
		break;

	    case PROCESS_Q_SLOW:
		syslog( ll, "Child: queue runner %d.%ld for %s exited %d "
			"(%ld milliseconds, %d siblings remaining)",
			pid, p_remove->p_tv.tv_sec,
			*(p_remove->p_host) ? p_remove->p_host : S_UNEXPANDED,
			exitstatus, milliseconds, *p_remove->p_limit );
		break;

	    case PROCESS_RECEIVE:
		p_remove->p_ss->ss_count--;
		p_remove->p_cinfo->c_proc_total--;

		syslog( ll, "Child: %s receive process %d.%ld for %s exited %d "
			"(%ld milliseconds, %d siblings remaining, %d %s)",
			p_remove->p_ss->ss_service, pid, p_remove->p_tv.tv_sec,
			p_remove->p_host, exitstatus, milliseconds,
			*p_remove->p_limit, p_remove->p_ss->ss_count,
			p_remove->p_ss->ss_service );
		break;

	    default:
		retval--;
		syslog( LOG_ERR, "Child: unknown process %d.%ld exited %d "
			"(%ld milliseconds)",
			pid, p_remove->p_tv.tv_sec, exitstatus, milliseconds );
		break;
	    }

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "Child: %d.%ld died with signal %d "
		    "(%ld milliseconds)", pid, p_remove->p_tv.tv_sec,
		    WTERMSIG( status ), milliseconds );
	    retval--;

	} else {
	    syslog( LOG_ERR, "Child: %d.%ld died (%ld milliseconds)", pid,
		    p_remove->p_tv.tv_sec, milliseconds );
	    retval--;
	}

	if ( p_remove->p_host ) {
	    free( p_remove->p_host );
	}
	free( p_remove );

	if ( options == 0 ) {
	    /* We rely on the caller to loop as needed, since they might want
	     * to do work before waiting again.
	     */
	    break;
	}
    }

    return( retval );
}

/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
