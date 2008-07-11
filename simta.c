/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	simta.c	**********/
#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif /* HAVE_LIBSSL */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>
#include <db.h>

#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "expand.h"
#include "red.h"
#include "envelope.h"
#include "ml.h"
#include "simta.h"
#include "argcargv.h"
#include "mx.h"
#include "simta_ldap.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

/* global variables */

struct timeval		simta_tv_mid = { 0, 0 };
struct envelope		*simta_env_queue = NULL;
struct host_q		*simta_host_q = NULL;
struct host_q		*simta_deliver_q = NULL;
struct host_q		*simta_unexpanded_q = NULL;
struct host_q		*simta_punt_q = NULL;
struct simta_red	*simta_default_host = NULL;
struct simta_red	*simta_red_hosts = NULL;
struct simta_red	*simta_secondary_mx = NULL;
unsigned int		simta_bounce_seconds = 259200;
unsigned short		simta_smtp_port = 0;
int			simta_bitbucket = -1;
int			simta_aggressive_delivery = 1;
int			simta_smtp_port_defined = 0;
int			simta_rbl_verbose_logging = 0;
int			simta_queue_incoming_smtp_mail = 0;
int			simta_leaky_queue = 0;
int			simta_use_randfile = 0;
int			simta_listen_backlog = 5;
int			simta_disk_cycle = 0;
int			simta_receive_connections_max = SIMTA_MAXCONNECTIONS;
int			simta_receive_connections = 0;
int			simta_launch_limit = SIMTA_LAUNCH_LIMIT;
int			simta_min_work_time = SIMTA_MIN_WORK_TIME;
int			simta_q_runner_local_max = SIMTA_MAX_RUNNERS_LOCAL;
int			simta_q_runner_local = 0;
int			simta_q_runner_slow_max = SIMTA_MAX_RUNNERS_SLOW;
int			simta_q_runner_slow = 0;
int			simta_exp_level_max = 5;
int			simta_simsend_strict_from = 1;
int			simta_process_type = 0;
int			simta_filesystem_cleanup = 0;
int			simta_smtp_extension = 0;
int			simta_smtp_rcvbuf_min = 0;
int			simta_smtp_rcvbuf_max;
int			simta_strict_smtp_syntax = 0;
int			simta_dns_config = 1;
int			simta_no_sync = 0;
int			simta_max_received_headers = 100;
int			simta_max_bounce_lines;
int			simta_banner_delay = 0;
int			simta_banner_punishment = 0;
int			simta_max_failed_rcpts = 0;
int			simta_receive_wait = 600;
int			simta_data_transaction_wait = 3600;
int			simta_data_line_wait = 300;
int			simta_ignore_reverse = 0;
int			simta_ignore_connect_in_reverse_errors = 0;
int			simta_message_count = 0;
int			simta_smtp_outbound_attempts = 0;
int			simta_smtp_outbound_delivered = 0;
int			simta_fast_files = 0;
int			simta_smtp_punishment_mode = SMTP_MODE_TEMPFAIL;
int			simta_smtp_default_mode = SMTP_MODE_NORMAL;
int			simta_smtp_tarpit_default = 120;
int			simta_smtp_tarpit_connect = 0;
int			simta_smtp_tarpit_mail = 0;
int			simta_smtp_tarpit_rcpt = 0;
int			simta_smtp_tarpit_data = 0;
int			simta_smtp_tarpit_data_eof = 0;
int			simta_debug = 0;
int			simta_verbose = 0;
int			simta_tls = 0;
int			simta_sasl = 0;
int			simta_service_submission = 0;
#ifdef HAVE_LIBSSL
int			simta_service_smtps = 0;
const EVP_MD		*simta_checksum_md = NULL;
char			*simta_checksum_algorithm;
#endif /* HAVE_LIBSSL */
long int		simta_max_message_size = -1;
char			*simta_mail_filter = NULL;
char			*simta_data_url = NULL;
char			*simta_reverse_url = NULL;
char			*simta_punt_host = NULL;
char			*simta_jail_host = NULL;
char			*simta_postmaster = NULL;
char			*simta_domain = NULL;
struct rbl	     	*simta_rbls = NULL;
struct rbl     		*simta_user_rbls = NULL;
char			*simta_queue_filter = NULL;
char			*simta_dir_dead = NULL;
char			*simta_dir_local = NULL;
char			*simta_dir_slow = NULL;
char			*simta_dir_fast = NULL;
char			*simta_base_dir = NULL;
char			simta_hostname[ DNSR_MAX_HOSTNAME + 1 ] = "\0";
DNSR			*simta_dnsr = NULL;
char			*simta_default_alias_db = SIMTA_ALIAS_DB;
char			*simta_default_passwd_file = "/etc/passwd";
char			*simta_file_ca = "cert/ca.pem";
char			*simta_dir_ca = NULL;
char			*simta_file_cert = "cert/cert.pem";
char			*simta_file_private_key = "cert/cert.pem";
char			**simta_deliver_default_argv;
int			simta_deliver_default_argc;


    void
panic( char *message )
{
    syslog( LOG_CRIT, "%s", message );
    abort();
}


    char*
simta_sender( void )
{
    static char			*sender = NULL;
    struct passwd		*pw;

    if ( sender == NULL ) {
	if (( pw = getpwuid( getuid())) == NULL ) {
	    perror( "getpwuid" );
	    return( NULL );
	}

	if (( sender = (char*)malloc( strlen( pw->pw_name ) +
		strlen( simta_domain ) + 2 )) == NULL ) {
	    perror( "malloc" );
	    return( NULL );
	}
	sprintf( sender, "%s@%s", pw->pw_name, simta_domain );
    }

    return( sender );
}


/* XXX - need to add support for:
 * include files/dirs
 *   in dirs, only read .conf files, have depth limit and exit on duplicate
 * Timeouts
 * virtual users - user@wcbn.org -> wcbn.user@domain
 * bit bucket
 */
    int
simta_read_config( char *fname )
{
    int			red_code;
    int			lineno = 0;
    int			fd;
    int			ac;
    int			x;
    extern int		simta_debug;
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

    if ( simta_debug ) printf( "simta_config: %s\n", fname );

    /* Set up simta_hostname */
    if ( gethostname( simta_hostname, DNSR_MAX_HOSTNAME ) != 0 ) {
	perror( "gethostname" );
	return( -1 );
    }

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	if ( errno == ENOENT )  {
	    errno = 0;
	    if ( simta_debug ) printf(
		"warning: %s: simta config file not found", fname );
	    syslog( LOG_NOTICE, "%s: simta config file not found", fname );
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

    if (( acav = acav_alloc( )) == NULL ) {
	perror( "simta_read_config: acav_alloc" );
	snet_close( snet );
	return( -1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	lineno++;

	if (( line[ 0 ] == '\0' ) || ( line[ 0 ] == '#' )) {
	    /* blank line or comment */
	    continue;
	}

	if (( ac = acav_parse( acav, line, &av )) < 0 ) {
	    perror( "simta_read_config: acav_parse:" );
	    goto error;
	}

	/* @hostname RED OPTION */
	if ( *av[ 0 ] == '@' ) {
	    domain = av[ 0 ] + 1;
	    if ( strlen( domain ) > DNSR_MAX_HOSTNAME ) {
		printf( "len: %d\n", strlen( domain ));
		fprintf( stderr, "%s: line %d: domain name too long\n",
			fname, lineno );
		goto error;
	    }
	    /* XXX - need to lower-case domain */

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

	    if (( red = simta_red_add_host( domain,
		    RED_HOST_TYPE_LOCAL )) == NULL ) {
		perror( "malloc" );
		goto error;
	    }

	    if ( strcasecmp( av[ 2 ], "ALIAS" ) == 0 ) {
		if ( ac == 3 ) {
		    if ( simta_default_alias_db == NULL ) {
			fprintf( stderr,
				"%s: line %d: default alias DB disabled\n",
				fname, lineno );
			goto error;
		    }

		    f_arg = simta_default_alias_db;
		} else if ( ac == 4 ) {
		    f_arg = av[ 3 ];
		} else {
		    fprintf( stderr, "%s: line %d: incorrect syntax\n",
			    fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    if ( simta_red_add_action( red, RED_CODE_r,
			    EXPANSION_TYPE_ALIAS, f_arg ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		} else if ( red_code & RED_CODE_R ) {
		    if ( simta_red_add_action( red, RED_CODE_R,
			    EXPANSION_TYPE_ALIAS, f_arg ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

		if ( red_code & RED_CODE_E ) {
		    if ( simta_red_add_action( red, RED_CODE_E,
			    EXPANSION_TYPE_ALIAS, f_arg ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

	    } else if ( strcasecmp( av[ 2 ], "PASSWORD" ) == 0 ) {
		if ( ac == 3 ) {
		    f_arg = simta_default_passwd_file;
		} else if ( ac == 4 ) {
		    f_arg = av[ 3 ];
		} else {
		    fprintf( stderr, "%s: line %d: incorrect syntax\n",
			    fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    if ( simta_red_add_action( red, RED_CODE_r,
			    EXPANSION_TYPE_PASSWORD, f_arg ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		} else if ( red_code & RED_CODE_R ) {
		    if ( simta_red_add_action( red, RED_CODE_R,
			    EXPANSION_TYPE_PASSWORD, f_arg ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

		if ( red_code & RED_CODE_E ) {
		    if ( simta_red_add_action( red, RED_CODE_E,
			    EXPANSION_TYPE_PASSWORD, f_arg ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

	    } else if ( *(av[ 2 ]) == '/' ) {
		if ( ac <= 2 ) {
		    fprintf( stderr,
			    "%s: line %d: expected 1 or more arguments\n",
			    fname, lineno );
		    goto error;
		}

		if ( red_code != RED_CODE_D ) {
		    fprintf( stderr,
			    "%s: line %d: only D support for BINARY\n",
			    fname, lineno );
		    goto error;
		}

		if ( red->red_deliver_argc != 0 ) {
		    fprintf( stderr,
			    "%s: line %d: D already defined for %s\n",
			    fname, lineno, av[ 0 ]);
		    goto error;
		}

		/* store array */
		red->red_deliver_argc = ac - 2;
		if (( red->red_deliver_argv =
			(char**)malloc( sizeof(char*) * ( ac - 1 ))) == NULL ) {
		    perror( "malloc" );
		    goto error;
		}

		for ( x = 0; x < red->red_deliver_argc; x++ ) {
		    if (( red->red_deliver_argv[ x ] =
			    strdup( av[ x + 2 ])) == NULL ) {
			perror( "strdup" );
			goto error;
		    }
		}

		red->red_deliver_argv[ x ] = NULL;
		red->red_deliver_type = RED_DELIVER_BINARY;

	    } else if ( strcasecmp( av[ 0 ], "DEFAULT_LOCAL_MAILER" ) == 0 ) {
		if ( ac < 2 ) {
		    fprintf( stderr,
			    "%s: line %d: expected at least 1 argument\n",
			    fname, lineno );
		    goto error;
		}

		/* store array */
		simta_deliver_default_argc = ac - 1;
		if (( simta_deliver_default_argv =
			(char**)malloc( sizeof(char*) * ( ac ))) == NULL ) {
		    perror( "malloc" );
		    goto error;
		}

		for ( x = 0; x < simta_deliver_default_argc; x++ ) {
		    if (( simta_deliver_default_argv[ x ] =
			    strdup( av[ x + 1 ])) == NULL ) {
			perror( "strdup" );
			goto error;
		    }
		}

		red->red_deliver_argv[ x ] = NULL;
		red->red_deliver_type = RED_DELIVER_BINARY;

		if (( simta_mail_filter = strdup( av[ 1 ] )) == NULL ) {
		    perror( "strdup" );
		    goto error;
		}
		if ( simta_debug ) printf( "DEFAULT_LOCAL_MAILER: %s\n",
		    simta_mail_filter );

#ifdef HAVE_LDAP
	    } else if ( strcasecmp( av[ 2 ], "LDAP" ) == 0 ) {
		if ( ac != 4 ) {
		    fprintf( stderr, "%s: line %d: expected 2 argument\n",
			    fname, lineno );
		    goto error;
		}
		if (( ld = simta_ldap_config( av[ 3 ], domain )) == NULL ) {
		    fprintf( stderr, "%s: line %d: LDAP config %s failed, "
			    "please check the logs\n", fname, lineno, av[ 3 ]);
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    if (( a = simta_red_add_action( red, RED_CODE_r,
			    EXPANSION_TYPE_LDAP, NULL )) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		    a->a_ldap = ld;
		} else if ( red_code & RED_CODE_R ) {
		    if (( a = simta_red_add_action( red, RED_CODE_R,
			    EXPANSION_TYPE_LDAP, NULL )) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		    a->a_ldap = ld;
		}

		if ( red_code & RED_CODE_E ) {
		    if (( a = simta_red_add_action( red, RED_CODE_E,
			    EXPANSION_TYPE_LDAP, NULL )) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		    a->a_ldap = ld;
		}
#endif /* HAVE_LDAP */

	    } else {
		fprintf( stderr, "%s: line %d: unknown keyword: %s\n",
			fname, lineno, av[ 2 ] );
		goto error;
	    }

#ifdef HAVE_LIBSSL
	} else if ( strcasecmp( av[ 0 ], "CHECKSUM_ALGORITHM" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }

	    if ( simta_checksum_md != NULL ) {
		fprintf( stderr,
			"%s: line %d: CHECKSUM_ALGORITHM already defined\n",
			fname, lineno );
		goto error;
	    }

	    OpenSSL_add_all_digests();
	    simta_checksum_md = EVP_get_digestbyname( (const char*)(av[ 1 ]));
	    if ( simta_checksum_md == NULL ) {
		fprintf( stderr, "%s: line %d: Unknown message digest: %s\n",
			fname, lineno, av[ 1 ]);
		goto error;
	    }

	    if (( simta_checksum_algorithm = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }

	    if ( simta_debug ) printf( "CHECKSUM_ALGORITHM %s\n",
		    simta_checksum_algorithm );
#endif /* HAVE_LIBSSL */

	} else if ( strcasecmp( av[ 0 ], "MASQUERADE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		fprintf( stderr,
			"%s: line %d: domain name too long\n", fname, lineno );
		goto error;
	    }
	    /* XXX - need to lower-case domain */
	    if (( simta_domain = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "MASQUERADE as %s\n", simta_domain );

	} else if ( strcasecmp( av[ 0 ], "JAIL" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		fprintf( stderr,
			"%s: line %d: domain name too long\n", fname, lineno );
		goto error;
	    }
	    /* XXX - need to lower-case domain */
	    if (( simta_jail_host = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "JAIL to %s\n", simta_jail_host );

	} else if ( strcasecmp( av[ 0 ], "PUNT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( strlen( av[ 1 ]  ) > DNSR_MAX_HOSTNAME ) {
		fprintf( stderr,
			"%s: line %d: domain name too long\n", fname, lineno );
		goto error;
	    }
	    /* XXX - need to lower-case domain */
	    if (( simta_punt_host = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "PUNT to %s\n", simta_punt_host );

	} else if ( strcasecmp( av[ 0 ], "BASE_DIR" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( strlen( av[ 1 ]  ) > MAXPATHLEN ) {
		fprintf( stderr,
			"%s: line %d: path too long\n", fname, lineno );
		goto error;
	    }
	    if (( simta_base_dir = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "base dir: %s\n", simta_base_dir );

	} else if ( strcasecmp( av[ 0 ], "RECEIVE_WAIT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_receive_wait = atoi( av[ 1 ] );
	    if ( simta_receive_wait <= 0 ) {
		fprintf( stderr,
			"%s: line %d: RECEIVE_WAIT must be greater than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "RECEIVE_WAIT %d\n",
		    simta_receive_wait );

	} else if ( strcasecmp( av[ 0 ], "DATA_LINE_WAIT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_data_line_wait = atoi( av[ 1 ] );
	    if ( simta_data_line_wait <= 0 ) {
		fprintf( stderr,
			"%s: line %d: DATA_LINE_WAIT must be greater than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "DATA_LINE_WAIT %d\n",
		    simta_data_line_wait );

	} else if ( strcasecmp( av[ 0 ], "BOUNCE_LINES" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_max_bounce_lines = atoi( av[ 1 ] );
	    if ( simta_max_bounce_lines < 0 ) {
		fprintf( stderr, "%s: line %d: BOUNCE_LINES less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "BOUNCE_LINES: %d\n",
		simta_max_bounce_lines );

	} else if ( strcasecmp( av[ 0 ], "BITBUCKET" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_bitbucket = atoi( av[ 1 ] );
	    if ( simta_bitbucket < 0 ) {
		fprintf( stderr, "%s: line %d: BITBUCKET less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "BITBUCKET: %d\n", simta_bitbucket );

	} else if ( strcasecmp( av[ 0 ], "BOUNCE_SECONDS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_bounce_seconds = atoi( av[ 1 ] );
	    if ( simta_bounce_seconds < 0 ) {
		fprintf( stderr, "%s: line %d: BOUNCE_SECONDS less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "BOUNCE_SECONDS: %d\n",
		simta_bounce_seconds );

	} else if ( strcasecmp( av[ 0 ], "MAX_RECEIVE_CONNECTIONS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_receive_connections_max = atoi( av [ 1 ] );
	    if ( simta_receive_connections_max < 0 ) {
		fprintf( stderr, "%s: line %d: "
			"MAX_RECEIVE_CONNECTIONS can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MAX_RECEIVE_CONNECTIONS: %d\n",
		    simta_receive_connections_max );

	} else if ( strcasecmp( av[ 0 ], "MAX_RECEIVED_HEADERS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_max_received_headers = atoi( av [ 1 ] );
	    if ( simta_max_received_headers <= 0 ) {
		fprintf( stderr, "%s: line %d: "
			"MAX_RECEIVED_HEADERS must be greater than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MAX_RECEIVED_HEADERS: %d\n",
		simta_max_received_headers );

	} else if ( strcasecmp( av[ 0 ], "MAX_Q_RUNNERS_LOCAL" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_q_runner_local_max = atoi( av [ 1 ] );
	    if ( simta_q_runner_local_max < 0 ) {
		fprintf( stderr,
			"%s: line %d: MAX_Q_RUNNERS_LOCAL can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MAX_Q_RUNNERS_LOCAL: %d\n",
		simta_q_runner_local_max );

	} else if ( strcasecmp( av[ 0 ], "MAX_Q_RUNNERS_SLOW" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_q_runner_slow_max = atoi( av [ 1 ] );
	    if ( simta_q_runner_slow_max < 0 ) {
		fprintf( stderr,
			"%s: line %d: MAX_Q_RUNNERS_SLOW can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MAX_Q_RUNNERS_SLOW: %d\n",
		simta_q_runner_slow_max );

	} else if ( strcasecmp( av[ 0 ], "MAX_Q_RUNNERS_LAUNCH" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_launch_limit = atoi( av [ 1 ] );
	    if ( simta_launch_limit < 0 ) {
		fprintf( stderr, "%s: line %d: "
			"MAX_Q_RUNNERS_LAUNCH can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MAX_Q_RUNNERS_LAUNCH: %d\n",
		simta_launch_limit );

	} else if ( strcasecmp( av[ 0 ], "MIN_WORK_TIME" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_min_work_time = atoi( av [ 1 ] );
	    if ( simta_min_work_time < 0 ) {
		fprintf( stderr,
			"%s: line %d: MIN_WORK_TIME can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MIN_WORK_TIME: %d\n",
		simta_min_work_time );

	} else if ( strcasecmp( av[ 0 ], "CONTENT_FILTER" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_mail_filter = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "CONTENT_FILTER: %s\n",
		simta_mail_filter );

	} else if ( strcasecmp( av[ 0 ], "IGNORE_REVERSE" ) == 0 ) {
	    if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 arguments\n",
			fname, lineno );
		goto error;
	    }
	    simta_ignore_reverse = 1;
	    if ( simta_debug ) printf( "IGNORE_REVERSE\n" );

	} else if ( strcasecmp( av[ 0 ], "SMTP_DATA_URL" ) == 0 ) {
	    if ( ac != 2 ) {
                fprintf( stderr, "%s: line %d: expected 1 arguments\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_data_url = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_DATA_URL: %s\n", simta_data_url );

	} else if ( strcasecmp( av[ 0 ], "REVERSE_URL" ) == 0 ) {
	    if ( ac != 2 ) {
                fprintf( stderr, "%s: line %d: expected 1 arguments\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_reverse_url = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "REVERSE_URL: %s\n", simta_reverse_url );

        } else if ( strcasecmp( av[ 0 ], "QUEUE_INCOMING_SMTP_MAIL" ) == 0 ) {
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
                goto error;
            }
            simta_queue_incoming_smtp_mail = 1;
            if ( simta_debug ) printf( "QUEUE_INCOMING_SMTP_MAIL" );

        } else if ( strcasecmp( av[ 0 ],
                "IGNORE_CONNECT_IN_DNS_ERRORS" ) == 0 ) {
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
                goto error;
            }
            simta_ignore_connect_in_reverse_errors = 1;
	    simta_ignore_reverse = 1;
            if ( simta_debug ) printf( "IGNORE_CONNECT_IN_DNS_ERRORS\n" );

	} else if ( strcasecmp( av[ 0 ], "RBL_VERBOSE_LOGGING" ) == 0 ) {
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 arguments\n",
			fname, lineno );
                goto error;
            }
	    simta_rbl_verbose_logging = 1;
            if ( simta_debug ) printf( "RBL_VERBOSE_LOGGING\n" );

	} else if ( strcasecmp( av[ 0 ], "RBL_BLOCK" ) == 0 ) {
            if ( ac != 3 ) {
                fprintf( stderr, "%s: line %d: expected 2 argument\n",
                    fname, lineno );
                goto error;
            }

	    if ( rbl_add( &simta_rbls, RBL_BLOCK, av[ 1 ], av[ 2 ]) != 0 ) {
		perror( "malloc" );
		goto error;
	    }

            if ( simta_debug ) {
		printf( "RBL_BLOCK: %s\tURL: %s\n", av[ 1 ], av[ 2 ]);
	    }

	} else if ( strcasecmp( av[ 0 ], "RBL_ACCEPT" ) == 0 ) {
            if ( ac != 2 ) {
                fprintf( stderr, "%s: line %d: expected 1 argument\n",
                    fname, lineno );
                goto error;
            }

	    if ( rbl_add( &simta_rbls, RBL_ACCEPT, av[ 1 ], "") != 0 ) {
		perror( "malloc" );
		goto error;
	    }

            if ( simta_debug ) {
		printf( "RBL_ACCEPT: %s\n", av[ 1 ]);
	    }

	} else if ( strcasecmp( av[ 0 ], "USER_RBL_BLOCK" ) == 0 ) {
            if ( ac != 3 ) {
                fprintf( stderr, "%s: line %d: expected 2 argument\n",
                    fname, lineno );
                goto error;
            }

	    if ( rbl_add( &simta_user_rbls, RBL_BLOCK, av[ 1 ],
		    av[ 2 ]) != 0 ) {
		perror( "malloc" );
		goto error;
	    }

            if ( simta_debug ) {
		printf( "USER_RBL_BLOCK: %s\tURL: %s\n", av[ 1 ], av[ 2 ]);
	    }

	} else if ( strcasecmp( av[ 0 ], "USER_RBL_ACCEPT" ) == 0 ) {
            if ( ac != 2 ) {
                fprintf( stderr, "%s: line %d: expected 1 argument\n",
                    fname, lineno );
                goto error;
            }

	    if ( rbl_add( &simta_user_rbls, RBL_ACCEPT, av[ 1 ], "" ) != 0 ) {
		perror( "malloc" );
		goto error;
	    }

            if ( simta_debug ) {
		printf( "USER_RBL_ACCEPT: %s\n", av[ 1 ]);
	    }

	} else if ( strcasecmp( av[ 0 ], "PRIVATE_KEY_FILE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_file_private_key = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) {
		printf( "PRIVATE_KEY_FILE: %s\n", simta_file_private_key );
	    }

	} else if ( strcasecmp( av[ 0 ], "CERT_FILE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_file_cert = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) {
		printf( "CERT_FILE: %s\n", simta_file_cert );
	    }

	} else if ( strcasecmp( av[ 0 ], "CA_FILE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_file_ca = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) {
		printf( "CA_FILE: %s\n", simta_file_ca );
	    }

	} else if ( strcasecmp( av[ 0 ], "CA_DIRECTORY" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_dir_ca = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) {
		printf( "CA_DIRECTORY: %s\n", simta_file_ca );
	    }

	} else if ( strcasecmp( av[ 0 ], "ALIAS_DB" ) == 0 ) {
	    if ( ac == 2 ) {
		if (( simta_default_alias_db = strdup( av[ 1 ] )) == NULL ) {
		    perror( "strdup" );
		    goto error;
		}
	    } else if ( ac == 1 ) {
		simta_default_alias_db = NULL;

	    } else {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }

	    if ( simta_debug ) {
		printf( "ALIAS_DB: %s\n", simta_default_alias_db ?
			simta_default_alias_db : "Disabled" );
	    }

        } else if ( strcasecmp( av[ 0 ], "SIMSEND_STRICT_FROM_OFF" ) == 0 ) {
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
                goto error;
            }
	    simta_simsend_strict_from = 0;
            if ( simta_debug ) printf( "SIMSEND_STRICT_FROM_OFF\n" );

        } else if ( strcasecmp( av[ 0 ], "SUBMISSION_PORT" ) == 0 ) {
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
                goto error;
            }
            simta_service_submission = SERVICE_SUBMISSION_ON;
            if ( simta_debug ) printf( "SUBMISSION_PORT\n" );

        } else if ( strcasecmp( av[ 0 ], "AUTHLEVEL" ) == 0 ) {
	    /* authlevel 0:none, 1:serv, 2:client & serv */
            if ( ac != 2 ) {
                fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
                goto error;
            }
            simta_service_smtps = atoi( av[ 1 ]);
            if (( simta_service_smtps < 0 ) || ( simta_service_smtps > 2 )) {
                fprintf( stderr, "%s: line %d: invalid authorization level\n",
			fname, lineno );
                goto error;
            }

        } else if ( strcasecmp( av[ 0 ], "TLS_ON" ) == 0 ) {
	    if ( simta_tls ) {
                fprintf( stderr, "%s: line %d: tls already started\n",
			fname, lineno );
                goto error;
            }
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
                goto error;
            }
            simta_tls = 1;
            if ( simta_debug ) printf( "TLS_ON\n" );

        } else if ( strcasecmp( av[ 0 ], "USE_RANDFILE" ) == 0 ) {
            if ( ac != 1 ) {
                fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
                goto error;
            }
	    simta_use_randfile = 1;
            if ( simta_debug ) printf( "USE_RANDFILE\n" );

	} else if ( strcasecmp( av[ 0 ], "DNS_CONFIG_OFF" ) == 0 ) {
	    if ( ac != 1 ) {
		fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_dns_config = 0;
	    if ( simta_debug ) printf( "DNS_CONFIG_OFF\n" );

	} else if ( strcasecmp( av[ 0 ], "STRICT_SMTP_SYNTAX_OFF" ) == 0 ) {
	    if ( ac != 1 ) {
		fprintf( stderr, "%s: line %d: expected 0 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_strict_smtp_syntax = 0;
	    if ( simta_debug ) printf( "STRICT_SMTP_SYNTAX_OFF\n" );

	} else if ( strcasecmp( av[ 0 ], "SMTP_PORT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( atoi( av[ 1 ]) < 0 ) {
		fprintf( stderr, "%s: line %d: port must be 0 or greater\n",
			fname, lineno );
		goto error;
	    }
	    simta_smtp_port = htons( atoi( av[ 1 ]));
	    simta_smtp_port_defined = 1;
	    if ( simta_debug ) printf( "SMTP_PORT: %s\n", av[ 1 ] );

	} else if ( strcasecmp( av[ 0 ], "SMTP_RCVBUF" ) == 0 ) {
	    if ( ac == 2 ) {
		simta_smtp_rcvbuf_max = 0;

	    } else if ( ac == 3 ) {
		if (( simta_smtp_rcvbuf_max = atoi( av[ 2 ] )) < 0 ) {
		    fprintf( stderr, "%s: line %d: illegal argument: %s\n",
			    fname, lineno, av[ 2 ]);
		    goto error;
		}

	    } else {
		fprintf( stderr, "%s: line %d: expected 1 or 2 arguments\n",
			fname, lineno );
		goto error;
	    }

	    if (( simta_smtp_rcvbuf_min = atoi( av[ 1 ] )) <= 0 ) {
		fprintf( stderr, "%s: line %d: illegal argument: %s\n",
			fname, lineno, av[ 1 ]);
		goto error;
	    }

	    if (( simta_smtp_rcvbuf_max > 0 ) && ( simta_smtp_rcvbuf_max <
		    simta_smtp_rcvbuf_min )) {
		fprintf( stderr, "%s: line %d: max can't be smaller than min\n",
			fname, lineno );
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "SMTP_LISTEN_BACKLOG" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_listen_backlog = atoi( av[ 1 ] );
	    if ( simta_listen_backlog < 0 ) {
		fprintf( stderr, "%s: line %d: SMTP_LISTEN_BACKLOG less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_LISTEN_BACKLOG: %d\n",
		    simta_listen_backlog );

	} else if ( strcasecmp( av[ 0 ], "MAX_MESSAGE_SIZE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_max_message_size = strtol( av[ 1 ], &endptr, 10 );
	    if (( *av[ 1 ] == '\0' ) || ( *endptr != '\0' )) {
		fprintf( stderr, "%s: line %d: invalid argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( simta_max_message_size == LONG_MIN ) {
		fprintf( stderr, "%s: line %d: argument too small\n",
			fname, lineno );
		goto error;
	    }
	    if ( simta_max_message_size == LONG_MAX ) {
		fprintf( stderr, "%s: line %d: argument too big\n",
			fname, lineno );
		goto error;
	    }
	    if ( simta_max_message_size < 0 ) {
		fprintf( stderr, "%s: line %d: invalid negative argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_smtp_extension++;

	} else if ( strcasecmp( av[ 0 ], "MAX_FAILED_RCPTS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    simta_max_failed_rcpts = strtol( av[ 1 ], &endptr, 10 );
	    if (( *av[ 1 ] == '\0' ) || ( *endptr != '\0' )) {
		fprintf( stderr, "%s: line %d: invalid argument\n",
			fname, lineno );
		goto error;
	    }
	    if ( simta_max_failed_rcpts == LONG_MIN ) {
		fprintf( stderr, "%s: line %d: argument too small\n",
			fname, lineno );
		goto error;
	    }
	    if ( simta_max_failed_rcpts == LONG_MAX ) {
		fprintf( stderr, "%s: line %d: argument too big\n",
			fname, lineno );
		goto error;
	    }
	    if ( simta_max_failed_rcpts < 0 ) {
		fprintf( stderr, "%s: line %d: invalid negative argument\n",
			fname, lineno );
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "AGGRESSIVE_DELIVERY" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    } else if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		simta_aggressive_delivery = 0;
	    } else if ( strcasecmp( av[ 1 ], "ON" ) == 0 ) {
		simta_aggressive_delivery = 1;
	    } else {
		fprintf( stderr, "%s: line %d: illegal argument\n",
			fname, lineno );
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "SMTP_MODE" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    } else if ( strcasecmp( av[ 1 ], "NORMAL" ) == 0 ) {
		simta_smtp_default_mode = SMTP_MODE_NORMAL;
	    } else if ( strcasecmp( av[ 1 ], "OFF" ) == 0 ) {
		simta_smtp_default_mode = SMTP_MODE_OFF;
	    } else if ( strcasecmp( av[ 1 ], "REFUSE" ) == 0 ) {
		simta_smtp_default_mode = SMTP_MODE_REFUSE;
	    } else if ( strcasecmp( av[ 1 ], "GLOBAL_RELAY" ) == 0 ) {
		simta_smtp_default_mode = SMTP_MODE_GLOBAL_RELAY;
	    } else if ( strcasecmp( av[ 1 ], "TEMPFAIL" ) == 0 ) {
		simta_smtp_default_mode = SMTP_MODE_TEMPFAIL;
	    } else if ( strcasecmp( av[ 1 ], "TARPIT" ) == 0 ) {
		simta_smtp_default_mode = SMTP_MODE_TARPIT;
	    } else {
		fprintf( stderr, "%s: line %d: illegal argument\n",
			fname, lineno );
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "FAILED_RCPT_PUNISHMENT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    } else if ( strcasecmp( av[ 1 ], "TEMPFAIL" ) == 0 ) {
		simta_smtp_punishment_mode = SMTP_MODE_TEMPFAIL;
	    } else if ( strcasecmp( av[ 1 ], "TARPIT" ) == 0 ) {
		simta_smtp_punishment_mode = SMTP_MODE_TARPIT;
	    } else if ( strcasecmp( av[ 1 ], "DISCONNECT" ) == 0 ) {
		simta_smtp_punishment_mode = SMTP_MODE_OFF;
	    } else {
		fprintf( stderr, "%s: line %d: illegal argument\n",
			fname, lineno );
		goto error;
	    }

	} else if ( strcasecmp( av[ 0 ], "SMTP_TARPIT_DEFAULT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_smtp_tarpit_default = atoi( av [ 1 ] )) < 0 ) {
		fprintf( stderr,
			"%s: line %d: SMTP_TARPIT_DEFAULT can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_TARPIT_DEFAULT: %d\n",
		simta_smtp_tarpit_default );

	} else if ( strcasecmp( av[ 0 ], "SMTP_TARPIT_CONNECT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_smtp_tarpit_connect = atoi( av [ 1 ] )) < 0 ) {
		fprintf( stderr,
			"%s: line %d: SMTP_TARPIT_CONNECT can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_TARPIT_CONNECT: %d\n",
		simta_smtp_tarpit_connect );

	} else if ( strcasecmp( av[ 0 ], "SMTP_TARPIT_MAIL" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_smtp_tarpit_mail = atoi( av [ 1 ] )) < 0 ) {
		fprintf( stderr,
			"%s: line %d: SMTP_TARPIT_MAIL can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_TARPIT_MAIL: %d\n",
		simta_smtp_tarpit_mail );

	} else if ( strcasecmp( av[ 0 ], "SMTP_TARPIT_RCPT" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_smtp_tarpit_rcpt = atoi( av [ 1 ] )) < 0 ) {
		fprintf( stderr,
			"%s: line %d: SMTP_TARPIT_RCPT can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_TARPIT_RCPT: %d\n",
		simta_smtp_tarpit_rcpt );

	} else if ( strcasecmp( av[ 0 ], "SMTP_TARPIT_DATA" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_smtp_tarpit_data = atoi( av [ 1 ] )) < 0 ) {
		fprintf( stderr,
			"%s: line %d: SMTP_TARPIT_DATA can't be less than 0",
			fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_TARPIT_DATA: %d\n",
		simta_smtp_tarpit_data );

	} else if ( strcasecmp( av[ 0 ], "SMTP_TARPIT_DATA_EOF" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		goto error;
	    }
	    if (( simta_smtp_tarpit_data_eof = atoi( av [ 1 ] )) < 0 ) {
		fprintf( stderr,
			"%s: line %d: SMTP_TARPIT_DATA_EOF "
			"can't be less than 0", fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "SMTP_TARPIT_DATA_EOF: %d\n",
		simta_smtp_tarpit_data_eof );

	} else if ( strcasecmp( av[ 0 ], "WRITE_BEFORE_BANNER" ) == 0 ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "%s: line %d: expected 2 arguments\n",
		    fname, lineno );
		goto error;
	    }
	    if (( simta_banner_delay = atoi( av[ 1 ])) < 1 ) {
		fprintf( stderr, "%s: line %d: invalid argument\n",
		    fname, lineno );
		goto error;
	    }
	    if (( simta_banner_punishment = atoi( av[ 2 ])) < 1 ) {
		fprintf( stderr, "%s: line %d: invalid argument\n",
		    fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "WRITE_BEFORE_BANNER: %d %d\n",
		    simta_banner_delay, simta_banner_punishment );

	} else if ( strcasecmp( av[ 0 ], "LOW_PREF_MX" ) == 0 ) {
	   if ( simta_secondary_mx != NULL ) {
	       fprintf( stderr, "%s: line %d: duplicate secondary_mx\n",
		       fname, lineno );
	       goto error;
	   }
	   if ( ac != 2 ) {
	       fprintf( stderr, "%s: line %d: expected 1 argument\n",
		       fname, lineno );
	       goto error;
	   }
	   /* Do not allow local host to be secondary_mx */
	   if ( strcasecmp( simta_hostname, av[ 1 ] ) == 0 ) {
	       fprintf( stderr, "%s: line %d: invalid host",
		       fname, lineno );
	       goto error;
	   }
	   if (( red = simta_red_add_host( av[ 1 ],
		    RED_HOST_TYPE_SECONDARY_MX)) == NULL ) {
	       perror( "malloc" );
	       goto error;
	   }
	   if ( simta_debug ) printf( "LOW_PREF_MX: %s\n",
		   simta_secondary_mx->red_host_name );

	} else if ( strcasecmp( av[ 0 ], "SASL_ON" ) == 0 ) {
	   if ( ac != 1 ) {
	       fprintf( stderr, "%s: line %d: expected 0 argument\n",
		       fname, lineno );
	       goto error;
	   }
	   simta_sasl++;
	   simta_smtp_extension++;
	   if ( simta_debug ) printf( "SASL_ON\n" );

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
simta_config( char *base_dir )
{
    struct simta_red	*red = NULL;
    char		path[ MAXPATHLEN + 1 ];

    if ( simta_jail_host != NULL ) {
	if ( strcasecmp( simta_jail_host, simta_hostname ) == 0 ) {
	    fprintf( stderr, "punt host can't be localhost\n" );
	    return( -1 );
	}
    }

    if ( simta_punt_host != NULL ) {
	if ( strcasecmp( simta_punt_host, simta_hostname ) == 0 ) {
	    fprintf( stderr, "punt host can't be localhost\n" );
	    return( -1 );
	}
    }

    /* simta_domain defaults to simta_hostname */
    simta_domain = simta_hostname;

    if (( simta_postmaster = (char*)malloc( 12 + strlen( simta_hostname )))
	    == NULL ) {
	perror( "malloc" );
	return( -1 );
    }
    sprintf( simta_postmaster, "postmaster@%s", simta_hostname );

    /* set our local mailer */
    if ( set_local_mailer() != 0 ) {
	fprintf( stderr, "simta_config: set_local_mailer failed!\n" );
	return( -1 );
    }

    simta_max_bounce_lines = SIMTA_BOUNCE_LINES;

    if (( red = simta_red_add_host( simta_hostname,
	    RED_HOST_TYPE_LOCAL )) == NULL ) {
	return( -1 );
    }
    simta_default_host = red;

    if ( simta_red_action_default( red ) != 0 ) {
	perror( "malloc" );
	return( -1 );
    }

    /* check base_dir before using it */
    if ( base_dir == NULL ) {
	fprintf( stderr, "No base directory defined.\n" );
	return( -1 );
    }

    /* set up data dir pathnames */
    sprintf( path, "%s/%s", base_dir, "fast" );
    if (( simta_dir_fast = strdup( path )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    sprintf( path, "%s/%s", base_dir, "slow" );
    if (( simta_dir_slow = strdup( path )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    sprintf( path, "%s/%s", base_dir, "dead" );
    if (( simta_dir_dead = strdup( path )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    sprintf( path, "%s/%s", base_dir, "local" );
    if (( simta_dir_local = strdup( path )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    return( 0 );
}
