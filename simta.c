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
#endif /* HAVE_LIBSSL */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

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

#include "red.h"
#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "expand.h"
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

struct envelope		*simta_env_queue = NULL;
int			(*simta_local_mailer)(int, char *, struct recipient *);
struct host_q		*simta_host_q = NULL;
struct host_q		*simta_deliver_q = NULL;
struct host_q		*simta_unexpanded_q = NULL;
struct host_q		*simta_punt_q = NULL;
struct simta_red	*simta_default_host = NULL;
struct simta_red	*simta_red_hosts = NULL;
struct simta_red	*simta_secondary_mx = NULL;
unsigned int		simta_bounce_seconds = 259200;
int			simta_disk_cycle = 0;
int			simta_disk_period = 300;
int			simta_receive_connections_max = SIMTA_MAXCONNECTIONS;
int			simta_receive_connections = 0;
int			simta_launch_limit = SIMTA_LAUNCH_LIMIT;
int			simta_q_runner_local_max = SIMTA_MAX_RUNNERS_LOCAL;
int			simta_q_runner_local = 0;
int			simta_q_runner_slow_max = SIMTA_MAX_RUNNERS_SLOW;
int			simta_q_runner_slow = 0;
int			simta_exp_level_max = 5;
int			simta_simsend_strict_from = 1;
int			simta_process_type = 0;
int			simta_use_alias_db = 0;
int			simta_filesystem_cleanup = 0;
int			simta_smtp_extension = 0;
int			simta_strict_smtp_syntax = 0;
int			simta_dns_config = 1;
int			simta_no_sync = 0;
int			simta_max_received_headers = 100;
int			simta_max_bounce_lines;
int			simta_max_failed_rcpts = 0;
int			simta_receive_wait = 600;
int			simta_ignore_reverse = 0;
int			simta_message_count = 0;
int			simta_smtp_outbound_attempts = 0;
int			simta_smtp_outbound_delivered = 0;
int			simta_fast_files = 0;
int			simta_global_relay = 0;
int			simta_debug = 0;
int			simta_verbose = 0;
int			simta_tls = 0;
int			simta_sasl = 0;
int			simta_service_smtp = 1;
int			simta_service_submission = 0;
#ifdef HAVE_LIBSSL
int			simta_service_smtps = 0;
#endif /* HAVE_LIBSSL */
long int		simta_max_message_size = -1;
char			*simta_mail_filter = NULL;
char			*simta_reverse_url = NULL;
char			*simta_punt_host = NULL;
char			*simta_postmaster = NULL;
char			*simta_domain = NULL;
char			*simta_rbl_domain = NULL;
char			*simta_rbl_url = NULL;
char			*simta_user_rbl_domain = NULL;
char			*simta_user_rbl_url = NULL;
char			*simta_queue_filter = NULL;
char			*simta_dir_dead = NULL;
char			*simta_dir_local = NULL;
char			*simta_dir_slow = NULL;
char			*simta_dir_fast = NULL;
char			*simta_base_dir = NULL;
char			simta_hostname[ DNSR_MAX_HOSTNAME + 1 ] = "\0";
DNSR			*simta_dnsr = NULL;

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
    extern int		simta_debug;
    char		*endptr;
    char		*line;
    char		*c;
    ACAV		*acav;
    char		**av;
    SNET		*snet;
    char		*domain;
    struct simta_red	*red;

    if ( simta_debug ) printf( "simta_config: %s\n", fname );

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

		default:
		    fprintf( stderr, "%s: line %d: bad RED arg: %s\n",
			fname, lineno, av[ 1 ]);
		    goto error;
		}
	    }

	    if (( red = simta_red_add_host( domain,
		    RED_HOST_TYPE_LOCAL )) == NULL ) {
		perror( "malloc" );
		goto error;
	    }

	    if ( strcasecmp( av[ 2 ], "ALIAS" ) == 0 ) {
		if ( ac != 3 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    if ( simta_red_add_action( red, RED_CODE_r,
			    EXPANSION_TYPE_ALIAS ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		} else if ( red_code & RED_CODE_R ) {
		    if ( simta_red_add_action( red, RED_CODE_R,
			    EXPANSION_TYPE_ALIAS ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

		if ( red_code & RED_CODE_E ) {
		    if ( simta_red_add_action( red, RED_CODE_E,
			    EXPANSION_TYPE_ALIAS ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

	    } else if ( strcasecmp( av[ 2 ], "PASSWORD" ) == 0 ) {
		if ( ac != 3 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    if ( simta_red_add_action( red, RED_CODE_r,
			    EXPANSION_TYPE_PASSWORD ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		} else if ( red_code & RED_CODE_R ) {
		    if ( simta_red_add_action( red, RED_CODE_R,
			    EXPANSION_TYPE_PASSWORD ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

		if ( red_code & RED_CODE_E ) {
		    if ( simta_red_add_action( red, RED_CODE_E,
			    EXPANSION_TYPE_PASSWORD ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

#ifdef HAVE_LDAP
	    } else if ( strcasecmp( av[ 2 ], "LDAP" ) == 0 ) {
		if ( ac != 4 ) {
		    fprintf( stderr, "%s: line %d: expected 2 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_ldap_config( av[ 3 ] ) != 0 ) {
		    goto error;
		}

		if ( red_code & RED_CODE_r ) {
		    if ( simta_red_add_action( red, RED_CODE_r,
			    EXPANSION_TYPE_LDAP ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		} else if ( red_code & RED_CODE_R ) {
		    if ( simta_red_add_action( red, RED_CODE_R,
			    EXPANSION_TYPE_LDAP ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}

		if ( red_code & RED_CODE_E ) {
		    if ( simta_red_add_action( red, RED_CODE_E,
			    EXPANSION_TYPE_LDAP ) == NULL ) {
			perror( "malloc" );
			goto error;
		    }
		}
#endif /* HAVE_LDAP */

	    } else {
		fprintf( stderr, "%s: line %d: unknown keyword: %s\n",
		    fname, lineno, av[ 2 ] );
		goto error;
	    }

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
		    "%s: line %d: RECEIVE_EAIT must be greater than 0",
		    fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "RECEIVE_WAIT %d\n",
		simta_receive_wait );

	} else if ( strcasecmp( av[ 0 ], "BOUNCE_LINES" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_max_bounce_lines = atoi( av[ 1 ] );
	    if ( simta_max_bounce_lines < 0 ) {
		fprintf( stderr,
		    "%s: line %d: BOUNCE_LINES less than 0", fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "BOUNCE_LINES: %d\n",
		simta_max_bounce_lines );

	} else if ( strcasecmp( av[ 0 ], "BOUNCE_SECONDS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_bounce_seconds = atoi( av[ 1 ] );
	    if ( simta_bounce_seconds < 0 ) {
		fprintf( stderr,
		    "%s: line %d: BOUNCE_SECONDS less than 0", fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "BOUNCE_SECONDS: %d\n",
		simta_bounce_seconds );

	} else if ( strcasecmp( av[ 0 ], "MAX_RECEIVED_HEADERS" ) == 0 ) {
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_max_received_headers = atoi( av [ 1 ] );
	    if ( simta_max_received_headers <= 0 ) {
		fprintf( stderr,
		    "%s: line %d: MAX_RECEIVED_HEADERS must be greater than 0",
		    fname, lineno );
		goto error;
	    }
	    if ( simta_debug ) printf( "MAX_RECEIVED_HEADERS: %d\n",
		simta_max_received_headers );

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
	    if ( ac != 2 ) {
		fprintf( stderr, "%s: line %d: expected 1 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_ignore_reverse = 1;
	    if (( simta_reverse_url = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "IGNORE_REVERSE\tREVERSE_URL: %s\n",
		simta_reverse_url );

	} else if ( strcasecmp( av[ 0 ], "RBL_DOMAIN" ) == 0 ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "%s: line %d: expected 2 argument\n",
		    fname, lineno );
		goto error;
	    }
	    if (( simta_rbl_domain = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if (( simta_rbl_url = strdup( av[ 2 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) printf( "RBL_DOMAIN: %s\tRBL_URL: %s\n",
		simta_rbl_domain, simta_rbl_url );

	} else if ( strcasecmp( av[ 0 ], "USER_RBL_DOMAIN" ) == 0 ) {
	    if ( ac != 3 ) {
		fprintf( stderr, "%s: line %d: expected 2 argument\n",
		    fname, lineno );
		goto error;
	    }
	    if (( simta_user_rbl_domain = strdup( av[ 1 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if (( simta_user_rbl_url = strdup( av[ 2 ] )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if ( simta_debug ) {
		printf( "USER_RBL_DOMAIN: %s\tUSER_RBL_URL: %s\n",
		    simta_user_rbl_domain, simta_user_rbl_url );
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

	} else if ( strcasecmp( av[ 0 ], "SERVICE_SMTP_REFUSE" ) == 0 ) {
	    if ( ac != 1 ) {
		fprintf( stderr, "%s: line %d: expected 0 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_service_smtp = SERVICE_SMTP_REFUSE;

	    if ( simta_debug ) printf( "SERVICE_SMTP_REFUSE\n" );

	} else if ( strcasecmp( av[ 0 ], "SERVICE_SMTP_OFF" ) == 0 ) {
	    if ( ac != 1 ) {
		fprintf( stderr, "%s: line %d: expected 0 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_service_smtp = SERVICE_SMTP_OFF;

	    if ( simta_debug ) printf( "NO_INBOUND_SMTP\n" );

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
	    /* Add 1 to include max in failed rcpt count */
	    simta_max_failed_rcpts++;

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

	} else if ( strcasecmp( av[ 0 ], "GLOBAL_RELAY" ) == 0 ) {
	   if ( ac != 1 ) {
	       fprintf( stderr, "%s: line %d: expected 0 argument\n",
		   fname, lineno );
	       goto error;
	   }
	   simta_global_relay = 1;
	   if ( simta_debug ) printf( "GLOBAL_RELAY\n" );

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

    if ( simta_punt_host != NULL ) {
	if ( strcasecmp( simta_punt_host, simta_hostname ) == 0 ) {
	    fprintf( stderr, "punt host can't be localhost\n" );
	    return( -1 );
	}
    }

    /* Set up simta_hostname */
    if ( gethostname( simta_hostname, DNSR_MAX_HOSTNAME ) != 0 ) {
	perror( "gethostname" );
	return( -1 );
    }

    /* simta_domain defaults to simta_hostname */
    simta_domain = simta_hostname;

    if (( simta_postmaster = (char*)malloc( 12 + strlen( simta_hostname )))
	    == NULL ) {
	perror( "malloc" );
	return( -1 );
    }
    sprintf( simta_postmaster, "postmaster@%s", simta_hostname );

    /* get our local mailer */
    if (( simta_local_mailer = get_local_mailer()) == NULL ) {
	fprintf( stderr, "simta_config: get_local_mailer failed!\n" );
	return( -1 );
    }

    simta_max_bounce_lines = SIMTA_BOUNCE_LINES;

    if (( red = simta_red_add_host( simta_hostname,
	    RED_HOST_TYPE_LOCAL )) == NULL ) {
	return( -1 );
    }
    simta_default_host = red;

    /* Add list of default expansions to default host */
    if ( access( SIMTA_ALIAS_DB, R_OK ) == 0 ) {
	simta_use_alias_db = 1;
    } else {
	if ( simta_verbose != 0 ) {
	    fprintf( stderr, "simta_config access %s: ", SIMTA_ALIAS_DB );
	    perror( NULL );
	}
	syslog( LOG_NOTICE, "simta_config access %s: %m, not using alias db",
		SIMTA_ALIAS_DB );
    }

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
