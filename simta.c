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

/* global variables */

int			(*simta_local_mailer)(int, char *, struct recipient *);
struct host_q		*simta_null_q = NULL;
struct stab_entry	*simta_hosts = NULL;
struct host		*simta_default_host = NULL;
unsigned int		simta_bounce_seconds = 259200;
int			simta_dns_config = 1;
int			simta_no_sync = 0;
int			simta_max_received_headers = 100;
int			simta_max_bounce_lines;
int			simta_receive_wait = 600;
int			simta_ignore_reverse = 0;
int			simta_message_count = 0;
int			simta_smtp_outbound_attempts = 0;
int			simta_smtp_outbound_delivered = 0;
int			simta_fast_files = 0;
int			simta_global_relay = 0;
int			simta_debug = 0;
int			simta_verbose = 0;
char			*simta_mail_filter = NULL;
char			*simta_punt_host = NULL;
char			*simta_postmaster = NULL;
char			*simta_domain = NULL;
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
    int			lineno = 0;
    int			fd;
    int			ac;
    extern int		simta_debug;
    char		*line;
    ACAV		*acav;
    char		**av;
    SNET		*snet;
    char		*domain;
    struct host		*host;

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

	if ( *av[ 0 ] == '@' ) {
	    if ( strlen( av[ 0 ] + 1 ) > DNSR_MAX_HOSTNAME ) {
		printf( "len: %d\n", strlen( av[ 0 ] + 1 ));
		fprintf( stderr, "%s: line %d: domain name too long\n",
		    fname, lineno );
		goto error;
	    }
	    /* XXX - need to lower-case domain */
	    if (( domain = strdup( av[ 0 ] + 1 )) == NULL ) {
		perror( "strdup" );
		goto error;
	    }
	    if (( host = add_host( domain, HOST_LOCAL )) == NULL ) {
		goto error;
	    }

	    if ( strcasecmp( av[ 1 ], "BOUNCE" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_debug ) printf( "%s -> BOUNCE\n", domain );

	    } else if ( strcasecmp( av[ 1 ], "REFUSE" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_debug ) printf( "%s -> REFUSE\n", domain );

	    } else if ( strcasecmp( av[ 1 ], "HIGH_PREF_MX" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_debug ) printf( "%s -> HIGH_PREF_MX\n", domain );

	    } else if ( strcasecmp( av[ 1 ], "ALIAS" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_debug ) printf( "%s -> ALIAS\n", domain );

	    } else if ( strcasecmp( av[ 1 ], "PASSWORD" ) == 0 ) {
		if ( ac != 2 ) {
		    fprintf( stderr, "%s: line %d: expected 1 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_debug ) printf( "%s -> PASSWORD\n", domain );

#ifdef HAVE_LDAP
	    } else if ( strcasecmp( av[ 1 ], "LDAP" ) == 0 ) {
		if ( ac != 3 ) {
		    fprintf( stderr, "%s: line %d: expected 2 argument\n",
			fname, lineno );
		    goto error;
		}
		if ( simta_ldap_config( av[ 2 ] ) != 0 ) {
		    goto error;
		}

		if ( add_expansion( host, EXPANSION_TYPE_LDAP ) != 0 ) {
		    perror( "add_expansion" );
		    goto error;
		}

		if ( simta_debug ) printf( "%s -> LDAP\n", domain );
#endif /* HAVE_LDAP */
	    } else {
		fprintf( stderr, "%s: line %d: unknown keyword: %s\n",
		    fname, lineno, av[ 1 ] );
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
	    if ( simta_debug ) printf( "RECEIVE_WAIT %d\n", simta_receive_wait );

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
	    if ( simta_debug ) printf( "BOUNCE_LINES: %d\n", simta_max_bounce_lines );

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
	    if ( simta_debug ) printf( "BOUNCE_SECONDS: %d\n", simta_bounce_seconds );

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
	    if ( simta_debug ) printf( "CONTENT_FILTER: %s\n", simta_mail_filter );

	} else if ( strcasecmp( av[ 0 ], "DNS_CONFIG_OFF" ) == 0 ) {
	    if ( ac != 1 ) {
		fprintf( stderr, "%s: line %d: expected 0 argument\n",
		    fname, lineno );
		goto error;
	    }
	    simta_dns_config = 0;

	    if ( simta_debug ) printf( "DNS_CONFIG_OFF\n" );

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
    struct host		*host = NULL;
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

    if (( host = add_host( simta_hostname, HOST_LOCAL )) == NULL ) {
	return( -1 );
    }
    simta_default_host = host;

    /* Add list of expansions */
    if ( access( SIMTA_ALIAS_DB, R_OK ) == 0 ) {
	if ( add_expansion( host, EXPANSION_TYPE_ALIAS ) != 0 ) {
	    return( -1 );
	}
    } else {
	if ( simta_verbose != 0 ) {
	    fprintf( stderr, "simta_config access %s: ", SIMTA_ALIAS_DB );
	    perror( NULL );
	}
	syslog( LOG_NOTICE, "simta_config access %s: %m, not using alias db",
		SIMTA_ALIAS_DB );
    }

    if ( add_expansion( host, EXPANSION_TYPE_PASSWORD ) != 0 ) {
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
