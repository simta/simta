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

#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "expand.h"
#include "nlist.h"
#include "envelope.h"
#include "ml.h"
#include "simta.h"
#include "argcargv.h"

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
int			simta_dns_config = 0;
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
char			simta_hostname[ MAXHOSTNAMELEN + 1 ] = "\0";
char			simta_ename[ MAXPATHLEN + 1 ];
char			simta_ename_slow[ MAXPATHLEN + 1 ];
char			simta_dname[ MAXPATHLEN + 1 ];
char			simta_dname_slow[ MAXPATHLEN + 1 ];
DNSR			*simta_dnsr = NULL;


struct nlist		simta_nlist[] = {
#define	NLIST_MASQUERADE		0
    { "masquerade",					NULL,	0 },
#define	NLIST_PUNT					1
    { "punt",						NULL,	0 },
#define	NLIST_BASE_DIR					2
    { "base_dir",					NULL,	0 },
#define	NLIST_RECEIVE_WAIT				3
    { "receive_wait",					NULL,	0 },
#define	NLIST_BOUNCE_LINES				4
    { "bounce_lines",					NULL,	0 },
#define	NLIST_BOUNCE_SECONDS				5
    { "bounce_seconds",					NULL,	0 },
#define	NLIST_MAX_RECEIVED_HEADERS			6
    { "max_received_headers",				NULL,	0 },
#define	NLIST_MAIL_FILTER				7
    { "mail_filter",					NULL,	0 },
#define	NLIST_DOMAIN_CONFIG				8
    { "domain",						NULL,	0 },
#ifdef HAVE_LDAP
#define	NLIST_LDAP					9
    { "ldap",						NULL,	0 },
#endif /* HAVE_LDAP */
    { NULL,						NULL,	0 },
};


    void
panic( char *message )
{
    syslog( LOG_WARNING, "%s", message );
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


    int
simta_config( char *conf_fname, char *base_dir )
{
    int			result;
    struct host		*host = NULL;
    char		fname[ MAXPATHLEN ];

    /* Set up simta_hostname */
    if ( gethostname( simta_hostname, MAXHOSTNAMELEN ) != 0 ) {
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

    /* set up simta_hosts stab */
    simta_hosts = NULL;

    /* Add localhost to hosts list */
    if (( host = malloc( sizeof( struct host ))) == NULL ) {
	perror( "simta_config malloc" );
	return( -1 );
    }
    memset( host, 0, sizeof( struct host ));

    simta_default_host = host;
    host->h_type = HOST_LOCAL;
    host->h_expansion = NULL;
    host->h_name = simta_hostname;

    /* Add list of expansions */
    if ( access( SIMTA_ALIAS_DB, R_OK ) == 0 ) {
	if ( ll_insert_tail( &(host->h_expansion), EXPANSION_TYPE_ALIAS,
		EXPANSION_TYPE_ALIAS ) != 0 ) {
	    perror( "simta_config ll_insert_tail" );
	    return( -1 );
	}

    } else {
	if ( simta_verbose != 0 ) {
	    fprintf( stderr, "simta_config access %s: ", SIMTA_ALIAS_DB );
	    perror( NULL );
	}

	syslog( LOG_INFO, "simta_config access %s: %m, not using alias db",
		SIMTA_ALIAS_DB );
    }

    if ( ll_insert_tail( &(host->h_expansion), EXPANSION_TYPE_PASSWORD,
	    EXPANSION_TYPE_PASSWORD ) != 0 ) {
	fprintf( stderr, "simta_config ll_insert_tail: " );
	perror( NULL );
	return( -1 );
    }

    if ( ll_insert( &simta_hosts, host->h_name, host, NULL ) != 0 ) {
	fprintf( stderr, "simta_config ll_insert: " );
	perror( NULL );
	return( -1 );
    }

    /* read config file */
    if (( result = nlist( simta_nlist, conf_fname )) < 0 ) {
	return( -1 );

    } else if ( result == 0 ) {
	/* currently checking for the following fields:
	 *	    masquerade
	 *	    punt
	 */

	if ( simta_nlist[ NLIST_MASQUERADE ].n_data != NULL ) {
	    simta_domain = simta_nlist[ NLIST_MASQUERADE ].n_data;
	}

	if ( simta_nlist[ NLIST_PUNT ].n_data != NULL ) {
	    simta_punt_host = simta_nlist[ NLIST_PUNT ].n_data;

	    if ( strcasecmp( simta_punt_host, simta_hostname ) == 0 ) {
		fprintf( stderr,
			"file %s line %d: punt host can't be localhost",
			conf_fname, simta_nlist[ NLIST_PUNT ].n_lineno );
		return( -1 );
	    }
	}

	if ( simta_nlist[ NLIST_BASE_DIR ].n_data != NULL ) {
	    base_dir = simta_nlist[ NLIST_BASE_DIR ].n_data;
	}

	if ( simta_nlist[ NLIST_BOUNCE_LINES ].n_data != NULL ) {
	    simta_max_bounce_lines =
		atoi( simta_nlist[ NLIST_BOUNCE_LINES ].n_data );
	    if ( simta_max_bounce_lines < 0 ) {
		fprintf( stderr,
		    "file %s line %d: bounce_seconds may not be less than 0",
		    conf_fname,
		    simta_nlist[ NLIST_BOUNCE_LINES ].n_lineno );
		return( -1 );
	    }
	}

	if ( simta_nlist[ NLIST_BOUNCE_SECONDS ].n_data != NULL ) {
	    simta_bounce_seconds =
		atoi( simta_nlist[ NLIST_BOUNCE_SECONDS ].n_data );
	    if ( simta_bounce_seconds < 0 ) {
		fprintf( stderr,
		    "file %s line %d: bounce_seconds may not be less than 0",
		    conf_fname,
		    simta_nlist[ NLIST_BOUNCE_SECONDS ].n_lineno );
		return( -1 );
	    }
	}

	if ( simta_nlist[ NLIST_RECEIVE_WAIT ].n_data != NULL ) {
	    simta_receive_wait =
		atoi( simta_nlist[ NLIST_RECEIVE_WAIT ].n_data );
	    if ( simta_receive_wait <= 0 ) {
		fprintf( stderr,
		    "file %s line %d: receive_wait must be greater than 0",
		    conf_fname,
		    simta_nlist[ NLIST_RECEIVE_WAIT ].n_lineno );
		return( -1 );
	    }
	}

	if ( simta_nlist[ NLIST_MAX_RECEIVED_HEADERS ].n_data != NULL ) {
	    simta_receive_wait =
		atoi( simta_nlist[ NLIST_MAX_RECEIVED_HEADERS ].n_data );
	    if ( simta_max_received_headers <= 0 ) {
		fprintf( stderr,
		    "file %s line %d: receive_wait must be greater than 0",
		    conf_fname,
		    simta_nlist[ NLIST_MAX_RECEIVED_HEADERS ].n_lineno );
		return( -1 );
	    }
	}

	if ( simta_nlist[ NLIST_MAIL_FILTER ].n_data != NULL ) {
	    simta_mail_filter = simta_nlist[ NLIST_MAIL_FILTER ].n_data;
	}

	if ( simta_nlist[ NLIST_DOMAIN_CONFIG ].n_data != NULL ) {
	    if ( simta_domain_config(
		    simta_nlist[ NLIST_DOMAIN_CONFIG ].n_data ) != 0 ) {
		return( -1 );
	    }
	}

#ifdef HAVE_LDAP
	if ( simta_nlist[ NLIST_LDAP ].n_data != NULL ) {
	    if ( simta_ldap_config( simta_nlist[ NLIST_LDAP ].n_data ) != 0 ) {
		return( -1 );
	    }
	}

	/* XXX add hosts that ldap will resolv for to simta_hosts */

	if (( host = malloc( sizeof( struct host ))) == NULL ) {
	    perror( "simta_config malloc" );
	    return( -1 );
	}
	memset( host, 0, sizeof( struct host ));

	host->h_type = HOST_MX;
	host->h_expansion = NULL;
	/* XXX hardcoded "umich.edu" for ldap searchdomain for now */
	host->h_name = "umich.edu";

	/* add ldap to host expansion table */
	if ( ll_insert_tail( &(host->h_expansion), EXPANSION_TYPE_LDAP,
		EXPANSION_TYPE_LDAP ) != 0 ) {
	    perror( "simta_config ll_insert_tail" );
	    return( -1 );
	}

	if ( ll_insert( &simta_hosts, host->h_name, host, NULL ) != 0 ) {
	    fprintf( stderr, "simta_config ll_insert: " );
	    perror( NULL );
	    return( -1 );
	}

#endif /* HAVE_LDAP */

    } else {
	/* no config file found */
	if ( simta_verbose != 0 ) {
	    printf( "simta_config file not found: %s\n", conf_fname );
	    syslog( LOG_INFO, "simta_config file not found: %s",
		    conf_fname );
	}
    }

    /* check base_dir before using it */
    if ( base_dir == NULL ) {
	fprintf( stderr, "No base directory defined.\n" );
	return( -1 );
    }

    /* set up data dir pathnames */
    sprintf( fname, "%s/%s", base_dir, "fast" );
    if (( simta_dir_fast = strdup( fname )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    sprintf( fname, "%s/%s", base_dir, "slow" );
    if (( simta_dir_slow = strdup( fname )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    sprintf( fname, "%s/%s", base_dir, "dead" );
    if (( simta_dir_dead = strdup( fname )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    sprintf( fname, "%s/%s", base_dir, "local" );
    if (( simta_dir_local = strdup( fname )) == NULL ) {
	perror( "strdup" );
	return( -1 );
    }

    return( 0 );
}

    int
simta_domain_config( char * fname )
{
    ACAV		*acav;
    int			ac;
    char		**av;
    int			lineno = 0;
    int			fd;
    char		*line;
    char		*rval;
    char		*lval;
    SNET		*snet;
    struct nlist	*n;

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	fprintf( stderr, "simta_domain_config: open %s: ", fname );
	perror( NULL );
	return( -1 );
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	perror( "simta_domain_config: snet_attach" );
	close( fd );
	return( -1 );
    }

    if (( acav = acav_alloc( )) == NULL ) {
	perror( "simta_domain_config: acav_alloc" );
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
	    perror( "simta_domain_config: acav_parse:" );
	    goto error;
	}

	fprintf( stderr, "%d: host: %s\n", lineno, acav[ 0 ] );

    }

    if ( snet_close( snet ) != 0 ) {
	perror( "simta_domain_config: snet_close" );
	return( -1 );
    }

    acav_free( acav );
    return( 0 );

error:
    snet_close( snet );
    acav_free( acav );
    return( -1 );
}

