/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	simta.c	**********/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>

#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "ll.h"
#include "queue.h"
#include "nlist.h"
#include "simta.h"

/* global variables */
struct host_q		*simta_null_q = NULL;
struct stab_entry	*simta_hosts = NULL;
char			*dnsr_resolvconf_path = SIMTA_RESOLV_CONF;
int			simta_debug = 0;
int			simta_verbose = 0;
char			*simta_punt_host = NULL;
char			*simta_postmaster = NULL;
char			*simta_domain = NULL;
char			simta_hostname[ MAXHOSTNAMELEN + 1 ] = "\0";


struct nlist		simta_nlist[] = {
#define	NLIST_MASQUERADE		0
    { "masquerade",	NULL,	0 },
#define	NLIST_PUNT			1
    { "punt",		NULL,	0 },
    { NULL,		NULL,	0 },
};


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
simta_config( void )
{
    int			result;
    struct host		*host = NULL;

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

    /* read config file */
    if (( result = nlist( simta_nlist, SIMTA_FILE_CONFIG )) < 0 ) {
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
			SIMTA_FILE_CONFIG, simta_nlist[ NLIST_PUNT ].n_lineno );
		return( -1 );
	    }
	}

    } else {
	/* no config file found */
	if ( simta_verbose != 0 ) {
	    printf( "simta_config file not found: %s\n", SIMTA_FILE_CONFIG );
	    syslog( LOG_INFO, "simta_config file not found: %s",
		    SIMTA_FILE_CONFIG );
	}
    }

    /* set up simta_hosts stab */
    simta_hosts = NULL;

    /* Add localhost to hosts list */
    if (( host = malloc( sizeof( struct host ))) == NULL ) {
	perror( "simta_config malloc" );
	return( -1 );
    }

    host->h_type = HOST_LOCAL;
    host->h_expansion = NULL;
    host->h_name = simta_hostname;

    /* Add list of expansions */
    if ( access( SIMTA_ALIAS_DB, R_OK ) == 0 ) {
	if ( ll_insert_tail( &(host->h_expansion), "alias",
		"alias" ) != 0 ) {
	    perror( "simta_config ll_insert_tail" );
	    return( -1 );
	}

    } else {
	if ( simta_verbose != 0 ) {
	    fprintf( stderr, "simta_config access %s: ", SIMTA_ALIAS_DB );
	    perror( NULL );
	}

	syslog( LOG_INFO, "simta_config access %s: %m", SIMTA_ALIAS_DB );
    }

    if ( ll_insert_tail( &(host->h_expansion), "password",
	    "password" ) != 0 ) {
	fprintf( stderr, "simta_config ll_insert_tail: " );
	perror( NULL );
	return( -1 );
    }

    if ( ll_insert( &simta_hosts, host->h_name, host, NULL ) != 0 ) {
	fprintf( stderr, "simta_config ll_insert: " );
	perror( NULL );
	return( -1 );
    }

    return( 0 );
}
