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
#include "simta.h"

char	*dnsr_resolvconf_path = SIMTA_RESOLV_CONF;
struct stab_entry	*simta_hosts;

    char*
simta_gethostname( void )
{
    static char			localhostname[ MAXHOSTNAMELEN + 1 ] = "\0";

    if ( *localhostname == '\0' ) {
	if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
	    perror( "gethostname" );
	    return( NULL );
	}
    }

    return( localhostname );
}


    char*
simta_local_domain( void )
{
    static char			domain[ MAXHOSTNAMELEN + 1 ] = "\0";

    if ( *domain == '\0' ) {
	if ( gethostname( domain, MAXHOSTNAMELEN ) != 0 ) {
	    perror( "gethostname" );
	    return( NULL );
	}
    }

    return( domain );
}


    char*
simta_sender( void )
{
    static char			*sender = NULL;
    char			*domain;
    struct passwd		*pw;

    if ( sender == NULL ) {
	if (( domain = simta_local_domain()) == NULL ) {
	    return( NULL );
	}

	if (( pw = getpwuid( getuid())) == NULL ) {
	    perror( "getpwuid" );
	    return( NULL );
	}

	if (( sender = (char*)malloc( strlen( pw->pw_name ) +
		strlen( domain ) + 2 )) == NULL ) {
	    perror( "malloc" );
	    return( NULL );
	}

	sprintf( sender, "%s@%s", pw->pw_name, domain );
    }

    return( sender );
}


    int
simta_init_hosts( void )
{
    struct host		*host = NULL;

    simta_hosts = NULL;

    /* Add localhost to hosts list */
    if (( host = malloc( sizeof( struct host ))) == NULL ) {
	syslog( LOG_ERR, "simta_config_host: malloc: %m" );
	return( -1 );
    }
    host->h_type = HOST_LOCAL;
    host->h_expansion = NULL;

    if (( host->h_name = simta_gethostname()) == NULL ) {
	return( -1 );
    }

    /* Add list of expansions */
    if ( access( SIMTA_ALIAS_DB, R_OK ) == 0 ) {
	if ( ll_insert_tail( &(host->h_expansion), "alias",
		"alias" ) != 0 ) {
	    syslog( LOG_ERR, "simta_config_host: ll_insert_tail: %m" );
	    return( -1 );
	}
    } else {
	syslog( LOG_INFO, "simta_config_host: %s: %m", SIMTA_ALIAS_DB );
    }

    if ( ll_insert_tail( &(host->h_expansion), "password",
	    "password" ) != 0 ) {
	syslog( LOG_ERR, "simta_config_host: ll_insert_tail: %m" );
	return( -1 );
    }

    if ( ll_insert( &simta_hosts, host->h_name, host, NULL ) != 0 ) {
	syslog( LOG_ERR, "simta_config_host: ll_insert: %m" );
	return( -1 );
    }

    return( 0 );
}
