/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/**********	simta.c	**********/

#include <sys/param.h>
#include <sys/types.h>

#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>

#include "simta.h"


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
