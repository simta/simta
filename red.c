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
#include <dirent.h>

#include "denser.h"
#include "ll.h"
#include "expand.h"
#include "red.h"
#include "envelope.h"
#include "simta.h"
#include "argcargv.h"
#include "mx.h"
#include "simta_ldap.h"
#include "queue.h"
#include "ml.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif


    void
simta_red_stdout( void )
{
    struct simta_red		*red;
    struct action		*a;

    for ( red = simta_red_hosts; red != NULL; red = red->red_next ) {
	printf( "RED %d %s:\n", red->red_host_type, red->red_host_name );

	if (( a = red->red_receive ) == NULL ) {
	    printf( "\tNo Receive Methods\n" );
	} else {
	    do {
		printf( "\tR %d %d\n", a->a_action, a->a_flags );
		a = a->a_next;
	    } while ( a != NULL );
	}

	if (( a = red->red_expand ) == NULL ) {
	    printf( "\tNo Expand Methods\n" );
	} else {
	    do {
		printf( "\tE %d %d\n", a->a_action, a->a_flags );
		a = a->a_next;
	    } while ( a != NULL );
	}
	printf( "\n" );
    }

    return;
}


#ifdef HAVE_LDAP
    void
simta_red_close_ldap_dbs( void )
{
    struct simta_red		*red;
    struct action		*a;

    for ( red = simta_red_hosts; red != NULL; red = red->red_next ) {
	for ( a = red->red_receive; a != NULL; a = a->a_next ) {
	    if ( a->a_ldap != NULL ) {
		simta_ldap_unbind( a->a_ldap );
	    }
	}

	for ( a = red->red_expand; a != NULL; a = a->a_next ) {
	    if ( a->a_ldap != NULL ) {
		simta_ldap_unbind( a->a_ldap );
	    }
	}
    }

    return;
}
#endif /* HAVE_LDAP */


    struct simta_red *
simta_red_lookup_host( char *host_name )
{
    struct simta_red		*red;
    int				d;
    char			*dot = NULL;

    if ( simta_domain_trailing_dot != 0 ) {
	dot = host_name + strlen( host_name ) - 1;
	if ( *dot == '.' ) {
	    *dot = '\0';
	} else {
	    dot = NULL;
	}
    }

    for ( red = simta_red_hosts; red != NULL; red = red->red_next ) {
	if (( d = strcasecmp( host_name, red->red_host_name )) == 0 ) {
	    break;
	} else if ( d > 0 ) {
	    red = NULL;
	    break;
	}
    }

    if ( dot != NULL ) {
	*dot = '.';
    }

    return( red );
}


    /* this function only takes the RE of RED in to consideration at the
     * moment.  This will obviously change.
     */

    struct action *
simta_red_add_action( struct simta_red *red, int red_type, int action,
	char *fname )
{
    struct action		*a;
    struct action		**insert;
    int				flags = 0;

    switch ( red_type ) {
    case RED_CODE_R:
	flags = ACTION_SUFFICIENT;
	for ( insert = &(red->red_receive); *insert != NULL;
		insert = &((*insert)->a_next))
	    ;
	break;

    case RED_CODE_r:
	flags = ACTION_REQUIRED;
	for ( insert = &(red->red_receive); *insert != NULL;
		insert = &((*insert)->a_next))
	    ;
	break;

    case RED_CODE_E:
	for ( insert = &(red->red_expand); *insert != NULL;
		insert = &((*insert)->a_next))
	    ;
	break;

    default:
	syslog( LOG_ERR, "simta_red_add_expansion: invalid red_type" );
	return( NULL );
    }

    if (( a = (struct action*)malloc( sizeof( struct action )))
	    == NULL ) {
	syslog( LOG_ERR, "simta_red_add_expansion: malloc: %m" );
	return( NULL );
    }
    memset( a, 0, sizeof( struct action ));

    /* note that while we're still using an int payload in the expansion
     * structure, it might change in the future.  This would be a great
     * place to store information like LDAP settings to remote servers,
     * etc.
     */
    *insert = a;
    a->a_action = action;
    a->a_flags = flags;
    if ( fname != NULL ) {
	if (( a->a_fname = strdup( fname )) == NULL ) {
	    return( NULL );
	}
    }

    return( a );
}


    struct simta_red *
simta_red_add_host( char *host_name, int host_type )
{
    struct simta_red		*red;
    struct simta_red		**insert;
    int				d;

    switch ( host_type ) {
    case RED_HOST_TYPE_SECONDARY_MX:
	/* this might become a linked list in the future */
	if ( simta_secondary_mx != NULL ) {
	    syslog( LOG_ERR, "simta_red_create: multiple low pref MX hosts "
		    "not supported at this time" );
	    return( NULL );
	}

	if (( red = (struct simta_red*)malloc(
		sizeof( struct simta_red ))) == NULL ) {
	    syslog( LOG_ERR, "simta_red_create: malloc: %m" );
	    return( NULL );
	}
	memset( red, 0, sizeof( struct simta_red ));

	red->red_host_type = host_type;
	if (( red->red_host_name = strdup( host_name )) == NULL ) {
	    syslog( LOG_ERR, "simta_red_create: malloc: %m" );
	    free( red );
	    return( NULL );
	}

	simta_secondary_mx = red;
	break;

    case RED_HOST_TYPE_LOCAL:
	for ( insert = &simta_red_hosts; *insert != NULL;
		insert = &((*insert)->red_next )) {
	    if (( d = strcasecmp((*insert)->red_host_name, host_name )) == 0 ) {
		return( *insert );
	    } else if ( d < 0 ) {
		break;
	    }
	}

	if (( red = (struct simta_red*)malloc(
		sizeof( struct simta_red ))) == NULL ) {
	    syslog( LOG_ERR, "simta_red_create: malloc: %m" );
	    return( NULL );
	}
	memset( red, 0, sizeof( struct simta_red ));

	if (( red->red_host_name = strdup( host_name )) == NULL ) {
	    syslog( LOG_ERR, "simta_red_create: malloc: %m" );
	    free( red );
	}

	red->red_host_type = host_type;
	red->red_next = *insert;
	*insert = red;
	break;

    default:
	syslog( LOG_ERR, "simta_red_create: host type out of range" );
	free( red );
	return( NULL );
    }

    return( red );
}

    /* Default RED actions are:
     *     R ALIAS simta_default_alias_db
     *     E ALIAS simta_default_alias_db
     *     R PASSWORD simta_default_password_file
     *     E PASSWORD simta_default_password_file
     */

    int
simta_red_action_default( struct simta_red *red )
{
    if ( red->red_receive == NULL ) {
	if ( simta_red_add_action( red, RED_CODE_R,
		EXPANSION_TYPE_ALIAS, simta_default_alias_db ) == NULL ) {
	    return( -1 );
	}

	if ( simta_red_add_action( red, RED_CODE_R,
		EXPANSION_TYPE_PASSWORD, simta_default_passwd_file ) == NULL ) {
	    return( -1 );
	}
    }

    if ( red->red_expand == NULL ) {
	if ( simta_red_add_action( red, RED_CODE_E,
		EXPANSION_TYPE_ALIAS, simta_default_alias_db ) == NULL ) {
	    return( -1 );
	}

	if ( simta_red_add_action( red, RED_CODE_E,
		EXPANSION_TYPE_PASSWORD, simta_default_passwd_file ) == NULL ) {
	    return( -1 );
	}
    }

    if ( red->red_deliver_type == 0 ) {
	red->red_deliver_type = RED_DELIVER_BINARY;
    }

    return( 0 );
}
