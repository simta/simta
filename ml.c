/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*********            ml.c          **********/

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <sys/types.h>
#include <sys/wait.h>

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include <snet.h>

#include "ml.h"


char		*maillocalargv[] = { "mail.local", "-f", 0, "-d", "--", 0, 0 };
char		*maillocal =	"/usr/lib/mail.local";


    /* return 0 on success
     * <0 on syscall failure
     * >0 on recoverable failure, mail not delivered
     *
     * syslog errors before returning
     */

    int
mail_local( int f, char *sender, char *recipient )
{
    int			fd[ 2 ];
    int			pid;
    int			status;
    SNET		*snet;
    char		*line;

    if ( pipe( fd ) < 0 ) {
	syslog( LOG_ERR, "mail_local pipe: %m" );
	return( -1 );
    }

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "mail_local fork: %m" );
	return( -1 );

    case 0 :
	/* use fd[ 0 ] to communicate with parent, parent uses fd[ 1 ] */
	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_local close: %m" );
	    exit( -1 );
	}

	/* stdout -> fd[ 0 ] */
	if ( dup2( fd[ 0 ], 1 ) < 0 ) {
	    syslog( LOG_ERR, "mail_local dup2: %m" );
	    exit( -1 );
	}

	/* stderr -> fd[ 0 ] */
	if ( dup2( fd[ 0 ], 2 ) < 0 ) {
	    syslog( LOG_ERR, "mail_local dup2: %m" );
	    exit( -1 );
	}

	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_local close: %m" );
	    exit( -1 );
	}

	/* f -> stdin */
	if ( dup2( f, 0 ) < 0 ) {
	    syslog( LOG_ERR, "mail_local dup2: %m" );
	    exit( -1 );
	}

	maillocalargv[ 2 ] = sender;
	maillocalargv[ 5 ] = recipient;

	execv( maillocal, maillocalargv );
	/* if we are here, there is an error */
	syslog( LOG_ERR, "mail_local execv: %m" );
	exit( -1 );

    default :
	/* use fd[ 1 ] to communicate with child, child uses fd[ 0 ] */
	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_local close: %m" );
	    return( -1 );
	}

	if (( snet = snet_attach( fd[ 1 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    return( -1 );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    syslog( LOG_INFO, "mail_local %d: %s", pid, line );

#ifdef DEBUG
	    printf( "mail_local %d: %s\n", pid, line );
#endif /* DEBUG */
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "mail_local snet_close: %m" );
	    return( -1 );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    syslog( LOG_ERR, "mail_local waitpid: %m" );
	    return( -1 );
	}

	if ( WIFEXITED( status )) {
	    if ( WEXITSTATUS( status )) {
		syslog( LOG_ERR, "mail.local %d died %d\n", pid, 
			WEXITSTATUS( status ));
		return( 1 );

	    } else {
		syslog( LOG_INFO, "mail.local %d done\n", pid );
	    }
	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "mail.local %d died on signal %d\n", pid, 
		    WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "mail.local %d died\n", pid );
	    return( 1 );
	}
    }

    return( 0 );
}
