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
#include <unistd.h>
#include <errno.h>

#include <snet.h>

#include "ml.h"


char		*maillocalargv[] = { "mail.local", 0, 0 };
char		*maillocal =	"/usr/lib/mail.local";


    int
mail_local( char *recipient, SNET *snet )
{
    int			fd[ 2 ];
    int			pid;
    FILE		*fp;
    int			status;
    char		*line;

    if ( pipe( fd ) < 0 ) {
	perror( "pipe" );
	exit( 1 );
    }

    switch ( pid = fork()) {
    case -1 :
	perror( "fork" );
	exit( 1 );

    case 0 :
	if ( close( fd[ 1 ] ) < 0 ) {
	    perror( "close" );
	    exit( 1 );
	}

	if ( dup2( fd[ 0 ], 0 ) < 0 ) {
	    perror( "dup2" );
	    exit( 1 );
	}

	if ( close( fd[ 0 ] ) < 0 ) {
	    perror( "close" );
	    exit( 1 );
	}

	maillocalargv[ 1 ] = recipient;

	execv( maillocal, maillocalargv );
	/* if we are here, there is an error */
	perror( "execv" );
	exit( 1 );

    default :
	if ( close( fd[ 0 ] ) < 0 ) {
	    perror( "close" );
	    exit( 1 );
	}

	if (( fp = fdopen( fd[ 1 ], "w" )) == NULL ) {
	    perror( "fdopen" );
	    exit( 1 );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    fprintf( fp, "%s\n", line );
	}

	errno = 0;

	if (( fclose( fp ) != 0 ) || ( errno != 0 )) {
	    perror( "fclose" );
	    exit( 1 );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    perror( "waitpid" );
	    exit( 1 );
	}

	if ( WIFEXITED( status )) {
	    if ( WEXITSTATUS( status )) {
		fprintf( stderr, "mail.local %d dies with %d\n", pid, 
			WEXITSTATUS( status ));
	    } else {
		printf( "mail.local %d done\n", pid );
	    }
	} else if ( WIFSIGNALED( status )) {
	    fprintf( stderr, "mail.local %d died on signal %d\n", pid, 
		    WTERMSIG( status ));
	} else {
	    fprintf( stderr, "mail.local %d died\n", pid );
	}
    }

    return( 0 );
}
