/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*********            ml.c          **********/

#include <sys/types.h>
#include <sys/wait.h>

#include <stdio.h>
#include <unistd.h>
#include <errno.h>


#include "ml.h"


char		*maillocalargv[] = { "mail.local", "-f", "epcjr@umich.edu",
			"epcjr", 0 };
char		*maillocal =	"/usr/lib/mail.local";


    int
mail_local( void )
{
    int			fd[ 2 ];
    int			pid;
    FILE		*fp;
    int			status;

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

	/* From sender-address time-stamp */
	//fprintf( fp, "From epcjr@umich.edu Fri Apr  4 00:50:00 2003\n" );

	fprintf( fp, "\n" );
	fprintf( fp, "TEST\n" );

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
