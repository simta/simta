/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*********            ml.c          **********/
#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <netdb.h>

#include <snet.h>

#include "queue.h"
#include "envelope.h"
#include "ml.h"
#include "line_file.h"


char		*maillocal_argv[] = { "mail.local", "-f", 0, "--", 0, 0 };
char		*maillocal_bin = SIMTA_MAIL_LOCAL;

char		*procmail_argv[] = { "procmail", "-f", 0, "-d", 0, 0 };
char		*procmail_bin = SIMTA_PROCMAIL;

    int
(*get_local_mailer( void ))( int, char *, struct recipient * )
{
    if (( procmail_bin != NULL ) && ( *procmail_bin != '\0' )) {
	return( procmail );
    }

    if (( maillocal_bin != NULL ) && ( *maillocal_bin != '\0' )) {
	return( mail_local );
    }

    return( NULL );
}


    /* return 0 on success
     * return <0 on syscall failure
     * return >0 return code from procmail system binary
     *
     * syslog errors before returning
     */

    int
procmail( int f, char *sender, struct recipient *recipient )
{
    int			fd[ 2 ];
    int			pid;
    int			val;
    int			status;
    SNET		*snet;
    char		*line;
    char		*at;

    if (( procmail_bin == NULL ) || ( *procmail_bin == '\0' )) {
	syslog( LOG_ERR, "procmail not supported" );
	return( EX_TEMPFAIL );
    }

    if ( pipe( fd ) < 0 ) {
	syslog( LOG_ERR, "procmail pipe: %m" );
	return( EX_TEMPFAIL );
    }

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "procmail fork: %m" );
	return( EX_TEMPFAIL );

    case 0 :
	/* use fd[ 1 ] to communicate with parent, parent uses fd[ 0 ] */
	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "procmail close: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* stdout -> fd[ 1 ] */
	if ( dup2( fd[ 1 ], 1 ) < 0 ) {
	    syslog( LOG_ERR, "procmail dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* stderr -> fd[ 1 ] */
	if ( dup2( fd[ 1 ], 2 ) < 0 ) {
	    syslog( LOG_ERR, "procmail dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "procmail close: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* f -> stdin */
	if ( dup2( f, 0 ) < 0 ) {
	    syslog( LOG_ERR, "procmail dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	procmail_argv[ 2 ] = sender;

	if (( at = index( recipient->r_rcpt, '@' )) != NULL ) {
	    *at = '\0';
	    procmail_argv[ 4 ] = recipient->r_rcpt;
	} else {
	    procmail_argv[ 4 ] = "postmaster";
	}

	execv( procmail_bin, procmail_argv );
	/* if we are here, there is an error */
	syslog( LOG_ERR, "procmail execv: %m" );
	exit( EX_TEMPFAIL);

    default :
	/* use fd[ 0 ] to communicate with child, child uses fd[ 1 ] */
	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "procmail close: %m" );
	    return( EX_TEMPFAIL );
	}

	if (( snet = snet_attach( fd[ 0 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    close( fd[ 0 ] );
	    return( EX_TEMPFAIL );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    syslog( LOG_INFO, "procmail %d: %s", pid, line );

	    if ( recipient->r_err_text == NULL ) {
		if (( recipient->r_err_text = line_file_create()) == NULL ) {
		    syslog( LOG_ERR, "line_file_create: %m" );
		    snet_close( snet );
		    return( EX_TEMPFAIL );
		}
	    }

	    if ( line_append( recipient->r_err_text, line, COPY ) == NULL ) {
		syslog( LOG_ERR, "line_append: %m" );
		snet_close( snet );
		return( EX_TEMPFAIL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "procmail snet_close: %m" );
	    return( EX_TEMPFAIL );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    syslog( LOG_ERR, "procmail waitpid: %m" );
	    return( EX_TEMPFAIL );
	}

	if ( WIFEXITED( status )) {
	    if (( val = WEXITSTATUS( status )) == 0 ) {
		syslog( LOG_INFO, "procmail %d done\n", pid );

	    } else if ( val == EX_TEMPFAIL ) {
		syslog( LOG_WARNING, "procmail %d died %d EX_TEMPFAIL\n", pid,
			val );

	    } else {
		syslog( LOG_WARNING, "procmail %d died %d\n", pid, val );
	    }

	    return( val );

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "procmail %d died on signal %d\n", pid, 
		    WTERMSIG( status ));
	    return( EX_TEMPFAIL);

	} else {
	    syslog( LOG_ERR, "procmail %d died\n", pid );
	    return( EX_TEMPFAIL);
	}
    }
}


    /* return 0 on success
     * return <0 on syscall failure
     * return >0 return code from mail.local system binary
     *
     * syslog errors before returning
     */

    int
mail_local( int f, char *sender, struct recipient *recipient )
{
    int			fd[ 2 ];
    int			pid;
    int			val;
    int			status;
    SNET		*snet;
    char		*line;
    char		*at;

    if (( maillocal_bin == NULL ) || ( *maillocal_bin == '\0' )) {
	syslog( LOG_WARNING, "mail.local not supported" );
	return( EX_TEMPFAIL );
    }

    if ( pipe( fd ) < 0 ) {
	syslog( LOG_ERR, "mail_local pipe: %m" );
	return( EX_TEMPFAIL );
    }

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "mail_local fork: %m" );
	return( EX_TEMPFAIL );

    case 0 :
	/* use fd[ 0 ] to communicate with parent, parent uses fd[ 1 ] */
	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_local close: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* stdout -> fd[ 0 ] */
	if ( dup2( fd[ 0 ], 1 ) < 0 ) {
	    syslog( LOG_ERR, "mail_local dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* stderr -> fd[ 0 ] */
	if ( dup2( fd[ 0 ], 2 ) < 0 ) {
	    syslog( LOG_ERR, "mail_local dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_local close: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* f -> stdin */
	if ( dup2( f, 0 ) < 0 ) {
	    syslog( LOG_ERR, "mail_local dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	maillocal_argv[ 2 ] = sender;
	maillocal_argv[ 4 ] = recipient->r_rcpt;

	if (( at = index( recipient->r_rcpt, '@' )) != NULL ) {
	    *at = '\0';
	    maillocal_argv[ 4 ] = recipient->r_rcpt;
	} else {
	    maillocal_argv[ 4 ] = "postmaster";
	}

	execv( maillocal_bin, maillocal_argv );
	/* if we are here, there is an error */
	syslog( LOG_ERR, "mail_local execv: %m" );
	exit( EX_TEMPFAIL);

    default :
	/* use fd[ 1 ] to communicate with child, child uses fd[ 0 ] */
	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "mail_local close: %m" );
	    return( EX_TEMPFAIL );
	}

	if (( snet = snet_attach( fd[ 1 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    return( EX_TEMPFAIL );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    syslog( LOG_INFO, "mail.local %d: %s", pid, line );

	    if ( recipient->r_err_text == NULL ) {
		if (( recipient->r_err_text = line_file_create()) == NULL ) {
		    syslog( LOG_ERR, "line_file_create: %m" );
		    return( EX_TEMPFAIL );
		}
	    }

	    if ( line_append( recipient->r_err_text, line, COPY ) == NULL ) {
		syslog( LOG_ERR, "line_append: %m" );
		return( EX_TEMPFAIL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "mail_local snet_close: %m" );
	    return( EX_TEMPFAIL );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    syslog( LOG_ERR, "mail_local waitpid: %m" );
	    return( EX_TEMPFAIL );
	}

	if ( WIFEXITED( status )) {
	    if (( val = WEXITSTATUS( status )) == 0 ) {
		syslog( LOG_INFO, "mail.local %d done\n", pid );

	    } else if ( val == EX_TEMPFAIL ) {
		syslog( LOG_WARNING, "mail.local %d died %d EX_TEMPFAIL\n", pid,
			val );

	    } else {
		syslog( LOG_WARNING, "mail.local %d died %d\n", pid, val );
	    }

	    return( val );

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "mail.local %d died on signal %d\n", pid, 
		    WTERMSIG( status ));
	    return( EX_TEMPFAIL);

	} else {
	    syslog( LOG_ERR, "mail.local %d died\n", pid );
	    return( EX_TEMPFAIL);
	}
    }
}
