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
#include <string.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "queue.h"
#include "envelope.h"
#include "ml.h"
#include "line_file.h"
#include "simta.h"


char		*maillocal_argv[] = { SIMTA_MAIL_LOCAL,
					    "-f", "$S", "--", "$R", 0 };
char		*procmail_argv[] = { SIMTA_PROCMAIL,
					    "-f", "$S", "-d", "$R", 0 };

    int
set_local_mailer( void )
{
    if ( simta_deliver_default_argc != 0 ) {
	return( 0 );
    }

    if (( procmail_argv[ 0 ] != NULL ) && ( *(procmail_argv[ 0 ]) != '\0' )) {
	simta_deliver_default_argv = procmail_argv;
	simta_deliver_default_argc = 5;
	return( 0 );
    }

    if (( maillocal_argv[ 0 ] != NULL ) && ( *(maillocal_argv[ 0 ]) != '\0' )) {
	simta_deliver_default_argv = maillocal_argv;
	simta_deliver_default_argc = 5;
	return( 0 );
    }

    syslog( LOG_ERR, "no local mailer defined" );
    return( 1 );
}


    /* return 0 on success
     * return <0 on syscall failure
     * return >0 return code from binary program
     *
     * syslog errors before returning
     */

    int
deliver_binary( struct deliver *d )
{
    int			x;
    int			fd[ 2 ];
    int			pid;
    int			val;
    int			status;
    SNET		*snet;
    char		*slash;
    char		*line;
    char		*recipient;
    char		*at;
    char		*binary;
    char		*domain = "NULL";

    if ( pipe( fd ) < 0 ) {
	syslog( LOG_ERR, "deliver_binary pipe: %m" );
	return( EX_TEMPFAIL );
    }

    simta_gettimeofday( NULL );

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "deliver_binary fork: %m" );
	return( EX_TEMPFAIL );

    case 0 :
	simta_openlog( 1 );
	/* use fd[ 0 ] to communicate with parent, parent uses fd[ 1 ] */
	if ( close( fd[ 1 ] ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary close: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* stdout -> fd[ 0 ] */
	if ( dup2( fd[ 0 ], 1 ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* stderr -> fd[ 0 ] */
	if ( dup2( fd[ 0 ], 2 ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary close: %m" );
	    exit( EX_TEMPFAIL);
	}

	/* f -> stdin */
	if ( dup2( d->d_dfile_fd, 0 ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary dup2: %m" );
	    exit( EX_TEMPFAIL);
	}

	recipient = d->d_rcpt->r_rcpt;

	if (( at = strchr( recipient, '@' )) != NULL ) {
	    *at = '\0';
	    domain = at + 1;
	} else {
	    recipient = STRING_POSTMASTER;
	    domain = at + 1;
	}

	binary = d->d_deliver_argv[ 0 ];
	if (( slash = strrchr( binary, '/' )) != NULL ) {
	    d->d_deliver_argv[ 0 ] = slash;
	}

	/* variable replacement on the args */
	for ( x = 1; x < d->d_deliver_argc; x++ ) {
	    if ( *(d->d_deliver_argv[ x ]) == '$' ) {
		switch ( *(d->d_deliver_argv[ x ] + 1 )) {
		/* $S Sender */
		case 'S':
		    if ( *(d->d_deliver_argv[ x ] + 2 ) == '\0' ) {
			d->d_deliver_argv[ x ] = d->d_env->e_mail;
		    }
		    break;

		/* $R Recipient */
		case 'R':
		    if ( *(d->d_deliver_argv[ x ] + 2 ) == '\0' ) {
			d->d_deliver_argv[ x ] = recipient;
		    }
		    break;

		/* $D Domain */
		case 'D':
		    if ( *(d->d_deliver_argv[ x ] + 2 ) == '\0' ) {
			d->d_deliver_argv[ x ] = domain;
		    }
		    break;

		default:
		    /* unsupported option? */
		    break;
		}
	    }
	}

	execv( binary, d->d_deliver_argv );
	/* if we are here, there is an error */
	syslog( LOG_ERR, "deliver_binary execv: %m" );
	exit( EX_TEMPFAIL);

    default :
	/* use fd[ 1 ] to communicate with child, child uses fd[ 0 ] */
	if ( close( fd[ 0 ] ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary close: %m" );
	    return( EX_TEMPFAIL );
	}

	if (( snet = snet_attach( fd[ 1 ], 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    return( EX_TEMPFAIL );
	}

	while (( line = snet_getline( snet, NULL )) != NULL ) {
	    syslog( LOG_NOTICE, "mail.local %d: %s", pid, line );

	    if ( d->d_rcpt->r_err_text == NULL ) {
		if (( d->d_rcpt->r_err_text = line_file_create()) == NULL ) {
		    syslog( LOG_ERR, "line_file_create: %m" );
		    snet_close( snet );
		    return( EX_TEMPFAIL );
		}
	    }

	    if ( line_append( d->d_rcpt->r_err_text, line, COPY ) == NULL ) {
		syslog( LOG_ERR, "line_append: %m" );
		snet_close( snet );
		return( EX_TEMPFAIL );
	    }
	}

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "deliver_binary snet_close: %m" );
	    return( EX_TEMPFAIL );
	}

	if (( waitpid( pid, &status, 0 ) < 0 ) && ( errno != ECHILD )) {
	    syslog( LOG_ERR, "deliver_binary waitpid: %m" );
	    return( EX_TEMPFAIL );
	}

	if ( WIFEXITED( status )) {
	    if (( val = WEXITSTATUS( status )) == 0 ) {
		syslog( LOG_NOTICE, "mail.local %d done\n", pid );

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
