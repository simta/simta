/*
 * RFC's of interest:
 *
 * RFC 822  "Standard for the format of ARPA Internet text messages"
 * RFC 1123 "Requirements for Internet Hosts -- Application and Support"
 * RFC 2476 "Message Submission"
 * RFC 2822 "Internet Message Format"
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>

#include <snet.h>

#include "queue.h"
#include "line_file.h"
#include "envelope.h"
#include "header.h"
#include "simta.h"

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

void catch_sigint ___P(( int ));

/* dfile vars are global to unlink dfile if SIGINT */
int		dfile_fd = -1;
char		dfile_fname[ MAXPATHLEN ];


    /* catch SIGINT */

    void
catch_sigint( int sigint )
{
    if ( dfile_fd > 0 ) {
	unlink( dfile_fname );
    }

    exit( EX_TEMPFAIL );
}


    int
main( int argc, char *argv[] )
{
    SNET		*snet_stdin;
    char		*line;
    char		*wsp;
    struct line_file	*lf;
    struct line		*l;
    struct envelope	*env;
    int			usage = 0;
    int			line_no = 0;
    int			c;
    int			ignore_dot = 0;
    int			x;
    int			header;
    int			result;
    FILE		*dfile = NULL;
    int			read_headers = 0;
    int			pidfd;
    int			pid;
    FILE		*pf;

    /* ignore a good many options */
    opterr = 0;

    openlog( argv[ 0 ], 0, LOG_SIMTA );

    while (( c = getopt( argc, argv, "b:io:t" )) != -1 ) {
	switch ( c ) {
	case 'b':
	    if ( strlen( optarg ) == 1 ) {
		switch ( *optarg ) {
		case 'a':
		    /* -ba ARPANET mode */
		case 'd':
		    /* -bd Daemon mode, background */
		case 's':
		    /* 501 Permission denied */
		    printf( "501 Mode not supported\n" );
		    exit( EX_USAGE );
		    break;

		case 'D':
		    /* -bD Daemon mode, foreground */
		case 'i':
		    /* -bi init the alias db */
		case 'p':
		    /* -bp surmise the mail queue*/
		case 't':
		    /* -bt address test mode */
		case 'v':
		    /* -bv verify names only */
		    printf( "Mode not supported\n" );
		    exit( EX_USAGE );
		    break;

		case 'm':
		    /* -bm deliver mail the usual way */
		default:
		    /* ignore all other flags */
		    break;
		}
	    }
	    break;

	case 'i':
	    /* Ignore a single dot on a line as an end of message marker */
    	    ignore_dot = 1;
	    break;

	case 'o':
	    if ( strcmp( optarg, "i" ) == 0 ) {
		/* -oi ignore dots */
		ignore_dot = 1;
	    }
	    break;

	case 't':
	    /* Read message headers for recipients */
	    read_headers = 1;
	    break;

	default:
	    break;
	}
    }

    if ( usage != 0 ) {
	fprintf( stderr, "Usage: %s "
		"[ -b option ] "
		"[ -i ] "
		"[ -o option ] "
		"[ -t ] "
		"[[ -- ] to-address ...]\n", argv[ 0 ] );
	exit( EX_USAGE );
    }

    if (( read_headers == 0 ) && ( optind == argc )) {
	fprintf( stderr, "%s: no recipients\n", argv[ 0 ]);
	exit( EX_USAGE );
    }

    /* init simta config / defaults */
    if ( simta_config() != 0 ) {
	exit( EX_TEMPFAIL );
    }

    /* create envelope */
    if (( env = env_create( NULL )) == NULL ) {
	perror( "env_create" );
	exit( EX_TEMPFAIL );
    }

    if ( env_gettimeofday_id( env ) != 0 ) {
	perror( "gettimeofday" );
	exit( EX_TEMPFAIL );
    }

    env->e_mail = simta_sender();

    /* optind = first to-address */
    for ( x = optind; x < argc; x++ ) {
	if ( env_recipient( env, argv[ x ] ) != 0 ) {
	    perror( "malloc" );
	    exit( EX_TEMPFAIL );
	}
    }

    /* create line_file for headers */
    if (( lf = line_file_create()) == NULL ) {
	perror( "malloc" );
	exit( EX_TEMPFAIL );
    }

    /* need to read stdin in a line-oriented fashon */
    if (( snet_stdin = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( EX_TEMPFAIL );
    }

    /* start in header mode */
    header = 1;

    /* RFC 2822 2.1.1. Line Length Limits:
     * There are two limits that this standard places on the number of    
     * characters in a line. Each line of characters MUST be no more than   
     * 998 characters, and SHOULD be no more than 78 characters, excluding
     * the CRLF.
     */

    /* catch SIGINT and cleanup */
    if ( signal( SIGINT, catch_sigint ) == SIG_ERR ) {
	perror( "signal" );
	exit( EX_TEMPFAIL );
    }

    while (( line = snet_getline( snet_stdin, NULL )) != NULL ) {
	line_no++;

	if ( strlen( line ) > 998 ) {
	    fprintf( stderr, "%s: line %d too long\n", argv[ 0 ], line_no );

	    if ( header == 0 ) {
		goto cleanup;
	    }

	    exit( EX_DATAERR );
	}

	if ( ignore_dot == 0 ) {
	    if (( line[ 0 ] == '.' ) && ( line[ 1 ] =='\0' )) {
		/* single dot on a line */
		break;
	    }
	}

	if ( header == 1 ) {

	    if ( header_end( lf, line ) != 0 ) {
		if (( result = header_correct( read_headers, lf, env ))
			!= 0 ) {
		    if ( result > 0 ) {
			exit( EX_DATAERR );

		    } else {
			exit( EX_TEMPFAIL );
		    }
		}

		/* make sure we have a recipient */
		if ( env->e_rcpt == NULL ) {
		    fprintf( stderr, "%s: no recipients\n", argv[ 0 ]);
		    exit( EX_DATAERR );
		}

		/* open Dfile */
		sprintf( dfile_fname, "%s/D%s", SIMTA_DIR_LOCAL, env->e_id );

		if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT |
			O_EXCL, 0600 ))
			< 0 ) {
		    fprintf( stderr, "open %s: ", dfile_fname );
		    perror( NULL );
		    exit( EX_TEMPFAIL );
		}

		if (( dfile = fdopen( dfile_fd, "w" )) == NULL ) {
		    perror( "fdopen" );
		    goto cleanup;
		}

		/* print received stamp */
		if ( header_timestamp( env, dfile ) != 0 ) {
		    perror( "header_timestamp" );
		    fclose( dfile );
		    goto cleanup;
		}

		/* print headers to Dfile */
		if ( header_file_out( lf, dfile ) != 0 ) {
		    perror( "header_file_out" );
		    fclose( dfile );
		    goto cleanup;
		}

		/* insert a blank line if need be */
		if ( *line != '\0' ) {
		    fprintf( dfile, "\n" );
		}

		/* print line to Dfile */
		fprintf( dfile, "%s\n", line );
		header = 0;

	    } else {

		/* append line to headers if it's not whitespace */
		for ( wsp = line; *wsp != '\0'; wsp++ ) {
		    if (( *wsp != ' ' ) && ( *wsp != '\t' )) {
			if (( l = line_append( lf, line )) == NULL ) {
			    perror( "malloc" );
			    exit( EX_TEMPFAIL );
			}

			l->line_no = line_no;

			break;
		    }
		}
	    }

	} else {
	    /* print line to Dfile */
	    fprintf( dfile, "%s\n", line );
	}
    }

    if ( snet_close( snet_stdin ) != 0 ) {
	perror( "snet_close" );

	if ( dfile == NULL ) {
	    exit( EX_TEMPFAIL );

	} else {
	    fclose( dfile );
	    goto cleanup;
	}
    }

    if ( header == 1 ) {
	if (( result = header_correct( read_headers, lf, env ))
		!= 0 ) {
	    if ( result > 0 ) {
		exit( EX_DATAERR );

	    } else {
		exit( EX_TEMPFAIL );
	    }
	}

	/* open Dfile */
	sprintf( dfile_fname, "%s/D%s", SIMTA_DIR_LOCAL, env->e_id );

	if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT |
		O_EXCL, 0600 ))
		< 0 ) {
	    fprintf( stderr, "open %s: ", dfile_fname );
	    perror( NULL );
	    exit( EX_TEMPFAIL );
	}

	if (( dfile = fdopen( dfile_fd, "w" )) == NULL ) {
	    perror( "fdopen" );
	    goto cleanup;
	}

	/* print received stamp */
	if ( header_timestamp( env, dfile ) != 0 ) {
	    perror( "header_timestamp" );
	    goto cleanup;
	}

	/* print headers to Dfile */
	if ( header_file_out( lf, dfile ) != 0 ) {
	    perror( "header_file_out" );
	    fclose( dfile );
	    goto cleanup;
	}
    }

    /* close Dfile */
    if ( fclose( dfile ) != 0 ) {
	perror( "fclose" );
	goto cleanup;
    }

    /* store Efile */
    if ( env_outfile( env, SIMTA_DIR_LOCAL ) != 0 ) {
	perror( "env_outfile" );
	goto cleanup;
    }

    /* if possible, signal server */
    /* XXX add error message & logging */
    if (( pidfd = open( SIMTA_FILE_PID, O_RDONLY, 0 )) < 0 ) {
	return( 0 );
    }

    if (( pf = fdopen( pidfd, "r" )) == NULL ) {
	return( 0 );
    }

    fscanf( pf, "%d\n", &pid );

    if ( pid <= 0 ) {
	return( 0 );
    }

    if ( kill( pid, SIGUSR1 ) < 0 ) {
	return( 0 );
    }

    return( 0 );

cleanup:
    if ( dfile_fd > 0 ) {
	unlink( dfile_fname );
    }

    exit( EX_TEMPFAIL );
}
