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

#include <snet.h>

#include "line_file.h"
#include "envelope.h"
#include "header.h"

/* XXX need for FAST_DIR.  really need a simta.h */
#include "queue.h"

#define	TEST_DIR	"local"

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */


    int
main( int argc, char *argv[] )
{
    SNET		*snet_stdin;
    char		*line;
    struct line_file	*lf;
    struct line		*l;
    struct envelope	*env;
    int			usage = 0;
    int			c;
    int			ignore_dot = 0;
    int			x;
    int			header;
    int			dfile_fd;
    char		dfile_fname[ MAXPATHLEN ];
    FILE		*dfile = NULL;

    /* ignore a good many options */
    opterr = 0;

    while (( c = getopt( argc, argv, "b:io:" )) != -1 ) {
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
		    exit( 1 );
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
		    exit( 1 );
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

	default:
	    /* XXX log command line options we don't understand? */
	    break;
	}
    }

    if ( usage != 0 ) {
	fprintf( stderr, "Usage: %s "
		"[ -b option ] "
		"[ -i ] "
		"[ -o option ] "
		"[[ -- ] to-address ...]\n", argv[ 0 ] );
	exit( 1 );
    }

    /* create envelope */
    if (( env = env_create( NULL )) == NULL ) {
	perror( "env_create" );
	exit( 1 );
    }

    if ( env_gettimeofday_id( env ) != 0 ) {
	perror( "env_gettimeofday_id" );
	exit( 1 );
    }

    /* optind = first to-address */
    for ( x = optind; x < argc; x++ ) {
	if ( env_recipient( env, argv[ x ] ) != 0 ) {
	    perror( "env_recipient" );
	    exit( 1 );
	}
    }

    /* create line_file for headers */
    if (( lf = line_file_create()) == NULL ) {
	perror( "line_file_create" );
	exit( 1 );
    }

    /* need to read stdin in a line-oriented fashon */
    if (( snet_stdin = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    /* start in header mode */
    header = 1;

    /* XXX RFC 2822 2.1.1. Line Length Limits
     * There are two limits that this standard places on the number of    
     * characters in a line. Each line of characters MUST be no more than   
     * 998 characters, and SHOULD be no more than 78 characters, excluding
     * the CRLF.
     */

    while (( line = snet_getline( snet_stdin, NULL )) != NULL ) {
	if ( ignore_dot == 0 ) {
	    if (( line[ 0 ] == '.' ) && ( line[ 1 ] =='\0' )) {
		/* single dot on a line */
		break;
	    }
	}

	if ( header == 1 ) {
	    if ( header_end( lf, line ) != 0 ) {
		if ( header_correct( lf, env ) != 0 ) {
		    exit( 1 );
		}

		/* open Dfile */
		sprintf( dfile_fname, "%s/D%s", FAST_DIR, env->e_id );

		if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT |
			O_EXCL, 0600 ))
			< 0 ) {
		    fprintf( stderr, "open %s: ", dfile_fname );
		    perror( NULL );
		    return( -1 );
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
		if (( l = line_append( lf, line )) == NULL ) {
		    perror( "line_append" );
		    exit( 1 );
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
	    exit( 1 );

	} else {
	    fclose( dfile );
	    goto cleanup;
	}
    }

    if ( header == 1 ) {
	if ( header_correct( lf, env ) != 0 ) {
	    exit( 1 );
	}

	/* open Dfile */
	sprintf( dfile_fname, "%s/D%s", FAST_DIR, env->e_id );

	if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT |
		O_EXCL, 0600 ))
		< 0 ) {
	    fprintf( stderr, "open %s: ", dfile_fname );
	    perror( NULL );
	    return( -1 );
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
    if ( env_outfile( env, FAST_DIR ) != 0 ) {
	perror( "env_outfile" );
	goto cleanup;
    }

    return( 0 );

cleanup:
    unlink( dfile_fname );

    return( -1 );
}
