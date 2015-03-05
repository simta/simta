/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

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

#include <ctype.h>
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
#include <stdio.h>
#include <dirent.h>

#include <yasl.h>

#include "expand.h"
#include "red.h"
#include "envelope.h"
#include "simta.h"
#include "dns.h"
#include "simta_ldap.h"
#include "queue.h"
#include "ml.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */

#ifdef HAVE_LMDB
#include "simta_lmdb.h"
#endif /* HAVE_LMDB */

#define	    ALIAS_WHITE	0
#define	    ALIAS_CONT	1
#define	    ALIAS_WORD  2
#define	    ALIAS_QUOTE 3

int simalias_dump( void );
int simalias_create( void );

int		verbose = 0;
char		*input;
char		*output;
char		*progname;
FILE		*finput;
FILE		*foutput;

    int
main( int argc, char **argv )
{
    int			c, err = 0;
    int			dump = 0;
    extern char		*optarg;

    if (( progname = strrchr( argv[ 0 ], '/' )) == NULL ) {
	progname = argv[ 0 ];
    } else {
	progname++;      
    }

    while (( c = getopt( argc, argv, "di:o:v" )) != -1 ) {
	switch ( c ) {
	case 'd':
	    dump++;
	    break;

	case 'i':
	    input = optarg;
	    break;

	case 'o':
	    output = optarg;
	    break;

	case 'v':
	    verbose++;
	    break;

	default:
	    err++;
	}
    }

    if ( err ) {
	fprintf( stderr, "usage: %s ", progname );
	fprintf( stderr, "[ -d ] [ -i input-file ] [ -o output-file ]" );
	fprintf( stderr, "\n" );
	exit( 1 );
    }

    if ( simta_read_config( SIMTA_FILE_CONFIG ) < 0 ) {
	fprintf( stderr, "simta_read_config error: %s\n", SIMTA_FILE_CONFIG );
	exit( 1 );
    }

    /* Make sure error and verbose output are nicely synced */
    setbuf( stdout, NULL );

    if ( dump ) {
	if ( input == NULL ) {
	    input = simta_default_alias_db;
	}
	if ( output == NULL ) {
	    foutput = stdout;
	} else { 
	    if (( foutput = fopen( output, "r" )) == NULL ) {
		perror( output );
		exit( 1 );
	    }
	}
	exit( simalias_dump( ));

    } else {
	/* not dump */
	if (( input == NULL ) && ( strcmp( progname, "newaliases" ) == 0 )) {
	    input = simta_default_alias_file;
	}

	if ( input == NULL ) {
	    finput = stdin;
	} else {
	    if (( finput = fopen( input, "r" )) == NULL ) {
		perror( input );
		exit( 1 );
	    }
	}
	if ( output == NULL ) {
	    output = simta_default_alias_db;
	}
	exit( simalias_create( ));
    }
}

    int
simalias_dump( void )
{
    int ret = 0;
#ifdef HAVE_LMDB
    struct simta_dbh	*dbh = NULL;
    struct simta_dbc	*dbc = NULL;
    yastr		key = NULL, value = NULL;
    int			rc;

    ret = 1;

    if (( rc = simta_db_open_r( &dbh, input )) != 0 ) {
	fprintf( stderr, "simta_db_open_r: %s: %s\n", input,
		simta_db_strerror( rc ));
	goto error;
    }

    key = yaslempty( );
    value = yaslempty( );

    if (( rc = simta_db_cursor_open( dbh, &dbc )) != 0 ) {
	fprintf( stderr, "simta_db_cursor_open: %s: %s\n", input,
	    simta_db_strerror( rc ));
	goto error;
    }

    while (( rc = simta_db_cursor_get( dbc, &key, &value )) == 0 ) {
	printf( "%s:\t\t%s\n", key, value );
    }
    if ( rc != SIMTA_DB_NOTFOUND ) {
	fprintf( stderr, "simta_db_cursor_get: %s: %s\n", input,
		simta_db_strerror( rc ));
	goto error;
    }

    ret = 0;

error:
    yaslfree( key );
    yaslfree( value );
    simta_db_cursor_close( dbc );
    simta_db_close( dbh );
#endif /* HAVE_LMDB */

    return( ret );
}

    int
simalias_create( void )
{
    int			linenum = 0, i;
    int			state = ALIAS_WHITE;
    char		rawline[ MAXPATHLEN ];
    yastr		line, key, value;
    char		*p;
#ifdef HAVE_LMDB
    int			rc;
    struct simta_dbh	*dbh = NULL;
#endif /* HAVE_LMDB */

    unlink( output );    

#ifdef HAVE_LMDB
    if (( rc = simta_db_new( &dbh, output )) != 0 ) {
	fprintf( stderr, "simta_db_new: %s: %s\n", output,
		simta_db_strerror( rc ));
	return( 1 );
    }
#else /* HAVE_LMDB */
    fprintf( stderr, "Compiled without DB support, data will not be saved.\n" );
#endif /* HAVE_LMDB */

    line = yaslempty( );
    key = yaslempty( );
    value = yaslempty( );
    while ( fgets( rawline, MAXPATHLEN, finput ) != NULL ) {
	linenum++;

	line = yaslcpy( line, rawline );
	yasltrim( line, " \f\n\r\t\v" );

	/* Blank line or comment */
	if (( *line == '\0' ) || ( *line == '#' )) {
	    continue;
	}

	yasltolower( line );
	line = yaslcatlen( line, "\n", 1 );

	if ( isspace( *rawline )) {
	    if ( state == ALIAS_WHITE ) {
		/* How unexpected. */
		fprintf( stderr, "%s line %d: Unexpected continuation line.\n",
			input, linenum );
		state = ALIAS_CONT;
	    }
	} else if ( state == ALIAS_CONT ) {
	    fprintf( stderr, "%s line %d: Expected a continuation line.\n",
		    input, linenum );
	    state = ALIAS_WHITE;
	}

	if ( state == ALIAS_WHITE ) {
	    if (( p = strchr( line, ':' )) != NULL ) {
		key = yaslcpylen( key, line, p - line );
		yaslrange( line, p - line + 1, -1 );

		if ( strncmp( key, "owner-", 6 ) == 0 ) {
		    /* Canonicalise sendmail-style owner */
		    if ( verbose ) {
			fprintf ( stderr, "%s line %d: noncanonical owner %s "
				"will be made canonical\n",
				input, linenum, key );
		    }
		    yaslrange( key, 6, -1 );
		    key = yaslcat( key, "-errors" );
		} else if ((( p = strrchr( key, '-' )) != NULL ) &&
			(( strcmp( p, "-owner" ) == 0 ) ||
			( strcmp( p, "-owners" ) == 0 ) ||
			( strcmp( p, "-error" ) == 0 ) ||
			( strcmp( p, "-request" ) == 0 ) ||
			( strcmp( p, "-requests" ) == 0 ))) {
		    /* Canonicalise simta-style owner */
		    if ( verbose ) {
			fprintf ( stderr, "%s line %d: noncanonical owner %s "
				"will be made canonical\n",
				input, linenum, key );
		    }
		    yaslrange( key, 0, p - key );
		    key = yaslcat( key, "-errors" );
		}
	    } else {
		fprintf( stderr,
			"%s line %d: Expected a colon somewhere. Skipping.\n",
			input, linenum );
		continue;
	    }
	} else {
	    state = ALIAS_WHITE;
	}

	i = 0;
	yaslclear( value );
	for ( p = line ; *p != '\0' ; p++ ) {
	    if ( *p == '"' ) {
		if ( i > 0 && ( value[ i - 1 ] == '\\' )) {
		    value[ i - 1 ] = '"';
		} else if ( state == ALIAS_QUOTE ) {
		    state = ALIAS_WHITE;
		    if ( *value == '\0' ) {
			fprintf( stderr, "%s line %d: Empty quoted value.\n",
				input, linenum );
		    }
		} else if ( state == ALIAS_WORD ) {
		    fprintf( stderr, "%s line %d: Unexpected quote.\n",
			input, linenum );
		} else {
		    state = ALIAS_QUOTE;
		}
	    } else if ( *p == ',' ) {
		switch ( state ) {
		case ALIAS_QUOTE:
		    value = yaslcatlen( value, p, 1 );
		    break;
		case ALIAS_CONT:
		    fprintf( stderr, "%s line %d: Empty list element.\n",
			    input, linenum );
		    break;
		default :
		    state = ALIAS_CONT;
		}
	    } else if ( isspace( *p )) {
		switch ( state ) {
		case ALIAS_QUOTE:
		    value = yaslcatlen( value, p, 1 );
		    break;
		case ALIAS_WORD :
		    state = ALIAS_WHITE;
		    break;
		default :
		    break;
		}
	    } else {
		if ( state == ALIAS_WHITE || state == ALIAS_CONT ) {
		    state = ALIAS_WORD;
		}
		value = yaslcatlen( value, p, 1 );
	    }

	    if ( *value != '\0' &&
		    ( state == ALIAS_WHITE || state == ALIAS_CONT )) {

		/* Check for known but unsupported syntax */
		if ( *value == '/' ) {
		    /* We have special support for nullrouting, so that's OK. */
		    if ( strcmp( value, "/dev/null" ) != 0 ) {
			fprintf( stderr,
				"%s line %d: Unsupported: delivery to file\n",
				input, linenum );
		    }
		} else if ( *value == '|' ) {
		    fprintf( stderr, "%s line %d: Unsupported: delivery to pipe\n",
			    input, linenum );
		} else if ( strncmp( value, ":include:", 9 ) == 0 ) {
		    fprintf( stderr, "%s line %d: Unsupported: file include\n",
			    input, linenum );
#ifdef HAVE_LMDB
		} else if (( rc = simta_db_put( dbh, key, value )) != 0 ) {
		    fprintf( stderr, "simta_db_put: %s: %s\n", input,
			    simta_db_strerror( rc ));
		    return( 1 );
#endif /* HAVE_LMDB */
		} else if ( verbose ) {
		    printf( "%s line %d: Added %s -> %s\n",
			    input, linenum, key, value );
		}

		yaslclear( value );
		i = 0;
	    }
	}
    }

#ifdef HAVE_LMDB
    simta_db_close( dbh );
    if ( verbose ) printf( "%s: created\n", output );
#else /* HAVE_LMDB */
    if ( verbose ) printf( "%s: not created\n", output );
#endif /* HAVE_LMDB */

    yaslfree( line );
    yaslfree( key );
    yaslfree( value );

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
