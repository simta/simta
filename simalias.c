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

#include <snet.h>

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
#include <db.h>
#include <dirent.h>

#include "denser.h"
#include "ll.h"
#include "expand.h"
#include "red.h"
#include "envelope.h"
#include "simta.h"
#include "argcargv.h"
#include "dns.h"
#include "simta_ldap.h"
#include "bdb.h"
#include "queue.h"
#include "ml.h"

#ifdef HAVE_LDAP
#include <ldap.h>
#include "ldap.h"
#endif /* HAVE_LDAP */

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
    DB		*dbp;
    DBC		*dbcp;
    DBT		 key, data;
    int		 ret, close_db = 0, close_dbc = 0;

    if (( ret = db_open_r( &dbp, input, NULL )) != 0 ) {
	fprintf( stderr, "db_open_r: %s: %s\n", input, db_strerror( ret ));
	goto error;
    }
    close_db = 1;

    if (( ret = dbp->cursor( dbp, NULL, &dbcp, 0 )) != 0 ) {
	dbp->err(dbp, ret, "DB->cursor");
	goto error;
    }
    close_dbc = 1;

    memset( &key, 0, sizeof( key ));
    memset( &data, 0, sizeof(data ));

    while (( ret = dbcp->c_get( dbcp, &key, &data, DB_NEXT )) == 0 ) {
	printf("%s:\t\t%s\n", (char *)key.data, (char *)data.data);
    }
    if ( ret != DB_NOTFOUND ) {
	dbp->err(dbp, ret, "DBcursor->get");
	goto error;
    }

    if ( close_dbc && (( ret = dbcp->c_close( dbcp )) != 0 )) {
	    dbp->err(dbp, ret, "DBcursor->close");
	    goto error;
    }
    if ( close_db && (( ret = dbp->close( dbp, 0 )) != 0 )) {
	fprintf(stderr,
	    "%s: DB->close: %s\n", progname, db_strerror(ret));
	goto error;
    }

    return( 0 );

error:
    if ( close_dbc ) {
	dbcp->c_close( dbcp );
    }
    close_dbc = 0;
    if ( close_db ) {
	dbp->close( dbp, 0 );
    }
    close_db = 0;

    return( 1 );
}

    int
simalias_create( void )
{
    int			linenum = 0, ret, i;
    int			state = ALIAS_WHITE;
    char		line[ MAXPATHLEN ];
    char		key[ MAXPATHLEN ];
    char		value[ MAXPATHLEN ];
    char		*l;
    char		*p;
    char		*v;
    DB			*dbp = NULL;

    if (( ret = db_new( &dbp, DB_DUP, output, NULL, DB_HASH )) != 0 ) {
	fprintf( stderr, "db_new: %s: %s\n", output, db_strerror( ret ));
	return( 1 );
    }

    while ( fgets( line, MAXPATHLEN, finput ) != NULL ) {
	linenum++;

	/* Skip leading whitespace */
	for ( l = line; isspace( *l ) ; l++ );

	/* Blank line or comment */
	if (( *l == '\0' ) || ( *l == '#' )) {
	    continue;
	}

	/* Force lowercase */
	for ( p = l ; *p != '\0' ; p++ ) {
	    *p = tolower( *p );
	}

	if ( isspace( *line )) {
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
	    if (( v = strchr( l, ':' )) != NULL ) {
		*v = '\0';
		v++;

		if ( strncmp( l, "owner-", 6 ) == 0 ) {
		    /* Canonicalise sendmail-style owner */
		    if ( verbose ) {
			fprintf ( stderr, "%s line %d: noncanonical owner %s "
				"will be made canonical\n",
				input, linenum, l );
		    }
		    strncpy( key, l + 6, MAXPATHLEN - 8 );
		    strcat( key, "-errors" );
		} else if ((( p = strrchr( l, '-' )) != NULL ) &&
			(( strcmp( p, "-owner" ) == 0 ) ||
			( strcmp( p, "-owners" ) == 0 ) ||
			( strcmp( p, "-error" ) == 0 ) ||
			( strcmp( p, "-request" ) == 0 ) ||
			( strcmp( p, "-requests" ) == 0 ))) {
		    /* Canonicalise simta-style owner */
		    if ( verbose ) {
			fprintf ( stderr, "%s line %d: noncanonical owner %s "
				"will be made canonical\n",
				input, linenum, l );
		    }
		    *p = '\0';
		    strncpy( key, l, MAXPATHLEN - 8 );
		    strcat( key, "-errors" );
		} else {
		    strncpy( key, l, MAXPATHLEN - 1 );
		}
	    } else {
		fprintf( stderr,
			"%s line %d: Expected a colon somewhere. Skipping.\n",
			input, linenum );
		continue;
	    }

	    l = v;
	} else {
	    state = ALIAS_WHITE;
	}

	memset( value, 0, MAXPATHLEN );
	i = 0;
	for ( p = l ; *p != '\0' ; p++ ) {
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
		case ALIAS_QUOTE :
		    value[ i++ ] = *p;
		    break;
		case ALIAS_CONT :
		    fprintf( stderr, "%s line %d: Empty list element.\n",
			    input, linenum );
		    break;
		default :
		    state = ALIAS_CONT;
		}
	    } else if ( isspace( *p )) {
		switch ( state ) {
		case ALIAS_QUOTE :
		    value[ i++ ] = *p;
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
		value[ i++ ] = *p;
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
		} else if (( ret = db_put( dbp, key, value )) != 0 ) {
		    dbp->err( dbp, ret, "%s", value );
		    return( 1 );
		} else if ( verbose ) {
		    printf( "%s line %d: Added %s -> %s\n",
			    input, linenum, key, value );
		}

		memset( value, 0, MAXPATHLEN );
		i = 0;
	    }
	}
    }

    if (( ret = db_close( dbp )) != 0 ) {
	fprintf( stderr, "db_close failed: %s\n", db_strerror( ret ));
	return( 1 );
    }

    if ( verbose ) printf( "%s: created\n", output );

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
