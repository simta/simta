/**********         nlist.c          ***********/
#include "config.h"
#include <sys/param.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>

#include <snet.h>

#include "denser.h"
#include "nlist.h"

#define	SPACECHARS	" \t"


    /* return -1 on syserror
     * return -1 if bad syntax
     * return 0 if nlist successfully read
     * return 1 if no nlist file, or bad syntax
     *
     * read lines in a file for lval/rval pairs.
     * lines may be blank, comments that start with '#', or a lval/rval
     * pair.
     */

    int
nlist( struct nlist *nl, char *fname )
{
    int			lineno = 0;
    int			errs = 0;
    int			fd;
    char		*line;
    char		*rval;
    char		*lval;
    SNET		*snet;
    struct nlist	*n;

    /* zero out nlist before reading */
    for ( n = nl; n->n_key != NULL; n++ ) {
	n->n_data = NULL;
	n->n_lineno = 0;
    }

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	if ( errno == ENOENT ) {
	    errno = 0;
	    return( 1 );

	} else {
	    fprintf( stderr, "nlist open %s: ", fname );
	    perror( NULL );
	    return( -1 );
	}
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	perror( "nlist snet_attach" );
	return( -1 );
    }

    while (( line = snet_getline( snet, NULL )) != NULL ) {
	lineno++;

	lval = strtok( line, SPACECHARS );

	if (( lval == NULL ) || ( *lval == '\0' ) || ( *lval == '#' )) {
	    /* blank line or comment */
	    continue;
	}

	for ( n = nl; n->n_key != NULL; n++ ) {
	    if ( strcmp( n->n_key, lval ) == 0 ) {
		if ( n->n_data != NULL ) {
		    /* duplicate entry in nlist file */
		    fprintf( stderr, "nlist %s line %d: "
			    "lval %s redefined from line %d\n", 
			    fname, lineno, n->n_key, n->n_lineno );
		    errs--;

		} else {
		    if (( rval = strtok( NULL, SPACECHARS )) == NULL ) { 
			fprintf( stderr, "nlist %s line %d: "
				"missing rval\n", fname, lineno );
			errs--;

		    } else {
			if (( n->n_data = strdup( rval )) == NULL ) {
			    perror( "nlist strdup" );
			    return( -1 );
			}

			n->n_lineno = lineno;
		    }
		}

		break;
	    }
	}

	if ( n->n_key == NULL ) {
	    fprintf( stderr, "nlist %s line %d unknown lval: %s\n", fname,
		    lineno, lval );
	    errs--;
	}

	if ( strtok( NULL, SPACECHARS ) != NULL ) {
	    fprintf( stderr, "nlist %s line %d: extra token\n", fname, lineno );
	    errs--;
	}
    }

    if ( snet_close( snet ) != 0 ) {
	perror( "nlist snet_close" );
	return( -1 );
    }

    return( errs );
}
