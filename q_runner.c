#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "ll.h"
#include "queue.h"

void file_stab_stdout( void * );


    void
file_stab_stdout( void *data )
{
    struct q_file		*q;

    q = (struct q_file*)data;

    q_file_stdout( q );

    printf( "\n" );
}


    int
main( int argc, char *argv[] )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct q_file		*q;
    struct stab_entry		*file_stab = NULL;
    struct stab_entry		*valid_stab = NULL;
    struct stab_entry		*st = NULL;
    struct stat			sb;
    char			fname[ MAXPATHLEN ];

    if (( dirp = opendir( SLOW_DIR )) == NULL ) {
	fprintf( stderr, "opendir: %s: ", SLOW_DIR );
	perror( NULL );
	return( 1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* examine a directory */
    while (( entry = readdir( dirp )) != NULL ) {

	/* ignore '.' and '..' */
	if ( entry->d_name[ 0 ] == '.' ) {
	    if ( entry->d_name[ 1 ] == '\0' ) {
		continue;
	    } else if ( entry->d_name[ 1 ] == '.' ) {
		if ( entry->d_name[ 2 ] == '\0' ) {
		    continue;
		}
	    }
	}

	if (( *entry->d_name == 'E' ) || ( *entry->d_name == 'D' )) {
	    if (( q = (struct q_file*)
		    ll_lookup( file_stab, entry->d_name + 1 )) == NULL ) {

		if (( q = q_file_create( entry->d_name + 1 )) == NULL ) {
		    perror( "q_file_create" );
		    exit( 1 );
		}

		if (( ll_insert( &file_stab, q->q_id, q, NULL ))
			!= 0 ) {
		    perror( "ll_insert" );
		    exit( 1 );
		}
	    }

	    if ( *entry->d_name == 'E' ) {
		q->q_efile++;
	    } else {
		q->q_dfile++;
	    }

	} else {
	    /* XXX not an efile or a dfile */
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	perror( "readdir" );
	return( 1 );
    }

    /* ll_walk( file_stab, file_stab_stdout ); */

    for ( st = file_stab; st != NULL; st = st->st_next ) {
	/* printf( "key:\t%s\n", st->st_key ); */
	q = (struct q_file*)st->st_data;

	if (( q->q_efile != 1 ) || ( q->q_dfile != 1 )) {
	    /* XXX q is missing either its efile or dfile */
	    /* printf( "XXXfile:\t%s\n", q->q_id ); */

	} else {
	    /* get efile modification time */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( stat( fname, &sb ) != 0 ) {
		perror( "stat" );
		exit( 1 );
	    }

	    q->q_etime = sb.st_mtimespec;

	    if (( ll_insert( &valid_stab, q->q_id, q, NULL )) != 0 ) {
		perror( "ll_insert" );
		exit( 1 );
	    }
	}
    }

    ll_walk( valid_stab, file_stab_stdout );

    return( 0 );
}
