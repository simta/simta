/**********          q_cleanup.c          **********/

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


int inode_compare( void *, void * );
void inode_stdout( void * );


    int
inode_compare( void *a, void *b )
{
    struct q_file		*qa;
    struct q_file		*qb;

    qa = (struct q_file*)a;
    qb = (struct q_file*)b;

    if ( qa->q_dfile_ino == qb->q_dfile_ino ) {
	return( 0 );
    } else if ( qa->q_dfile_ino > qb->q_dfile_ino ) {
	return( 1 );
    }
    return( -1 );
}


    void
inode_stdout( void *data )
{
    struct q_file		*q;

    q = (struct q_file*)data;

    printf( "INODE:\t%d\n", q->q_dfile_ino );

    while ( q != NULL ) {
	q_file_stdout( q );
	q = q->q_inode_next;
    }
}


    /* 1. move everything from FAST and LOCAL to SLOW:
     *     -collisions are fatal
     *
     * 2. examine SLOW:
     *     -clip t files
     *     -clip orphan D files
     *     -warn about orphan E files
     *     -warn about non t, E, or D files
     *
     * 3. for all pairs of E and D files:
     *     -if Dfile ref count > 1 and its Efile isn't expanded, clip all
     *         other Efile Dfile pairs that share the unexpanded Dfile's
     *         inode.
     */

    int
main( int argc, char *argv[] )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct q_file		*q;
    struct q_file		*q_inode;
    struct stab_entry		*file_stab = NULL;
    struct stab_entry		*inode_stab = NULL;
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

	} else if ( *entry->d_name == 't' ) {
	    /* clip orphan tfiles */
	    printf( "Clip tfile:\t%s/%s\n", SLOW_DIR, entry->d_name );
	} else {
	    /* not a tfile, Efile or Dfile */
	    printf( "Unknown file:\t%s/%s\n", SLOW_DIR, entry->d_name );
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	perror( "readdir" );
	return( 1 );
    }

    for ( st = file_stab; st != NULL; st = st->st_next ) {
	/* printf( "key:\t%s\n", st->st_key ); */
	q = (struct q_file*)st->st_data;

	if ( q->q_efile == 0 ) {
	    /* Dfile missing its Efile */
	    printf( "Clip orphan Dfile:\t%s/D%s\n", SLOW_DIR, q->q_id );

	} else if ( q->q_dfile == 0 ) {
	    /* Efile missing its Dfile */
	    printf( "Warning orphan Efile:\t%s/E%s\n", SLOW_DIR, q->q_id );

	} else {
	    /* get Dfile ref count */
	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( stat( fname, &sb ) != 0 ) {
		perror( "stat" );
		exit( 1 );
	    }

	    q->q_dfile_ino = sb.st_ino;
	    if (( q->q_dfile_nlink = sb.st_nlink ) > 1 ) {
		/* Insert inode stab here */
		if (( q_inode = ll__lookup( inode_stab, q, inode_compare ))
			== NULL ) {
		    if ( ll__insert( &inode_stab, q, inode_compare ) != 0 ) {
			perror( "ll__insert" );
			exit( 1 );
		    }

		} else {
		    q->q_inode_next = q_inode->q_inode_next;
		    q_inode->q_inode_next = q;
		}
	    }
	}
    }

    ll_walk( inode_stab, inode_stdout );

    return( 0 );
}
