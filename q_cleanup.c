/**********          q_cleanup.c          **********/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include <snet.h>

#include "ll.h"
#include "queue.h"
#include "envelope.h"


int	inode_compare ___P(( void *, void * ));
void	inode_stab_stdout ___P(( void * ));
int	move_to_slow ___P(( char * ));


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
inode_stab_stdout( void *data )
{
    struct q_file		*q;

    q = (struct q_file*)data;

    printf( "INODE:\t%ld\n", (long)q->q_dfile_ino );

    while ( q != NULL ) {
	q_file_stdout( q );
	q = q->q_inode_next;
    }

    printf( "\n" );
}


    /* move Efiles and Dfiles from dir to SLOW */

    int
move_to_slow( char *dir )
{
    DIR				*dirp;
    struct dirent		*entry;
    char			lname[ MAXPATHLEN ];
    char			fname[ MAXPATHLEN ];

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "opendir: %m" );
	return( 1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* examine a directory */
    while (( entry = readdir( dirp )) != NULL ) {

	/* ignore "." and ".." */
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
	    sprintf( fname, "%s/%s", dir, entry->d_name );
	    sprintf( lname, "%s/%s", SLOW_DIR, entry->d_name );

	    if ( link( fname, lname ) != 0 ) {
		syslog( LOG_ERR, "link %s %s: %m", fname, lname );
		return( 1 );
	    }

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "move\t%s %s\n", fname, lname );
#endif /* DEBUG */

	} else if ( *entry->d_name == 't' ) {
	    sprintf( fname, "%s/%s", dir, entry->d_name );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "unlink\t%s\n", fname );
#endif /* DEBUG */

	} else {
	    syslog( LOG_WARNING, "unknown file: %s/%s\n", dir, entry->d_name );

#ifdef DEBUG
	    printf( "Warning unknown file:\t%s/%s\n", dir, entry->d_name );
#endif /* DEBUG */
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "readdir %m" );
	return( 1 );
    }

    return( 0 );
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
    struct stab_entry		*st;
    struct stat			sb;
    char			fname[ MAXPATHLEN ];
    int				result;

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    if ( move_to_slow( FAST_DIR ) != 0 ) {
	return( 1 );
    }

    if ( move_to_slow( LOCAL_DIR ) != 0 ) {
	return( 1 );
    }

    if (( dirp = opendir( SLOW_DIR )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", SLOW_DIR );
	return( 1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* examine a directory */
    while (( entry = readdir( dirp )) != NULL ) {

	/* ignore "." and ".." */
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

		if (( q = q_file_char( entry->d_name + 1 )) == NULL ) {
		    syslog( LOG_ERR, "q_file_char: %m" );
		    exit( 1 );
		}

		if (( ll_insert( &file_stab, q->q_id, q, NULL ))
			!= 0 ) {
		    syslog( LOG_ERR, "ll_insert: %m" );
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
	    sprintf( fname, "%s/%s", SLOW_DIR, entry->d_name );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "unlink tfile:\t%s\n", fname );
#endif /* DEBUG */

	} else {
	    /* not a tfile, Efile or Dfile */
	    syslog( LOG_WARNING, "unknown file: %s/%s\n", SLOW_DIR,
		    entry->d_name );

#ifdef DEBUG
	    printf( "Warning unknown file:\t%s/%s\n", SLOW_DIR, entry->d_name );
#endif /* DEBUG */

	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "readdir: %m" );
	return( 1 );
    }

    for ( st = file_stab; st != NULL; st = st->st_next ) {
	q = (struct q_file*)st->st_data;

	if ( q->q_efile == 0 ) {
	    /* Dfile missing its Efile */
	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "unlink orphan Dfile:\t%s\n", fname );
#endif /* DEBUG */

	} else if ( q->q_dfile == 0 ) {
	    /* Efile missing its Dfile */
	    syslog( LOG_WARNING, "Missing Dfile: %s/D%s\n", SLOW_DIR, q->q_id );

#ifdef DEBUG
	    printf( "Warning orphan Efile:\t%s/E%s\n", SLOW_DIR, q->q_id );
#endif /* DEBUG */

	} else {
	    /* get Dfile ref count */
	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( stat( fname, &sb ) != 0 ) {
		syslog( LOG_ERR, "stat %s: %m", fname );
		exit( 1 );
	    }

	    q->q_dfile_ino = sb.st_ino;
	    if (( q->q_dfile_nlink = sb.st_nlink ) > 1 ) {
		/* Insert inode stab here */
		if (( q_inode = ll__lookup( inode_stab, q, inode_compare ))
			== NULL ) {
		    if ( ll__insert( &inode_stab, q, inode_compare ) != 0 ) {
			syslog( LOG_ERR, "ll__insert: %m" );
			exit( 1 );
		    }

		} else {
		    q->q_inode_next = q_inode->q_inode_next;
		    q_inode->q_inode_next = q;
		}
	    }
	}
    }

#ifdef DEBUG
    printf( "\n" );
    ll_walk( inode_stab, inode_stab_stdout );
#endif /* DEBUG */

    /* check to see if any Efiles haven't been expanded */
    for ( st = inode_stab; st != NULL; st = st->st_next ) {
	for ( q = (struct q_file*)st->st_data; q != NULL;
		q = q->q_inode_next ) {

	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if (( result = env_unexpanded( fname, &q->q_unexpanded )) < 0 ) {
		syslog( LOG_ERR, "env_unexpanded %s: %m", fname );
		exit( 1 );

	    } else if ( result > 0 ) {
		/* syntax error */
		syslog( LOG_WARNING, "file %s: syntax error", fname );

#ifdef DEBUG
		printf( "file %s: syntax error\n", fname );
#endif /* DEBUG */

		continue;
	    }

	    /* if an unexpanded envelope exists, delete all other
	     * envelopes that share the same inode.
	     */
	    if ( q->q_unexpanded == 1 ) {

#ifdef DEBUG
		printf( "Unexpanded envelope:\t%s\n", fname );
#endif /* DEBUG */

		for ( q = (struct q_file*)st->st_data; q != NULL;
			q = q->q_inode_next ) {
		    if ( q->q_unexpanded != 1 ) {

		    if ( unlink( fname ) != 0 ) {
			syslog( LOG_ERR, "unlink %s: %m", fname );
			return( 1 );
		    }

#ifdef DEBUG
		    printf( "unlink\t%s\n", fname );
#endif /* DEBUG */

		    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

		    if ( unlink( fname ) != 0 ) {
			syslog( LOG_ERR, "unlink %s: %m", fname );
			return( 1 );
		    }

#ifdef DEBUG
		    printf( "unlink\t%s\n", fname );
#endif /* DEBUG */

		    }
		}
		break;
	    }
	}
    }

    return( 0 );
}
