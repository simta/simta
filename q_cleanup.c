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
#include "simta.h"


struct q_file {
    char			*q_id;
    char			*q_expanded;
    struct q_file		*q_inode_next;
    struct q_file		*q_etime_next;
    struct envelope		*q_env;
    struct message_data		*q_data;
    int				q_action;
    int				q_unexpanded;
    int				q_efile;
    int				q_dfile;
    ino_t			q_dfile_ino;
    nlink_t			q_dfile_nlink;
    struct timespec		q_dtime;
    struct timespec		*q_etime;
};


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
	    sprintf( lname, "%s/%s", SIMTA_DIR_SLOW, entry->d_name );

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

    if ( move_to_slow( SIMTA_DIR_FAST ) != 0 ) {
	return( 1 );
    }

    if ( move_to_slow( SIMTA_DIR_LOCAL ) != 0 ) {
	return( 1 );
    }

    if (( dirp = opendir( SIMTA_DIR_SLOW )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", SIMTA_DIR_SLOW );
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
	    sprintf( fname, "%s/%s", SIMTA_DIR_SLOW, entry->d_name );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "unlink tfile:\t%s\n", fname );
#endif /* DEBUG */

	} else {
	    /* not a tfile, Efile or Dfile */
	    syslog( LOG_WARNING, "unknown file: %s/%s\n", SIMTA_DIR_SLOW,
		    entry->d_name );

#ifdef DEBUG
	    printf( "Warning unknown file:\t%s/%s\n", SIMTA_DIR_SLOW, entry->d_name );
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
	    sprintf( fname, "%s/D%s", SIMTA_DIR_SLOW, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		return( 1 );
	    }

#ifdef DEBUG
	    printf( "unlink orphan Dfile:\t%s\n", fname );
#endif /* DEBUG */

	} else if ( q->q_dfile == 0 ) {
	    /* Efile missing its Dfile */
	    syslog( LOG_WARNING, "Missing Dfile: %s/D%s\n", SIMTA_DIR_SLOW,
		    q->q_id );

#ifdef DEBUG
	    printf( "Warning orphan Efile:\t%s/E%s\n", SIMTA_DIR_SLOW,
		    q->q_id );
#endif /* DEBUG */

	} else {
	    /* get Dfile ref count */
	    sprintf( fname, "%s/D%s", SIMTA_DIR_SLOW, q->q_id );

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

	    sprintf( fname, "%s/E%s", SIMTA_DIR_SLOW, q->q_id );

	    if (( result = env_unexpanded( fname, &q->q_unexpanded )) < 0 ) {
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

		    sprintf( fname, "%s/D%s", SIMTA_DIR_SLOW, q->q_id );

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


    /*
     * 1. Clean SLOW queue:
     *	    - Delete all orphan Dfiles & tfiles
     *	    - Warn about orphan Efiles & unknown files
     *	    - Build list of valid Efile/Dfile pairs
     *
     * 2. Clean LOCAL queue:
     *	    - Delete all orphan Dfiles & tfiles
     *	    - Warn about orphan Efiles & unknown files
     *	    - Build list of valid Efile/Dfile pairs
     *
     * 3. Move LOCAL queue:
     *	    - Move all messages to SLOW, if collision delete LOCAL copy
     *
     * 4. Clean FAST queue:
     *	    - Delete all orphan Dfiles & tfiles
     *	    - Warn about orphan Efiles & unknown files
     *	    - Build list of valid Efile/Dfile pairs
     *
     * 5. Move FAST queue:
     *	    - Move all messages to SLOW, if collision delete FAST copy
     *
     * 6. for all Dfiles in SLOW:
	    if ( Dfile_ref_count > 1 ) {
		if ( Efile == EXPANDED ) {
		    if ( matching_inode_list == EXPANDED ) {
			add to matching_inode_list;
		    } else {
			delete message;
		    }
		} else {
		    delete all messages in matching_inodes_list;
		    add to matching_inodes_list;
		}
	    }
     */

    /* call openlog() before this function */

int	q_clean ___P(( char *, struct message ** ));
int	move_to_slow ___P(( struct message **, struct message ** ));


    int
q_cleanup( void )
{
    struct message		*slow = NULL;
    struct message		*other = NULL;

    if ( q_clean( SIMTA_DIR_SLOW, &slow ) != 0 ) {
	return( -1 );
    }

    if ( q_clean( SIMTA_DIR_LOCAL, &other ) != 0 ) {
	return( -1 );
    }

    if ( move_to_slow( &slow, &other ) != 0 ) {
	return( -1 );
    }

    /* XXX debug check for NULL? */
    other = NULL;

    if ( q_clean( SIMTA_DIR_FAST, &other ) != 0 ) {
	return( -1 );
    }

    if ( move_to_slow( &slow, &other ) != 0 ) {
	return( -1 );
    }

    /* XXX */

    return( 0 );
}


    int
move_to_slow( struct messages **slow_q, struct messages **other_q )
{
    struct message		*m;	
    struct message		**slow;
    int				result;
    char			d_original[ MAXPATHLEN ];
    char			e_original[ MAXPATHLEN ];
    char			d_slow[ MAXPATHLEN ];
    char			e_slow[ MAXPATHLEN ];

    slow = slow_q;

    while (( m = *other_q ) != NULL ) {
	*other_q = m->m_next;

	for ( ; ; ) {
	    if (( *slow != NULL ) && (( result = strcmp( m->m_id,
		    (*slow)->m_id )) > 0 )) {
		*slow = (*slow)->m_next;

	    } else {
		sprintf( d_original, "%s/D%s", m->m_dir, m->m_id );
		sprintf( e_original, "%s/E%s", m->m_dir, m->m_id );

		if (( *slow == NULL ) || ( result != 0 )) {
		    /* move message files to SLOW */
		    sprintf( d_slow, "%s/D%s", SIMTA_DIR_SLOW, m->m_id );
		    sprintf( e_slow, "%s/E%s", SIMTA_DIR_SLOW, m->m_id );

		    if ( link( d_original, d_slow != 0 ) {
			fprintf( stderr, "move_to_slow link %s %s: ",
				d_original, d_slow );
			perror( NULL );
			return( -1 );
		    }

		    if ( link( e_original, e_slow != 0 ) {
			fprintf( stderr, "move_to_slow link %s %s: ",
				e_original, e_slow );
			perror( NULL );
			return( -1 );
		    }

		    /* insert node */
		    m->m_next = *slow;
		    m->m_dir = SIMTA_DIR_SLOW;
		    *slow = m;
		    slow = &(m->m_next);

		} else {
		    /* collision - delete message files from other_q */
		    message_free( m );
		}

		if ( unlink( e_original ) != 0 ) {
		    fprintf( stderr, "move_to_slow unlink %s: ", e_original );
		    perror( NULL );
		    return( -1 );
		}

		if ( unlink( d_original ) != 0 ) {
		    fprintf( stderr, "move_to_slow unlink %s: ", e_original );
		    perror( NULL );
		    return( -1 );
		}

		break;
	    }
	}
    }

    return( 0 );
}


    int
q_clean( char *dir, struct message **messages )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct message		*mp;
    char			fname[ MAXPATHLEN ];

    if (( dirp = opendir( dir )) == NULL ) {
	fprintf( stderr, "q_clean opendir %s: ", dir );
	perror( NULL );
	return( -1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* start from scratch */
    *messages = NULL;

    /*
     * foreach file in dir:
     *	    - ignore "." && ".."
     *	    - add message info for "D*" || "E*"
     *	    - delete "t*"
     *	    - warn anything else
     */

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
	    mp = messages; 

	    for ( ; ; ) {
		if (( *mp == NULL ) || (( result = strcmp( entry->d_name + 1,
			(*mp)->m_id )) <= 0 )) {
		    if ( result != 0 ) {
			if (( m = message_create( entry->d_name + 1 ))
				== NULL ) {
			    perror( "malloc" );
			    return( -1 );
			}

			m->m_dir = dir;
			m->m_next = *mp;
			*mp = m;

		    } else {
			m = *mp;
		    }

		    if ( *entry->d_name == 'E' ) {
			m->m_efile = 1;

		    } else {
			m->m_dfile = 1;
		    }

		    break;
		}

		mp = &((*mp)->m_next); 
	    }

	} else if ( *entry->d_name == 't' ) {
	    /* clip orphan tfiles */
	    sprintf( fname, "%s/%s", dir, entry->d_name );

	    if ( unlink( fname ) != 0 ) {
		fprintf( stderr, "unlink %s: ", fname );
		perror( NULL );
		return( -1 );
	    }

#ifdef DEBUG
	    printf( "q_clean unlink tfile:\t%s\n", fname );
#endif /* DEBUG */

	} else {
	    /* not a tfile, Efile or Dfile */
	    fprintf( stderr, "unknown file: %s\n", dir, entry->d_name );
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	fprintf( stderr, "q_clean readdir %s: " );
	perror( NULL );
	return( -1 );
    }

    /*
     * foreach message in messages:
     *	    - warn Efile no Dfile
     *	    - delete Dfile no Efile
     */

    mp = messages; 

    while (( m = *mp ) != NULL ) {
	if ( m->m_dfile == 0 ) {
	    fprintf( stderr, "%s/E%s: Missing Dfile\n", dir, m->m_id );

	    *mp = m->m_next;
	    message_free( m );

	} else if ( m->m_efile == 0 ) {
	    sprintf( fname, "%s/D%s", dir, m->m_id );

	    if ( unlink( fname ) != 0 ) {
		fprintf( stderr, "unlink %s: ", fname );
		perror( NULL );
		return( -1 );
	    }

	    *mp = m->m_next;
	    message_free( m );

	} else {
	    mp = &((*mp)->m_next);
	}
    }

    return( 0 );
}
