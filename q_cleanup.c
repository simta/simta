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
#include "q_cleanup.h"
#include "envelope.h"
#include "simta.h"

int	q_clean ___P(( char *, struct message ** ));
int	move_to_slow ___P(( struct message **, struct message ** ));


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
     *	    - if ref count > 1 && unexpanded, delete all other messages
     *		with matching dfile inode #s.
     */


    /* call openlog() before this function */

    int
q_cleanup( void )
{
    struct message		*slow = NULL;
    struct message		*other = NULL;
    struct message		*m;
    struct message		*m_delete;
    struct message		**mp;
    char			fname[ MAXPATHLEN ];
    struct stat			sb;
    int				result;

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

    /* XXX debug check for NULL? */
    other = NULL;

    /* XXX */

    /*
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

    while (( m = slow ) != NULL ) {
	slow = m->m_next;

	sprintf( fname, "%s/D%s", SIMTA_DIR_SLOW, m->m_id );

	if ( stat( fname, &sb ) != 0 ) {
	    fprintf( stderr, "stat %s: ", fname );
	    perror( NULL );
	    return( -1 );
	}

	m->m_dfile = sb.st_ino;

	if ( sb.st_nlink > 1 ) {
	    sprintf( fname, "%s/E%s", SIMTA_DIR_SLOW, m->m_id );

	    if (( result = env_info( m, NULL, 0 )) != 0 ) {
		if ( result < 0 ) {
		    fprintf( stderr, "q_cleanup env_info %s: ", fname );
		    perror( NULL );
		    return( -1 );

		} else {
		    fprintf( stderr, "q_cleanup bad efile: %s\n", fname );
		    message_free( m );
		    continue;
		}
	    }

	    for ( mp = &other; *mp != NULL; mp = &((*mp)->m_next)) {
		if ( m->m_dfile <= (*mp)->m_dfile ) {
		    break;
		}
	    }

	    if (( *mp != NULL ) && ( m->m_dfile == (*mp)->m_dfile )) {
		if ((*mp)->m_expanded == 0 ) {
		    /* unexpanded message in queue, delete current message */

		    if ( unlink( fname ) != 0 ) {
			fprintf( stderr, "q_cleanup unlink %s: ", fname );
			perror( NULL );
			return( -1 );
		    }

		    sprintf( fname, "%s/D%s", SIMTA_DIR_SLOW, m->m_id );

		    if ( unlink( fname ) != 0 ) {
			fprintf( stderr, "q_cleanup unlink %s: ", fname );
			perror( NULL );
			return( -1 );
		    }

		    message_free( m );
		    continue;

		} else if ( m->m_expanded == 0 ) {
		    /* have unexpanded message, delete queued messages */
		    do {
			m_delete = *mp;
			*mp = m_delete->m_next;

			sprintf( fname, "%s/E%s", SIMTA_DIR_SLOW,
				m_delete->m_id );

			if ( unlink( fname ) != 0 ) {
			    fprintf( stderr, "q_cleanup unlink %s: ", fname );
			    perror( NULL );
			    return( -1 );
			}

			sprintf( fname, "%s/D%s", SIMTA_DIR_SLOW,
				m_delete->m_id );

			if ( unlink( fname ) != 0 ) {
			    fprintf( stderr, "q_cleanup unlink %s: ", fname );
			    perror( NULL );
			    return( -1 );
			}

			message_free( m_delete );

		    } while (( *mp != NULL ) &&
			    ( m->m_dfile == (*mp)->m_dfile ));
		}
	    }

	    m->m_next = *mp;
	    *mp = m;

	} else {
	    message_free( m );
	}
    }

    while (( m = other ) != NULL ) {
	other = m->m_next;
    	message_free( m );
    }

    return( 0 );
}


    int
move_to_slow( struct message **slow_q, struct message **other_q )
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
	    result = 0;

	    if (( *slow != NULL ) && (( result = strcmp( m->m_id,
		    (*slow)->m_id )) > 0 )) {
		slow = &((*slow)->m_next);

	    } else {
		sprintf( d_original, "%s/D%s", m->m_dir, m->m_id );
		sprintf( e_original, "%s/E%s", m->m_dir, m->m_id );

		if (( *slow == NULL ) || ( result != 0 )) {
		    /* move message files to SLOW */
		    sprintf( d_slow, "%s/D%s", SIMTA_DIR_SLOW, m->m_id );
		    sprintf( e_slow, "%s/E%s", SIMTA_DIR_SLOW, m->m_id );

		    if ( link( d_original, d_slow ) != 0 ) {
			fprintf( stderr, "move_to_slow link %s %s: ",
				d_original, d_slow );
			perror( NULL );
			return( -1 );
		    }

		    if ( link( e_original, e_slow ) != 0 ) {
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
		    slow = &((*slow)->m_next);
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
    struct message		*m;
    struct message		**mp;
    char			fname[ MAXPATHLEN ];
    int				result;

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
		    if (( *mp == NULL ) || ( result != 0 )) {
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
	    fprintf( stderr, "unknown file: %s/%s\n", dir, entry->d_name );
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	fprintf( stderr, "q_clean readdir %s: ", dir );
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
