/**********          q_cleanup.c          **********/
#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/types.h>
#include <sys/wait.h>
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

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "simta.h"

int	q_cleanup_child( void );
int	q_clean( char *, struct envelope ** );
int	move_to_slow( struct envelope **, struct envelope **);


    int
q_cleanup( void )
{
    int				pid;
    int				status;

    switch ( pid = fork()) {
    case -1 :
	syslog( LOG_ERR, "q_cleanup fork: %m" );
	return( 1 );

    case 0 :
	exit( q_cleanup_child());

    default :
	if ( waitpid( pid, &status, 0 ) < 0 ) {
	    syslog( LOG_ERR, "q_cleanup waitpid: %m" );
	    return( 1  );
	}

	if ( WIFEXITED( status )) {
	    return( WEXITSTATUS( status ));

	} else if ( WIFSIGNALED( status )) {
	    syslog( LOG_ERR, "q_cleanup %d died on signal %d\n", pid, 
		    WTERMSIG( status ));
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "q_cleanup %d died\n", pid );
	    return( 1 );
	}
    }
}


    /*
     * - Clean & build SLOW queue
     * - Clean & build  LOCAL queue
     * - Move LOCAL queue to SLOW
     * - Clean & build  FAST queue
     * - Move FAST queue to SLOW
     * - for all Dfiles in SLOW:
     *	    + if ref count > 1 && unexpanded, delete all other messages
     *		with matching dfile inode #s.
     */

    int
q_cleanup_child( void )
{
    struct envelope		*slow = NULL;
    struct envelope		*other = NULL;
    struct envelope		*env;
    struct envelope		*e_delete;
    struct envelope		**env_p;
    char			fname[ MAXPATHLEN ];
    struct stat			sb;
    int				result;

    if ( q_clean( simta_dir_slow, &slow ) != 0 ) {
	return( -1 );
    }

    if ( q_clean( simta_dir_local, &other ) != 0 ) {
	return( -1 );
    }

    if ( move_to_slow( &slow, &other ) != 0 ) {
	return( -1 );
    }

    if ( q_clean( simta_dir_fast, &other ) != 0 ) {
	return( -1 );
    }

    if ( move_to_slow( &slow, &other ) != 0 ) {
	return( -1 );
    }

    /* 6. for all Dfiles in SLOW:
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

    while (( env = slow ) != NULL ) {
	slow = slow->e_next;

	sprintf( fname, "%s/D%s", simta_dir_slow, env->e_id );

	if ( stat( fname, &sb ) != 0 ) {
	    syslog( LOG_ERR, "q_cleanup_child stat %s: %m", fname );
	    return( -1 );
	}

	env->e_dinode = sb.st_ino;

	if ( sb.st_nlink > 1 ) {
	    if (( result = env_read_queue_info( env )) != 0 ) {
		syslog( LOG_ERR, "q_cleanup_child env_info %s: %m",
			env->e_id  );
		return( -1 );
	    }

	    for ( env_p = &other; *env_p != NULL; env_p = &((*env_p)->e_next)) {
		if ( env->e_dinode <= (*env_p)->e_dinode ) {
		    break;
		}
	    }

	    if (( *env_p != NULL ) && ( env->e_dinode == (*env_p)->e_dinode )) {
		if ((*env_p)->e_hostname == 0 ) {
		    /* unexpanded message in queue, delete current message */
		    if ( env_unlink( env ) != 0 ) {
			syslog( LOG_ERR, "q_cleanup_child env_unlink %s: %m",
				env->e_id );
			return( -1 );
		    }
		    env_free( env );
		    continue;

		} else if (*(env->e_hostname) == '\0' ) {
		    /* have unexpanded message, delete queued messages */
		    do {
			e_delete = *env_p;
			*env_p = e_delete->e_next;

			if ( env_unlink( e_delete ) != 0 ) {
			    syslog( LOG_ERR,
				    "q_cleanup_child env_unlink %s: %m",
				    e_delete->e_id );
			    return( -1 );
			}

			env_free( env );

		    } while (( *env_p != NULL ) &&
			    ( env->e_dinode == (*env_p)->e_dinode ));
		}
	    }

	    env->e_next = *env_p;
	    *env_p = env;

	} else {
	    env_free( env );
	}
    }

    while (( env = other ) != NULL ) {
	other = other->e_next;
    	env_free( env );
    }

    /* XXX check for existance of a DEAD queue */

    /* Reset the fast file counter to 0 */
    simta_fast_files = 0;

    return( 0 );
}


    int
move_to_slow( struct envelope **slow_q, struct envelope **other_q )
{
    struct envelope		*move;
    struct envelope		**slow;
    int				result;

    for ( slow = slow_q; *other_q != NULL; ) {
	/* pop move odd other_q */
	move = *other_q;
	*other_q = move->e_next;

	for ( ; ; ) {
	    if (( *slow != NULL ) && (( result = strcmp( move->e_id,
		    (*slow)->e_id )) > 0 )) {
		/* advance the slow list by one */
		slow = &((*slow)->e_next);

	    } else {
		if (( *slow == NULL ) || ( result < 0 )) {
		    /* move message files to SLOW */
		    if ( env_slow( move ) != 0 ) {
			syslog( LOG_ERR, "move_to_slow env_slow %s: %m",
				move->e_id );
			return( 1 );
		    }

		    /* insert move to slow_q */
		    move->e_next = *slow;
		    move->e_dir = simta_dir_slow;
		    *slow = move;

		} else {
		    /* collision - delete message files from other_q */
		    if ( env_unlink( move ) != 0 ) {
			return( 1 );
		    }

		    env_free( move );
		}

		slow = &((*slow)->e_next);
		break;
	    }
	}
    }

    return( 0 );
}


    int
q_clean( char *dir, struct envelope **messages )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct envelope		*env;
    struct envelope		**env_p;
    int				result;
    int				fatal = 0;

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "q_clean opendir %s: %m", dir );
	return( 1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* start from scratch */
    *messages = NULL;

    /*
     * foreach file in dir:
     *	    - ignore "." && ".."
     *	    - add message info for "D*" || "E*"
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
	    for ( env_p = messages; *env_p != NULL;
		    env_p = &((*env_p)->e_next)) {
		if (( result =
			strcmp( entry->d_name + 1, (*env_p)->e_id )) <= 0 ) {
		    break;
		}
	    }

	    if (( *env_p == NULL ) || ( result != 0 )) {
		if (( env = env_create( NULL )) == NULL ) {
		    syslog( LOG_ERR, "q_clean malloc: %m" );
		    return( 1 );
		}

		if ( env_set_id( env, entry->d_name + 1 ) != 0 ) {
		    syslog( LOG_ERR, "q_clean: illegal name length: %s\n",
			    entry->d_name );
		    env_free( env );
		    continue;
		}

		env->e_dir = dir;
		env->e_next = *env_p;
		*env_p = env;

	    } else {
		env = *env_p;
	    }

	    if ( *entry->d_name == 'E' ) {
		env->e_flags = env->e_flags | ENV_EFILE;
	    } else {
		env->e_flags = env->e_flags | ENV_DFILE;
	    }

	} else {
	    /* not a Efile or Dfile */
	    syslog( LOG_ERR, "q_clean unknown file: %s/%s\n", dir,
		    entry->d_name );
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "q_clean readdir %s: %m", dir );
	return( 1 );
    }

    /*
     * foreach message in messages:
     *	    - warn Efile no Dfile, and refuse to run
     *	    - warn Dfile no Efile
     */

    for ( env_p = messages; *env_p != NULL; ) {
	env = *env_p;

	if (( env->e_flags & ENV_DFILE ) == 0 ) {
	    syslog( LOG_ALERT, "q_clean: %s/E%s: Missing Dfile\n", dir,
		    env->e_id );
	    fatal++;
	    *env_p = env->e_next;
	    env_free( env );

	} else if (( env->e_flags & ENV_EFILE ) == 0 ) {
	    syslog( LOG_ALERT, "q_clean %s/D%s: Missing Efile\n", dir,
		    env->e_id );
	    *env_p = env->e_next;
	    env_free( env );

	} else {
	    env_p = &((*env_p)->e_next);
	}
    }

    return( fatal );
}
