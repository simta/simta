#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "ll.h"
#include "envelope.h"
#include "queue.h"
#include "message.h"

void	host_stab_stdout( void * );
void	q_file_stab_stdout( void * );
int	efile_time_compare( void *, void * );


    int
efile_time_compare( void *a, void *b )
{
    struct q_file		*qa;
    struct q_file		*qb;

    qa = (struct q_file*)a;
    qb = (struct q_file*)b;

    if ( qa->q_etime.tv_sec > qb->q_etime.tv_sec ) {
	return( 1 );
    } else if ( qa->q_etime.tv_sec < qb->q_etime.tv_sec ) {
	return( -1 );
    }

    if ( qa->q_etime.tv_nsec > qb->q_etime.tv_nsec ) {
	return( 1 );
    } else if ( qa->q_etime.tv_nsec < qb->q_etime.tv_nsec ) {
	return( -1 );
    }

    return( 0 );
}


    void
q_file_stab_stdout( void *data )
{
    struct q_file		*q;

    q = (struct q_file*)data;

    q_file_stdout( q );
}


    void
host_stab_stdout( void *data )
{
    struct host_q		*hq;

    hq = (struct host_q*)data;

    host_q_stdout( hq );

    ll_walk( hq->hq_qfiles, q_file_stab_stdout );

    printf( "\n" );
}


    /* 1. For each efile:
     *      -organize by host
     *      -organize under host in reverse chronological order
     *
     * 2. For each host:
     *      -try to send messages
     *      -if there is a failure, stat all the d files to see if a bounce
     *           needs to be generated.
     */

    int
main( int argc, char *argv[] )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct q_file		*q;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*hs;
    struct stab_entry		*qs;
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

	/* organize Efiles by host and modification time */
	if ( *entry->d_name == 'E' ) {
	    if (( q = q_file_create( entry->d_name + 1 )) == NULL ) {
		perror( "q_file_create" );
		exit( 1 );
	    }

	    if (( q->q_env = env_infile( SLOW_DIR, q->q_id )) == NULL ) {
		perror( "env_infile" );
		exit( 1 );
	    }
	    q->q_hostname = q->q_env->e_hostname;

	    /* get efile modification time */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( stat( fname, &sb ) != 0 ) {
		perror( "stat" );
		exit( 1 );
	    }

	    q->q_etime = sb.st_mtimespec;

	    /* XXX Hostname lookup if unexpanded? */

	    if (( hq = (struct host_q*)ll_lookup( host_stab, q->q_hostname ))
		    == NULL ) {
		if (( hq = host_q_create( q->q_hostname )) == NULL ) {
		    perror( "host_q_create" );
		    exit( 1 );
		}

		if ( ll_insert( &host_stab, hq->hq_name, hq, NULL ) != 0 ) {
		    perror( "ll_insert" );
		    exit( 1 );
		}
	    }

	    if ( ll__insert( &(hq->hq_qfiles), q, efile_time_compare ) != 0 ) {
		perror( "ll__insert" );
		exit( 1 );
	    }
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	perror( "readdir" );
	return( 1 );
    }

    ll_walk( host_stab, host_stab_stdout );

    /*
     * 2. For each host:
     *      -try to send messages
     *      -if there is a failure, stat all the d files to see if a bounce
     *           needs to be generated.
     */

    for ( hs = host_stab; hs != NULL; hs = hs->st_next ) {
	hq = (struct host_q*)hs->st_data;
	for ( qs = hq->hq_qfiles; qs != NULL; qs = qs->st_next ) {
	    q = (struct q_file*)qs->st_data;

	    /* get message_data */
	    /* XXX what if ENOENT? */
	    if (( q->q_data = data_infile( SLOW_DIR, q->q_id )) == NULL ) {
		perror( "data_infile" );
		exit( 1 );
	    }

	    /* send message */
	    /* if send failure, update efile modification time */
	    /* if send failure, check remaining dfiles for bounce generation */
	}
    }

    return( 0 );
}
