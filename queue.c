#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>

#include "ll.h"
#include "queue.h"


    void
host_q_stdout( struct host_q *hq )
{
    printf( "host_q:\t%s\n", hq->hq_name );
}


    void
q_file_stdout( struct q_file *q )
{
    printf( "qfile id:\t%s\n", q->q_id );
    printf( "qfile efile time:\t%ld.%ld\n", q->q_etime.tv_sec,
	    q->q_etime.tv_nsec );
    printf( "efiles:\t%d\n", q->q_efile );
    printf( "dfiles:\t%d\n", q->q_dfile );
    /* env_stdout( q->q_env ); */
}


    /* return pointer to a struct q_file with q->q_id = id
     * return NULL if syserror
     */

    struct q_file *
q_file_create( char *id )
{
    struct q_file		*q;

    if (( q = (struct q_file*)malloc( sizeof( struct q_file ))) == NULL ) {
	return( NULL );
    }
    memset( q, 0, sizeof( struct q_file ));

    if (( q->q_id = strdup( id )) == NULL ) {
	return( NULL );
    }

    return( q );
}


    void
q_file_free ( struct q_file *q )
{
    free( q->q_id );
    free( q );
}


    /* return pointer to a struct host_q with hq->hq_name = hostname
     * return NULL if syserror
     */

    struct host_q*
host_q_create( char *hostname )
{
    struct host_q		*hq;

    if (( hq = (struct host_q*)malloc( sizeof( struct host_q ))) == NULL ) {
	return( NULL );
    }
    memset( hq, 0, sizeof( struct host_q ));

    if (( hq->hq_name = strdup( hostname )) == NULL ) {
	return( NULL );
    }

    return( hq );
}


    struct host_q *
host_q_lookup( struct stab_entry **host_stab, char *host ) 
{
    struct host_q		*hq;
    static char			localhostname[ MAXHOSTNAMELEN ] = "\0";

    if ( *localhostname == '\0' ) {
	if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
	    syslog( LOG_ERR, "gethostname: %m" );
	    return( NULL );
	}
    }

    if (( hq = (struct host_q*)ll_lookup( *host_stab, host ))
	    == NULL ) {
	if (( hq = host_q_create( host )) == NULL ) {
	    syslog( LOG_ERR, "host_q_create: %m" );
	    return( NULL );
	}

	if ( ll_insert( host_stab, hq->hq_name, hq, NULL ) != 0 ) {
	    syslog( LOG_ERR, "ll_insert: %m" );
	    return( NULL );
	}	

	/* XXX DNS test for local queues */
	if ( strcasecmp( localhostname, hq->hq_name ) == 0 ) {
	    hq->hq_local = 1;
	}
    }

    return( hq );
}


    void
host_q_cleanup( struct host_q *hq )
{
    struct stab_entry		**qs;
    struct stab_entry		*qs_remove;
    struct q_file		*q;

    qs = &hq->hq_qfiles;

    while ( *qs != NULL ) {
	q = (struct q_file*)((*qs)->st_data);

	if ( q->q_action == Q_REMOVE ) {
	    /* reorder linked list, and free node to be removed */
	    qs_remove = *qs;
	    *qs = (*qs)->st_next;

	    q_file_free( q );
	    free( qs_remove );

	} else if ( q->q_action == Q_REORDER ) {
	    /* XXX add reorder code */
	    qs = &((*qs)->st_next);

	} else {
	    qs = &((*qs)->st_next);
	}
    }
}
