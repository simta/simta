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


    void
host_q_stdout( struct host_q *hq )
{
    printf( "host_q:\t%s\n", hq->hq_name );
}


    void
q_file_stdout( struct q_file *q )
{
    printf( "qfile id:\t%s\n", q->q_id );
    printf( "qfile efile time:\t%ld.%d\n", q->q_etime.tv_sec,
	    q->q_etime.tv_nsec );
    printf( "efiles:\t%d\n", q->q_efile );
    printf( "dfiles:\t%d\n", q->q_dfile );
}


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
