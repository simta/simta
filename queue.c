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
q_file_stdout( struct q_file *q )
{
    printf( "qfile id:\t%s\n", q->q_id );
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
