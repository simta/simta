#include <sys/types.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "ll.h"
#include "message.h"
#include "envelope.h"

#define	TEST_DIR	"slow"

void print_message_stab( void *data )
{
    struct message		*m;

    m = (struct message*)data;

    message_stdout( m );
}


    int
main( int argc, char *argv[] )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct stab_entry		*message_stab = NULL;
    struct message		*m;

    if (( dirp = opendir( TEST_DIR )) == NULL ) {
	fprintf( stderr, "opendir: %s: ", TEST_DIR );
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
	    if (( m = (struct message*)
		    ll_lookup( message_stab, entry->d_name + 1 )) == NULL ) {

		if (( m = message_create( entry->d_name + 1 )) == NULL ) {
		    perror( "message_create" );
		    exit( 1 );
		}

		if (( ll_insert( &message_stab, m->m_env->e_id, m, NULL ))
			!= 0 ) {
		    perror( "ll_insert" );
		    exit( 1 );
		}
	    }

	    if ( *entry->d_name == 'E' ) {
		m->m_efile++;
	    } else {
		m->m_dfile++;
	    }

	} else {
printf( "not:\t%s\n", entry->d_name );
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	perror( "readdir" );
	return( 1 );
    }

    ll_walk( message_stab, print_message_stab );

    return( 0 );
}
