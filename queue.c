#include <sys/types.h>

#include <stdio.h>
#include <errno.h>
#include <dirent.h>


#define	TEST_DIR	"slow"

    int
main( int argc, char *argv[] )
{
    DIR			*dirp;
    struct dirent	*entry;

    if (( dirp = opendir( TEST_DIR )) == NULL ) {
	fprintf( stderr, "opendir: %s: ", TEST_DIR );
	perror( NULL );
	return( 1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* print a directory */
    while (( entry = readdir( dirp )) != NULL ) {

	/* '.' and '..' are safe */
	if ( entry->d_name[ 0 ] == '.' ) {
	    if ( entry->d_name[ 1 ] == '\0' ) {
		continue;
	    } else if ( entry->d_name[ 1 ] == '.' ) {
		if ( entry->d_name[ 2 ] == '\0' ) {
		    continue;
		}
	    }
	}

	printf( "%s/%s\n", TEST_DIR, entry->d_name );
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	perror( "readdir" );
	return( 1 );
    }

    return( 0 );
}
