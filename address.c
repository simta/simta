#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <pwd.h>

#include "address.h"

/*
 * Return values:
 *	< 0	error
 *	  0 	local address
 * 	> 0	non-local address
 */

    int
address_local( char *address )
{
    char		*user, *p;	
    struct passwd	*passwd;

    if (( user = strdup( address )) == NULL ) {
	return( -1 );
    }
    if (( p = strchr( user, '@' )) == NULL ) {
	free( user );
	return( -1 );
    }
    *p = '\0';

    /* XXX check alias file */

    /* Check password file */
    if (( passwd = getpwnam( user )) == NULL ) {
	free( user );
	return( 1 );
    }

    /* XXX do we check .forward? */
    free( user );
    return( 0 );
}

/*
 * Return values:
 *	< 0	non-local address
 *	  0 	no expansion
 *	> 0	number of expanded addresses
 */

    int
address_expand( char *address, char **expansion )
{
    int			count = 0;
    char		path[ MAXPATHLEN + 1];
    struct passwd	*passwd;
    FILE		*f;

    expansion = NULL;

    /* XXX check alias file */

    /* Check password file */
    if (( passwd = getpwnam( address )) == NULL ) {
	return( -1 );
    }

    /* Check .forward */
    sprintf( path, "%s%s", passwd->pw_dir, ".forward" );
    if (( f = fopen( path, "r" )) == NULL ) {
	/* XXX ( how? ) should we return error? */
	return( NULL );
    }

    return( count );
}
