#include "config.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <stdio.h>

#include "receive.h"

/*
 * So far, we know of two ways of doing this: Solaris 2.6 (>?) has a
 * collection of extern's called timezone, altzone, and daylight.  *BSD
 * (and probably Linux) has tm_gmtoff.
 */
    char *
tz( struct tm *tm )
{
    static char	zone[ 6 ];	/* ( "+" / "-" ) 4DIGIT */
    int		gmtoff;

#ifdef HAVE_TM_GMTOFF
    gmtoff = tm->tm_gmtoff;
#else /* HAVE_TM_GMTOFF */
    if ( daylight ) {
	gmtoff = altzone;
    } else {
	gmtoff = timezone;
    }
#endif /* HAVE_TM_GMTOFF */

    sprintf( zone, "%s%.2d%.2d", ( gmtoff < 0 ? "" : "+" ),
	    gmtoff / 60 / 60,
	    gmtoff / 60 % 60 );

    return( zone );
}
