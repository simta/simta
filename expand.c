#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sysexits.h>
#include <utime.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>

#include <snet.h>

#include "queue.h"
#include "envelope.h"
#include "simta.h"
#include "expand.h"


    /* return 0 on success
     * return -1 on syserror
     * syslog errors
     */

    int
expand( struct host_q **hq_stab, struct envelope *env )
{
    struct message		*m;
    struct host_q		*hq;
    char			*expanded_hostname;
    struct timeval		tv;

    /* 30 comes from envelope.h, might be changed in the future */
    char			new_id[ 30 ];

    /* expand env->e_rcpt addresses */

    /* foreach expanded host */
	/* this tv can be used to generate a new message id, and for
	 * the new message's Efile time.
	 */
	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    syslog( LOG_ERR, "gettimeofday: %m" );
	    return( -1 );
	}

	/* a possible new id */
	sprintf( new_id, "%lX.%lX", (unsigned long)tv.tv_sec,
		    (unsigned long)tv.tv_usec );

	/* Dfile: link Dold_id SIMTA_DIR_FAST/Dnew_id */
	/* Efile: write SIMTA_DIR_FAST/Enew_id for all recipients at host */
	/* check out envelope.c env_outfile( ... ); */

	/* create message to put in host queue */
	if (( m = message_create( new_id )) == NULL ) {
	    return( -1 );
	}

	/* create all messages we are expanding in the FAST queue */
	m->m_dir = SIMTA_DIR_FAST;

	/* don't bother doing a stat on the Efile, we just created it */
	m->m_etime.tv_sec = tv.tv_sec;

	/* find / create the expanded host queue */
	if (( hq = host_q_lookup( hq_stab, expanded_hostname )) == NULL ) {
	    return( -1 );
	}

	/* queue message "m" in host queue "hq" */
	if ( message_queue( hq, m ) != 0 ) {
	    return( -1 );
	}

    /* end foreach */

    /* if no rcpts expanded */
	/* return( 1 ) */

    /* else if evey rcpt was expanded */
	/* unlink original unexpanded Efile */
	/* unlink original unexpanded Dfile */

    /* else there are unexpanded rcpts from original env */
	/* rewrite original unexpanded Efile */
    /* endif */

    return( 0 );
}
