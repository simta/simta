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

#include "ll.h"
#include "queue.h"
#include "envelope.h"

#include "ml.h"
#include "line_file.h"
#include "smtp.h"
#include "simta.h"

/* GLOBAL VARS */
struct host_q		*simta_null_q;


    void
message_stdout( struct message *m )
{
    printf( "\t%s\n", m->m_id );
}


    void
q_stdout( struct host_q *hq )
{
    struct message		*m;

    if (( hq->hq_hostname == NULL ) || ( *hq->hq_hostname == '\0' )) {
	printf( "%d\tNULL:\n", hq->hq_entries );
    } else {
	printf( "%d\t%s:\n", hq->hq_entries, hq->hq_hostname );
    }

    for ( m = hq->hq_message_first; m != NULL; m = m->m_next ) {
	message_stdout( m );
    }
}

    void
q_list_stdout( struct host_q *hq )
{
    for ( ; hq != NULL; hq = hq->hq_next ) {
	q_stdout( hq );
    }

    printf( "\n" );
}


    struct message *
message_create( char *id )
{
    struct message		*m;

    if (( m = (struct message*)malloc( sizeof( struct message ))) == NULL ) {
	syslog( LOG_ERR, "malloc: %m" );
	return( NULL );
    }
    memset( m, 0, sizeof( struct message ));

    if (( m->m_id = strdup( id )) == NULL ) {
	syslog( LOG_ERR, "strdup: %m" );
	return( NULL );
    }

    return( m );
}


    int
message_queue( struct host_q *hq, struct message *m )
{
    struct message		**mp;

    mp = &(hq->hq_message_first );

    for ( ; ; ) {
	if (( *mp == NULL ) || ( m->m_etime.tv_sec < (*mp)->m_etime.tv_sec )) {
	    break;
	}

	mp = &((*mp)->m_next);
    }

    if (( m->m_next = *mp ) == NULL ) {
	hq->hq_message_last = m;
    }

    *mp = m;
    hq->hq_entries++;

    return( 0 );
}


    /* look up a given host in the host_q.  if not found, create */

    struct host_q *
host_q_lookup( struct host_q **host_q, char *hostname ) 
{
    struct host_q		*hq;
    static char			localhostname[ MAXHOSTNAMELEN ] = "\0";

    for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	if ( strcasecmp( hq->hq_hostname, hostname ) == 0 ) {
	    break;
	}
    }

    if ( hq == NULL ) {
	if (( hq = (struct host_q*)malloc( sizeof( struct host_q ))) == NULL ) {
	    syslog( LOG_ERR, "malloc: %m" );
	    return( NULL );
	}
	memset( hq, 0, sizeof( struct host_q ));

	if (( hq->hq_hostname = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "malloc: %m" );
	    return( NULL );
	}

	/* add this host to the host_q */
	hq->hq_next = *host_q;
	*host_q = hq;

	/* XXX DNS test for local queues more than gethostname? */
	if ( *localhostname == '\0' ) {
	    if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
		syslog( LOG_ERR, "gethostname: %m" );
		return( NULL );
	    }
	}

	if ( strcasecmp( localhostname, hq->hq_hostname ) == 0 ) {
	    hq->hq_status = HOST_LOCAL;

	} else if (( hostname == NULL ) || ( *hostname == '\0' )) {
	    hq->hq_status = HOST_NULL;

	} else {
	    hq->hq_status = HOST_REMOTE;
	}
    }

    return( hq );
}


    int
bounce( struct envelope *env, SNET *message )
{
    return( 0 );
}


    int
q_deliver( struct host_q *hq )
{
    return( 0 );
}


    int
q_runner( struct host_q *host_q )
{
    struct host_q		*hq;
    struct host_q		*deliver_q = NULL;
    struct host_q		**dq;
    struct message		*unexpanded;
    int				result;

    for ( hq = host_q; hq != NULL; hq = hq->hq_next ) {
	/* if hq is expanded+deliverable, add to deliver_q */
	/* if hq is LOOPed, bounce it all */

	if (( hq->hq_status == HOST_LOCAL ) ||
		( hq->hq_status == HOST_REMOTE )) {
	    /* queue it up */
	    dq = & deliver_q;

	    for ( ; ; ) {
		if (( *dq == NULL ) ||
			( hq->hq_entries >= (*dq)->hq_entries )) {
		    break;
		}
	    }

	    hq->hq_deliver = *dq;
	    *dq = hq;

	} else {
	    hq->hq_deliver = NULL;

	    if ( hq->hq_status == HOST_MAIL_LOOP ) {
		/* bounce queue */
	    }
	}
    }

    for ( ; ; ) {
	/* deliver all mail in every expanded queue */
	while ( deliver_q != NULL ) {
	    if (( result = q_deliver( deliver_q )) < 0 ) {
		return( -1 );

	    } else if ( result > 0 ) {
		/* XXX error case */
	    }

	    deliver_q = deliver_q->hq_deliver;
	}

return( 0 );

	/* delivered all expanded mail, check for unexpanded */
	if (( unexpanded = simta_null_q->hq_message_first ) == NULL ) {
	    break;
	}

	/* XXX unexpand one message */
    }

    return( 0 );
}


    int
q_read_dir( char *dir, struct host_q **host_q )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct host_q		*hq;
    char			hostname[ MAXHOSTNAMELEN + 1 ];
    struct message		*m;
    int				result;

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", dir );
	return( EX_TEMPFAIL );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* organize a directory's messages by host and timestamp */
    while (( entry = readdir( dirp )) != NULL ) {
	if ( *entry->d_name == 'E' ) {
	    if (( m = message_create( entry->d_name + 1 )) == NULL ) {
		return( -1 );
	    }

	    m->m_dir = dir;

	    if (( result = env_info( m, hostname )) < 0 ) {
		return( -1 );

	    } else if ( result > 0 ) {
		/* XXX free message */
		continue;
	    }

	    if (( hq = host_q_lookup( host_q, hostname )) == NULL ) {
		return( -1 );
	    }

	    if ( message_queue( hq, m ) < 0 ) {
		return( -1 );
	    }

	    hq->hq_entries++;
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "readdir: %m" );
	return( EX_TEMPFAIL );
    }

    return( 0 );
}


    int
q_runner_dir( char *dir )
{
    struct host_q		*host_q = NULL;

    /* create NULL host queue for unexpanded messages */
    if (( simta_null_q = host_q_lookup( &host_q, "\0" )) == NULL ) {
	exit( EX_TEMPFAIL );
    }

    /* XXX queue runner only reads dir once */
    /* read dir for efiles, sort by hostname & efile time */
    if ( q_read_dir( dir, &host_q ) != 0 ) {
	exit( EX_TEMPFAIL );
    }

#ifdef DEBUG
    printf( "q_runner_dir %s:\n", dir );
    q_list_stdout( host_q );
#endif /* DEBUG */

    if ( q_runner( host_q ) != 0 ) {
	exit( EX_TEMPFAIL );
    }

    return( 0 );
}
