#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>

#include <snet.h>

#include "ll.h"
#include "envelope.h"
#include "queue.h"
#include "message.h"
#include "ml.h"

void	host_stab_stdout ___P(( void * ));
void	q_file_stab_stdout ___P(( void * ));
int	efile_time_compare ___P(( void *, void * ));


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
    SNET			*snet;
    struct dirent		*entry;
    struct q_file		*q;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*hs;
    struct stab_entry		*qs;
    struct stat			sb;
    int				result;
    char			fname[ MAXPATHLEN ];
    char			localhostname[ MAXHOSTNAMELEN ];

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    if (( dirp = opendir( SLOW_DIR )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", SLOW_DIR );
	exit( 1 );
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
		syslog( LOG_ERR, "q_file_create: %m" );
		exit( 1 );
	    }

	    if (( q->q_env = env_create( q->q_id )) == NULL ) {
		syslog( LOG_ERR, "env_create: %m" );
		exit( 1 );
	    }

	    sprintf( fname, "%s/%s", SLOW_DIR, entry->d_name );

	    if (( result = env_infile( q->q_env, fname )) < 0 ) {
		/* syserror */
		syslog( LOG_ERR, "env_infile %s: %m", fname );
		exit( 1 );

	    } else if ( result > 1 ) {
		/* syntax error */
		syslog( LOG_WARNING, "env_infile %s: syntax error", fname );
		continue;
	    }

	    q->q_expanded = q->q_env->e_expanded;

	    /* get efile modification time */
	    if ( stat( fname, &sb ) != 0 ) {
		syslog( LOG_ERR, "stat %s: %m", fname );
		exit( 1 );
	    }

#ifdef sun
	    q->q_etime.tv_sec = sb.st_mtime;
#else	/* sun */
	    q->q_etime = sb.st_mtimespec;
#endif	/* sun */

	    /* XXX Hostname lookup if unexpanded? */

	    if (( hq = (struct host_q*)ll_lookup( host_stab, q->q_expanded ))
		    == NULL ) {
		if (( hq = host_q_create( q->q_expanded )) == NULL ) {
		    syslog( LOG_ERR, "host_q_create: %m" );
		    exit( 1 );
		}

		if ( ll_insert( &host_stab, hq->hq_name, hq, NULL ) != 0 ) {
		    syslog( LOG_ERR, "ll_insert: %m" );
		    exit( 1 );
		}
	    }

	    if ( ll__insert( &(hq->hq_qfiles), q, efile_time_compare ) != 0 ) {
		syslog( LOG_ERR, "ll__insert: %m" );
		exit( 1 );
	    }
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "readdir: %m" );
	exit( 1 );
    }

#ifdef DEBUG
    ll_walk( host_stab, host_stab_stdout );
#endif /* DEBUG */

    /*
     * 2. For each host:
     *      -try to send messages
     *      -if there is a failure, stat all the d files to see if a bounce
     *           needs to be generated.
     */

    if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
	syslog( LOG_ERR, "gethostname: %m" );
	exit( 1 );
    }

    for ( hs = host_stab; hs != NULL; hs = hs->st_next ) {
	hq = (struct host_q*)hs->st_data;
	for ( qs = hq->hq_qfiles; qs != NULL; qs = qs->st_next ) {
	    q = (struct q_file*)qs->st_data;

	    /* send message */

	    if ( strcasecmp( localhostname, q->q_expanded ) == 0 ) {
		/* deliver locally */
		/* get message_data */
		errno = 0;
		sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

		if (( snet = snet_open( fname, O_RDONLY, 0, 1024 * 1024 ))
			== NULL ) {
		    if ( errno == ENOENT ) {

#ifdef DEBUG
			printf( "Dfile missing: %s/D%s\n", SLOW_DIR, q->q_id );
#endif /* DEBUG */

			errno = 0;
			syslog( LOG_WARNING, "Missing Dfile: %s", fname );
			continue;

		    } else {
			syslog( LOG_ERR, "snet_open %s: %m", fname );
			exit( 1 );
		    }
		}

		/* XXX */
		if ( mail_local( "q_runner", "epcjr", snet ) != 0 ) {
		    exit( 1 );
		}

		if ( snet_close( snet ) != 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    exit( 1 );
		}

		/* delete Efile then Dfile */
		sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

		if ( unlink( fname ) != 0 ) {
		    syslog( LOG_ERR, "unlink %s: %m", fname );
		    return( 1 );
		}

#ifdef DEBUG
		printf( "unlink\t%s\n", fname );
#endif /* DEBUG */

		sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

		if ( unlink( fname ) != 0 ) {
		    syslog( LOG_ERR, "unlink %s: %m", fname );
		    return( 1 );
		}

#ifdef DEBUG
		printf( "unlink\t%s\n", fname );
#endif /* DEBUG */

	    }

	    /* if send failure, update efile modification time */
	    /* if send failure, check remaining dfiles for bounce generation */
	}
    }

    return( 0 );
}
