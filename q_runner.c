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
#include "smtp.h"

void	host_stab_stdout ___P(( void * ));
void	q_file_stab_stdout ___P(( void * ));
int	efile_time_compare ___P(( void *, void * ));
int	deliver_local ___P(( struct stab_entry * ));
int	deliver_remote ___P(( struct host_q * ));


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
    struct dirent		*entry;
    struct q_file		*q;
    struct envelope		*env;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*hs;
    struct stat			sb;
    int				result;
    char			fname[ MAXPATHLEN ];
    char			localhostname[ MAXHOSTNAMELEN ];

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
	syslog( LOG_ERR, "gethostname: %m" );
	exit( 1 );
    }

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
	    if (( env = env_create( entry->d_name + 1 )) == NULL ) {
		syslog( LOG_ERR, "env_create: %m" );
		exit( 1 );
	    }

	    sprintf( fname, "%s/%s", SLOW_DIR, entry->d_name );

	    if (( result = env_infile( env, fname )) < 0 ) {
		/* syserror */
		syslog( LOG_ERR, "env_infile %s: %m", fname );
		exit( 1 );

	    } else if ( result > 1 ) {
		/* syntax error */
		/* XXX env_free( env ); */
		/* XXX env_infile should syslog for more granularity */
		syslog( LOG_WARNING, "env_infile %s: syntax error", fname );
		continue;
	    }

	    if (( q = q_file_create( entry->d_name + 1 )) == NULL ) {
		syslog( LOG_ERR, "q_file_create: %m" );
		exit( 1 );
	    }

	    q->q_env = env;
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

    for ( hs = host_stab; hs != NULL; hs = hs->st_next ) {
	if (( hs->st_key == NULL ) || ( *hs->st_key == '\0' )) {
	    /* XXX NULL queue */

	} else if ( strcasecmp( localhostname, hs->st_key ) == 0 ) {
	    hq = (struct host_q*)hs->st_data;
	    deliver_local( hq->hq_qfiles );

	} else {
	    /* XXX deliver hs->st_data off machine */
	    hq = (struct host_q*)hs->st_data;
	    deliver_remote( hq );
	}
    }

    return( 0 );
}


    int
deliver_local( struct stab_entry *qfiles )
{
    struct q_file		*q;
    struct stab_entry		*qs;
    int				mailed;
    int				fd;
    char			fname[ MAXPATHLEN ];

    for ( qs = qfiles; qs != NULL; qs = qs->st_next ) {
	q = (struct q_file*)qs->st_data;

	/* get message_data */
	errno = 0;
	sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	    if ( errno == ENOENT ) {
		errno = 0;
		syslog( LOG_WARNING, "Missing Dfile: %s", fname );
		continue;

	    } else {
		syslog( LOG_ERR, "open %s: %m", fname );
		exit( 1 );
	    }
	}

	/* XXX */
	if (( mailed = mail_local( fd, "satan@hell.edu", "epcjr" ))
		< 0 ) {
	    exit( 1 );
	}

	/* XXX */
	if ( lseek( fd, 0, SEEK_SET ) != 0 ) {
	    syslog( LOG_ERR, "lseek: %m" );
	    exit( 1 );
	}

	/* XXX */
	if (( mailed = procmail( fd, "satan@hell.edu", "epcjr" ))
		< 0 ) {
	    exit( 1 );
	}

	if ( close( fd ) != 0 ) {
	    syslog( LOG_ERR, "close: %m" );
	    exit( 1 );
	}

	/* XXX mailed == 1 is recoverable failure */
	/* XXX touch Efile, see if Dfile time > bounce time */
	/* if send failure, update efile modification time */
	/* if send failure, check remaining dfiles for bounce generation */

	if ( mailed == 0  ) {
	    /* delete Efile then Dfile */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }

	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }
	}
    }

    return( 0 );
}


    int
deliver_remote( struct host_q *hq )
{
    struct q_file		*q;
    struct stab_entry		*qs;
    int				mailed;
    int				fd;
    char			fname[ MAXPATHLEN ];
    SNET			*snet;
    SNET			*message;
    void                        (*logger)(char *) = NULL;

#ifdef DEBUG
    logger = stdout_logger;
#endif /* DEBUG */

    /* XXX send only to terminator for now */
    if ( strcasecmp( hq->hq_name, "terminator.rsug.itd.umich.edu" ) != 0 ) {
	return( 0 );
    }

    if (( snet = smtp_connect( hq->hq_name, 25, logger )) == NULL ) {
	/* XXX syscall not only failure reason */
	syslog( LOG_ERR, "smtp_connect: %m\n" );
	exit( 1 );
    }

    for ( qs = hq->hq_qfiles; qs != NULL; qs = qs->st_next ) {
	q = (struct q_file*)qs->st_data;

	/* get message_data */
	errno = 0;
	sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	    if ( errno == ENOENT ) {
		errno = 0;
		syslog( LOG_WARNING, "Missing Dfile: %s", fname );
		continue;

	    } else {
		syslog( LOG_ERR, "open %s: %m", fname );
		exit( 1 );
	    }
	}

	if (( message = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    exit( 1 );
	}

	if (( mailed = smtp_send( snet, q->q_env, message, logger )) < 0 ) {
	    exit( 1 );
	}

	if ( snet_close( message ) != 0 ) {
	    syslog( LOG_ERR, "close: %m" );
	    exit( 1 );
	}

	/* XXX mailed == 1 is recoverable failure */
	/* XXX touch Efile, see if Dfile time > bounce time */
	/* if send failure, update efile modification time */
	/* if send failure, check remaining dfiles for bounce generation */

	if ( mailed == 0  ) {
	    /* delete Efile then Dfile */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }

	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }
	}

	if ( qs->st_next != NULL ) {
	    /* XXX better error cases */
	    if ( smtp_rset( snet, logger ) != 0 ) {
		syslog( LOG_ERR, "smtp_rset %m" );
		exit( 1 );
	    }
	}
    }

    if ( smtp_quit( snet, logger ) != 0 ) {
	/* XXX better error cases */
	syslog( LOG_ERR, "smtp_quit: %m" );
	exit( 1 );
    }

    return( 0 );
}
