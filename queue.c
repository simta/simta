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

int	simta_queued_messages;
struct host_q		*null_queue;
struct stab_entry	*simta_bad_efiles;

void	host_stab_stdout ___P(( void * ));
void	q_file_stab_stdout ___P(( void * ));


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


    int
efile_time_compare( void *a, void *b )
{
    struct q_file		*qa;
    struct q_file		*qb;

    qa = (struct q_file*)a;
    qb = (struct q_file*)b;

    if ( qa->q_etime->tv_sec > qb->q_etime->tv_sec ) {
	return( 1 );
    } else if ( qa->q_etime->tv_sec < qb->q_etime->tv_sec ) {
	return( -1 );
    }

    if ( qa->q_etime->tv_nsec > qb->q_etime->tv_nsec ) {
	return( 1 );
    } else if ( qa->q_etime->tv_nsec < qb->q_etime->tv_nsec ) {
	return( -1 );
    }

    return( 0 );
}


    void
host_q_stdout( struct host_q *hq )
{
    printf( "host_q:\t%s\n", hq->hq_name );
}


    void
q_file_stdout( struct q_file *q )
{
    printf( "qfile id:\t%s\n", q->q_id );
    printf( "qfile efile time:\t%ld.%d\n", q->q_etime->tv_sec,
	    q->q_etime->tv_nsec );
    printf( "efiles:\t%d\n", q->q_efile );
    printf( "dfiles:\t%d\n", q->q_dfile );
    /* env_stdout( q->q_env ); */
}


    struct q_file *
q_file_env( struct envelope *env )
{
    struct q_file		*q;

    if (( q = (struct q_file*)malloc( sizeof( struct q_file ))) == NULL ) {
	return( NULL );
    }
    memset( q, 0, sizeof( struct q_file ));

    if (( q->q_id = strdup( env->e_id )) == NULL ) {
	return( NULL );
    }

    q->q_env = env;
    q->q_expanded = env->e_expanded;
    q->q_etime = &(q->q_env->e_etime);

    return( q );
}

    /* return pointer to a struct q_file with q->q_id = id
     * return NULL if syserror
     */

    struct q_file *
q_file_char( char *id )
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


    void
q_file_free ( struct q_file *q )
{
    free( q->q_id );
    free( q );
}


    /* return pointer to a struct host_q with hq->hq_name = hostname
     * return NULL if syserror
     */

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


    struct host_q *
host_q_lookup( struct stab_entry **host_stab, char *host ) 
{
    struct host_q		*hq;
    static char			localhostname[ MAXHOSTNAMELEN ] = "\0";

    if ( *localhostname == '\0' ) {
	if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
	    syslog( LOG_ERR, "gethostname: %m" );
	    return( NULL );
	}
    }

    if (( hq = (struct host_q*)ll_lookup( *host_stab, host ))
	    == NULL ) {
	if (( hq = host_q_create( host )) == NULL ) {
	    syslog( LOG_ERR, "host_q_create: %m" );
	    return( NULL );
	}

	if ( ll_insert( host_stab, hq->hq_name, hq, NULL ) != 0 ) {
	    syslog( LOG_ERR, "ll_insert: %m" );
	    return( NULL );
	}	

	/* XXX DNS test for local queues */
	if ( strcasecmp( localhostname, hq->hq_name ) == 0 ) {
	    hq->hq_status = HOST_LOCAL;

	} else if (( host == NULL ) || ( *host == '\0' )) {
	    hq->hq_status = HOST_NULL;

	} else {
	    hq->hq_status = HOST_REMOTE;
	}
    }

    return( hq );
}



    int
deliver( struct host_q *hq )
{
    int				result;
    int				dfile_fd;
    int				sent;
    char			*at;
    char			dfile_fname[ MAXPATHLEN ];
    struct stat			sb;
    struct timeval		tv;
    struct q_file		*q;
    struct stab_entry		*qs;
    struct stab_entry		**qclean;
    struct stab_entry		*qs_remove;
    struct recipient		*r;
    SNET			*dfile_snet = NULL;
    SNET			*snet = NULL;
    void			(*logger)(char *) = NULL;
    static int			(*local_mailer)(int, char *,
					struct recipient *) = NULL;

    if ( hq->hq_status == HOST_LOCAL ) {
	/* figure out what our local mailer is */
	if ( local_mailer == NULL ) {
	    if (( local_mailer = get_local_mailer()) == NULL ) {
		syslog( LOG_ALERT, "deliver local: no local mailer!" );
		return( -1 );
	    }
	}

    } else if ( hq->hq_status == HOST_REMOTE ) {
	/* XXX send only to terminator (or alias rsug), for now */
	if (( strcasecmp( hq->hq_name, "terminator.rsug.itd.umich.edu" ) != 0 )
		&& ( strcasecmp( hq->hq_name, "rsug.itd.umich.edu" ) != 0 )) {
	    return( 0 );
	}

	/* HOST_REMOTE sent is used to count how many messages have been
	 * sent to a SMTP host.
	 */
	sent = 0;

#ifdef DEBUG
	logger = stdout_logger;
#endif /* DEBUG */

    } else {
	syslog( LOG_ERR, "deliver: unreachable code" );
	return( -1 );
    }

    for ( qs = hq->hq_qfiles; qs != NULL; qs = qs->st_next ) {
	q = (struct q_file*)qs->st_data;

	/* get message data fd */
	errno = 0;
	sprintf( dfile_fname, "%s/D%s", q->q_env->e_dir, q->q_id );

	if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
	    if ( errno == ENOENT ) {
		errno = 0;
		syslog( LOG_WARNING, "deliver: missing Dfile: %s",
			dfile_fname );
		q->q_action = Q_IGNORE;
		continue;

	    } else {
		syslog( LOG_ERR, "open %s: %m", dfile_fname );
		return( -1 );
	    }
	}

	/* XXX LOCK dfile_fd */

	/* stat dfile to see if it's old */
	if ( fstat( dfile_fd, &sb ) != 0 ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    return( -1 );
	}

	q->q_dtime.tv_sec = sb.st_mtime;

	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    syslog( LOG_ERR, "gettimeofday" );
	    return( -1 );
	}

	/* XXX consider Dfiles old if they're over 3 days? */
	if (( tv.tv_sec - q->q_dtime.tv_sec ) > ( 60 * 60 * 24 * 3 )) {
	    q->q_env->e_old_dfile = 1;
	}

	q->q_env->e_failed = 0;
	q->q_env->e_tempfail = 0;
	q->q_env->e_success = 0;

	if ( hq->hq_status == HOST_LOCAL ) {
	    /* HOST_LOCAL sent is incremented every time we send
	     * a message to a user via. a local mailer.
	     */
	    sent = 0;

	    for ( r = q->q_env->e_rcpt; r != NULL; r = r->r_next ) {
		if ( sent != 0 ) {
		    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
			syslog( LOG_ERR, "lseek: %m" );
			return( -1 );
		    }
		}

		for ( at = r->r_rcpt; ; at++ ) {
		    if ( *at == '@' ) {
			*at = '\0';
			break;

		    } else if ( *at == '\0' ) {
			at = NULL;
			break;
		    }
		}

		if (( result = (*local_mailer)( dfile_fd, q->q_env->e_mail,
			r )) < 0 ) {
		    /* syserror */
		    return( -1 );

		} else if ( result == 0 ) {
		    /* success */
		    r->r_delivered = R_DELIVERED;
		    q->q_env->e_success++;

		} else if ( result == EX_TEMPFAIL ) {
		    if ( q->q_env->e_old_dfile != 0 ) {
			r->r_delivered = R_FAILED;
			q->q_env->e_failed++;
		    } else {
			r->r_delivered = R_TEMPFAIL;
			q->q_env->e_tempfail++;
		    }

		} else {
		    /* hard failure */
		    r->r_delivered = R_FAILED;
		    q->q_env->e_failed++;
		}

		if ( at != NULL ) {
		    *at = '@';
		}

		sent++;
	    }

	} else if ( hq->hq_status == HOST_REMOTE ) {
	    if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "snet_attach: %m" );
		return( -1 );
	    }

	    if ( sent != 0 ) {
		if (( result = smtp_rset( snet, logger )) ==
			SMTP_ERR_SYSCALL ) {
		    return( -1 );

		} else if ( result == SMTP_ERR_SYNTAX ) {
		    break;
		}
	    }

	    /* open connection, completely ready to send at least one message */
	    if ( snet == NULL ) {
		if (( snet = smtp_connect( hq->hq_name, 25 )) == NULL ) {
		    return( -1 );
		}

		if (( result = smtp_helo( snet, logger )) ==
			SMTP_ERR_SYSCALL ) {
		    return( -1 );

		} else if ( result == SMTP_ERR_SYNTAX ) {
		    if ( snet_close( dfile_snet ) != 0 ) {
			syslog( LOG_ERR, "close: %m" );
			return( -1 );
		    }
		    return( 0 );

		} else if ( result == SMTP_ERR_MAIL_LOOP ) {
		    /* mail loop */
		    if ( snet_close( dfile_snet ) != 0 ) {
			syslog( LOG_ERR, "close: %m" );
			return( -1 );
		    }

		    syslog( LOG_ALERT, "Hostname %s is not a remote host",
			    hq->hq_name );

		    hq->hq_status = HOST_MAIL_LOOP;
		    /* XXX deliver_bounce( hq ); */
		    return( 0 );
		}
	    }

	    if (( result = smtp_send( snet, q->q_env, dfile_snet, logger ))
		    == SMTP_ERR_SYSCALL ) {
		return( -1 );

	    } else if ( result == SMTP_ERR_SYNTAX ) {
		/* XXX error case? */
	    }

	    sent++;
	}

	if ( q->q_env->e_failed > 0 ) {
	    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
		syslog( LOG_ERR, "lseek: %m" );
		return( -1 );
	    }

	    if ( dfile_snet == NULL ) {
		if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 ))
			== NULL ) {
		    syslog( LOG_ERR, "snet_attach: %m" );
		    return( -1 );
		}
	    }

	    if (( result = bounce( q->q_env, dfile_snet )) < 0 ) {
		return( -1 );
	    }
	}

	if ( dfile_snet == NULL ) {
	    if ( close( dfile_fd ) != 0 ) {
		syslog( LOG_ERR, "close: %m" );
		return( -1 );
	    }

	} else {
	    if ( snet_close( dfile_snet ) != 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( -1 );
	    }
	}

	if ( q->q_env->e_tempfail == 0  ) {
	    /* no retries, only successes and bounces */
	    /* delete Efile then Dfile */
	    q->q_action = Q_REMOVE;

	    if ( env_unlink( q->q_env ) != 0 ) {
		return( -1 );
	    }

	    if ( unlink( dfile_fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", dfile_fname );
		return( -1 );
	    }

	    q_file_free( q );
	    free( qs_remove );

	} else {
	    /* some retries; place in retry list */
	    q->q_action = Q_REORDER;

	    if (( q->q_env->e_success != 0 ) || ( q->q_env->e_failed != 0 )) {

		/* some retries, and some sent.  re-write envelope */
		env_cleanup( q->q_env );

		if ( env_outfile( q->q_env, q->q_env->e_dir ) != 0 ) {
		    return( -1 );
		}

	    } else {
		/* all retries.  touch envelope */
		if ( env_touch( q->q_env ) != 0 ) {
		    return( -1 );
		}
	    }
	} 
    }

    if ( snet != NULL ) {
	if (( result = smtp_quit( snet, logger )) < 0 ) {
	    return( -1 );
	}
    }

    /* clean up the q */
    qclean = &hq->hq_qfiles;

    while ( *qclean != NULL ) {
	q = (struct q_file*)((*qclean)->st_data);

	if ( q->q_action == Q_REMOVE ) {

	    /* reorder linked list, and free node to be removed */
	    qs_remove = *qclean;
	    *qclean = (*qclean)->st_next;

	    q_file_free( q );
	    free( qs_remove );
	    simta_queued_messages--;
	    hq->hq_entries--;

	} else if ( q->q_action == Q_IGNORE ) {

	    qs_remove = *qclean;
	    *qclean = (*qclean)->st_next;
	    qs_remove->st_next = simta_bad_efiles;
	    simta_bad_efiles = qs_remove;
	    simta_queued_messages--;
	    hq->hq_entries--;

	} else if ( q->q_action == Q_REORDER ) {

	    qs_remove = *qclean;
	    *qclean = (*qclean)->st_next;

	    if ( ll__insert( &(hq->hq_qfiles), q, efile_time_compare ) != 0 ) {
		syslog( LOG_ERR, "ll__insert: %m" );
		return( -1 );
	    }

	    free( qs_remove );

	} else {
	    qclean = &((*qclean)->st_next);
	}
    }

    return( 0 );
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
q_runner( int mode )
{
    DIR				*dirp;
    char			*dir;
    struct dirent		*entry;
    struct q_file		*q;
    struct envelope		*env;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*hs;
    struct stab_entry		*bad;
    int				result;

    simta_bad_efiles = NULL;
    simta_queued_messages = 0;

    if (( null_queue = host_q_lookup( &host_stab, "\0" )) == NULL ) {
	syslog( LOG_ERR, "host_q_create: %m" );
	exit( EX_TEMPFAIL );
    }

    for ( ; ; ) {
	if ( mode == Q_RUNNER_LOCAL ) {
	    if (( dirp = opendir( SIMTA_DIR_LOCAL )) == NULL ) {
		syslog( LOG_ERR, "opendir %s: %m", SIMTA_DIR_LOCAL );
		return( EX_TEMPFAIL );
	    }

	    dir = SIMTA_DIR_LOCAL;

	} else {
	    syslog( LOG_ERR, "q_runner: unsupported mode" );
	    return( EX_TEMPFAIL );
	}

	/* create NULL host queue for bounced messages later on */
	if (( simta_null_host_q = host_q_lookup( &host_stab, "\0" )) == NULL ) {
	    syslog( LOG_ERR, "host_q_create: %m" );
	    return( EX_TEMPFAIL );
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
		/* check to see if this is a known bad efile */
		for ( bad = simta_bad_efiles; bad != NULL;
			bad = bad->st_next ) {
		    q = (struct q_file*)bad->st_data;

		    if ( strcmp( entry->d_name + 1, q->q_id ) == 0 ) {
			break;
		    }
		}

		if ( bad != NULL ) {
		    continue;
		}

		if (( env = env_create( entry->d_name + 1 )) == NULL ) {
		    return( EX_TEMPFAIL );
		}

		/* XXX what if file's not there? */
		if (( result = env_infile( env, dir )) < 0 ) {
		    /* syserror */
		    return( EX_TEMPFAIL );

		} else if ( result > 1 ) {
		    /* syntax error */
		    env_free( env );
		    continue;
		}

		if (( q = q_file_env( env )) == NULL ) {
		    syslog( LOG_ERR, "q_file_env: %m" );
		    return( EX_TEMPFAIL );
		}

		/* XXX DNS lookup if q->q_expanded == NULL? */

		if (( hq = host_q_lookup( &host_stab, q->q_expanded ))
			== NULL ) {
		    return( EX_TEMPFAIL );
		}

		if ( ll__insert( &(hq->hq_qfiles), q, efile_time_compare )
			!= 0 ) {
		    syslog( LOG_ERR, "ll__insert: %m" );
		    return( EX_TEMPFAIL );
		}

		hq->hq_entries++;

		/* XXX DEBUG */
		if ( null_queue != hq ) {
		    simta_queued_messages++;
		}
	    }
	}

	/* did readdir finish, or encounter an error? */
	if ( errno != 0 ) {
	    syslog( LOG_ERR, "readdir: %m" );
	    return( EX_TEMPFAIL );
	}

#ifdef DEBUG
	ll_walk( host_stab, host_stab_stdout );
#endif /* DEBUG */

	/* break if there are no messages in any host queues */
	if ( simta_queued_messages == 0 ) {
	    break;
	}

	for ( ; ; ) {
	    /*
	     * 2. For each host:
	     *      -try to send messages
	     *      -if failure, stat all the d files to see if a bounce
	     *           needs to be generated.
	     */

	    for ( hs = host_stab; hs != NULL; hs = hs->st_next ) {
		hq = (struct host_q*)hs->st_data;

		if ( hq->hq_status == HOST_NULL ) {
		    /* XXX NULL host queue.  Add DNS code */

		} else if (( hq->hq_status == HOST_LOCAL ) ||
			( hq->hq_status == HOST_REMOTE )) {
		    deliver( hq );

		} else if ( hq->hq_status == HOST_MAIL_LOOP ) {
		    /* XXX deliver_bounce( hq ); */

		} else {
		    /* big error */
		    syslog( LOG_ERR, "q_runner: unreachable code" );
		    return( EX_TEMPFAIL );
		}
	    }

	    /* loop until all messages in all host queues are gone */
	    if ( simta_queued_messages == 0 ) {
		break;
	    } else {
printf( "messages: %d\n", simta_queued_messages );
	    }
	}

#ifdef DEBUG
	ll_walk( host_stab, host_stab_stdout );
#endif /* DEBUG */
    }

    return( 0 );
}


    int
bounce( struct envelope *env, SNET *message )
{
    struct envelope		*bounce_env;
    char			dfile_fname[ MAXPATHLEN ];
    int				dfile_fd;
    FILE			*dfile;
    struct recipient		*r;
    struct line			*l;
    int				line_no = 0;
    char			*line;
    struct q_file		*q;

    if (( bounce_env = env_create( NULL )) == NULL ) {
	return( -1 );
    }

    if ( env_gettimeofday_id( bounce_env ) != 0 ) {
	return( -1 );
    }

    if (( env->e_mail != NULL ) && ( *env->e_mail != '\0' )) {
	if ( env_recipient( bounce_env, env->e_mail ) != 0 ) {
	    return( -1 );
	}

    } else {
	if ( env_recipient( bounce_env, SIMTA_POSTMASTER ) != 0 ) {
	    return( -1 );
	}
    }

    sprintf( dfile_fname, "%s/D%s", SIMTA_DIR_FAST, bounce_env->e_id );

    if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 ))
	    < 0 ) {
	syslog( LOG_ERR, "open %s: %m", dfile_fname );
	return( -1 );
    }

    if (( dfile = fdopen( dfile_fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "fdopen %s: %m", dfile_fname );
	close( dfile_fd );
	goto cleanup;
    }

    /* XXX headers */
    fprintf( dfile, "Headers\n" );
    fprintf( dfile, "\n" );

    fprintf( dfile, "Your mail was bounced.\n" );
    fprintf( dfile, "\n" );

    if ( env->e_old_dfile != 0 ) {
	fprintf( dfile, "It was over three days old.\n" );
	fprintf( dfile, "\n" );
    }

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( r->r_delivered == R_FAILED ) {
	    fprintf( dfile, "address %s\n", r->r_rcpt );

	    if ( r->r_text != NULL ) {
		for ( l = r->r_text->l_first; l != NULL; l = l->line_next ) {
		    fprintf( dfile, "%s\n", l->line_data );
		}
	    }

	    fprintf( dfile, "\n" );
	}
    }

    fprintf( dfile, "Bounced message:\n" );
    fprintf( dfile, "\n" );

    while (( line = snet_getline( message, NULL )) != NULL ) {
	line_no++;

	if ( line_no > SIMTA_BOUNCE_LINES ) {
	    break;
	}

	fprintf( dfile, "%s\n", line );
    }

    if ( fclose( dfile ) != 0 ) {
	goto cleanup;
    }

    if ( env_outfile( bounce_env, SIMTA_DIR_FAST ) != 0 ) {
	goto cleanup;
    }

    if (( q = q_file_env( bounce_env )) == NULL ) {
	syslog( LOG_ERR, "q_file_env: %m" );
	return( -1 );
    }

    if ( ll__insert( &(null_queue->hq_qfiles), q, efile_time_compare ) != 0 ) {
	syslog( LOG_ERR, "ll__insert: %m" );
	return( -1 );
    }

    /* XXX DEBUG simta_queued_messages++; */
    null_queue->hq_entries++;

    return( 0 );

cleanup:
    unlink( dfile_fname );

    return( -1 );
}
