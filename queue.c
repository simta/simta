#include "config.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <assert.h>
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <utime.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "red.h"
#include "wildcard.h"
#include "denser.h"
#include "ll.h"
#include "envelope.h"
#include "queue.h"
#include "ml.h"
#include "line_file.h"
#include "smtp.h"
#include "expand.h"
#include "simta.h"
#include "mx.h"

void	q_deliver( struct host_q * );
void	deliver_local( struct deliver *d );
void	deliver_remote( struct deliver *d, struct host_q * );
void	hq_clear_errors( struct host_q * );
int	next_dnsr_host( struct deliver *, struct host_q * );
void	hq_free( struct host_q * );
struct envelope* queue_env_lookup( char * );


    struct host_q *
host_q_lookup( char *hostname ) 
{
    struct host_q		*hq;

    /* XXX sort this list */
    for ( hq = simta_host_q; hq != NULL; hq = hq->hq_next ) {
	if ( strcasecmp( hq->hq_hostname, hostname ) == 0 ) {
	    break;
	}
    }

    return( hq );
}


    /* look up a given host in the host_q.  if not found, create */

    struct host_q *
host_q_create_or_lookup( char *hostname ) 
{
    struct host_q		*hq;

    /* create NULL host queue for unexpanded messages.  we always need to
     * have a NULL queue for error reporting. 
     */
    if ( simta_unexpanded_q == NULL ) {
	if (( simta_unexpanded_q = (struct host_q*)malloc(
		sizeof( struct host_q ))) == NULL ) {
	    syslog( LOG_ERR, "host_q_create_or_lookup malloc: %m" );
	    return( NULL );
	}
	memset( simta_unexpanded_q, 0, sizeof( struct host_q ));

	/* add this host to the host_q */
	simta_unexpanded_q->hq_hostname = "";
	simta_unexpanded_q->hq_status = HOST_NULL;
	simta_unexpanded_q->hq_next = simta_host_q;
	simta_host_q = simta_unexpanded_q;

	if ( simta_punt_host != NULL ) {
	    if (( simta_punt_q = (struct host_q*)malloc(
		    sizeof( struct host_q ))) == NULL ) {
		syslog( LOG_ERR, "host_q_create_or_lookup malloc: %m" );
		return( NULL );
	    }
	    memset( simta_punt_q, 0, sizeof( struct host_q ));

	    simta_punt_q->hq_hostname = simta_punt_host;
	    simta_punt_q->hq_status = HOST_PUNT;
	}
    }

    if (( hostname == NULL ) || ( *hostname == '\0' )) {
	return( simta_unexpanded_q );
    }

    if (( hq = host_q_lookup( hostname )) == NULL ) {
	if (( hq = (struct host_q*)malloc( sizeof( struct host_q ))) == NULL ) {
	    syslog( LOG_ERR, "host_q_create_or_lookup malloc: %m" );
	    return( NULL );
	}
	memset( hq, 0, sizeof( struct host_q ));

	if (( hq->hq_hostname = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "host_q_create_or_lookup strdup: %m" );
	    free( hq );
	    return( NULL );
	}

	if ((( hq->hq_red = simta_red_lookup_host( hostname )) != NULL ) &&
		( hq->hq_red->red_deliver_argc != 0 )) {
	    hq->hq_status = HOST_LOCAL;
	} else {
	    /* determine if it's LOCAL or MX later */
	    hq->hq_status = HOST_UNKNOWN;
	}

	/* add this host to the host_q_head */
	hq->hq_next = simta_host_q;
	simta_host_q = hq;
    }

    return( hq );
}


    void
hq_clear_errors( struct host_q *hq )
{
    if ( hq->hq_err_text != NULL ) {
	line_file_free( hq->hq_err_text );
	hq->hq_err_text = NULL;
    }
}


    int
queue_envelope( struct envelope *env )
{
    struct envelope		**ep;
    struct host_q		*hq;

    /* don't queue it if it's going in the dead queue */
    if ( env->e_dir == simta_dir_dead ) {
	return( 0 );
    }

    /* find the appropriate hq */
    if ( env->e_flags & ENV_FLAG_PUNT ) {
	hq = simta_punt_q;

    } else if (( hq = env->e_hq ) == NULL ) {
	if (( hq = host_q_create_or_lookup( env->e_hostname )) == NULL ) {
	    return( 1 );
	}
    }

    /* not already queued */
    if ( env->e_hq == NULL ) {
	/* sort queued envelopes by access time */
	for ( ep = &(hq->hq_env_head); *ep != NULL; ep = &((*ep)->e_hq_next)) {
	    if ( env->e_etime.tv_sec < (*ep)->e_etime.tv_sec ) {
		break;
	    }
	}

	env->e_hq_next = *ep;
	*ep = env;
	env->e_hq = hq;

	/* XXX sort this list */
	env->e_list_next = simta_env_queue;
	env->e_list_prev = NULL;

	if ( simta_env_queue != NULL ) {
	    simta_env_queue->e_list_prev = env;
	}
	simta_env_queue = env;
    }

    /* touch the env */
    env->e_cycle = simta_disk_cycle;
    hq->hq_entries++;

    /* manage queue's deliver times and cycle */
    if ( hq->hq_cycle != simta_disk_cycle ) {
	hq->hq_cycle = simta_disk_cycle;
	hq->hq_max_etime.tv_sec = env->e_etime.tv_sec;
	hq->hq_min_dtime.tv_sec = env->e_dtime.tv_sec;

    } else {
	if ( hq->hq_max_etime.tv_sec < env->e_etime.tv_sec ) {
	    hq->hq_max_etime.tv_sec = env->e_etime.tv_sec;
	}

	if ( hq->hq_min_dtime.tv_sec > env->e_dtime.tv_sec ) {
	    hq->hq_min_dtime.tv_sec = env->e_dtime.tv_sec;
	}
    }

    return( 0 );
}


    void
queue_remove_envelope( struct envelope *env )
{
    struct envelope		**ep;

    if ( env != NULL ) {
	for ( ep = &(env->e_hq->hq_env_head ); *ep != env;
		ep = &((*ep)->e_hq_next))
	    ;

	*ep = env->e_hq_next;

	env->e_hq->hq_entries--;
	env->e_hq = NULL;
	env->e_hq_next = NULL;

	if ( env->e_list_prev ) {
	    assert( env != simta_env_queue );
	    env->e_list_prev->e_list_next = env->e_list_next;
	} else {
	    assert( env == simta_env_queue );
	    simta_env_queue = env->e_list_next;
	}

	if ( env->e_list_next ) {
	    env->e_list_next->e_list_prev = env->e_list_prev;
	}

	env->e_list_prev = NULL;
	env->e_list_next = NULL;
    }

    return;
}


    int
q_runner( void )
{
    SNET			*snet_dfile;
    struct host_q		*hq;
    struct host_q		*deliver_q;
    struct host_q		**dq;
    struct envelope		*env_bounce;
    struct envelope		*env_punt;
    struct envelope		*unexpanded;
    int				dfile_fd;
    char                        dfile_fname[ MAXPATHLEN ];
    struct timeval		tv_start;
    struct timeval		tv_end;
    int				day;
    int				hour;
    int				min;
    int				sec;

    assert( simta_fast_files >= 0 );

    if (( simta_host_q == NULL ) && ( simta_unexpanded_q == NULL )) {
	syslog( LOG_ERR, "q_runner: no host_q" );
	return( simta_fast_files );
    }

    /* get start time for metrics */
    if ( gettimeofday( &tv_start, NULL ) != 0 ) {
	syslog( LOG_ERR, "q_runner gettimeofday: %m" );
	return( simta_fast_files );
    }

    for ( ; ; ) {
	/* build the deliver_q by number of messages */
	deliver_q = NULL;

	for ( hq = simta_host_q; hq != NULL; hq = hq->hq_next ) {
	    hq->hq_deliver = NULL;

	    if (( hq->hq_env_head == NULL ) || ( hq == simta_unexpanded_q )) {
		continue;
	    }

	    switch ( hq->hq_status ) {
	    case HOST_UNKNOWN:
	    case HOST_LOCAL:
	    case HOST_MX:
		/*
		 * we're going to try to deliver this messages in this host 
		 * queue, so put it in the delivery queue.
		 *
		 * sort mail queues by number of messages with non-generated
		 * From addresses first, then by overall number of messages in
		 * the queue.
		 */
		for ( dq = &deliver_q; *dq != NULL; dq = &((*dq)->hq_deliver)) {
		    if ( hq->hq_entries >= ((*dq)->hq_entries)) {
			break;
		    }
		}

		hq->hq_deliver = *dq;
		*dq = hq;
		break;

	    case HOST_DOWN:
	    case HOST_BOUNCE:
		q_deliver( hq );
		break;

	    default:
		syslog( LOG_ERR, "q_runner: bad host type %d", hq->hq_status );
		return( 1 );
	    }
	}

	/* deliver all mail in every expanded queue */
	for ( ; deliver_q != NULL; deliver_q = deliver_q->hq_deliver ) {
	    q_deliver( deliver_q );
	}

	/* punt any undelivered mail, if possible */
	if (( simta_punt_q != NULL ) && ( simta_punt_q->hq_env_head != NULL )) {
	    syslog( LOG_DEBUG, "q_runner: punting undelivered mail to %s",
		    simta_punt_host );
	    q_deliver( simta_punt_q );
	}

	/* EXPAND ONE MESSAGE */
	for ( ; ; ) {
	    if (( unexpanded = simta_unexpanded_q->hq_env_head ) == NULL ) {
		/* no more unexpanded mail.  we're done */
		goto q_runner_done;
	    }

	    /* pop message off unexpanded message queue */
	    queue_remove_envelope( unexpanded );

	    if ( unexpanded->e_rcpt == NULL ) {
		if ( env_move( unexpanded, simta_dir_fast )) {
		    goto unexpanded_clean_up;
		}

		if ( env_read_delivery_info( unexpanded, NULL ) != 0 ) {
		    goto unexpanded_clean_up;
		}
	    } else {
		assert( unexpanded->e_dir == simta_dir_fast );
	    }
	    /* expand message */
	    if ( expand( unexpanded ) == 0 ) {
		/* at least one address was expanded.  try to deliver it */
		env_free( unexpanded );
		break;
	    }

	    /* message not expandable */
	    if ( simta_process_type == PROCESS_Q_SLOW ) {
		/* check message's age */
		sprintf( dfile_fname, "%s/D%s", unexpanded->e_dir,
			unexpanded->e_id );
		if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
		    syslog( LOG_WARNING, "q_deliver bad Dfile: %s",
			    dfile_fname );
		    goto unexpanded_clean_up;
		}

		if ( env_is_old( unexpanded, dfile_fd ) == 0 ) {
		    /* not old */
		    close( dfile_fd );

		} else {
		    /* old unexpanded message, create bounce */
		    unexpanded->e_flags |= ENV_FLAG_BOUNCE;
		    if (( snet_dfile = snet_attach( dfile_fd,
			    1024 * 1024 )) == NULL ) {
			close( dfile_fd );
			goto unexpanded_clean_up;
		    }

		    if (( env_bounce = bounce( NULL, unexpanded,
			    snet_dfile )) == NULL ) {
			snet_close( snet_dfile );
			goto unexpanded_clean_up;
		    }

		    if ( env_unlink( unexpanded ) == 0 ) {
			queue_envelope( env_bounce );
			syslog( LOG_INFO,
				"Deliver %s: Message Deleted: Bounced",
				unexpanded->e_id );

		    } else {
			if ( env_unlink( env_bounce ) != 0 ) {
			    syslog( LOG_INFO, "Deliver %s: System "
				    "Error: Can't unwind bounce", 
				    env_bounce->e_id );
			} else {
			    syslog( LOG_INFO, "Deliver %s: Message "
				    "Deleted: System error, unwound "
				    "bounce", env_bounce->e_id );
			}
		    }

		    snet_close( snet_dfile );
		}
	    }

unexpanded_clean_up:
	    env_move( unexpanded, simta_dir_slow );
	    env_free( unexpanded );
	}
    }

q_runner_done:
    /* get end time for metrics */
    if ( gettimeofday( &tv_end, NULL ) != 0 ) {
	syslog( LOG_ERR, "q_runner gettimeofday: %m" );

    } else {
	tv_end.tv_sec -= tv_start.tv_sec;
	day = ( tv_end.tv_sec / 86400 );
	hour = (( tv_end.tv_sec % 86400 ) / 3600 );
	min = (( tv_end.tv_sec % 3600 ) / 60 );
	sec = ( tv_end.tv_sec % 60 );

	if ( simta_message_count > 0 ) {
	    if ( day > 0 ) {
		if ( day > 99 ) {
		    day = 99;
		}

		syslog( LOG_NOTICE, "q_runner metrics: %d messages, "
			"%d outbound_attempts, %d outbound_delivered, "
			"%d+%02d:%02d:%02d",
			simta_message_count, simta_smtp_outbound_attempts,
			simta_smtp_outbound_delivered,
			day, hour, min, sec );

	    } else {
		syslog( LOG_NOTICE, "q_runner metrics: %d messages, "
			"%d outbound_attempts, %d outbound_delivered, "
			"%02d:%02d:%02d",
			simta_message_count, simta_smtp_outbound_attempts,
			simta_smtp_outbound_delivered,
			hour, min, sec );
	    }
	}
    }

    /* move any unpuntable message to the slow queue */
    if ( simta_punt_q != NULL ) {
	while (( env_punt = simta_punt_q->hq_env_head ) != NULL ) {
	    queue_remove_envelope( env_punt );
	    env_move( env_punt, simta_dir_slow );
	    env_free( env_punt );
	}
    }

    if ( simta_fast_files != 0 ) {
	syslog( LOG_WARNING, "q_runner exiting with %d fast_files",
		simta_fast_files );
	return( SIMTA_EXIT_ERROR );
    } else if ( simta_leaky_queue ) {
	return( SIMTA_EXIT_OK_LEAKY );
    }

    return( SIMTA_EXIT_OK );
}


    int
q_runner_dir( char *dir )
{
    struct dirent		*entry;
    struct envelope		*env;
    DIR				*dirp;

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "q_runner_dir opendir %s: %m", dir );
	return( EXIT_OK );
    }

    /* organize a directory's messages by host and timestamp */
    while (( entry = readdir( dirp )) != NULL ) {
	if ( *entry->d_name == 'E' ) {
	    if (( env = env_create( NULL, NULL )) == NULL ) {
		return( -1 );
	    }

	    if ( env_set_id( env, entry->d_name + 1 ) != 0 ) {
		env_free( env );
		return( -1 );
	    }
	    env->e_dir = dir;

	    if ( env_read_queue_info( env ) != 0 ) {
		env_free( env );
		continue;
	    }

	    if ( simta_queue_filter != NULL ) {
		/* check to see if we should skip this message */
		if (( env->e_hostname == NULL ) || ( wildcard(
			simta_queue_filter, env->e_hostname, 0 ) == 0 )) {
		    env_free( env );
		    continue;
		}
	    }

	    if ( queue_envelope( env ) != 0 ) {
		env_free( env );
		return( -1 );
	    }

	    simta_message_count++;
	}
    }

    if ( closedir( dirp ) != 0 ) {
	syslog( LOG_ERR, "q_runner_dir closedir %s: %m", dir );
	return( -1 );
    }

    exit ( q_runner() != 0 );
}


    struct envelope *
queue_env_lookup( char *id )
{
    struct envelope		*e;

    for ( e = simta_env_queue; e != NULL; e = e->e_list_next ) {
	if ( strcmp( id, e->e_id ) == 0 ) {
	    break;
	}
    }

    return( e );
}


    void
hq_deliver_push( struct host_q *hq, struct timeval *tv_now )
{
    long			diff;
    int				max_wait = 80 * 60;
    int				min_wait = 5 * 60;
    int				wait;
    int				half;
    int				delay;
    int				next_launch;
    struct host_q		*insert;

    /* first launch can be derived from last env touch */
    if ( hq->hq_last_launch.tv_sec == 0 ) {
	hq->hq_last_launch.tv_sec = hq->hq_max_etime.tv_sec;
    }

    /* first down can be derived from oldest overall message */
    if ( hq->hq_last_up.tv_sec == 0 ) {
	hq->hq_last_up.tv_sec = hq->hq_min_dtime.tv_sec;
    }

    /* how many seconds the queue has been down */
    diff = hq->hq_last_launch.tv_sec - hq->hq_last_up.tv_sec;

    /* next wait time falls between min and max wait values */
    if ( diff <= min_wait ) {
	wait = min_wait;

    } else {
	for ( wait = max_wait;
		((( half = wait / 2 ) > diff ) && ( half > min_wait ));
		wait = half )
	    ;
    }

    /* compute possible next launch time */
    next_launch = hq->hq_last_launch.tv_sec + wait;

    if ( next_launch < tv_now->tv_sec ) {
	delay = random() % wait;
	next_launch = tv_now->tv_sec + delay;
    }

    /* pick the lowest computed launch time */
    if (( hq->hq_next_launch.tv_sec == 0 ) ||
	    ( hq->hq_next_launch.tv_sec > next_launch )) {
	hq->hq_next_launch.tv_sec = next_launch;
    }

    /* add to launch queue sorted on launch time */
    if (( simta_deliver_q == NULL ) ||
	    ( simta_deliver_q->hq_next_launch.tv_sec >=
		    hq->hq_next_launch.tv_sec )) {
	if (( hq->hq_deliver_next = simta_deliver_q ) != NULL ) {
	    simta_deliver_q->hq_deliver_prev = hq;
	}
	simta_deliver_q = hq;

    } else {
	for ( insert = simta_deliver_q;
		(( insert->hq_deliver_next != NULL ) &&
		( insert->hq_deliver_next->hq_next_launch.tv_sec <=
			hq->hq_next_launch.tv_sec ));
		insert = insert->hq_deliver_next )
	    ;

	if (( hq->hq_deliver_next = insert->hq_deliver_next ) != NULL ) {
	    hq->hq_deliver_next->hq_deliver_prev = hq;
	}
	insert->hq_deliver_next = hq;
	hq->hq_deliver_prev = insert;
    }

    return;
}


    void
hq_deliver_pop( struct host_q *hq_pop )
{
    if ( hq_pop ) {
	if ( hq_pop->hq_deliver_prev == NULL ) {
	    if ( simta_deliver_q == hq_pop ) {
		simta_deliver_q = hq_pop->hq_deliver_next;
	    }

	} else {
	    hq_pop->hq_deliver_prev->hq_deliver_next =
		    hq_pop->hq_deliver_next;
	}

	if ( hq_pop->hq_deliver_next != NULL ) {
	    hq_pop->hq_deliver_next->hq_deliver_prev =
		    hq_pop->hq_deliver_prev;
	}

	hq_pop->hq_deliver_next = NULL;
	hq_pop->hq_deliver_prev = NULL;
    }

    return;
}


    void
hq_free( struct host_q *hq_free )
{
    if ( hq_free ) {
	hq_deliver_pop( hq_free );
	free( hq_free->hq_hostname );
	free( hq_free );
    }

    return;
}


    int
q_read_dir( char *dir )
{
    struct dirent		*entry;
    struct envelope		*env;
    struct envelope		*new_envs = NULL;
    struct envelope		**e;
    DIR				*dirp;
    char			path[ MAXPATHLEN + 1 ];
    struct stat			sb;
    int				r;
    int				ret = -1;
    int				messages;
    struct host_q		**hq;
    struct host_q		*h_free;
    struct timeval		tv_schedule;

    /* metrics */
    struct timeval		tv_start;
    struct timeval		tv_stop;
    int				remain_hq = 0;
    int				old = 0;
    int				new = 0;
    int				removed = 0;

    if ( gettimeofday( &tv_start, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: q_read_dir gettimeofday: %m" );
	return( -1 );
    }

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "Syserror: q_read_dir opendir %s: %m", dir );
	return( -1 );
    }

    simta_disk_cycle++;

    /* organize a directory's messages by host and timestamp */
    for ( errno = 0; ( entry = readdir( dirp )) != NULL; errno = 0 ) {
	if (( *entry->d_name != 'E' ) && ( *entry->d_name != 'D' )) {
	    continue;
	}

	/* check to see if we've already seen this env in a previous read */
	if (( env = queue_env_lookup( entry->d_name + 1 )) != NULL ) {
	    if ( *entry->d_name == 'E' ) {
		/* check to see if this env's timestamps have changed */
		snprintf( path, MAXPATHLEN, "%s/%s", dir, entry->d_name );
		if ( stat( path, &sb ) != 0 ) {
		    syslog( LOG_ERR, "Syserror: q_read_dir stat %s: %m",
			    path );
		    continue;
		}

		/* re-queue env if it's timestamp has changed */
		if ( env->e_etime.tv_sec > sb.st_mtime ) {
		    env->e_etime.tv_sec = sb.st_mtime;
		    queue_remove_envelope( env );
		}

		old++;

		if ( queue_envelope( env ) != 0 ) {
		    goto error;
		}
	    }

	} else {
	    /* look for the file in the new_envs list */
	    for ( e = &new_envs; *e != NULL; e = &((*e)->e_next)) {
		if (( r = strcmp( entry->d_name + 1, (*e)->e_id )) == 0 ) {
		    env = *e;
		    break;
		} else if ( r > 0 ) {
		    break;
		}
	    }

	    if ( !env ) {
		if (( env = env_create( NULL, NULL )) == NULL ) {
		    continue;
		}

		if ( env_set_id( env, entry->d_name + 1 ) != 0 ) {
		    env_free( env );
		    goto error;
		}
		env->e_dir = dir;

		env->e_next = *e;
		*e = env;
	    }

	    if ( *entry->d_name == 'E' ) {
		assert( !( env->e_flags & ENV_FLAG_EFILE ));
		env->e_flags |= ENV_FLAG_EFILE;

		if ( env_read_queue_info( env ) != 0 ) {
		    continue;
		}

	    } else {
		assert( !( env->e_flags & ENV_FLAG_DFILE ));

		snprintf( path, MAXPATHLEN, "%s/%s", dir, entry->d_name );
		if ( stat( path, &sb ) != 0 ) {
		    syslog( LOG_ERR, "Syserror: q_read_dir stat %s: %m",
			    path );
		    continue;
		}
		env->e_dtime.tv_sec = sb.st_mtime;
		env->e_flags |= ENV_FLAG_DFILE;
	    }

	    if (( env->e_flags & ENV_FLAG_EFILE ) &&
		    ( env->e_flags & ENV_FLAG_DFILE )) {
		*e = env->e_next;
		env->e_next = NULL;
		new++;

		if ( queue_envelope( env ) != 0 ) {
		    goto error;
		}
	    }
	}
    }

    if ( errno != 0 ) {
	syslog( LOG_ERR, "q_read_dir readdir %s: %m", dir );
    } else {
	ret = 0;
    }

error:
    if ( closedir( dirp ) != 0 ) {
	syslog( LOG_ERR, "q_read_dir closedir %s: %m", dir );
	return( -1 );
    }

    if ( ret != 0 ) {
	return( ret );
    }

    /* make sure new list is empty */
    while (( env = new_envs ) != NULL ) {
	new_envs = new_envs->e_next;
	env_free( env );
    }

    if ( gettimeofday( &tv_schedule, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: q_read_dir gettimeofday: %m" );
	return( -1 );
    }

    /* post disk-read queue management */
    hq = &simta_host_q;
    while ( *hq != NULL ) {
	e = &(*hq)->hq_env_head;
	messages = 0;
	/* make sure that all envs in all host queues are up to date */
	while ( *e != NULL ) {
	    if ((*e)->e_cycle != simta_disk_cycle ) {
		env = *e;
		*e = (*e)->e_hq_next;
		removed++;
		env_free( env );

	    } else {
		messages++;
		e = &((*e)->e_hq_next);
	    }
	}

	(*hq)->hq_entries = messages;

	if ( *hq == simta_unexpanded_q ) {
	    hq = &((*hq)->hq_next);

	} else {
	    /* remove any empty host queues */
	    if ( (*hq)->hq_env_head == NULL ) {
		/* delete this host */
		h_free = *hq;
		*hq = (*hq)->hq_next;
		syslog( LOG_INFO, "Queue Removing: %s", h_free->hq_hostname );
		hq_free( h_free );

	    } else {
		/* add new host queues to the deliver queue */
		if ( (*hq)->hq_last_launch.tv_sec == 0 ) {
		    syslog( LOG_INFO, "Queue Adding: %s %d messages",
			    (*hq)->hq_hostname, (*hq)->hq_entries );
		    hq_deliver_push( *hq, &tv_schedule );
		}

		remain_hq++;
		hq = &((*hq)->hq_next);
	    }
	}
    }

    if ( gettimeofday( &tv_stop, NULL ) != 0 ) {
	syslog( LOG_ERR, "Syserror: q_read_dir gettimeofday: %m" );
	return( -1 );
    }

    syslog( LOG_INFO, "Queue Metrics: Disk Read %d: %d messages in %d seconds: "
	    "%d new messages %d removed messages %d hosts", simta_disk_cycle,
	    old + new, tv_stop.tv_sec - tv_start.tv_sec, new, removed,
	    remain_hq );

    return( 0 );
}


    void
q_deliver( struct host_q *deliver_q )
{
    int                         touch = 0;
    int                         n_processed = 0;
    int                         n_rcpt_remove;
    int                         dfile_fd;
    SNET                        *snet_dfile = NULL;
    SNET			*snet_lock;
    char                        dfile_fname[ MAXPATHLEN ];
    struct simta_red		*red;
    struct recipient		**r_sort;
    struct recipient		*remove;
    struct envelope		*env_deliver;
    struct envelope		*env_bounce = NULL;
    struct deliver		d;

    memset( &d, 0, sizeof( struct deliver ));

    syslog( LOG_DEBUG, "q_deliver: delivering %s total %d",
	    deliver_q->hq_hostname, deliver_q->hq_entries );

    /* determine if the host we are delivering to is a local host or a
     * remote host if we have not done so already.
     */
    if ( deliver_q->hq_status == HOST_UNKNOWN ) {
	if ((( red = host_local( deliver_q->hq_hostname )) == NULL ) ||
		( red->red_host_type == RED_HOST_TYPE_SECONDARY_MX )) {
	    deliver_q->hq_status = HOST_MX;
	} else if (( simta_dnsr != NULL ) &&
		( simta_dnsr->d_errno == DNSR_ERROR_TIMEOUT )) {
	    deliver_q->hq_status = HOST_DOWN;
	} else {
	    deliver_q->hq_status = HOST_LOCAL;
	    d.d_deliver_argc = red->red_deliver_argc;
	    d.d_deliver_argv = red->red_deliver_argv;
	}
    }

    /* always try to punt the mail */
    if ( deliver_q->hq_status == HOST_PUNT_DOWN ) {
	deliver_q->hq_status = HOST_PUNT;
    }

    /* process each envelope in the queue */
    while ( deliver_q->hq_env_head != NULL ) {
	env_deliver = deliver_q->hq_env_head;
	queue_remove_envelope( env_deliver );

	if ( env_deliver->e_rcpt == NULL ) {
	    /* lock & read envelope to deliver */
	    if ( env_read_delivery_info( env_deliver, &snet_lock ) != 0 ) {
		/* envelope not valid.  disregard */
		env_free( env_deliver );
		continue;
	    }

	} else {
	    snet_lock = NULL;
	}

	/* don't memset entire structure because we reuse connection data */
	d.d_env = env_deliver;
	d.d_dfile_fd = 0;
	d.d_n_rcpt_accepted = 0;
	d.d_n_rcpt_failed = 0;
	d.d_n_rcpt_tempfail = 0;
	d.d_delivered = 0;
	d.d_unlinked = 0;

	/* open Dfile to deliver */
        sprintf( dfile_fname, "%s/D%s", env_deliver->e_dir, env_deliver->e_id );
        if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
	    syslog( LOG_WARNING, "q_deliver bad Dfile: %s", dfile_fname );
	    goto message_cleanup;
        }

	d.d_dfile_fd = dfile_fd;

	switch ( deliver_q->hq_status ) {
        case HOST_LOCAL:
	    deliver_local( &d );
	    break;

        case HOST_MX:
        case HOST_PUNT:
	    if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "q_deliver snet_attach: %m" );
		goto message_cleanup;
	    }
	    d.d_snet_dfile = snet_dfile;

	    deliver_remote( &d, deliver_q );

	    /* return if smtp transaction to the punt host failed */
	    if ( deliver_q->hq_status == HOST_PUNT_DOWN ) {
		snet_close( snet_dfile );
		if ( snet_lock != NULL ) {
		    snet_close( snet_lock );
		}
		/* requeue env_deliver */
		env_clear_errors( env_deliver );
		env_deliver->e_flags |= ENV_FLAG_PUNT;
		queue_envelope( env_deliver );
		return;
	    }
	    break;

        case HOST_DOWN:
	    break;

        case HOST_BOUNCE:
	    env_deliver->e_flags |= ENV_FLAG_BOUNCE;
	    break;

	default:
	    panic( "q_deliver host_status out of range" );
	}

	/* check to see if this is the primary queue, and if it has leaked */
	if (( deliver_q->hq_primary ) &&
		( d.d_n_rcpt_accepted || d.d_n_rcpt_failed )) {
	    simta_leaky_queue = 1;
	}

	n_rcpt_remove = d.d_n_rcpt_failed;

	if ( d.d_delivered ) {
	    n_rcpt_remove += d.d_n_rcpt_accepted;
	}

	/* check the age of the original message unless we've created
	 * a bounce for the entire message, or if we've successfully
	 * delivered the message and no recipients tempfailed.
	 * note that this is the exact opposite of the test to delete
	 * a message: it is not nessecary to check a message's age
	 * for bounce purposes when it is already slated for deletion.
	 */
	if (( n_rcpt_remove != env_deliver->e_n_rcpt ) &&
		(( env_deliver->e_flags & ENV_FLAG_BOUNCE ) == 0 )) {
	    if ( env_is_old( env_deliver, dfile_fd ) != 0 ) {
		    syslog( LOG_NOTICE, "q_deliver %s: old message, bouncing",
			    env_deliver->e_id );
		    env_deliver->e_flags |= ENV_FLAG_BOUNCE;
	    } else {
		syslog( LOG_DEBUG, "q_deliver %s: not old",
			env_deliver->e_id );
	    }
	}

	/* bounce the message if the message is bad, or
	 * if some recipients are bad.
	 */
	if (( env_deliver->e_flags & ENV_FLAG_BOUNCE ) || d.d_n_rcpt_failed ) {
            if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                syslog( LOG_ERR, "q_deliver lseek: %m" );
		panic( "q_deliver lseek fail" );
            }

	    if ( snet_dfile == NULL ) {
		if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 ))
			== NULL ) {
		    syslog( LOG_ERR, "q_deliver snet_attach: %m" );
		    /* fall through, just won't get to append dfile */
		}
	    } else {
		if ( lseek( snet_fd( snet_dfile ), (off_t)0, SEEK_SET ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver lseek: %m" );
		    panic( "q_deliver lseek fail" );
		}
	    }

	    if (( env_bounce = bounce( deliver_q, env_deliver, snet_dfile ))
		    == NULL ) {
		syslog( LOG_ERR, "q_deliver bounce failed" );
		goto message_cleanup;
            }
        }

	/* delete the original message if we've created
	 * a bounce for the entire message, or if we've successfully
	 * delivered the message and no recipients tempfailed.
	 */
	if (( n_rcpt_remove == env_deliver->e_n_rcpt ) ||
		( env_deliver->e_flags & ENV_FLAG_BOUNCE )) {
	    if ( env_truncate_and_unlink( env_deliver, snet_lock ) != 0 ) {
		goto message_cleanup;
	    }

	    d.d_unlinked = 1;

	    if ( env_deliver->e_flags & ENV_FLAG_BOUNCE ) {
		syslog( LOG_INFO, "Deliver %s: Message Deleted: Bounced",
			env_deliver->e_id );
	    } else {
		syslog( LOG_INFO, "Deliver %s: Message Deleted: Delivered",
			env_deliver->e_id );
	    }

	/* else we remove rcpts that were delivered or hard failed */
        } else if ( n_rcpt_remove ) {
	    syslog( LOG_INFO, "Deliver %s: Rewriting Envelope",
		    env_deliver->e_id );

	    r_sort = &(env_deliver->e_rcpt);
	    while ( *r_sort != NULL ) {
		/* remove rcpts that were delivered or hard failed */
		if (( d.d_delivered && ((*r_sort)->r_status == R_ACCEPTED )) ||
			((*r_sort)->r_status == R_FAILED )) {
		    remove = *r_sort;
		    *r_sort = (*r_sort)->r_next;
		    env_deliver->e_n_rcpt--;

		    if ( remove->r_status == R_FAILED ) {
			syslog( LOG_INFO, "Deliver %s: Removing To <%s> From "
				"<%s>: Failed",
				env_deliver->e_id, remove->r_rcpt,
				env_deliver->e_mail );

		    } else {
			syslog( LOG_INFO, "Deliver %s: Removing To <%s> From "
				"<%s>: Delivered",
				env_deliver->e_id, remove->r_rcpt,
				env_deliver->e_mail );
		    }

		    rcpt_free( remove );

		} else {
		    syslog( LOG_INFO, "Deliver %s: Keeping To <%s> From <%s>",
			    env_deliver->e_id, (*r_sort)->r_rcpt,
			    env_deliver->e_mail );
		    r_sort = &((*r_sort)->r_next);
		}
	    }

            assert( env_deliver->e_n_rcpt > 0 );
 
            if ( env_outfile( env_deliver ) == 0 ) {
                syslog( LOG_INFO, "Deliver %s: Rewrote %d recipients",
                        env_deliver->e_id, env_deliver->e_n_rcpt );
            } else {
                syslog( LOG_INFO, "Deliver %s: Failed Rewrite, "
                        "Double Deliver will occur", env_deliver->e_id );
		goto message_cleanup;
	    }

	    if ( env_deliver->e_dir == simta_dir_fast ) {
		/* overwrote fast file, not created a new one */
		simta_fast_files--;
	    }

	    assert( simta_fast_files >= 0 );

	/* else we need to touch the envelope if we started an attempt
	 * deliver the message, but it was unsuccessful.  Note that we
	 * need to have a positive or negitive rcpt reply to prevent the
	 * queue from preserving order in the case of a perm tempfail
	 * situation.
	 */
	} else if ( d.d_n_rcpt_accepted ) {
	    touch++;
	}

	if ( env_bounce != NULL ) {
	    queue_envelope( env_bounce );
	    env_bounce = NULL;
	}

message_cleanup:
        if ((( touch ) || ( n_processed == 0 )) &&
                ( env_deliver->e_dir == simta_dir_slow ) &&
		( d.d_unlinked == 0 ))  {
	    touch = 0;
	    env_touch( env_deliver );
	}

	n_processed++;

	if ( env_bounce != NULL ) {
	    if ( env_unlink( env_bounce ) != 0 ) {
		syslog( LOG_INFO,
			"Deliver %s: System Error: Can't unwind bounce",
			env_bounce->e_id );
	    } else {
		syslog( LOG_INFO, "Deliver %s: Message Deleted: "
			"System error, unwound bounce", env_bounce->e_id );
	    }

	    env_free( env_bounce );
	    env_bounce = NULL;
	}

	if ( d.d_unlinked == 0 ) {
	    if (( simta_punt_q != NULL ) && ( deliver_q != simta_punt_q ) &&
		    ( deliver_q->hq_no_punt == 0 )) {
		env_clear_errors( env_deliver );
		env_deliver->e_flags |= ENV_FLAG_PUNT;
		queue_envelope( env_deliver );
	    } else {
		env_move( env_deliver, simta_dir_slow );
		env_free( env_deliver );
	    }
	} else {
	    env_free( env_deliver );
	}

        if ( snet_dfile == NULL ) {
	    if ( dfile_fd > 0 ) {
		if ( close( dfile_fd ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver close: %m" );
		}
	    }

        } else {
            if ( snet_close( snet_dfile ) != 0 ) {
                syslog( LOG_ERR, "q_deliver snet_close: %m" );
            }
	    snet_dfile = NULL;
        }

	if ( snet_lock != NULL ) {
	    if ( snet_close( snet_lock ) != 0 ) {
		syslog( LOG_ERR, "q_deliver snet_close: %m" );
	    }
	}
    }

    if ( d.d_snet_smtp != NULL ) {
	syslog( LOG_DEBUG, "q_deliver: calling smtp_quit" );
        smtp_quit( deliver_q, &d );
	if ( snet_close( d.d_snet_smtp ) != 0 ) {
	    syslog( LOG_ERR, "q_deliver snet_close: %m" );
	}
	if ( d.d_dnsr_result_ip != NULL ) {
	    dnsr_free_result( d.d_dnsr_result_ip );
	}
	dnsr_free_result( d.d_dnsr_result );
    }

    return;
}


    void
deliver_local( struct deliver *d )
{
    int                         ml_error;

    syslog( LOG_NOTICE, "deliver_local %s: attempting local delivery",
	    d->d_env->e_id );

    for ( d->d_rcpt = d->d_env->e_rcpt; d->d_rcpt != NULL;
	    d->d_rcpt = d->d_rcpt->r_next ) {
	ml_error = EX_TEMPFAIL;

	if ( lseek( d->d_dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
	    syslog( LOG_ERR, "deliver_local lseek: %m" );
	    goto lseek_fail;
	}

	if ( d->d_deliver_argc == 0 ) {
	    d->d_deliver_argc = simta_deliver_default_argc;
	    d->d_deliver_argv = simta_deliver_default_argv;
	}

	ml_error = deliver_binary( d );

lseek_fail:
	switch ( ml_error ) {
	case EXIT_SUCCESS:
	    /* success */
	    d->d_rcpt->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> From <%s> Accepted",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail );
	    break;

	default:
	case EX_TEMPFAIL:
	    d->d_rcpt->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfail++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> From <%s> "
		    "Tempfailed: %d", d->d_env->e_id, d->d_rcpt->r_rcpt,
		    d->d_env->e_mail, ml_error );
	    break;

	case EX_DATAERR:
	case EX_NOUSER:
	    /* hard failure caused by bad user data, or no local user */
	    d->d_rcpt->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> From <%s> Failed: %d",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
		    ml_error );
	    break;
	}

	syslog( LOG_INFO, "Deliver.local %s: Accepted %d Tempfailed %d "
		"Failed %d", d->d_env->e_id, d->d_n_rcpt_accepted,
		d->d_n_rcpt_tempfail, d->d_n_rcpt_failed );
    }

    d->d_delivered = 1;

    return;
}


    void
deliver_remote( struct deliver *d, struct host_q *hq )
{
    int				r_smtp;
    int				s;
    struct timeval		tv;

    switch ( hq->hq_status ) {
    case HOST_MX:
	hq->hq_status = HOST_DOWN;
	break;

    case HOST_PUNT:
	hq->hq_status = HOST_PUNT_DOWN;
    	break;

    default:
	panic( "deliver_remote: status out of range" );
    }

    for ( ; ; ) {
	if ( d->d_snet_smtp == NULL ) {
	    /* need to build SMTP connection */
	    if ( next_dnsr_host( d, hq ) != 0 ) {
		if ( d->d_dnsr_result_ip != NULL ) {
		    dnsr_free_result( d->d_dnsr_result_ip );
		    d->d_dnsr_result_ip = NULL;
		    d->d_cur_dnsr_result++;
		    continue;
		}

		dnsr_free_result( d->d_dnsr_result );
		d->d_dnsr_result = NULL;
		return;
	    }

	    /* build snet */
	    if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
		syslog( LOG_ERR, "deliver_remote %s: socket: %m",
			hq->hq_hostname );
		goto connect_cleanup;
	    }

	    if ( connect( s, (struct sockaddr*)&(d->d_sin),
		    sizeof( struct sockaddr_in )) < 0 ) {
		syslog( LOG_ERR, "Connect.out [%s] %s: Failed: connect: %m",
			inet_ntoa( d->d_sin.sin_addr ), hq->hq_hostname );
		close( s );
		goto connect_cleanup;
	    }

	    if (( d->d_snet_smtp = snet_attach( s, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "deliver_remote %s snet_attach: %m",
			hq->hq_hostname );
		close( s );
		goto connect_cleanup;
	    }

	    memset( &tv, 0, sizeof( struct timeval ));
	    tv.tv_sec = 5 * 60;
	    snet_timeout( d->d_snet_smtp, SNET_WRITE_TIMEOUT, &tv );

	    simta_smtp_outbound_attempts++;

	    hq_clear_errors( hq );

	    if (( r_smtp = smtp_connect( hq, d )) != SMTP_OK ) {
		goto smtp_cleanup;
	    }

	} else {
	    /* already have SMTP connection, say RSET and send message */
	    if (( r_smtp = smtp_rset( hq, d )) != SMTP_OK ) {
		goto smtp_cleanup;
	    }
	}

	env_clear_errors( d->d_env );
	d->d_n_rcpt_accepted = 0;
	d->d_n_rcpt_failed = 0;
	d->d_n_rcpt_tempfail = 0;

	if (( r_smtp = smtp_send( hq, d )) == SMTP_OK ) {
	    switch ( hq->hq_status ) {
	    case HOST_DOWN:
		hq->hq_status = HOST_MX;
		break;

	    case HOST_PUNT_DOWN:
		env_clear_errors( d->d_env );
		hq->hq_status = HOST_PUNT;
		break;

	    default:
		panic( "deliver_remote: status out of range" );
	    }

	    simta_smtp_outbound_delivered++;
	    return;
	}

smtp_cleanup:
	if ( r_smtp == SMTP_ERROR ) {
	    smtp_quit( hq, d );
	}

	snet_close( d->d_snet_smtp );
	d->d_snet_smtp = NULL;

	if ( hq->hq_status == HOST_PUNT_DOWN ) {
	    hq_clear_errors( hq );
	}

	if ( hq->hq_status == HOST_BOUNCE ) {
	    if ( d->d_dnsr_result_ip != NULL ) {
		dnsr_free_result( d->d_dnsr_result_ip );
		dnsr_free_result( d->d_dnsr_result );
	    } else if ( d->d_dnsr_result != NULL ) {
		dnsr_free_result( d->d_dnsr_result );
	    }
	    return;
	}

connect_cleanup:
	if ( d->d_dnsr_result_ip != NULL ) {
	    d->d_cur_dnsr_result_ip++;
	} else {
	    d->d_cur_dnsr_result++;
	}
    }
}


    int
next_dnsr_host( struct deliver *d, struct host_q *hq )
{
    char			*ip;
    int 			i;

    if ( d->d_dnsr_result == NULL ) {
	hq->hq_no_punt = 0;
	d->d_mx_preference_cutoff = 0;
	d->d_cur_dnsr_result = 0;

	switch ( hq->hq_status ) {
	case HOST_DOWN:
	    if (( d->d_dnsr_result = get_mx( hq->hq_hostname )) == NULL ) {
		hq->hq_no_punt = 1;
		syslog( LOG_ERR, "next_dnsr_host: get_mx %s failed",
			hq->hq_hostname );
		return( 1 );
	    }

	    /* Check to make sure the MX entry doesn't have 0 entries, and
	     * that it doesn't conatin a single CNAME entry only */
	    if (( d->d_dnsr_result->r_ancount != 0 ) &&
		    (( d->d_dnsr_result->r_ancount != 1 ) ||
		    ( d->d_dnsr_result->r_answer[ 0 ].rr_type !=
		    DNSR_TYPE_CNAME ))) {
		/* check remote host's mx entry for our local hostname and
		 * loew_pref_mx_domain if configured.
		 * If we find one, we never punt mail destined for this host,
		 * and we only try remote delivery to mx entries that have a
		 * lower mx_preference than for what was matched.
		 */
		for ( i = 0; i < d->d_dnsr_result->r_ancount; i++ ) {
		    if ( d->d_dnsr_result->r_answer[ i ].rr_type ==
			    DNSR_TYPE_MX ) {
			if (( strcasecmp( simta_hostname,
		d->d_dnsr_result->r_answer[ i ].rr_mx.mx_exchange ) == 0 )
				|| (( simta_secondary_mx != NULL ) &&
				( strcasecmp(
				simta_secondary_mx->red_host_name,
		d->d_dnsr_result->r_answer[ i ].rr_mx.mx_exchange ) == 0 ))) {
			    hq->hq_no_punt = 1;
			    d->d_mx_preference_cutoff =
				    d->d_dnsr_result->r_answer[ i 
				    ].rr_mx.mx_preference;
			    break;
			}
		    }
		}

	    } else {
		if ( d->d_dnsr_result != NULL ) {
		    dnsr_free_result( d->d_dnsr_result );
		}
		if (( d->d_dnsr_result = get_a( hq->hq_hostname )) == NULL ) {
		    return( 1 );
		}

		if ( d->d_dnsr_result->r_ancount == 0 ) {
		    dnsr_free_result( d->d_dnsr_result );
		    d->d_dnsr_result = NULL;
		    if ( hq->hq_err_text == NULL ) {
			if (( hq->hq_err_text = line_file_create()) == NULL ) {
			    syslog( LOG_ERR,
				    "next_dnsr_host line_file_create: %m" );
			    return( 1 );
			}
		    }
		    if ( line_append( hq->hq_err_text, "Host does not exist",
			    COPY ) == NULL ) {
			syslog( LOG_ERR, "next_dnsr_host line_append: %m" );
			return( 1 );
		    }
		    hq->hq_status = HOST_BOUNCE;
		    d->d_env->e_flags |= ENV_FLAG_BOUNCE;
		    return( 1 );
		}
	    }

	    break;

	case HOST_PUNT_DOWN:
	    if (( d->d_dnsr_result = get_a( simta_punt_host )) == NULL ) {
		return( 1 );
	    }
	    if ( d->d_dnsr_result->r_ancount == 0 ) {
		syslog( LOG_WARNING,
			"next_dnsr_host: punt host has 0 DNS entries" );
		dnsr_free_result( d->d_dnsr_result );
		d->d_dnsr_result = NULL;
		return( 1 );
	    }
	    break;

	default:
	    panic( "next_dnsr_host: varaible out of range" );
	}
    }

    /* here you have dnsr information */
    memset( &(d->d_sin), 0, sizeof( struct sockaddr_in ));
    d->d_sin.sin_family = AF_INET;
    d->d_sin.sin_port = htons( SIMTA_SMTP_PORT );

    if ( d->d_dnsr_result_ip == NULL ) {
	for ( ; d->d_cur_dnsr_result < d->d_dnsr_result->r_ancount;
		d->d_cur_dnsr_result++ ) {
	    if ( d->d_dnsr_result->r_answer[ d->d_cur_dnsr_result ].rr_type ==
		    DNSR_TYPE_A ) {
		memcpy( &(d->d_sin.sin_addr.s_addr),
			&(d->d_dnsr_result->r_answer[
			d->d_cur_dnsr_result ].rr_a ),
			sizeof( struct in_addr ));
		if ( hq->hq_status == HOST_DOWN ) {
		    /* prevent spammers from using obviously fake addresses */
		    ip = inet_ntoa( d->d_sin.sin_addr );
		    if (( strcmp( ip, "127.0.0.1" ) == 0 ) ||
			    ( strcmp( ip, "0.0.0.0" ) == 0 )) {
			syslog( LOG_DEBUG,
				"next_dnsr_host %s: skipping invalid "
				"A record: %s", hq->hq_hostname, ip );
			continue;
		    }
		}
		return( 0 );

	    } else if (( d->d_dnsr_result->r_answer[
		    d->d_cur_dnsr_result ].rr_type == DNSR_TYPE_MX )
		    && ( hq->hq_status == HOST_DOWN )) {

		/* Stop checking hosts if we know the local hostname is in
		 * the mx record, and if we've reached it's preference level.
		 */
		if (( hq->hq_no_punt != 0 ) && ( d->d_mx_preference_cutoff == 
			d->d_dnsr_result->r_answer[ d->d_cur_dnsr_result
			].rr_mx.mx_preference )) {
		    return( 1 );
		}

		if ( d->d_dnsr_result->r_answer[ d->d_cur_dnsr_result
			].rr_ip != NULL ) {
		    memcpy( &(d->d_sin.sin_addr.s_addr),
			    &(d->d_dnsr_result->r_answer[
			    d->d_cur_dnsr_result ].rr_ip->ip_ip ),
			    sizeof( struct in_addr ));
		    return( 0 );

		} else {
		    if (( d->d_dnsr_result_ip =
			    get_a( d->d_dnsr_result->r_answer[
			    d->d_cur_dnsr_result ].rr_mx.mx_exchange ))
			    == NULL ) {
			continue;
		    }

		    if ( d->d_dnsr_result_ip->r_ancount == 0 ) {
			dnsr_free_result( d->d_dnsr_result_ip );
			d->d_dnsr_result_ip = NULL;
			continue;
		    }

		    d->d_cur_dnsr_result_ip = 0;
		    break;
		}

	    } else {
		syslog( LOG_DEBUG,
			"next_dnsr_host %s: uninteresting dnsr rr type:"
			" %d", d->d_dnsr_result->r_answer[
			d->d_cur_dnsr_result ].rr_name,
			d->d_dnsr_result->r_answer[
			d->d_cur_dnsr_result ].rr_type );
		continue;
	    }
	}
    }

    if ( d->d_dnsr_result_ip != NULL ) {
	for ( ; d->d_cur_dnsr_result_ip < d->d_dnsr_result_ip->r_ancount;
		d->d_cur_dnsr_result_ip++ ) {
	    if ( d->d_dnsr_result_ip->r_answer[ d->d_cur_dnsr_result_ip
		    ].rr_type == DNSR_TYPE_A ) {
		memcpy( &(d->d_sin.sin_addr.s_addr),
			&(d->d_dnsr_result_ip->r_answer[
			d->d_cur_dnsr_result_ip ].rr_a ),
			sizeof( struct in_addr ));
		ip = inet_ntoa( d->d_sin.sin_addr );
		if (( strcmp( ip, "127.0.0.1" ) == 0 ) ||
			( strcmp( ip, "0.0.0.0" ) == 0 )) {
		    syslog( LOG_DEBUG,
			"next_dnsr_host %s: skipping invalid MX IP: %s",
			hq->hq_hostname, ip );
		} else {
		    return( 0 );
		}
	    } else {
		syslog( LOG_DEBUG,
		    "next_dnsr_host %s: uninteresting dnsr rr type: %d",
		    d->d_dnsr_result_ip->r_answer[
			    d->d_cur_dnsr_result_ip ].rr_name,
		    d->d_dnsr_result_ip->r_answer[
			    d->d_cur_dnsr_result_ip ].rr_type );
	    }
	}
    }

    return( 1 );
}


    void
queue_log_metrics( struct host_q *hq_schedule )
{
    char		filename[ MAXPATHLEN ];
    int			fd;
    FILE		*f;
    struct timeval	tv;
    struct host_q	*hq;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_DEBUG, "metric log file failed: gettimeofday: %m" );
	return;
    }

    sprintf( filename, "%setc/%lX", simta_base_dir,
	    (unsigned long)tv.tv_sec );

    if (( fd = creat( filename, 0666 )) < 0 ) {
	syslog( LOG_DEBUG, "metric log file failed: creat %s: %m", filename );
	return;
    }

    if (( f = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_DEBUG, "metric log file failed: fdopen %s: %m", filename );
	return;
    }

    fprintf( f, "Disk Read:\t%d\n\n", simta_disk_cycle );

    if ( simta_unexpanded_q != NULL ) {
	fprintf( f, "Unexpanded Messages:\t%d\n\n",
		simta_unexpanded_q->hq_entries );
    }

    fprintf( f, "Next\tMessages\tQueue\n" );

    for ( hq = hq_schedule; hq != NULL; hq = hq->hq_deliver_next ) {
	fprintf( f, "%d\t%d\t%s\n", hq->hq_next_launch.tv_sec - tv.tv_sec,
		hq->hq_entries, hq->hq_hostname );
    }

    fclose( f );

    return;
}
