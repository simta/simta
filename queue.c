/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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

#include <denser.h>
#include <snet.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include "simta.h"
#include "wildcard.h"
#include "envelope.h"
#include "queue.h"
#include "ml.h"
#include "line_file.h"
#include "smtp.h"
#include "expand.h"
#include "red.h"
#include "dns.h"

static int	deliver_checksockaddr( struct deliver *, struct host_q * );
static void	real_q_deliver( struct deliver *, struct host_q * );
void	q_deliver( struct host_q * );
void	deliver_local( struct deliver *d );
void	deliver_remote( struct deliver *d, struct host_q * );
void	hq_clear_errors( struct host_q * );
int	next_dnsr_host( struct deliver *, struct host_q * );
int	next_dnsr_host_lookup( struct deliver *, struct host_q * );
void	hq_free( struct host_q * );
void	connection_data_free( struct deliver *, struct connection_data * );
int	get_outbound_dns( struct deliver *, struct host_q * );
struct connection_data *connection_data_create( struct deliver * );
void	queue_time_order( struct host_q * );
void	prune_messages( struct host_q *hq );


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
	simta_unexpanded_q = calloc( 1, sizeof( struct host_q ));

	/* add this host to the host_q */
	simta_unexpanded_q->hq_hostname = S_UNEXPANDED;
	simta_unexpanded_q->hq_status = HOST_NULL;

	if ( simta_punt_host != NULL ) {
	    simta_punt_q = calloc( 1, sizeof( struct host_q ));

	    simta_punt_q->hq_hostname = simta_punt_host;
	    simta_punt_q->hq_status = HOST_PUNT;
	}
    }

    if (( hostname == NULL ) || ( *hostname == '\0' )) {
	return( simta_unexpanded_q );
    }

    if (( hq = host_q_lookup( hostname )) == NULL ) {
	hq = calloc( 1, sizeof( struct host_q ));

	hq->hq_wait_max = simta_wait_max;
	hq->hq_wait_min = simta_wait_min;

	hq->hq_hostname = strdup( hostname );

	if ( simta_bitbucket >= 0 ) {
	    hq->hq_status = HOST_BITBUCKET;

	} else if (( hq->hq_red = red_host_lookup( hostname )) != NULL ) {
	    if ( hq->hq_red->red_deliver_type == RED_DELIVER_BINARY ) {
		hq->hq_status = HOST_LOCAL;
	    }
	    if ( hq->hq_red->red_wait_set != 0 ) {
		hq->hq_wait_min = hq->hq_red->red_wait_min;
		hq->hq_wait_max = hq->hq_red->red_wait_max;
	    }
	} else if (( simta_jail_host != NULL ) &&
		( strcasecmp( simta_jail_host, hostname )) == 0 ) {
	    hq->hq_no_punt = NOPUNT_CONFIG;
	}

	if (( hq->hq_status == HOST_UNKNOWN ) &&
		( simta_queue_incoming_smtp_mail != 0 ) &&
		( simta_process_type == PROCESS_RECEIVE )) {
	    hq->hq_status = HOST_SUPPRESSED;
	    hq->hq_no_punt |= NOPUNT_MX;
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

    /* check to see if it's already already queued */
    if ( env->e_hq == NULL ) {
	/* find the appropriate hq */
	if ( env->e_flags & ENV_FLAG_PUNT ) {
	    hq = simta_punt_q;

	} else if (( hq =
		host_q_create_or_lookup( env->e_hostname )) == NULL ) {
	    return( 1 );
	}

	/* sort queued envelopes by priority and access time */
	for ( ep = &(hq->hq_env_head); *ep != NULL; ep = &((*ep)->e_hq_next)) {
	    /*
	    if ( env->e_priority > (*ep)->e_priority ) {
		break;
	    }
	    */

	    if ( env->e_etime.tv_sec < (*ep)->e_etime.tv_sec ) {
		break;
	    }
	}

	env->e_hq_next = *ep;
	*ep = env;
	env->e_hq = hq;
	hq->hq_entries++;

	if ( env->e_jail == ENV_JAIL_PRISONER ) {
	    hq->hq_jail_envs++;
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
	if ( env->e_jail == ENV_JAIL_PRISONER ) {
	    env->e_hq->hq_jail_envs--;
	}
	env->e_hq = NULL;
	env->e_hq_next = NULL;
    }

    return;
}


    void
queue_time_order( struct host_q *hq )
{
    char		fname[ MAXPATHLEN ];
    struct envelope	*envs;
    struct envelope	*sort;
    struct stat		sb;

    if ( hq != NULL ) {
	/* sort the envs based on etime */
	envs = hq->hq_env_head;
	hq->hq_entries = 0;
	hq->hq_jail_envs = 0;
	hq->hq_env_head = NULL;
	while ( envs != NULL ) {
	    sort = envs;
	    envs = envs->e_hq_next;
	    /* zero out hq so it gets sorted */
	    sort->e_hq = NULL;
	    sort->e_hq_next = NULL;
	    sprintf( fname, "%s/E%s", sort->e_dir, sort->e_id );
	    if ( stat( fname, &sb ) != 0 ) {
		if ( errno != ENOENT ) {
		    syslog( LOG_ERR,
			    "Syserror: simta_child_q_runner stat %s: %m",
			    fname );
		}
		env_free( sort );
		continue;
	    }
	    queue_envelope( sort );
	}
    }
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
    int				expanded;
    char                        dfile_fname[ MAXPATHLEN ];
    struct timeval		tv_start;
    struct timeval		tv_end;
    int				day;
    int				hour;
    int				min;
    int				sec;

    assert( simta_fast_files >= 0 );

    if (( simta_host_q == NULL ) && ( simta_unexpanded_q == NULL )) {
	syslog( LOG_ERR, "Queue.manage: no host_q" );
	return( simta_fast_files );
    }

    queue_time_order( simta_unexpanded_q );

    for ( hq = simta_host_q; hq != NULL; hq = hq->hq_next ) {
	queue_time_order( hq );
    }

    if ( simta_gettimeofday( &tv_start ) != 0 ) {
	return( simta_fast_files );
    }

    for ( ; ; ) {
	/* build the deliver_q by number of messages */
	deliver_q = NULL;

	for ( hq = simta_host_q; hq != NULL; hq = hq->hq_next ) {
	    hq->hq_deliver = NULL;

	    if ( hq->hq_env_head == NULL ) {
		continue;
	    }

	    switch ( hq->hq_status ) {
	    case HOST_UNKNOWN:
	    case HOST_LOCAL:
	    case HOST_MX:
	    case HOST_BITBUCKET:
		/*
		 * we're going to try to deliver this messages in this host
		 * queue, so put it in the delivery queue.
		 *
		 * sort mail queues by number of messages with non-generated
		 * From addresses first, then by overall number of messages in
		 * the queue.
		 */

		if ( simta_debug > 0 ) {
		    syslog( LOG_DEBUG,
			    "Queue %s: %d entries, adding to deliver queue",
			    hq->hq_hostname, hq->hq_entries );
		}

		for ( dq = &deliver_q; *dq != NULL; dq = &((*dq)->hq_deliver)) {
		    if ( hq->hq_entries >= ((*dq)->hq_entries)) {
			if ( simta_debug > 0 ) {
			    syslog( LOG_DEBUG,
				    "Queue %s: insert before %s (%d)",
				    hq->hq_hostname,
				    ((*dq)->hq_hostname),
				    ((*dq)->hq_entries));
			}
			break;
		    }

		    if ( simta_debug > 1 ) {
			syslog( LOG_DEBUG, "Queue %s: insert after %s (%d)",
				hq->hq_hostname,
				((*dq)->hq_hostname),
				((*dq)->hq_entries));
		    }
		}

		hq->hq_deliver = *dq;
		*dq = hq;
		break;

	    case HOST_SUPPRESSED:
	    case HOST_DOWN:
	    case HOST_BOUNCE:
		q_deliver( hq );
		break;

	    default:
		syslog( LOG_ERR, "Queue %s: bad host type %d",
			hq->hq_hostname, hq->hq_status );
		return( 1 );
	    }
	}

	/* deliver all mail in every expanded queue */
	for ( ; deliver_q != NULL; deliver_q = deliver_q->hq_deliver ) {
	    syslog( LOG_INFO, "Queue %s: Delivering mail",
		    deliver_q->hq_hostname );
	    q_deliver( deliver_q );
	}

	/* punt any undelivered mail, if possible */
	if (( simta_punt_q != NULL ) && ( simta_punt_q->hq_env_head != NULL )) {
	    syslog( LOG_INFO, "Queue %s: Punting undelivered mail to %s",
		    simta_punt_host, simta_punt_host );
	    q_deliver( simta_punt_q );
	}

	/* EXPAND MESSAGES */
	for ( expanded = 0 ; ; ) {
	    if (( unexpanded = simta_unexpanded_q->hq_env_head ) == NULL ) {
		/* no more unexpanded mail. we're done */
		if ( expanded == 0 ) {
		    /* no mail was expanded in this loop, we're all done */
		    goto q_runner_done;
		} else {
		    break;
		}
	    }

	    /* pop message off unexpanded message queue */
	    queue_remove_envelope( unexpanded );

	    if ( unexpanded->e_rcpt == NULL ) {
		if ( env_move( unexpanded, simta_dir_fast )) {
		    goto unexpanded_clean_up;
		}

		if ( env_read( READ_DELIVER_INFO, unexpanded, NULL ) != 0 ) {
		    goto unexpanded_clean_up;
		}
	    } else {
		assert( unexpanded->e_dir == simta_dir_fast );
	    }
	    /* expand message */
	    if ( expand( unexpanded ) == 0 ) {
		env_free( unexpanded );
		expanded++;
		if ( expanded >= simta_aggressive_expansion_max ) {
		    /* Try delivering mail */
		    break;
		}
		/* Keep expanding mail */
		continue;
	    }

	    /* message not expandable */
	    if ( simta_process_type == PROCESS_Q_SLOW ) {
		/* check message's age */
		sprintf( dfile_fname, "%s/D%s", unexpanded->e_dir,
			unexpanded->e_id );
		if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
		    syslog( LOG_ERR, "Queue.manage: bad Dfile: %s",
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

		    if (( env_bounce = bounce_snet( unexpanded, snet_dfile,
			    NULL, NULL )) == NULL ) {
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
    if ( simta_gettimeofday( &tv_end ) == 0 ) {
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

		syslog( LOG_NOTICE, "Queue Metrics: %d messages, "
			"%d outbound_attempts, %d outbound_delivered, "
			"%d+%02d:%02d:%02d",
			simta_message_count, simta_smtp_outbound_attempts,
			simta_smtp_outbound_delivered,
			day, hour, min, sec );

	    } else {
		syslog( LOG_NOTICE, "Queue Metrics: %d messages, "
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

#ifdef HAVE_LDAP
    red_close_ldap_dbs();
#endif /* HAVE_LDAP */

    if ( simta_fast_files != 0 ) {
	syslog( LOG_ERR, "Queue.manage: exiting with %d fast_files",
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
    struct simta_dirp		s_dirp;

    memset( &s_dirp, 0, sizeof( struct simta_dirp ));
    s_dirp.sd_dir = dir;

    do {
	if ( q_read_dir( &s_dirp ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_runner_dir opendir %s: %m", dir );
	    return( EXIT_OK );
	}
    } while ( s_dirp.sd_dirp != NULL );

    exit ( q_runner() != 0 );
}


    int
hq_deliver_push( struct host_q *hq, struct timeval *tv_now,
	struct timeval *tv_delay )
{
    int				order;
    struct timeval		next_launch;
    struct host_q		*insert;
    struct timeval		tv;
    struct timeval		wait_last;

    if ( tv_now == NULL ) {
	if ( simta_gettimeofday( &tv ) != 0 ) {
	    return( 1 );
	}

	tv_now = &tv;
    }

    /* if there is a provided delay, use it but respect hq->hq_wait_max */
    if ( tv_delay != NULL ) {
	if ( tv_delay->tv_sec > hq->hq_wait_max ) {
	    wait_last.tv_sec = hq->hq_wait_max;
	    next_launch.tv_sec = hq->hq_wait_max + tv_now->tv_sec;

	} else {
	    next_launch.tv_sec = tv_delay->tv_sec + tv_now->tv_sec;
	    if ( tv_delay->tv_sec < hq->hq_wait_min ) {
		wait_last.tv_sec = hq->hq_wait_min;
	    } else {
		wait_last.tv_sec = tv_delay->tv_sec;
	    }
	}

    /* if we're a jail, does this queue have any active mail? */
    } else if (( simta_mail_jail != 0 ) && 
	    ( hq->hq_entries == hq->hq_jail_envs )) {
	wait_last.tv_sec = simta_jail_seconds.tv_sec;
	if ( hq->hq_last_launch.tv_sec == 0 ) {
	    next_launch.tv_sec = random() % simta_jail_seconds.tv_sec +
		    tv_now->tv_sec;
	} else {
	    next_launch.tv_sec = simta_jail_seconds.tv_sec + tv_now->tv_sec;
	}

    /* have we never launched this queue? */
    } else if ( hq->hq_wait_last.tv_sec == 0 ) {
	wait_last.tv_sec = hq->hq_wait_min;
	if ( simta_queue_incoming_smtp_mail != 0 ) {
	    next_launch.tv_sec = tv_now->tv_sec;
	} else {
	    next_launch.tv_sec = random() % hq->hq_wait_min + tv_now->tv_sec;
	}
    
    /* is the queue leaky? */
    } else if ( hq->hq_leaky != 0 ) {
	hq->hq_leaky = 0;
	wait_last.tv_sec = hq->hq_wait_min;
	next_launch.tv_sec = random() % hq->hq_wait_min + tv_now->tv_sec;

    } else {
	/* wait twice what you did last time, but respect hq->hq_wait_max */
	if (( hq->hq_wait_last.tv_sec * 2 ) <= hq->hq_wait_max ) {
	    wait_last.tv_sec = hq->hq_wait_last.tv_sec * 2;
	    if ( wait_last.tv_sec < hq->hq_wait_min ) {
		wait_last.tv_sec = hq->hq_wait_min;
	    }
	} else {
	    wait_last.tv_sec = hq->hq_wait_max;
	}
	next_launch.tv_sec = wait_last.tv_sec + tv_now->tv_sec;
    }

    /* use next_launch if the queue has already launched, or it's sooner */
    if (( hq->hq_next_launch.tv_sec <= hq->hq_last_launch.tv_sec ) ||
	    ( hq->hq_next_launch.tv_sec > next_launch.tv_sec )) {
	hq->hq_wait_last.tv_sec = wait_last.tv_sec;
	hq->hq_next_launch.tv_sec = next_launch.tv_sec;
    }

    /* add to launch queue sorted on priority and launch time */
    if (( simta_deliver_q == NULL ) ||
	    /* ( simta_deliver_q->hq_priority < hq->hq_priority ) || */
	    ( simta_deliver_q->hq_next_launch.tv_sec >=
		    hq->hq_next_launch.tv_sec )) {
	if (( hq->hq_deliver_next = simta_deliver_q ) != NULL ) {
	    simta_deliver_q->hq_deliver_prev = hq;
	}
	simta_deliver_q = hq;
	order = 1;

    } else {
	for ( insert = simta_deliver_q, order = 2;
		(( insert->hq_deliver_next != NULL ) &&
		/* ( insert->hq_priority > hq->hq_priority ) && */
		( insert->hq_deliver_next->hq_next_launch.tv_sec <=
			hq->hq_next_launch.tv_sec ));
		insert = insert->hq_deliver_next, order++ )
	    ;

	if (( hq->hq_deliver_next = insert->hq_deliver_next ) != NULL ) {
	    hq->hq_deliver_next->hq_deliver_prev = hq;
	}
	insert->hq_deliver_next = hq;
	hq->hq_deliver_prev = insert;
    }

    syslog( LOG_DEBUG, "Queue %s: order %d, next %ld",
	    hq->hq_hostname, order,
	    hq->hq_next_launch.tv_sec - tv_now->tv_sec );

    return( 0 );
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


    void
prune_messages( struct host_q *hq )
{
    struct envelope		*env;
    struct envelope		**e;

    e = &(hq->hq_env_head);
    hq->hq_entries = 0;
    hq->hq_entries_new = 0;
    hq->hq_entries_removed = 0;
    hq->hq_jail_envs = 0;

    /* make sure that all envs in all host queues are up to date */
    while ( *e != NULL ) {
	if ((*e)->e_cycle != simta_disk_cycle ) {
	    env = *e;
	    env->e_list_next->e_list_prev = env->e_list_prev;
	    env->e_list_prev->e_list_next = env->e_list_next;
	    if ( simta_env_queue == env ) {
		if ( env->e_list_next == env ) {
		    simta_env_queue = NULL;
		} else {
		    simta_env_queue = env->e_list_next;
		}
	    }
	    env->e_list_next = NULL;
	    env->e_list_prev = NULL;

	    *e = (*e)->e_hq_next;
	    if ( simta_debug ) {
		syslog( LOG_DEBUG, "Queue %s: removed %s",
			hq->hq_hostname, env->e_id );
	    }
	    env_free( env );
	    hq->hq_entries_removed++;

	} else {
	    hq->hq_entries++;
	    if ( (*e)->e_jail == ENV_JAIL_PRISONER ) {
		hq->hq_jail_envs++;
	    }
	    e = &((*e)->e_hq_next);
	}
    }

    return;
}


    int
q_read_dir( struct simta_dirp *sd )
{
    struct dirent		*entry;

    struct envelope		*last_read = NULL;
    struct envelope		*env;
    struct host_q		**hq;
    struct host_q		*h_free;

    /* metrics */
    struct timeval		tv_stop;
    int				remain_hq = 0;
    int				total = 0;
    int				new = 0;
    int				removed = 0;

    if ( sd->sd_dirp == NULL ) {
	if ( simta_gettimeofday( &(sd->sd_tv_start)) != 0 ) {
	    return( 1 );
	}

	if (( sd->sd_dirp = opendir( sd->sd_dir )) == NULL ) {
	    syslog( LOG_ERR, "Syserror: q_read_dir opendir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	sd->sd_entries = 0;
	sd->sd_cycle++;
	return( 0 );
    }

    errno = 0;

    if (( entry = readdir( sd->sd_dirp )) == NULL ) {
	if ( errno != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_read_dir readdir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	if ( closedir( sd->sd_dirp ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_read_dir closedir %s: %m",
		    sd->sd_dir );
	    return( 1 );
	}

	sd->sd_dirp = NULL;

	if ( simta_gettimeofday( &tv_stop ) != 0 ) {
	    return( 1 );
	}

	/* post disk-read queue management */
	if ( simta_unexpanded_q != NULL ) {
	    prune_messages( simta_unexpanded_q );
	    if ( simta_debug ) {
		syslog( LOG_DEBUG, "Queue Metrics [Unexpanded]: entries %d, "
			"jail_entries %d",
			simta_unexpanded_q->hq_entries,
			simta_unexpanded_q->hq_jail_envs );
	    }
	}

	hq = &simta_host_q;
	while ( *hq != NULL ) {
	    prune_messages( *hq );

	    total += (*hq)->hq_entries;
	    new += (*hq)->hq_entries_new;
	    removed += (*hq)->hq_entries_removed;
	    (*hq)->hq_entries_new = 0;
	    (*hq)->hq_entries_removed = 0;

	    /* remove any empty host queues */
	    if ((*hq)->hq_env_head == NULL ) {
		h_free = *hq;
		if ( simta_debug ) {
		    syslog( LOG_DEBUG, "Queue.manage %s: 0 entries, removing",
			    h_free->hq_hostname );
		}
		/* delete this host */
		*hq = (*hq)->hq_next;
		hq_free( h_free );
		continue;
	    } else if ( simta_debug ) {
		syslog( LOG_DEBUG, "Queue Metrics %s: entries %d, "
			"jail_entries %d", (*hq)->hq_hostname,
			(*hq)->hq_entries, (*hq)->hq_jail_envs );
	    }

	    /* add new host queues to the deliver queue */
	    remain_hq++;

	    if ( (*hq)->hq_next_launch.tv_sec == 0 ) {
		syslog( LOG_INFO, "Queue %s: %d entries, adding",
			(*hq)->hq_hostname, (*hq)->hq_entries );
		if ( hq_deliver_push( *hq, &tv_stop, NULL ) != 0 ) {
		    return( 1 );
		}
	    }

	    hq = &((*hq)->hq_next);
	}

	syslog( LOG_INFO, "Queue Metrics: cycle %d messages %d "
		"milliseconds %ld new %d removed %d hosts %d",
		sd->sd_cycle, sd->sd_entries,
		SIMTA_ELAPSED_MSEC( sd->sd_tv_start, tv_stop ),
		new, removed, remain_hq );

	return( 0 );
    }

    switch ( *entry->d_name ) {
    /* "E*" */
    case 'E':
	sd->sd_entries++;
	break;

    /* "D*" */
    case 'D':
	return( 0 );

    /* "." && ".." */
    case '.':
	if ( * ( entry->d_name + 1 ) == '\0' ) {
	    /* "." */
	    return( 0 );
	} else if (( * ( entry->d_name + 1 ) == '.' ) &&
		( * ( entry->d_name + 2 ) == '\0' )) {
	    /* ".." */
	    return( 0 );
	}
	/* fall through to default */

    /* "*" */
    default:
	syslog( LOG_WARNING, "Queue.manage: unknown file: %s/%s", sd->sd_dir,
		entry->d_name );
	return( 0 );
    }

    env = NULL;

    if ( simta_env_queue != NULL ) {
	for ( ; ; env = env->e_list_next ) {
	    if ( env == NULL ) {
		if ( last_read != NULL ) {
		    env = last_read->e_list_next;
		} else {
		    env = simta_env_queue;
		}
	    } else if (( env == simta_env_queue ) &&
		    ( last_read == NULL )) {
		env = NULL;
		break;
	    }

	    if ( strcmp( entry->d_name + 1, env->e_id ) == 0 ) {
		break;
	    }

	    if ( env == last_read ) {
		env = NULL;
		break;
	    }
	}
    }

    if ( env != NULL ) {
	env->e_cycle = simta_disk_cycle;
	last_read = env;
	return( 0 );
    }

    /* here env is NULL, we need to create an envelope */
    if (( env = env_create( sd->sd_dir, entry->d_name + 1, NULL, NULL ))
	    == NULL ) {
	return( 1 );
    }

    if ( env_read( READ_QUEUE_INFO, env, NULL ) != 0 ) {
	env_free( env );
	return( 0 );
    }

    /* only stand-alone queue runners should do this */
    if ( simta_queue_filter != NULL ) {
	/* check to see if we should skip this message */
	if (( env->e_hostname == NULL ) || ( wildcard(
		simta_queue_filter, env->e_hostname, 0 ) == 0 )) {
	    env_free( env );
	    return( 0 );
	}
    }

    if ( queue_envelope( env ) != 0 ) {
	return( 1 );
    }

    env->e_cycle = simta_disk_cycle;

    if ( simta_env_queue == NULL ) {
	/* insert as the head */
	env->e_list_next = env;
	env->e_list_prev = env;
	simta_env_queue = env;
    } else if ( last_read == NULL ) {
	/* insert before the head */
	env->e_list_next = simta_env_queue;
	env->e_list_prev = simta_env_queue->e_list_prev;
	simta_env_queue->e_list_prev->e_list_next = env;
	simta_env_queue->e_list_prev = env;
	simta_env_queue = env;
    } else if ( last_read != NULL ) {
	/* insert after the last read */
	env->e_list_next = last_read->e_list_next;
	env->e_list_prev = last_read;
	last_read->e_list_next->e_list_prev = env;
	last_read->e_list_next = env;
	last_read = env;
    }

    return( 0 );
}


    void
q_deliver( struct host_q *deliver_q )
{
    struct deliver		d;
    struct timeval		tv_start;
    struct timeval		tv_stop;
    int				message_total;
    int				rcpt_total;

    if ( simta_gettimeofday( &tv_start ) != 0 ) {
	return;
    }

    memset( &d, 0, sizeof( struct deliver ));

    real_q_deliver( &d, deliver_q );

    if ( simta_gettimeofday( &tv_stop ) != 0 ) {
	return;
    }

    message_total = d.d_n_message_accepted_total +
	    d.d_n_message_failed_total + d.d_n_message_tempfailed_total;

    rcpt_total = d.d_n_rcpt_accepted_total +
	    d.d_n_rcpt_failed_total + d.d_n_rcpt_tempfailed_total;

    syslog( LOG_DEBUG, "Queue %s: Delivery complete: %ld milliseconds, "
	    "%d messages: %d A %d F %d T, %d rcpts %d A %d F %d T",
	    deliver_q->hq_hostname,
	    SIMTA_ELAPSED_MSEC( tv_start, tv_stop ),
	    message_total, 
	    d.d_n_message_accepted_total,
	    d.d_n_message_failed_total,
	    d.d_n_message_tempfailed_total,
	    rcpt_total, 
	    d.d_n_rcpt_accepted_total,
	    d.d_n_rcpt_failed_total,
	    d.d_n_rcpt_tempfailed_total );

    return;
}


    void
real_q_deliver( struct deliver *d, struct host_q *deliver_q )
{
    int                         touch = 0;
    int                         n_processed = 0;
    int                         n_rcpt_remove;
    int                         dfile_fd;
    int                         shuffle;
    SNET                        *snet_dfile = NULL;
    SNET			*snet_lock;
    char                        dfile_fname[ MAXPATHLEN ];
    struct simta_red		*red;
    struct recipient		**r_sort;
    struct recipient		*remove;
    struct envelope		*env_deliver;
    struct envelope		*env_bounce = NULL;
    struct stat			sbuf;

    memset( d, 0, sizeof( struct deliver ));

    syslog( LOG_INFO, "Queue %s: delivering %d messages",
	    deliver_q->hq_hostname, deliver_q->hq_entries );

    /* determine if the host we are delivering to is a local host or a
     * remote host if we have not done so already.
     */
    if ( deliver_q->hq_status == HOST_UNKNOWN ) {
	if ((( red = host_local( deliver_q->hq_hostname )) == NULL ) ||
		( red->red_deliver_type == RED_DELIVER_SMTP_DEFAULT ) ||
		( red->red_deliver_type == RED_DELIVER_SMTP )) {
	    deliver_q->hq_status = HOST_MX;
	} else if ( red->red_deliver_type == RED_DELIVER_BINARY ) {
	    deliver_q->hq_status = HOST_LOCAL;
	} else {
	    deliver_q->hq_status = HOST_DOWN;
	}
    }

    /* always try to punt the mail */
    if ( deliver_q->hq_status == HOST_PUNT_DOWN ) {
	deliver_q->hq_status = HOST_PUNT;
    }

    /* process each envelope in the queue */
    while ( deliver_q->hq_env_head != NULL ) {
	env_deliver = deliver_q->hq_env_head;

	if ( simta_queue_policy == QUEUE_POLICY_SHUFFLE ) {
	    for ( shuffle = ( random() % deliver_q->hq_entries );
		    shuffle > 0 ; shuffle-- ) {
		env_deliver = env_deliver->e_hq_next;
	    }
	}

	queue_remove_envelope( env_deliver );

	syslog( LOG_INFO, "Deliver %s: Attempting delivery",
		env_deliver->e_id );

	if ( env_deliver->e_rcpt == NULL ) {
	    /* lock & read envelope to deliver */
	    if ( env_read( READ_DELIVER_INFO, env_deliver, &snet_lock ) != 0 ) {
		/* envelope not valid.  disregard */
		env_free( env_deliver );
		env_deliver = NULL;
		continue;
	    }

	} else {
	    snet_lock = NULL;
	}

	/* don't memset entire structure because we reuse connection data */
	d->d_env = env_deliver;
	d->d_dfile_fd = 0;
	d->d_n_rcpt_accepted = 0;
	d->d_n_rcpt_failed = 0;
	d->d_n_rcpt_tempfailed = 0;
	d->d_delivered = 0;
	d->d_unlinked = 0;
	d->d_size = 0;
	d->d_sent = 0;

	/* open Dfile to deliver */
	sprintf( dfile_fname, "%s/D%s", env_deliver->e_dir, env_deliver->e_id );
	if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
	    syslog( LOG_ERR, "Queue %s: bad Dfile: %s",
		    deliver_q->hq_hostname, dfile_fname );
	    goto message_cleanup;
	}

	d->d_dfile_fd = dfile_fd;

	if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: q_deliver fstat %s: %m", dfile_fname );
	    goto message_cleanup;
	}

	d->d_size = sbuf.st_size;

	switch ( deliver_q->hq_status ) {
	case HOST_LOCAL:
	    if (( simta_mail_jail != 0 ) &&
		    ( env_deliver->e_jail == ENV_JAIL_PRISONER )) {
		syslog( LOG_DEBUG, "Deliver.remote %s: jail", d->d_env->e_id );
		break;
	    }
	    if (( deliver_q->hq_red != NULL ) &&
		    ( deliver_q->hq_red->red_deliver_argv != NULL )) {
		d->d_deliver_argc = deliver_q->hq_red->red_deliver_argc;
		d->d_deliver_argv = deliver_q->hq_red->red_deliver_argv;
	    }
	    deliver_local( d );
	    break;

	case HOST_MX:
	case HOST_PUNT:
	    if (( simta_mail_jail != 0 ) &&
		    ( env_deliver->e_jail == ENV_JAIL_PRISONER )) {
		syslog( LOG_DEBUG, "Deliver.remote %s: jail", d->d_env->e_id );
		break;
	    }
	    if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "Liberror: q_deliver snet_attach: %m" );
		goto message_cleanup;
	    }
	    d->d_snet_dfile = snet_dfile;
	    deliver_remote( d, deliver_q );

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

	case HOST_SUPPRESSED:
	    syslog( LOG_NOTICE, "Deliver.remote %s: host %s suppressed",
		    d->d_env->e_id, deliver_q->hq_hostname );
	    break;

	case HOST_DOWN:
	    syslog( LOG_NOTICE, "Deliver.remote %s: host %s down",
		    d->d_env->e_id, deliver_q->hq_hostname );
	    break;

	case HOST_BOUNCE:
	    syslog( LOG_NOTICE, "Deliver.remote %s: host %s bouncing mail",
		    d->d_env->e_id, deliver_q->hq_hostname );
	    env_deliver->e_flags |= ENV_FLAG_BOUNCE;
	    break;

	case HOST_BITBUCKET:
	    syslog( LOG_WARNING, "Deliver.remote %s: bitbucket in %d seconds",
		    env_deliver->e_id, simta_bitbucket );
	    sleep( simta_bitbucket );
	    d->d_delivered = 1;
	    d->d_n_rcpt_accepted = env_deliver->e_n_rcpt;
	    break;

	default:
	    panic( "q_deliver host_status out of range" );
	}

	/* check to see if this is the primary queue, and if it has leaked */
	if (( deliver_q->hq_primary ) && ( d->d_queue_movement != 0 )) {
	    simta_leaky_queue = 1;
	}

	if ( d->d_delivered != 0 ) {
	    d->d_n_message_accepted_total++;
	    n_rcpt_remove = d->d_n_rcpt_failed + d->d_n_rcpt_accepted;
	    d->d_n_rcpt_accepted_total += d->d_n_rcpt_accepted;
	    d->d_n_rcpt_failed_total += d->d_n_rcpt_failed;
	    d->d_n_rcpt_tempfailed_total += d->d_n_rcpt_tempfailed;
	} else if (( env_deliver->e_flags & ENV_FLAG_BOUNCE ) != 0 ) {
	    d->d_n_message_failed_total++;
	    n_rcpt_remove = env_deliver->e_n_rcpt;
	    d->d_n_rcpt_failed_total += env_deliver->e_n_rcpt;
	} else {
	    d->d_n_message_tempfailed_total++;
	    n_rcpt_remove = d->d_n_rcpt_failed;
	    d->d_n_rcpt_failed_total += d->d_n_rcpt_failed;
	    d->d_n_rcpt_tempfailed_total += d->d_n_rcpt_tempfailed +
		    d->d_n_rcpt_accepted;
	}

	/* check the age of the original message unless we've created
	 * a bounce for the entire message, or if we've successfully
	 * delivered the message and no recipients tempfailed.
	 * note that this is the exact opposite of the test to delete
	 * a message: it is not nessecary to check a message's age
	 * for bounce purposes when it is already slated for deletion.
	 */
	if ( n_rcpt_remove != env_deliver->e_n_rcpt ) {
	    if ( env_is_old( env_deliver, dfile_fd ) != 0 ) {
		    syslog( LOG_NOTICE, "Deliver %s: old message, bouncing",
			    env_deliver->e_id );
		    env_deliver->e_flags |= ENV_FLAG_BOUNCE;
	    } else {
		syslog( LOG_DEBUG, "Deliver %s: not old",
			env_deliver->e_id );
	    }
	} else {
	    syslog( LOG_DEBUG, "Deliver %s: not checking age of message",
		    env_deliver->e_id );
	}

	/* bounce the message if the message is bad, or
	 * if some recipients are bad.
	 */
	if (( env_deliver->e_flags & ENV_FLAG_BOUNCE ) ||
		d->d_n_rcpt_failed ) {
	    syslog( LOG_DEBUG, "Deliver %s: creating bounce",
		    env_deliver->e_id );
	    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
		syslog( LOG_ERR, "Syserror: q_deliver lseek: %m" );
		panic( "q_deliver lseek fail" );
	    }

	    if ( snet_dfile == NULL ) {
		if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 ))
			== NULL ) {
		    syslog( LOG_ERR, "Liberror: q_deliver snet_attach: %m" );
		    /* fall through, just won't get to append dfile */
		}
	    } else {
		if ( lseek( snet_fd( snet_dfile ),
			(off_t)0, SEEK_SET ) != 0 ) {
		    syslog( LOG_ERR, "Syserror: q_deliver lseek: %m" );
		    panic( "q_deliver lseek fail" );
		}
	    }

	    if (( env_bounce = bounce_snet( env_deliver, snet_dfile,
		    deliver_q, NULL )) == NULL ) {
		syslog( LOG_ERR, "Deliver %s: bounce failed",
			env_deliver->e_id );
		goto message_cleanup;
	    }

	} else {
	    syslog( LOG_DEBUG, "Deliver %s: no bounces created",
		    env_deliver->e_id );
	}

	/* delete the original message if we've created
	 * a bounce for the entire message, or if we've successfully
	 * delivered the message and no recipients tempfailed.
	 */
	if (( env_deliver->e_flags & ENV_FLAG_BOUNCE ) ||
		( n_rcpt_remove == env_deliver->e_n_rcpt )) {
	    if ( env_truncate_and_unlink( env_deliver, snet_lock ) != 0 ) {
		goto message_cleanup;
	    }

	    d->d_unlinked = 1;

	    if ( env_deliver->e_flags & ENV_FLAG_BOUNCE ) {
		syslog( LOG_INFO, "Deliver %s: Message Deleted: Bounced",
			env_deliver->e_id );
	    } else {
		syslog( LOG_INFO, "Deliver %s: Message Deleted: Delivered",
			env_deliver->e_id );
	    }

	/* else we remove rcpts that were delivered or hard failed */
	} else if ( n_rcpt_remove != 0 ) {
	    syslog( LOG_DEBUG, "Deliver %s: Rewriting envelope",
		    env_deliver->e_id );

	    r_sort = &(env_deliver->e_rcpt);
	    while ( *r_sort != NULL ) {
		/* remove rcpts that were delivered or hard failed */
		if (( d->d_delivered &&
			((*r_sort)->r_status == R_ACCEPTED )) ||
			((*r_sort)->r_status == R_FAILED )) {
		    remove = *r_sort;
		    *r_sort = (*r_sort)->r_next;
		    env_deliver->e_n_rcpt--;

		    if ( remove->r_status == R_FAILED ) {
			syslog( LOG_WARNING,
				"Deliver %s: Removing To <%s> From "
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
		    syslog( LOG_DEBUG, "Deliver %s: Keeping To <%s> From <%s>",
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
		syslog( LOG_WARNING, "Deliver %s: Rewrite failed, "
			"double delivery will occur", env_deliver->e_id );
		goto message_cleanup;
	    }

	    if ( env_deliver->e_dir == simta_dir_fast ) {
		/* overwrote fast file, not created a new one */
		simta_fast_files--;
		if ( simta_debug > 0 ) {
		    syslog( LOG_DEBUG, "Deliver %s: fast_files decrement %d",
			    env_deliver->e_id, simta_fast_files );
		}
	    }

	    assert( simta_fast_files >= 0 );

	/* else we need to touch the envelope if we started an attempt
	 * deliver the message, but it was unsuccessful.  Note that we
	 * need to have a positive or negitive rcpt reply to prevent the
	 * queue from preserving order in the case of a perm tempfail
	 * situation.
	 */
	} else if ( d->d_n_rcpt_accepted ) {
	    touch++;
	}

	if ( env_bounce != NULL ) {
	    queue_envelope( env_bounce );
	    env_bounce = NULL;
	}

message_cleanup:
	if ((( touch != 0 ) || ( n_processed == 0 )) &&
		( env_deliver->e_dir == simta_dir_slow ) &&
		( d->d_unlinked == 0 ))  {
	    touch = 0;
	    env_touch( env_deliver );
	    syslog( LOG_DEBUG, "Deliver %s: Envelope touched",
		    env_deliver->e_id );
	}

	n_processed++;

	if ( env_bounce != NULL ) {
	    if ( env_unlink( env_bounce ) != 0 ) {
		syslog( LOG_WARNING,
			"Deliver %s: System error, can't unwind bounce",
			env_bounce->e_id );
	    } else {
		syslog( LOG_WARNING, "Deliver %s: Message deleted: "
			"System error, unwound bounce", env_bounce->e_id );
	    }

	    env_free( env_bounce );
	    env_bounce = NULL;
	}

	/* per-host punting */
	if ( deliver_q->hq_red != NULL ) {
	    if ( deliver_q->hq_red->red_policy_punting ==
		    RED_PUNTING_ENABLED ) {
		deliver_q->hq_no_punt &= ~NOPUNT_MX;
	    } else if ( deliver_q->hq_red->red_policy_punting ==
		    RED_PUNTING_DISABLED ) {
		deliver_q->hq_no_punt |= NOPUNT_MX;
	    }
	}

	if ( d->d_unlinked == 0 ) {
	    if (( simta_punt_q != NULL ) && ( deliver_q != simta_punt_q ) &&
		    ( deliver_q->hq_no_punt == 0 )) {
		syslog( LOG_INFO, "Deliver %s: queueing for punt",
			env_deliver->e_id );
		env_clear_errors( env_deliver );
		env_deliver->e_flags |= ENV_FLAG_PUNT;
		queue_envelope( env_deliver );
	    } else {
		if (( simta_punt_q != NULL ) && ( deliver_q != simta_punt_q )) {
		    syslog( LOG_INFO, "Deliver %s: not puntable",
			    env_deliver->e_id );
		}
		env_move( env_deliver, simta_dir_slow );
		env_free( env_deliver );
		env_deliver = NULL;
		d->d_env = NULL;
	    }
	} else {
	    env_free( env_deliver );
	    env_deliver = NULL;
	    d->d_env = NULL;
	}

	if ( snet_dfile == NULL ) {
	    if ( dfile_fd > 0 ) {
		if ( close( dfile_fd ) != 0 ) {
		    syslog( LOG_ERR, "Syserror: q_deliver close: %m" );
		}
	    }

	} else {
	    if ( snet_close( snet_dfile ) != 0 ) {
		syslog( LOG_ERR, "Liberror: q_deliver snet_close: %m" );
	    }
	    snet_dfile = NULL;
	}

	if ( snet_lock != NULL ) {
	    if ( snet_close( snet_lock ) != 0 ) {
		syslog( LOG_ERR, "Liberror: q_deliver snet_close: %m" );
	    }
	}
    }

    if ( d->d_snet_smtp != NULL ) {
	syslog( LOG_DEBUG, "Queue %s: calling smtp_quit",
		deliver_q->hq_hostname );
	smtp_quit( deliver_q, d );
	if ( snet_close( d->d_snet_smtp ) != 0 ) {
	    syslog( LOG_ERR, "Liberror: q_deliver snet_close: %m" );
	}
	if ( d->d_dnsr_result_ip ) {
	    dnsr_free_result( d->d_dnsr_result_ip );
	}
	if ( d->d_dnsr_result_ip6 ) {
	    dnsr_free_result( d->d_dnsr_result_ip6 );
	}
	dnsr_free_result( d->d_dnsr_result );
    }

    return;
}


    void
deliver_local( struct deliver *d )
{
    int                         ml_error;

    syslog( LOG_NOTICE, "Deliver.local %s: local delivery attempt",
	    d->d_env->e_id );

    for ( d->d_rcpt = d->d_env->e_rcpt; d->d_rcpt != NULL;
	    d->d_rcpt = d->d_rcpt->r_next ) {

	/* Special handling for /dev/null */
	if ( strncasecmp( d->d_rcpt->r_rcpt, "/dev/null@", 10 ) == 0 ) {
	    d->d_rcpt->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> From <%s> Bitbucketed",
		    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail );
	    continue;
	}

	ml_error = EX_TEMPFAIL;

	if ( lseek( d->d_dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: deliver_local lseek: %m" );
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
	    d->d_n_rcpt_tempfailed++;
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
		d->d_n_rcpt_tempfailed, d->d_n_rcpt_failed );
    }

    d->d_delivered = 1;

    return;
}


    void
deliver_remote( struct deliver *d, struct host_q *hq )
{
    int				r_smtp;
    int				s;
    int				env_movement = 0;
    struct timeval		tv_start;
    struct timeval		tv_stop;

    if ( simta_gettimeofday( &tv_start ) != 0 ) {
	return;
    }

    switch ( hq->hq_status ) {
    case HOST_MX:
	syslog( LOG_NOTICE, "Deliver.remote %s: host %s", d->d_env->e_id,
		hq->hq_hostname );
	hq->hq_status = HOST_DOWN;
	break;

    case HOST_PUNT:
	syslog( LOG_NOTICE, "Deliver.remote %s: punt %s", d->d_env->e_id,
		hq->hq_hostname );
	hq->hq_status = HOST_PUNT_DOWN;
	break;

    default:
	panic( "deliver_remote: status out of range" );
    }

    for ( ; ; ) {
	if ( d->d_snet_smtp == NULL ) {
	    d->d_connection_msg_total = 0;
	    /* need to build SMTP connection */
	    if ( next_dnsr_host_lookup( d, hq ) != 0 ) {
		return;
	    }

retry:
	    /* build snet */
	    if (( s = socket( d->d_sa.ss_family, SOCK_STREAM, 0 )) < 0 ) {
		syslog( LOG_ERR, "Syserror: deliver_remote socket: %m" );
		continue;
	    }

	    if ( connect( s, (struct sockaddr *)&(d->d_sa),
		    (( d->d_sa.ss_family == AF_INET6 )
		    ? sizeof( struct sockaddr_in6 )
		    : sizeof( struct sockaddr_in ))) < 0 ) {
		syslog( LOG_ERR, "Connect.out [%s] %s: Failed: connect: %m",
			d->d_ip, hq->hq_hostname );
		close( s );
		continue;
	    }

	    syslog( LOG_DEBUG, "Connect.out [%s] %s: Success", d->d_ip,
		    hq->hq_hostname );

	    if (( d->d_snet_smtp = snet_attach( s, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "Liberror: deliver_remote snet_attach: %m" );
		close( s );
		continue;
	    }

	    simta_smtp_outbound_attempts++;
	    hq_clear_errors( hq );

	    if (( r_smtp = smtp_connect( hq, d )) == SMTP_BAD_TLS ) {
		snet_close( d->d_snet_smtp );
		d->d_snet_smtp = NULL;
		if ( hq->hq_red == NULL ) {
		    hq->hq_red = red_host_add( hq->hq_hostname );
		}
		syslog( LOG_INFO,
			"Deliver.remote %s: disabling TLS and retrying",
			hq->hq_hostname );
		hq->hq_red->red_policy_tls = TLS_POLICY_DISABLED;
		goto retry;
	    } else if ( r_smtp != SMTP_OK ) {
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
	d->d_n_rcpt_tempfailed = 0;
	d->d_sent = 0;
	d->d_connection_msg_total++;

	/* Reset to the beginning of the file... */
	if ( lseek( snet_fd( d->d_snet_dfile ), (off_t)0, SEEK_SET ) != 0 ) {
	    syslog( LOG_ERR, "Syserror: deliver_remote lseek: %m" );
	    return;
	}

	/* ...and clear the buffer of stale data */
	snet_flush( d->d_snet_dfile );

	r_smtp = smtp_send( hq, d );

	if (( d->d_n_rcpt_failed ) ||
		( d->d_delivered && d->d_n_rcpt_accepted )) {
	    d->d_queue_movement = 1;
	    env_movement = 1;
	    simta_smtp_outbound_delivered++;
	    simta_gettimeofday( &tv_stop );
	    syslog( LOG_DEBUG, "Queue %s: %s Delivery activity: "
		    "%d failed %d accepted %ld milliseconds", hq->hq_hostname,
		    d->d_env->e_id, d->d_n_rcpt_failed,
		    d->d_delivered ? d->d_n_rcpt_accepted : 0,
		    SIMTA_ELAPSED_MSEC( tv_start, tv_stop ));
	}

	if ( r_smtp == SMTP_OK ) {
	    /* Close the connection if we've hit the per-connection
	     * message limit. */
	    if ( simta_outbound_connection_msg_max > 0 &&
		    d->d_connection_msg_total >= simta_outbound_connection_msg_max ) {
		smtp_quit( hq, d );
		snet_close( d->d_snet_smtp );
		d->d_snet_smtp = NULL;
	    }
	    switch ( hq->hq_status ) {
	    case HOST_DOWN:
		hq->hq_status = HOST_MX;
		return;

	    case HOST_PUNT_DOWN:
		env_clear_errors( d->d_env );
		hq->hq_status = HOST_PUNT;
		return;

	    default:
		panic( "deliver_remote: status out of range" );
	    }
	}

smtp_cleanup:
	if ( r_smtp == SMTP_ERROR ) {
	    smtp_quit( hq, d );
	}

	snet_close( d->d_snet_smtp );
	d->d_snet_smtp = NULL;

	if ( hq->hq_status == HOST_PUNT_DOWN ) {
	    hq_clear_errors( hq );

	} else if ( hq->hq_status == HOST_BOUNCE ) {
	    dll_free( d->d_ip_list );
	    if ( d->d_dnsr_result_ip ) {
		dnsr_free_result( d->d_dnsr_result_ip );
	    }
	    if ( d->d_dnsr_result_ip6 ) {
		dnsr_free_result( d->d_dnsr_result_ip6 );
	    }
	    if ( d->d_dnsr_result ) {
		dnsr_free_result( d->d_dnsr_result );
	    }
	    return;

	} else if ( hq->hq_status == HOST_DOWN ) {
	    if ( env_movement != 0 ) {
		hq->hq_status = HOST_MX;
		return;
	    }
	}
    }
}


    int
next_dnsr_host_lookup( struct deliver *d, struct host_q *hq )
{
    if ( next_dnsr_host( d, hq ) == 0 ) {
	d->d_queue_movement = 0;
	return( 0 );
    }

    if ( d->d_dnsr_result ) {
	dnsr_free_result( d->d_dnsr_result );
	d->d_dnsr_result = NULL;
    }

    syslog( LOG_DEBUG, "DNS %s: DNS exhausted", hq->hq_hostname );

    return( 1 );
}


    int
get_outbound_dns( struct deliver *d, struct host_q *hq )
{
    int 			i;

    /*
     * RFC 5321 5.1 Locating the Target Host
     *
     * The lookup first attempts to locate an MX record associated with the
     * name.  If a CNAME record is found, the resulting name is processed as
     * if it were the initial name.  If a non-existent domain error is
     * returned, this situation MUST be reported as an error.  If a
     * temporary error is returned, the message MUST be queued and retried
     * later (see Section 4.5.4.1).  If an empty list of MXs is returned,
     * the address is treated as if it was associated with an implicit MX
     * RR, with a preference of 0, pointing to that host.  If MX records are
     * present, but none of them are usable, or the implicit MX is unusable,
     * this situation MUST be reported as an error.
     *
     * If one or more MX RRs are found for a given name, SMTP systems MUST
     * NOT utilize any address RRs associated with that name unless they are
     * located using the MX RRs; the "implicit MX" rule above applies only
     * if there are no MX records present.  If MX records are present, but
     * none of them are usable, this situation MUST be reported as an error.
     *
     * When a domain name associated with an MX RR is looked up and the
     * associated data field obtained, the data field of that response MUST
     * contain a domain name.  That domain name, when queried, MUST return
     * at least one address record (e.g., A or AAAA RR) that gives the IP
     * address of the SMTP server to which the message should be directed.
     * Any other response, specifically including a value that will return a
     * CNAME record when queried, lies outside the scope of this Standard.
     * The prohibition on labels in the data that resolve to CNAMEs is
     * discussed in more detail in RFC 2181, Section 10.3 [38].
     */

    /* The lookup first attempts to locate an MX record associated with the
     * name.
     */
    if (( d->d_dnsr_result = get_mx( hq->hq_hostname )) == NULL ) {
	hq->hq_no_punt |= NOPUNT_MX;
	syslog( LOG_ERR, "DNS %s: MX lookup failure, Punting disabled",
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
	 * low_pref_mx_domain if configured.
	 * If we find one, we never punt mail destined for this host,
	 * and we only try remote delivery to mx entries that have a
	 * lower mx_preference than for what was matched.
	 */
	syslog( LOG_DEBUG, "DNS %s: %d MX Record Entries", hq->hq_hostname,
		d->d_dnsr_result->r_ancount );

	for ( i = 0; i < d->d_dnsr_result->r_ancount; i++ ) {
	    struct action			*a;
	    /* If one or more MX RRs are found for a given name, SMTP
	     * systems MUST NOT utilize any address RRs associated with
	     * that name unless they are located using the MX RRs;
	     */
	    if ( d->d_dnsr_result->r_answer[ i ].rr_type != DNSR_TYPE_MX ) {
		continue;
	    }

	    /* set mx pref cutoff if we are listed in the MX record */
	    if (( strcasecmp( simta_hostname,
		    d->d_dnsr_result->r_answer[i].rr_mx.mx_exchange )) == 0 ) {
		hq->hq_no_punt |= NOPUNT_MX;
		d->d_mx_preference_set = 1;
		d->d_mx_preference_cutoff =
			d->d_dnsr_result->r_answer[ i ].rr_mx.mx_preference;
		syslog( LOG_ERR, "DNS %s: Entry %d: MX Record lists "
			"localhost at precedence %d, Punting disabled",
			hq->hq_hostname, i, d->d_mx_preference_cutoff );
		break;
	    }

	    /* set mx pref cutoff if our secondary MX exchange is listed */
	    for ( a = simta_red_action_secondary_mx;
		    a != NULL; a = a->a_next_secondary_mx ) {
		if ( strcasecmp( a->a_fname,
			d->d_dnsr_result->r_answer[i].rr_mx.mx_exchange )
			== 0 ) {
		    hq->hq_no_punt |= NOPUNT_MX;
		    d->d_mx_preference_set = 1;
		    d->d_mx_preference_cutoff =
			    d->d_dnsr_result->r_answer[ i ].rr_mx.mx_preference;
		    syslog( LOG_ERR, "DNS %s: Entry %d: MX Record lists "
			    "secondary MX %s at precedence %d, "
			    "Punting disabled",
			    hq->hq_hostname, i, a->a_fname,
			    d->d_mx_preference_cutoff );
		    break;
		}
	    }
	}

    } else {
	if ( d->d_dnsr_result->r_ancount == 0 ) {
	    /* If an empty list of MXs is returned, the address is
	     * treated as if it was associated with an implicit MX
	     * RR, with a preference of 0, pointing to that host.
	     */
	    syslog( LOG_INFO, "DNS %s: MX record has 0 entries, "
		    "getting address record", hq->hq_hostname );
	} else {
	    /* If a CNAME record is found, the resulting name is processed as
	     * if it were the initial name.
	     */
	    syslog( LOG_INFO, "DNS %s: MX record is a single CNAME, "
		    "getting address record", hq->hq_hostname );
	}
	dnsr_free_result( d->d_dnsr_result );

	if ( simta_ipv6 ) {
	    if (( d->d_dnsr_result = get_aaaa( hq->hq_hostname )) == NULL ) {
		syslog( LOG_INFO, "DNS %s: AAAA record lookup failed",
			hq->hq_hostname );
		if ( simta_ipv4 == 0 ) {
		    return( 1 );
		}
	    }
	    if ( d->d_dnsr_result->r_ancount > 0 ) {
		syslog( LOG_INFO, "DNS %s: %d AAAA record entries",
			hq->hq_hostname, d->d_dnsr_result->r_ancount );
		return( 0 );
	    }
	    dnsr_free_result( d->d_dnsr_result );
	    d->d_dnsr_result = NULL;
	}

	if ( simta_ipv4 ) {
	    if (( d->d_dnsr_result = get_a( hq->hq_hostname )) == NULL ) {
		syslog( LOG_INFO, "DNS %s: A record lookup failed",
			hq->hq_hostname );
		return( 1 );
	    }
	    if ( d->d_dnsr_result->r_ancount > 0 ) {
		syslog( LOG_INFO, "DNS %s: %d A record entries",
			hq->hq_hostname, d->d_dnsr_result->r_ancount );
		return( 0 );
	    }
	    dnsr_free_result( d->d_dnsr_result );
	    d->d_dnsr_result = NULL;
	}

	/* If MX records are present, but none of them are usable,
	 * or the implicit MX is unusable, this situation MUST be
	 * reported as an error.
	 */
	syslog( LOG_INFO, "DNS %s: address record missing, bouncing mail",
		hq->hq_hostname );
	if ( hq->hq_err_text == NULL ) {
	    if (( hq->hq_err_text = line_file_create()) == NULL ) {
		syslog( LOG_ERR,
			"Syserror: get_outbound_dns line_file_create: %m" );
		return( 1 );
	    }
	}
	if ( line_append( hq->hq_err_text, "Host does not exist",
		COPY ) == NULL ) {
	    syslog( LOG_ERR, "Syserror: get_outbound_dns line_append: %m" );
	    return( 1 );
	}
	hq->hq_status = HOST_BOUNCE;
	d->d_env->e_flags |= ENV_FLAG_BOUNCE;
	return( 1 );
    }

    return( 0 );
}

    int
next_dnsr_host( struct deliver *d, struct host_q *hq )
{
    struct connection_data	*cd;
    struct dnsr_rr		*rr;
    struct dnsr_result		*dnsr_result_ip;
    struct sockaddr_in		*sin;
    struct sockaddr_in6		*sin6;

    if ( d->d_dnsr_result == NULL ) {
	hq->hq_no_punt &= ~NOPUNT_MX;
	d->d_mx_preference_set = 0;
	d->d_cur_dnsr_result = 0;

	/* if the host is a regular MX host, try to get a valid MX record.
	 * failing that, try to get an A record.
	 *
	 * if the host is a punt host, just try to get the A record
	 */

	switch ( hq->hq_status ) {
	case HOST_DOWN:
	    if ( get_outbound_dns( d, hq ) != 0 ) {
		return( 1 );
	    }
	    break; /* case HOST_DOWN */

	case HOST_PUNT_DOWN:
	    if ( simta_ipv6 ) {
		if (( d->d_dnsr_result =
			get_aaaa( simta_punt_host )) == NULL ) {
		    syslog( LOG_WARNING,
			    "DNS %s: punt host AAAA record lookup failed",
			    simta_punt_host );
		    if ( simta_ipv4 == 0 ) {
			return( 1 );
		    }
		} else if ( d->d_dnsr_result->r_ancount == 0 ) {
		    dnsr_free_result( d->d_dnsr_result );
		    d->d_dnsr_result = NULL;
		}
	    }

	    if ( simta_ipv4 && ( d->d_dnsr_result == NULL )) {
		if (( d->d_dnsr_result = get_a( simta_punt_host )) == NULL ) {
		    syslog( LOG_WARNING,
			    "DNS %s: punt host A record lookup failed",
			    simta_punt_host );
		    return( 1 );
		}
		if ( d->d_dnsr_result->r_ancount == 0 ) {
		    dnsr_free_result( d->d_dnsr_result );
		    d->d_dnsr_result = NULL;
		}
	    }

	    if ( d->d_dnsr_result == NULL ) {
		syslog( LOG_WARNING, "DNS %s: punt host address record missing",
			simta_punt_host );
		return( 1 );
	    }
	    break; /* case HOST_PUNT_DOWN */

	default:
	    panic( "next_dnsr_host: variable out of range" );
	}
	d->d_cur_dnsr_result = -1;
    }

    /* the retry list is used for aggressive delivery.  a host gets on the
     * list when it allows queue movement, and falls off the list when it
     * fails to do so again.
     */
    if ( d->d_retry_cur != NULL ) {
	if ( d->d_queue_movement == 0 ) {
	    /* there was no queue movement on this host, we remove it */
	    cd = d->d_retry_cur;
	    d->d_retry_cur = d->d_retry_cur->c_next;
	    syslog( LOG_DEBUG, "DNS %s: removed %s from retry list",
		    hq->hq_hostname, cd->c_ip );
	    connection_data_free( d, cd );

	    if ( d->d_retry_cur == NULL ) {
		if ( d->d_retry_list != NULL ) {
		    d->d_retry_cur = d->d_retry_list;
		    syslog( LOG_DEBUG, "DNS %s: Retry list restarted",
			    hq->hq_hostname );
		} else {
		    /* we've removed our last item from the retry list */
		    syslog( LOG_DEBUG, "DNS %s: Retry list exhausted",
			    hq->hq_hostname );
		    return( 1 );
		}
	    }

	} else {
	    /* there was queue movement on this host, iterate */
	    if (( d->d_retry_cur = d->d_retry_cur->c_next ) == NULL ) {
		/* start the list over if we're at the end */
		d->d_retry_cur = d->d_retry_list;
		syslog( LOG_DEBUG, "DNS %s: Retry list restarted",
			hq->hq_hostname );
	    }
	}

retry:
	memcpy( &(d->d_sa), &(d->d_retry_cur->c_sa),
		sizeof( struct sockaddr_storage ));
	memcpy( d->d_ip, d->d_retry_cur->c_ip, sizeof( d->d_ip ));
	syslog( LOG_DEBUG, "DNS %s: Retry %s", hq->hq_hostname, d->d_ip );
	return( 0 );
    }

    /* see if we need to preserve the connection data for retry later */
    if (( simta_aggressive_delivery != 0 ) && ( d->d_queue_movement != 0 )) {
	if (( cd = connection_data_create( d )) != NULL ) {
	    syslog( LOG_DEBUG, "DNS %s: Added to Retry %s",
		    hq->hq_hostname, d->d_ip );
	}
    }

start:
    memset( &(d->d_sa), 0, sizeof( struct sockaddr_storage ));

    while ( d->d_dnsr_result_additional ) {
	d->d_cur_dnsr_result_ip = -3;
	memcpy( &(d->d_sa), &(d->d_dnsr_result_additional->ip_sa),
		sizeof( struct sockaddr_storage ));
	d->d_dnsr_result_additional = d->d_dnsr_result_additional->ip_next;
	if (( simta_ipv6 == 0 ) && ( d->d_sa.ss_family == AF_INET6 )) {
	    continue;
	} else if (( simta_ipv4 == 0 ) && ( d->d_sa.ss_family == AF_INET )) {
	    continue;
	}
	if ( deliver_checksockaddr( d, hq ) == 0 ) {
	    syslog( LOG_DEBUG, "DNS %s: Entry %d: Trying additional record: %s",
		    hq->hq_hostname, d->d_cur_dnsr_result, d->d_ip );
	    return( 0 );
	}
    }

    if ( d->d_cur_dnsr_result_ip < -1 ) {
	rr = d->d_dnsr_result->r_answer + d->d_cur_dnsr_result;

	if ( simta_ipv6 && ( d->d_cur_dnsr_result_ip == -3 )) {
	    if (( d->d_dnsr_result_ip6 = get_aaaa( rr->rr_mx.mx_exchange ))) {
		if ( d->d_dnsr_result_ip6->r_ancount > 0 ) {
		    syslog( LOG_INFO, "DNS %s: Entry %d: AAAA record found: %s",
			    hq->hq_hostname, d->d_cur_dnsr_result,
			    rr->rr_mx.mx_exchange );
		    d->d_cur_dnsr_result_ip = -1;
		    goto start;
		}
		dnsr_free_result( d->d_dnsr_result_ip6 );
		d->d_dnsr_result_ip6 = NULL;
	    }
	    syslog( LOG_INFO, "DNS %s: Entry %d: AAAA record not found: %s",
		    hq->hq_hostname, d->d_cur_dnsr_result,
		    rr->rr_mx.mx_exchange );
	}

	d->d_cur_dnsr_result_ip = -1;

	if ( simta_ipv4 == 0 ) {
	    goto start;
	}

	if (( d->d_dnsr_result_ip = get_a( rr->rr_mx.mx_exchange )) != NULL ) {
	    if ( d->d_dnsr_result_ip->r_ancount > 0 ) {
		syslog( LOG_INFO, "DNS %s: Entry %d: A record found: %s",
			hq->hq_hostname, d->d_cur_dnsr_result,
			rr->rr_mx.mx_exchange );
		goto start;
	    }
	    dnsr_free_result( d->d_dnsr_result_ip );
	    d->d_dnsr_result_ip = NULL;
	}
	syslog( LOG_INFO, "DNS %s: Entry %d: A record not found: %s",
		hq->hq_hostname, d->d_cur_dnsr_result, rr->rr_mx.mx_exchange );
    }

    dnsr_result_ip = d->d_dnsr_result_ip6
	    ? d->d_dnsr_result_ip6 : d->d_dnsr_result_ip;

    while ( dnsr_result_ip ) {
	for ( d->d_cur_dnsr_result_ip++;
		d->d_cur_dnsr_result_ip < dnsr_result_ip->r_ancount;
		d->d_cur_dnsr_result_ip++ ) {
	    rr = dnsr_result_ip->r_answer + d->d_cur_dnsr_result_ip;
	    if ( rr->rr_type == DNSR_TYPE_AAAA ) {
		sin6 = (struct sockaddr_in6 *)&(d->d_sa);
		sin6->sin6_family = AF_INET6;
		memcpy( &(sin6->sin6_addr), &(rr->rr_aaaa.aaaa_address),
			sizeof( struct in6_addr ));
	    } else if ( rr->rr_type == DNSR_TYPE_A ) {
		sin = (struct sockaddr_in *)&(d->d_sa);
		sin->sin_family = AF_INET;
		memcpy( &(sin->sin_addr), &(rr->rr_a.a_address),
			sizeof( struct in_addr ));
	    } else {
		syslog( LOG_DEBUG, "DNS %s: Entry %d.%d: "
			"uninteresting dnsr rr type %s: %d",
			hq->hq_hostname, d->d_cur_dnsr_result,
			d->d_cur_dnsr_result_ip, rr->rr_name, rr->rr_type );
		continue;
	    }

	    if ( deliver_checksockaddr( d, hq ) != 0 ) {
		continue;
	    }

	    syslog( LOG_DEBUG,
		    "DNS %s: Entry %d.%d: Trying address record: %s",
		    hq->hq_hostname, d->d_cur_dnsr_result,
		    d->d_cur_dnsr_result_ip, d->d_ip );
	    return( 0 );
	}
	dnsr_result_ip = NULL;
	if ( d->d_dnsr_result_ip6 ) {
	    dnsr_free_result( d->d_dnsr_result_ip6 );
	    d->d_dnsr_result_ip6 = NULL;
	    d->d_cur_dnsr_result_ip = -2;
	    goto start;
	}
	dnsr_free_result( d->d_dnsr_result_ip );
	d->d_dnsr_result_ip = NULL;
    }

    for ( d->d_cur_dnsr_result++;
	    d->d_cur_dnsr_result < d->d_dnsr_result->r_ancount;
	    d->d_cur_dnsr_result++ ) {
	rr = d->d_dnsr_result->r_answer + d->d_cur_dnsr_result;
	/* if the entry is an address record, use the associated IP info */
	if ( simta_ipv6 && ( rr->rr_type == DNSR_TYPE_AAAA )) {
	    sin6 = (struct sockaddr_in6 *)&(d->d_sa);
	    sin6->sin6_family = AF_INET6;
	    memcpy( &(sin6->sin6_addr), &(rr->rr_aaaa.aaaa_address),
		    sizeof( struct in6_addr ));
	    if ( deliver_checksockaddr( d, hq ) == 0 ) {
		syslog( LOG_DEBUG,
			"DNS %s: Entry %d: Trying AAAA record: %s",
			hq->hq_hostname, d->d_cur_dnsr_result, d->d_ip );
		return( 0 );
	    }
	    continue;

	} else if ( simta_ipv4 && ( rr->rr_type == DNSR_TYPE_A )) {
	    sin = (struct sockaddr_in *)&(d->d_sa);
	    sin->sin_family = AF_INET;
	    memcpy( &(sin->sin_addr), &(rr->rr_a.a_address),
		    sizeof( struct in_addr ));
	    if ( deliver_checksockaddr( d, hq ) == 0 ) {
		syslog( LOG_DEBUG,
			"DNS %s: Entry %d: Trying AAAA record: %s",
			hq->hq_hostname, d->d_cur_dnsr_result, d->d_ip );
		return( 0 );
	    }
	    continue;

	} else if (( rr->rr_type != DNSR_TYPE_MX ) ||
		( hq->hq_status != HOST_DOWN )) {
	    syslog( LOG_DEBUG,
		    "DNS %s: Entry %d: uninteresting dnsr rr type %s: %d",
		    hq->hq_hostname, d->d_cur_dnsr_result,
		    rr->rr_name, rr->rr_type );
	    continue;
	}

	/* Stop checking hosts if we know the local hostname is in
	 * the mx record and we've reached its preference level.
	 */
	if (( d->d_mx_preference_set != 0 ) &&
		( d->d_mx_preference_cutoff == rr->rr_mx.mx_preference )) {
	    syslog( LOG_INFO,
		    "DNS %s: Entry %d: MX preference %d: cutoff",
		    hq->hq_hostname, d->d_cur_dnsr_result,
		    rr->rr_mx.mx_preference );
	    break;
	}

	d->d_cur_dnsr_result_ip = -3;
	d->d_dnsr_result_additional = rr->rr_ip;
	goto start;
    }

    /* No more DNS data, start retrying */
    dll_free( d->d_ip_list );
    d->d_ip_list = NULL;

    if ( d->d_retry_list != NULL ) {
	d->d_retry_cur = d->d_retry_list;
	syslog( LOG_DEBUG, "DNS %s: Retry list start",
		hq->hq_hostname );
	goto retry;
    }

    return( 1 );
}

    static int
deliver_checksockaddr( struct deliver *d, struct host_q *hq )
{
    int			rc;
    struct dll_entry	*l;

    if (( rc = getnameinfo((struct sockaddr *)&(d->d_sa),
	    (( d->d_sa.ss_family == AF_INET6 )
	    ? sizeof( struct sockaddr_in6 )
	    : sizeof( struct sockaddr_in )), d->d_ip,
	    sizeof( d->d_ip ), NULL, 0, NI_NUMERICHOST )) != 0 ) {
	syslog( LOG_ERR, "Syserror: deliver_checksockaddr getnameinfo: %s",
		gai_strerror( rc ));
	return( 1 );
    }

    /* Reject loopback addresses, non-routable meta addresses, and
     * link-local addresses */
    if (
	    (( d->d_sa.ss_family == AF_INET ) && (
		( strncmp( d->d_ip, "127.", 4 ) == 0 ) ||
		( strcmp( d->d_ip, "0.0.0.0" ) == 0 ) ||
		( strncmp( d->d_ip, "169.254.", 8 ) == 0 ))) ||
	    (( d->d_sa.ss_family == AF_INET6 ) && (
		( strcmp( d->d_ip, "::1" ) == 0 ) ||
		( strncmp( d->d_ip, "fe80:", 5 ) == 0 )))) {
	syslog( LOG_INFO, "DNS %s: suppressing bad address: %s",
		hq->hq_hostname, d->d_ip );
	return( 1 );
    }

    l = dll_lookup_or_create( &d->d_ip_list, d->d_ip, 1 );
    if ( l->dll_data == NULL ) {
	l->dll_data = "SEEN";
    } else {
	syslog( LOG_INFO, "DNS %s: suppressing previously tried address: %s",
		hq->hq_hostname, d->d_ip );
	return( 1 );
    }

    /* Set the port */
    if ( d->d_sa.ss_family == AF_INET6 ) {
	((struct sockaddr_in6 *)&(d->d_sa))->sin6_port = htons( SIMTA_SMTP_PORT );
    } else {
	((struct sockaddr_in *)&(d->d_sa))->sin_port = htons( SIMTA_SMTP_PORT );
    }

    return( 0 );
}

    struct connection_data *
connection_data_create( struct deliver *d )
{
    struct connection_data		*cd;

    cd = calloc( 1, sizeof( struct connection_data ));
    memcpy( &(cd->c_sa), &(d->d_sa), sizeof( struct sockaddr_storage ));
    memcpy( cd->c_ip, d->d_ip, sizeof( cd->c_ip ));

    if ( d->d_retry_list_end == NULL ) {
	d->d_retry_list = cd;
	d->d_retry_list_end = cd;

    } else {
	d->d_retry_list_end->c_next = cd;
	cd->c_prev = d->d_retry_list_end;
	d->d_retry_list_end = cd;
    }

    return( cd );
}


    void
connection_data_free( struct deliver *d, struct connection_data *cd )
{
    if ( cd->c_prev != NULL ) {
	cd->c_prev->c_next = cd->c_next;
    } else {
	d->d_retry_list = cd->c_next;
    }

    if ( cd->c_next != NULL ) {
	cd->c_next->c_prev = cd->c_prev;
	d->d_retry_cur = cd->c_next;
    } else {
	d->d_retry_list_end = cd->c_prev;
	d->d_retry_cur = d->d_retry_list;
    }

    free( cd );
}


    void
queue_log_metrics( struct host_q *hq_schedule )
{
    char		filename[ MAXPATHLEN ];
    char		linkname[ MAXPATHLEN ];
    int			fd;
    FILE		*f;
    struct host_q	*hq;
    struct timeval	tv_now;
    struct stat		st_file;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return;
    }

    sprintf( linkname, "%s/etc/queue_schedule", simta_base_dir );
    sprintf( filename, "%s.%lX", linkname, (unsigned long)tv_now.tv_sec );

    if (( fd = open( filename, O_WRONLY | O_CREAT | O_TRUNC, 0666 )) < 0 ) {
	syslog( LOG_ERR, "Syserror: queue_log_metrics open: %m" );
	return;
    }

    if (( f = fdopen( fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "Syserror: queue_log_metrics fdopen: %m" );
	return;
    }

    fprintf( f, "Disk Read:\t%d\n\n", simta_disk_cycle );

    if ( simta_unexpanded_q != NULL ) {
	fprintf( f, "Unexpanded Messages:\t%d\n\n",
		simta_unexpanded_q->hq_entries );
    }

    fprintf( f, "Next\tMessages\tQueue\n" );

    for ( hq = hq_schedule; hq != NULL; hq = hq->hq_deliver_next ) {
	fprintf( f, "%d\t%d\t%s\n",
		(int)(hq->hq_next_launch.tv_sec - tv_now.tv_sec),
		hq->hq_entries, hq->hq_hostname );
    }

    fclose( f );

    if (( stat( linkname, &st_file ) == 0 ) && ( unlink( linkname ) != 0 )) {
	syslog( LOG_ERR, "Syserror: queue_log_metrics unlink: %m" );
    } else if ( link( filename, linkname ) != 0 ) {
	syslog( LOG_DEBUG, "Syserror: queue_log_metrics link: %m" );
    }
    
    return;
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
