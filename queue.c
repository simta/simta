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

void	q_deliver( struct host_q **, struct host_q * );
void	deliver_local( struct deliver *d );
void	deliver_remote( struct deliver *d, struct host_q * );
void	hq_clear_errors( struct host_q * );
int	next_dnsr_host( struct deliver *, struct host_q * );


    void
q_syslog( struct host_q *hq )
{
    struct envelope		*env;

    if ( hq == simta_null_q ) {
	syslog( LOG_DEBUG, "queue_syslog NULL queue" );
    } else {
	syslog( LOG_DEBUG, "queue_syslog %s", hq->hq_hostname );
    }

    for ( env = hq->hq_env_head; env != NULL; env = env->e_hq_next ) {
	env_syslog(  env );
    }

    return;
}


    void
q_stab_syslog( struct host_q *hq )
{
    struct host_q		*h;

    for ( h = hq; h != NULL; h = h->hq_next ) {
	q_syslog( h );
    }

    return;
}


    void
q_stdout( struct host_q *hq )
{
    struct envelope		*env;

    if (( hq->hq_hostname == NULL ) || ( *hq->hq_hostname == '\0' )) {
	printf( "%d\tNULL:\n", hq->hq_entries );
    } else {
	printf( "%d\t%s:\n", hq->hq_entries, hq->hq_hostname );
    }

    for ( env = hq->hq_env_head; env != NULL; env = env->e_hq_next ) {
	env_syslog( env );
    }

    return;
}


    void
q_stab_stdout( struct host_q *hq )
{
    for ( ; hq != NULL; hq = hq->hq_next ) {
	q_stdout( hq );
    }

    printf( "\n" );

    return;
}


    /* look up a given host in the host_q.  if not found, create */

    struct host_q *
host_q_create_or_lookup( struct host_q **host_q_head, char *hostname ) 
{
    struct host_q		*hq;

    /* create NULL host queue for unexpanded messages.  we always need to
     * have a NULL queue for error reporting. 
     */
    if ( simta_null_q == NULL ) {
	if (( simta_null_q = (struct host_q*)malloc(
		sizeof( struct host_q ))) == NULL ) {
	    syslog( LOG_ERR, "host_q_create_or_lookup malloc: %m" );
	    return( NULL );
	}
	memset( simta_null_q, 0, sizeof( struct host_q ));

	/* add this host to the host_q */
	simta_null_q->hq_hostname = "";
	simta_null_q->hq_next = *host_q_head;
	*host_q_head = simta_null_q;
	simta_null_q->hq_status = HOST_NULL;

	if ( simta_punt_host != NULL ) {
	    if (( simta_punt_q = (struct host_q*)malloc(
		    sizeof( struct host_q ))) == NULL ) {
		syslog( LOG_ERR, "host_q_create_or_lookup malloc: %m" );
		return( NULL );
	    }
	    memset( simta_punt_q, 0, sizeof( struct host_q ));

	    /* don't add this host to the host_q or a conflict could occur */
	    simta_punt_q->hq_hostname = simta_punt_host;
	    simta_punt_q->hq_status = HOST_PUNT;
	}
    }

    if ( hostname == NULL ) {
	return( simta_null_q );
    }

    for ( hq = *host_q_head; hq != NULL; hq = hq->hq_next ) {
	if ( strcasecmp( hq->hq_hostname, hostname ) == 0 ) {
	    break;
	}
    }

    if ( hq == NULL ) {
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

	/* add this host to the host_q_head */
	hq->hq_next = *host_q_head;
	*host_q_head = hq;
	/* determine if it's LOCAL or MX later */
	hq->hq_status = HOST_UNKNOWN;
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
queue_envelope( struct host_q **host_q_head, struct envelope *env )
{
    struct envelope		**ep;
    struct host_q		*hq;

    /* don't queue it if it's going in the dead queue */
    if ( env->e_dir == simta_dir_dead ) {
	return( 0 );
    }

    if ( env->e_flags & ENV_FLAG_PUNT ) {
	hq = simta_punt_q;

    } else {
	if (( hq = host_q_create_or_lookup( host_q_head, env->e_hostname ))
		== NULL ) {
	    return( 1 );
	}
    }

    /* sort queued envelopes by access time */
    for ( ep = &(hq->hq_env_head); *ep != NULL; ep = &((*ep)->e_hq_next)) {
	if ( env->e_last_attempt.tv_sec < (*ep)->e_last_attempt.tv_sec ) {
	    break;
	}
    }
    env->e_hq_next = *ep;
    *ep = env;

    hq->hq_entries++;
    env->e_hq = hq;

    if ( *(env->e_mail) != '\0' ) {
	hq->hq_from++;
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

	if ( *(env->e_mail) != '\0' ) {
	    env->e_hq->hq_from--;
	}

	env->e_hq = NULL;
	env->e_hq_next = NULL;
    }

    return;
}


    int
q_runner( struct host_q **host_q )
{
    SNET			*snet_lock;
    SNET			*snet_dfile;
    struct host_q		*hq;
    struct host_q		*deliver_q;
    struct host_q		**dq;
    struct envelope		*env_bounce;
    struct envelope		*env_punt;
    struct envelope		*unexpanded;
    int				result;
    int				dfile_fd;
    char                        dfile_fname[ MAXPATHLEN ];
    struct timeval		tv_start;
    struct timeval		tv_end;
    int				day;
    int				hour;
    int				min;
    int				sec;

    syslog( LOG_DEBUG, "q_runner starting" );

    assert( simta_fast_files >= 0 );

    if ( *host_q == NULL ) {
	syslog( LOG_ERR, "q_runner: NULL host_q" );
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

	for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	    hq->hq_deliver = NULL;

	    if (( hq->hq_entries == 0 ) || ( hq == simta_null_q )) {
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
		    if ( hq->hq_from > ((*dq)->hq_from)) {
			break;
		    }

		    if ( hq->hq_from == ((*dq)->hq_from)) {
			if ( hq->hq_entries >= ((*dq)->hq_entries)) {
			    break;
			}
		    }
		}

		hq->hq_deliver = *dq;
		*dq = hq;
		break;

	    case HOST_DOWN:
	    case HOST_BOUNCE:
		q_deliver( host_q, hq );
		break;

	    default:
		syslog( LOG_ERR, "q_runner: bad host type" );
		return( 1 );
	    }
	}

	/* deliver all mail in every expanded queue */
	for ( ; deliver_q != NULL; deliver_q = deliver_q->hq_deliver ) {
	    q_deliver( host_q, deliver_q );
	}

	/* punt any undelivered mail, if possible */
	if (( simta_punt_q != NULL ) && ( simta_punt_q->hq_entries > 0 )) {
	    syslog( LOG_DEBUG, "q_runner: punting undelivered mail to %s",
		    simta_punt_host );
	    q_deliver( host_q, simta_punt_q );
	}

	/* EXPAND ONE MESSAGE */
	for ( ; ; ) {
	    if (( unexpanded = simta_null_q->hq_env_head ) == NULL ) {
		/* no more unexpanded mail.  we're done */
		goto q_runner_done;
	    }

	    /* pop message off unexpanded message queue */
	    simta_null_q->hq_env_head = unexpanded->e_hq_next;
	    simta_null_q->hq_entries--;

	    if ( *(unexpanded->e_mail) != '\0' ) {
		simta_null_q->hq_from--;
	    }

	    /* if we don't have rcpts, we haven't read them off of the disk */
	    if ( unexpanded->e_rcpt == NULL ) {
		/* lock & read envelope to expand */
		if ( env_read_delivery_info( unexpanded, &snet_lock ) != 0 ) {
		    continue;
		}
	    } else {
		assert( unexpanded->e_dir == simta_dir_fast );
		snet_lock = NULL;
	    }

	    /* expand message */
	    result = expand( host_q, unexpanded );

	    if ( result != 0 ) {
		/* message not expandable */
		if ( unexpanded->e_dir != simta_dir_slow ) {
		    env_slow( unexpanded );

		} else {
		    /* message already in the slow queue, check it's age */
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

			if ( env_truncate_and_unlink( unexpanded,
				snet_lock ) == 0 ) {
			    queue_envelope( host_q, env_bounce );
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
	    }

unexpanded_clean_up:
	    if ( snet_lock != NULL ) {
		/* release lock */
		if ( snet_close( snet_lock ) != 0 ) {
		    syslog( LOG_ERR, "q_runner snet_close: %m" );
		}
	    }

	    env_free( unexpanded );

	    if ( result == 0 ) {
		/* at least one address was expanded.  try to deliver it */
		break;
	    }
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
	    simta_punt_q->hq_env_head = env_punt->e_hq_next;
	    simta_punt_q->hq_entries--;
	    if ( *(env_punt->e_mail) != '\0' ) {
		simta_punt_q->hq_from--;
	    }
	    env_slow( env_punt );
	    env_free( env_punt );
	}
    }

    if ( simta_fast_files != 0 ) {
	syslog( LOG_WARNING, "q_runner exiting with %d fast_files",
		simta_fast_files );
    }

    return( simta_fast_files );
}


    int
q_runner_dir( char *dir )
{
    struct host_q		*host_q = NULL;
    struct dirent		*entry;
    struct envelope		*env;
    DIR				*dirp;

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "q_runner_dir opendir %s: %m", dir );
	return( EXIT_OK );
    }

    errno = 0;

    /* organize a directory's messages by host and timestamp */
    while (( entry = readdir( dirp )) != NULL ) {
	if ( *entry->d_name == 'E' ) {
	    if (( env = env_create( NULL )) == NULL ) {
		continue;
	    }

	    if ( env_set_id( env, entry->d_name + 1 ) != 0 ) {
		env_free( env );
		continue;
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

	    if ( queue_envelope( &host_q, env ) != 0 ) {
		env_free( env );
	    }

	    simta_message_count++;
	}
    }

    if ( errno != 0 ) {
	syslog( LOG_ERR, "q_runner_dir readdir %s: %m", dir );
    }

    exit ( q_runner( &host_q ) != 0 );
}


    void
q_deliver( struct host_q **host_q, struct host_q *deliver_q )
{
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

    syslog( LOG_DEBUG, "q_deliver: delivering %s from %d total %d",
	    deliver_q->hq_hostname, deliver_q->hq_from, deliver_q->hq_entries );

    /* determine if the host we are delivering to is a local host or a
     * remote host if we have not done so already.
     */
    if ( deliver_q->hq_status == HOST_UNKNOWN ) {
	if ((( red = host_local( deliver_q->hq_hostname )) == NULL ) ||
		( red->red_host_type = RED_HOST_TYPE_SECONDARY_MX )) {
	    deliver_q->hq_status = HOST_MX;
	} else if (( simta_dnsr != NULL ) &&
		( simta_dnsr->d_errno == DNSR_ERROR_TIMEOUT )) {
	    deliver_q->hq_status = HOST_DOWN;
	} else {
	    deliver_q->hq_status = HOST_LOCAL;
	}
    }

    /* always try to punt the mail */
    if ( deliver_q->hq_status == HOST_PUNT_DOWN ) {
	deliver_q->hq_status = HOST_PUNT;
    }

    memset( &d, 0, sizeof( struct deliver ));

    /* process each envelope in the queue */
    while ( deliver_q->hq_env_head != NULL ) {
	env_deliver = deliver_q->hq_env_head;
	deliver_q->hq_env_head = deliver_q->hq_env_head->e_hq_next;

	if ( *(env_deliver->e_mail) != '\0' ) {
	    deliver_q->hq_from--;
	}

	assert( deliver_q->hq_from >= 0 );

	deliver_q->hq_entries--;

	assert( deliver_q->hq_entries >= 0 );

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

	/* open Dfile to deliver */
        sprintf( dfile_fname, "%s/D%s", env_deliver->e_dir, env_deliver->e_id );

        if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
	    syslog( LOG_WARNING, "q_deliver bad Dfile: %s", dfile_fname );
	    goto message_cleanup;
        }

	/* don't memset entire structure because we reuse connection data */
	d.d_env = env_deliver;
	d.d_dfile_fd = dfile_fd;
	d.d_n_rcpt_accepted = 0;
	d.d_n_rcpt_failed = 0;
	d.d_n_rcpt_tempfail = 0;
	d.d_attempt = 0;
	d.d_delivered = 0;
	d.d_unlinked = 0;

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
		queue_envelope( host_q, env_deliver );
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

	/* check the age of the original message unless we've created
	 * a bounce for the entire message, or if we've successfully
	 * delivered the message and no recipients tempfailed.
	 * note that this is the exact opposite of the test to delete
	 * a message: it is not nessecary to check a message's age
	 * for bounce purposes when it is already slated for deletion.
	 */
	if ((( env_deliver->e_flags & ENV_FLAG_BOUNCE ) == 0 ) &&
		(( d.d_delivered == 0 ) ||
		( d.d_n_rcpt_tempfail != 0 ))) {
	    if ( env_is_old( env_deliver, dfile_fd ) != 0 ) {
		    syslog( LOG_NOTICE, "q_deliver %s: old message, bouncing",
			    env_deliver->e_id );
		    env_deliver->e_flags |= ENV_FLAG_BOUNCE;
	    } else {
		syslog( LOG_DEBUG, "q_deliver %s: not old",
			env_deliver->e_id );
	    }
	}

	/* bounce the message if the host is bad, the message is bad, or
	 * if some recipients are bad.
	 */
	if (( env_deliver->e_flags & ENV_FLAG_BOUNCE ) ||
		(( d.d_delivered ) && ( d.d_n_rcpt_failed > 0 ))) {
            if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                syslog( LOG_ERR, "q_deliver lseek: %m" );
		panic( "q_deliver lseek fail" );
            }

	    if ( snet_dfile == NULL ) {
		if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 ))
			== NULL ) {
		    syslog( LOG_ERR, "q_deliver snet_attach: %m" );
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
        if (( env_deliver->e_flags & ENV_FLAG_BOUNCE ) ||
		(( d.d_delivered != 0 ) &&
		( d.d_n_rcpt_tempfail == 0 ))) {
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

	/* else we rewrite the message if its been successfully
	 * delivered, and some but not all recipients tempfail.
	 */
        } else if (( d.d_delivered != 0 ) &&
		(( d.d_n_rcpt_accepted != 0 ) ||
		( d.d_n_rcpt_failed != 0 ))) {
	    syslog( LOG_INFO, "Deliver %s: Rewriting Envelope",
		    env_deliver->e_id );
	    syslog( LOG_INFO, "Deliver %s: From <%s>", env_deliver->e_id,
		    env_deliver->e_mail );

	    r_sort = &(env_deliver->e_rcpt);
	    while ( *r_sort != NULL ) {
		if ((*r_sort)->r_status != R_TEMPFAIL ) {
		    remove = *r_sort;
		    *r_sort = (*r_sort)->r_next;
		    rcpt_free( remove );
		    free( remove );

		} else {
		    syslog( LOG_INFO, "Deliver %s: To <%s>",
			    env_deliver->e_id, (*r_sort)->r_rcpt );
		    r_sort = &((*r_sort)->r_next);
		}
	    }

	    if ( env_outfile( env_deliver ) != 0 ) {
		goto message_cleanup;
	    }

	    syslog( LOG_INFO, "Deliver %s: Envelope Rewritten",
		    env_deliver->e_id );

	    if ( env_deliver->e_dir == simta_dir_fast ) {
		/* overwrote fast file, not created a new one */
		simta_fast_files--;
	    }

	    assert( simta_fast_files >= 0 );

	/* else we need to touch the envelope if we started an attempt
	 * deliver the message, but it was unsuccessful.
	 */
	} else if (( d.d_attempt != 0 ) &&
		( env_deliver->e_dir == simta_dir_slow )) {
	    syslog( LOG_NOTICE, "q_deliver %s touching", env_deliver->e_id );
	    env_touch( env_deliver );
	}

	if ( env_bounce != NULL ) {
	    queue_envelope( host_q, env_bounce );
	    env_bounce = NULL;
	}

message_cleanup:
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
		queue_envelope( host_q, env_deliver );
	    } else {
		env_slow( env_deliver );
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
    struct recipient		*r;
    int                         ml_error;

    syslog( LOG_NOTICE, "deliver_local %s: attempting local delivery",
	    d->d_env->e_id );

    d->d_attempt = 1;

    for ( r = d->d_env->e_rcpt; r != NULL; r = r->r_next ) {
	ml_error = EX_TEMPFAIL;

	if ( lseek( d->d_dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
	    syslog( LOG_ERR, "deliver_local lseek: %m" );
	    goto lseek_fail;
	}

	syslog( LOG_INFO, "Deliver.local %s: From <%s>",
		d->d_env->e_id, r->r_rcpt );
	ml_error = (*simta_local_mailer)( d->d_dfile_fd, d->d_env->e_mail, r );

lseek_fail:
	switch ( ml_error ) {
	case EXIT_SUCCESS:
	    /* success */
	    r->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> Accepted",
		    d->d_env->e_id, r->r_rcpt );
	    break;

	default:
	case EX_TEMPFAIL:
	    r->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfail++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> Tempfailed: %d",
		    d->d_env->e_id, r->r_rcpt, ml_error );
	    break;

	case EX_DATAERR:
	case EX_NOUSER:
	    /* hard failure caused by bad user data, or no local user */
	    r->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
	    syslog( LOG_INFO, "Deliver.local %s: To <%s> Failed: %d",
		    d->d_env->e_id, r->r_rcpt, ml_error );
	    break;
	}

	syslog( LOG_INFO, "Deliver.local %s: Local delivery attempt complete",
		d->d_env->e_id );
    }

    d->d_delivered = 1;

    return;
}


    void
deliver_remote( struct deliver *d, struct host_q *hq )
{
    int				r_smtp;
    int				s;

    syslog( LOG_NOTICE, "deliver_remote %s: attempting remote delivery",
	    d->d_env->e_id );

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
		syslog( LOG_ERR, "deliver_remote %s socket: %m",
			hq->hq_hostname );
		goto connect_cleanup;
	    }

	    if ( connect( s, (struct sockaddr*)&(d->d_sin),
		    sizeof( struct sockaddr_in )) < 0 ) {
		syslog( LOG_ERR, "deliver_remote %s connect: %m",
			hq->hq_hostname );
		close( s );
		goto connect_cleanup;
	    }

	    if (( d->d_snet_smtp = snet_attach( s, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "deliver_remote %s snet_attach: %m",
			hq->hq_hostname );
		close( s );
		goto connect_cleanup;
	    }

	    simta_smtp_outbound_attempts++;
	    syslog( LOG_DEBUG, "deliver_remote %s: calling smtp_connect %s",
		    d->d_env->e_id, hq->hq_hostname );

	    hq_clear_errors( hq );

	    if (( r_smtp = smtp_connect( hq, d )) != SMTP_OK ) {
		goto smtp_cleanup;
	    }

	} else {
	    /* already have SMTP connection, say RSET and send message */
	    syslog( LOG_DEBUG, "deliver_remote %s: calling smtp_reset",
		    d->d_env->e_id );
	    if (( r_smtp = smtp_rset( hq, d )) != SMTP_OK ) {
		goto smtp_cleanup;
	    }
	}

	d->d_attempt = 1;
	syslog( LOG_DEBUG, "deliver_remote %s: calling smtp_send",
		d->d_env->e_id );

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

	env_clear_errors( d->d_env );

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
