#include "config.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

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

#include "denser.h"
#include "ll.h"
#include "envelope.h"
#include "queue.h"
#include "ml.h"
#include "line_file.h"
#include "smtp.h"
#include "expand.h"
#include "simta.h"
#include "bounce.h"
#include "mx.h"

void	q_deliver ( struct host_q **, struct host_q * );
void	deliver_local( struct deliver *d );
void	deliver_remote( struct deliver *d, SNET **, struct host_q * );


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
    }

    if ( *hostname == '\0' ) {
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

	if ( host_local( hq->hq_hostname ) != NULL ) {
	    hq->hq_status = HOST_LOCAL;
	} else {
	    hq->hq_status = HOST_MX;
	}
    }

    return( hq );
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

    if (( hq = host_q_create_or_lookup( host_q_head, env->e_hostname ))
	    == NULL ) {
	return( 1 );
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
	    case HOST_LOCAL:
	    case HOST_MX:
		/*
		 * hq is expanded and has at least one message, insert in to
		 * the delivery queue.
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
			syslog( LOG_DEBUG, "q_runner %s: old unexpandable "
				"message, bouncing", unexpanded->e_id );
			unexpanded->e_flags |= ENV_BOUNCE;
			if (( snet_dfile = snet_attach( dfile_fd,
				1024 * 1024 )) == NULL ) {
			    close( dfile_fd );
			    goto unexpanded_clean_up;
			}

			if (( env_bounce = bounce( hq, unexpanded,
				snet_dfile )) == NULL ) {
			    snet_close( snet_dfile );
			    goto unexpanded_clean_up;
			} else {
			    if ( env_unlink( unexpanded ) != 0 ) {
				env_unlink( env_bounce );
			    } else {
				queue_envelope( host_q, env_bounce );
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

		syslog( LOG_INFO, "q_runner metrics: %d messages, "
			"%d outbound_attempts, %d outbound_delivered, "
			"%d+%02d:%02d:%02d",
			simta_message_count, simta_smtp_outbound_attempts,
			simta_smtp_outbound_delivered,
			day, hour, min, sec );

	    } else {
		syslog( LOG_INFO, "q_runner metrics: %d messages, "
			"%d outbound_attempts, %d outbound_delivered, "
			"%02d:%02d:%02d",
			simta_message_count, simta_smtp_outbound_attempts,
			simta_smtp_outbound_delivered,
			hour, min, sec );
	    }
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

	    if ( queue_envelope( &host_q, env ) != 0 ) {
		env_free( env );
	    }

	    simta_message_count++;
	}
    }

    if ( errno != 0 ) {
	syslog( LOG_ERR, "q_runner_dir readdir %s: %m", dir );
    }

    if ( q_runner( &host_q ) != 0 ) {
	return( EXIT_FAST_FILE );
    }

    return( EXIT_OK );
}


    void
q_deliver( struct host_q **host_q, struct host_q *deliver_q )
{
    int                         dfile_fd;
    SNET                        *snet_dfile = NULL;
    SNET                        *snet_smtp = NULL;
    SNET			*snet_lock;
    SNET			*snet_bounce = NULL;
    char                        dfile_fname[ MAXPATHLEN ];
    char                        efile_fname[ MAXPATHLEN ];
    struct recipient		**r_sort;
    struct recipient		*remove;
    struct envelope		*env_deliver;
    struct envelope		*env_bounce = NULL;
    struct deliver		d;

    syslog( LOG_DEBUG, "q_deliver: delivering %s from %d total %d",
	    deliver_q->hq_hostname, deliver_q->hq_from, deliver_q->hq_entries );

    /* XXX epcjr and mcneal - determine if the host is local in the sense
     * that we use the local mailer or the SMTP outbounder here.
     */

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

	memset( &d, 0, sizeof( struct deliver ));
	d.d_env = env_deliver;
	d.d_dfile_fd = dfile_fd;

	switch ( deliver_q->hq_status ) {
        case HOST_LOCAL:
	    deliver_local( &d );
	    break;

        case HOST_MX:
	    if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "q_deliver snet_attach: %m" );
		goto message_cleanup;
	    }
	    d.d_dfile_snet = snet_dfile;

	    deliver_remote( &d, &snet_smtp, deliver_q );
	    break;

        case HOST_DOWN:
	    break;

        case HOST_BOUNCE:
	    break;

	default:
	    panic( "q_deliver host_status out of range" );
	}

	/* check the age of the envelope if the envelope has any tempfails or
	 * the host is HOST_DOWN, if we're not already bouncing the envelope
	 */
	if ((( d.d_n_rcpt_tempfail > 0 ) ||
		( deliver_q->hq_status == HOST_DOWN )) &&
		( ! ( env_deliver->e_flags & ENV_BOUNCE ))) {
	    if ( env_is_old( env_deliver, dfile_fd ) != 0 ) {
		    syslog( LOG_INFO, "q_deliver %s: old message, bouncing",
			    env_deliver->e_id );
		    env_deliver->e_flags |= ENV_BOUNCE;
	    } else {
		syslog( LOG_DEBUG, "q_deliver %s: not old",
			env_deliver->e_id );
	    }
	}

	/* bounce the message if the host is bad, the message is bad, or
	 * if some recipients are bad.
	 */
	if (( deliver_q->hq_status == HOST_BOUNCE ) ||
		( env_deliver->e_flags & ENV_BOUNCE ) ||
		( d.d_n_rcpt_failed > 0 )) {
	    snet_bounce = NULL;

            if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                syslog( LOG_ERR, "q_deliver lseek: %m" );
		panic( "q_deliver lseek fail" );
            }

	    if ( snet_dfile == NULL ) {
		if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 ))
			== NULL ) {
		    syslog( LOG_ERR, "q_deliver snet_attach: %m" );
		} else {
		    snet_bounce = snet_dfile;
		}
	    } else {
		snet_bounce = snet_dfile;
	    }

	    if (( env_bounce = bounce( deliver_q, env_deliver, snet_bounce ))
		    == NULL ) {
		syslog( LOG_ERR, "q_deliver bounce failed" );
		goto message_cleanup;
            }
	    syslog( LOG_INFO, "q_deliver %s: bounce %s generated",
		    env_deliver->e_id, env_bounce->e_id );
        }

	/* delete the original message if we've created
	 * a bounce for the entire message, or if we've successfully
	 * delivered the message and no recipients tempfailed.
	 */
        if (( deliver_q->hq_status == HOST_BOUNCE ) ||
		( env_deliver->e_flags & ENV_BOUNCE ) ||
		(( d.d_delivered != 0 ) &&
		( d.d_n_rcpt_tempfail == 0 ))) {
	    if ( snet_lock != NULL ) {
		if ( ftruncate( snet_fd( snet_lock ), (off_t)0 ) != 0 ) {
		    sprintf( efile_fname, "%s/E%s", env_deliver->e_dir,
			    env_deliver->e_id );
		    syslog( LOG_ERR, "q_deliver ftruncate %s: %m",
			    efile_fname );
		}
	    }

	    if ( env_unlink( env_deliver ) != 0 ) {
		goto message_cleanup;
	    }
	    d.d_unlinked = 1;

	/* else we rewrite the message if its been successfully
	 * delivered, and some but not all recipients tempfail.
	 */
        } else if (( d.d_delivered != 0 ) &&
		(( d.d_n_rcpt_accepted != 0 ) ||
		( d.d_n_rcpt_failed != 0 ))) {
	    syslog( LOG_INFO, "q_deliver %s rewriting", env_deliver->e_id );
	    r_sort = &(env_deliver->e_rcpt);

	    while ( *r_sort != NULL ) {
		if ((*r_sort)->r_status != R_TEMPFAIL ) {
		    remove = *r_sort;
		    *r_sort = (*r_sort)->r_next;
		    rcpt_free( remove );
		    free( remove );

		} else {
		    r_sort = &((*r_sort)->r_next);
		}
	    }

	    if ( env_outfile( env_deliver ) != 0 ) {
		goto message_cleanup;
	    }

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
	    syslog( LOG_INFO, "q_deliver %s touching", env_deliver->e_id );
	    env_touch( env_deliver );
	}

	if ( env_bounce != NULL ) {
	    queue_envelope( host_q, env_bounce );
	    env_bounce = NULL;
	}

message_cleanup:
	if ( env_bounce != NULL ) {
	    if ( env_unlink( env_bounce ) != 0 ) {
		syslog( LOG_INFO, "q_deliver env_unlink %s: can't unwind "
			"expansion", env_deliver->e_id );
	    } else {
		syslog( LOG_INFO, "q_deliver env_unlink %s: unwound "
			"expansion", env_deliver->e_id );
	    }

	    env_free( env_bounce );
	    env_bounce = NULL;
	}

	if ( d.d_unlinked == 0 ) {
	    env_slow( env_deliver );
	}

	env_free( env_deliver );

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

    if ( snet_smtp != NULL ) {
	syslog( LOG_DEBUG, "q_deliver: calling smtp_quit" );
        smtp_quit( snet_smtp, deliver_q );
	if ( snet_close( snet_smtp ) != 0 ) {
	    syslog( LOG_ERR, "q_deliver snet_close: %m" );
	}
    }

    return;
}


    void
deliver_remote( struct deliver *d, SNET **snet_smtp, struct host_q *deliver_q )
{
    int				smtp_error;

    syslog( LOG_INFO, "deliver_remote %s: attempting remote delivery",
	    d->d_env->e_id );

    /* open outbound SMTP connection, or say RSET */
    if ( *snet_smtp == NULL ) {
	simta_smtp_outbound_attempts++;
	syslog( LOG_DEBUG, "deliver_remote %s: calling smtp_connect( %s )",
		d->d_env->e_id, deliver_q->hq_hostname );
	if (( smtp_error = smtp_connect( snet_smtp, deliver_q )) !=
		SMTP_OK ) {
	    goto smtp_cleanup;
	}
    } else {
	syslog( LOG_DEBUG, "deliver_remote %s: calling smtp_reset",
		d->d_env->e_id );
	if (( smtp_error = smtp_rset( *snet_smtp, deliver_q ))
		!= SMTP_OK ) {
	    goto smtp_cleanup;
	}
    }

    d->d_attempt = 1;
    syslog( LOG_DEBUG, "deliver_remote %s: calling smtp_send",
	    d->d_env->e_id );

    if (( smtp_error = smtp_send( *snet_smtp, deliver_q, d )) == SMTP_OK ) {
	simta_smtp_outbound_delivered++;
	return;
    }

smtp_cleanup:
    if ( *snet_smtp != NULL ) {
	switch ( smtp_error ) {
	default:
	case SMTP_ERROR:
	    if ( snet_eof( *snet_smtp ) != 0 ) {
		syslog( LOG_DEBUG, "deliver_remote %s: call smtp_quit",
			d->d_env->e_id );
		smtp_quit( *snet_smtp, deliver_q );
	    }

	case SMTP_BAD_CONNECTION:
	    syslog( LOG_DEBUG, "deliver_remote %s: call snet_close",
		    d->d_env->e_id );
	    if ( snet_close( *snet_smtp ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
	    }
	    *snet_smtp = NULL;
	}
    }

    return;
}


    void
deliver_local( struct deliver *d )
{
    struct recipient		*r;
    int                         ml_error;

    syslog( LOG_INFO, "deliver_local %s: attempting local delivery",
	    d->d_env->e_id );

    d->d_attempt = 1;

    for ( r = d->d_env->e_rcpt; r != NULL; r = r->r_next ) {
	ml_error = EX_TEMPFAIL;

	if ( lseek( d->d_dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
	    syslog( LOG_ERR, "deliver_local lseek: %m" );
	    goto lseek_fail;
	}

	syslog( LOG_INFO, "deliver_local %s %s: attempting local delivery",
		d->d_env->e_id, r->r_rcpt );
	ml_error = (*simta_local_mailer)( d->d_dfile_fd, d->d_env->e_mail, r );

lseek_fail:
	switch ( ml_error ) {
	case EXIT_SUCCESS:
	    /* success */
	    r->r_status = R_ACCEPTED;
	    d->d_n_rcpt_accepted++;
	    syslog( LOG_INFO, "deliver_local %s %s: delivered locally",
		    d->d_env->e_id, r->r_rcpt );
	    break;

	default:
	case EX_TEMPFAIL:
	    r->r_status = R_TEMPFAIL;
	    d->d_n_rcpt_tempfail++;
	    syslog( LOG_INFO, "deliver_local %s %s: local delivery "
		    "tempfail %d", d->d_env->e_id, r->r_rcpt,
		    ml_error );
	    break;

	case EX_DATAERR:
	case EX_NOUSER:
	    /* hard failure caused by bad user data, or no local user */
	    r->r_status = R_FAILED;
	    d->d_n_rcpt_failed++;
	    syslog( LOG_INFO, "deliver_local %s %s: local delivery "
		    "hard failure", d->d_env->e_id, r->r_rcpt );
	    break;
	}
    }

    d->d_delivered = 1;

    return;
}
