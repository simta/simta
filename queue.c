#include "config.h"

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

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
#include "expand.h"
#include "simta.h"
#include "bounce.h"


void	q_deliver ___P(( struct host_q * ));
int	deliver_local ___P(( struct envelope *, int ));


    int
message_slow( struct message *m )
{
    /* move message to SLOW if it isn't there already */
    if ( strcmp( m->m_dir, simta_dir_slow ) != 0 ) {
	sprintf( simta_ename, "%s/E%s", m->m_dir, m->m_id );
	sprintf( simta_dname, "%s/D%s", m->m_dir, m->m_id );
	sprintf( simta_ename_slow, "%s/E%s", simta_dir_slow, m->m_id );
	sprintf( simta_dname_slow, "%s/D%s", simta_dir_slow, m->m_id );

	if ( link( simta_ename, simta_ename_slow ) != 0 ) {
	    syslog( LOG_ERR, "message_slow link %s %s: %m", simta_ename,
		    simta_ename_slow );
	    return( -1 );
	}

	if ( link( simta_dname, simta_dname_slow ) != 0 ) {
	    syslog( LOG_ERR, "message_slow link %s %s: %m", simta_dname,
		    simta_dname_slow );
	    return( -1 );
	}

	if ( unlink( simta_ename ) != 0 ) {
	    syslog( LOG_ERR, "message_slow unlink %s: %m", simta_ename );
	    return( -1 );
	}

	if ( strcmp( simta_dir_fast, m->m_dir ) == 0 ) {
	    simta_fast_files--;
	}

	if ( unlink( simta_dname_slow ) != 0 ) {
	    syslog( LOG_ERR, "message_slow unlink %s: %m", simta_dname );
	    return( -1 );
	}
    }

    return( 0 );
}


    void
message_stdout( struct message *m )
{
    while ( m != NULL ) {
	printf( "\t%s\n", m->m_id );
	m = m->m_next;
    }
}


    void
q_stdout( struct host_q *hq )
{
    if (( hq->hq_hostname == NULL ) || ( *hq->hq_hostname == '\0' )) {
	printf( "%d\tNULL:\n", hq->hq_entries );
    } else {
	printf( "%d\t%s:\n", hq->hq_entries, hq->hq_hostname );
    }

    message_stdout( hq->hq_message_first );
}


    void
q_stab_stdout( struct host_q *hq )
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
	syslog( LOG_ERR, "message_create malloc: %m" );
	return( NULL );
    }
    memset( m, 0, sizeof( struct message ));

    if (( m->m_id = strdup( id )) == NULL ) {
	syslog( LOG_ERR, "message_create strdup: %m" );
	free( m );
	return( NULL );
    }

    return( m );
}


    void
message_free( struct message *m )
{
    if ( m != NULL ) {
	free( m->m_id );
	free( m );
    }
}


    void
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

    hq->hq_entries++;
    m->m_hq = hq;

    *mp = m;
}


    void
message_remove( struct message *m )
{
    struct message		**mp;

    if ( m != NULL ) {
	for ( mp = &(m->m_hq->hq_message_first ); *mp != m;
		mp = &((*mp)->m_next))
	    ;

	*mp = m->m_next;
	m->m_hq->hq_entries--;
    }
}


    /* look up a given host in the host_q.  if not found, create */

    struct host_q *
host_q_lookup( struct host_q **host_q, char *hostname ) 
{
    struct host_q		*hq;

    if ( hostname == NULL ) {
	syslog( LOG_ERR, "host_q_lookup hostname: NULL not allowed" );
	return( NULL );
    }

    /* create NULL host queue for unexpanded messages */
    if ( simta_null_q == NULL ) {
	for ( simta_null_q = *host_q; simta_null_q != NULL;
		simta_null_q = simta_null_q->hq_next ) {
	    if ( strcasecmp( hq->hq_hostname, SIMTA_NULL_QUEUE ) == 0 ) {
		break;
	    }
	}

	if ( simta_null_q == NULL ) {
	    if (( simta_null_q = (struct host_q*)malloc(
		    sizeof( struct host_q ))) == NULL ) {
		syslog( LOG_ERR, "host_q_lookup malloc: %m" );
		return( NULL );
	    }
	    memset( simta_null_q, 0, sizeof( struct host_q ));

	    if (( simta_null_q->hq_hostname =
		    strdup( SIMTA_NULL_QUEUE )) == NULL ) {
		syslog( LOG_ERR, "host_q_lookup strdup: %m" );
		free( simta_null_q );
		return( NULL );
	    }

	    /* add this host to the host_q */
	    simta_null_q->hq_next = *host_q;
	    *host_q = simta_null_q;
	    simta_null_q->hq_status = HOST_NULL;
	}
    }

    for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	if ( strcasecmp( hq->hq_hostname, hostname ) == 0 ) {
	    break;
	}
    }

    if ( hq == NULL ) {
	if (( hq = (struct host_q*)malloc( sizeof( struct host_q ))) == NULL ) {
	    syslog( LOG_ERR, "host_q_lookup malloc: %m" );
	    return( NULL );
	}
	memset( hq, 0, sizeof( struct host_q ));

	if (( hq->hq_hostname = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "host_q_lookup strdup: %m" );
	    free( hq );
	    return( NULL );
	}

	/* add this host to the host_q */
	hq->hq_next = *host_q;
	*host_q = hq;

	if ( strcasecmp( simta_hostname, hq->hq_hostname ) == 0 ) {
	    hq->hq_status = HOST_LOCAL;
	} else {
	    hq->hq_status = HOST_MX;
	}
    }

    return( hq );
}


    /* return 0 on success
     * return -1 on fatal error (fast files are left behind)
     * syslog errors
     */

    int
q_runner( struct host_q **host_q )
{
    struct host_q		*hq;
    struct message		*m;

    syslog( LOG_DEBUG, "q_runner starting" );

    q_run( host_q );

    if ( simta_fast_files < 1 ) {
	return( 0 );
    }

    for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	for ( m = hq->hq_message_first; m != NULL; m = m->m_next ) {
	    if ( strcmp( m->m_dir, simta_dir_fast ) == 0 ) {
		message_slow( m );

		if ( simta_fast_files < 1 ) {
		    return( 0 );
		}
	    }
	}
    }

    return( -1 );
}


    /* only return 0 */

    int
q_run( struct host_q **host_q )
{
    struct host_q		*hq;
    struct host_q		*deliver_q;
    struct host_q		**dq;
    struct message		*unexpanded;
    SNET			*snet_lock;
    struct envelope		*env;
    struct envelope		env_local;
    int				result;

    syslog( LOG_DEBUG, "q_run started" );

    for ( ; ; ) {
	/* build the deliver_q by number of messages */
	syslog( LOG_DEBUG, "q_run building deliver queue" );
	deliver_q = NULL;

	for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	    if (( hq->hq_entries == 0 ) || ( hq == simta_null_q )) {
		hq->hq_deliver = NULL;

	    } else if (( hq->hq_status == HOST_LOCAL ) ||
		    ( hq->hq_status == HOST_MX )) {
		/*
		 * hq is expanded and has at least one message, insert in to
		 * the delivery queue.
		 */
		dq = &deliver_q;

		for ( ; ; ) {
		    if (( *dq == NULL ) ||
			    ( hq->hq_entries >= (*dq)->hq_entries )) {
			break;
		    }

		    dq = &((*dq)->hq_next);
		}

		hq->hq_deliver = *dq;
		*dq = hq;

	    } else if (( hq->hq_status == HOST_DOWN ) ||
		    ( hq->hq_status == HOST_BOUNCE )) {
		hq->hq_deliver = NULL;
		syslog( LOG_DEBUG, "q_run: calling deliver_q to bounce %s",
			deliver_q->hq_hostname );
		q_deliver( hq );

	    } else {
		syslog( LOG_ERR, "q_run: host_type %d out of range",
			hq->hq_status );
	    }
	}

	/* deliver all mail in every expanded queue */
	while ( deliver_q != NULL ) {
	    syslog( LOG_DEBUG, "q_run: calling deliver_q to deliver %s",
		    deliver_q->hq_hostname );
	    q_deliver( deliver_q );
	    deliver_q = deliver_q->hq_deliver;
	}

	/* EXPAND ONE MESSAGE */
	for ( ; ; ) {
	    /* delivered all expanded mail, check for unexpanded */
	    if (( unexpanded = simta_null_q->hq_message_first ) == NULL ) {
		/* no more unexpanded mail.  we're done */
		syslog( LOG_DEBUG, "q_run done: no more mail" );
		return( 0 );
	    }

	    /* pop message off unexpanded message queue */
	    simta_null_q->hq_message_first = unexpanded->m_next;
	    simta_null_q->hq_entries--;

	    if (( env = unexpanded->m_env ) == NULL ) {
		/* lock & read envelope to expand */
		env = &env_local;
		if ( env_read( unexpanded, &env_local, &snet_lock ) != 0 ) {
		    /* message not valid.  disregard */
		    if ( strcmp( unexpanded->m_dir, simta_dir_fast ) == 0 ) {
			simta_fast_files--;
		    }
		    message_free( unexpanded );
		    continue;
		}
	    } else {
		snet_lock = NULL;
	    }

	    /* expand message */
	    result = expand( host_q, env );

	    if ( snet_lock != NULL ) {
		/* release lock */
		if ( snet_close( snet_lock ) != 0 ) {
		    syslog( LOG_ERR, "q_run snet_close: %m" );
		}
	    }

	    /* clean up */
	    if ( unexpanded->m_env != NULL ) {
		env_free( unexpanded->m_env );
	    } else {
		env_reset( &env_local );
	    }
	    message_free( unexpanded );

	    if ( result != 0 ) {
		/* message not expandable, try the next one */
		continue;

	    } else {
		/* at least one address was expanded.  try to deliver it */
		break;
	    }
	}
    }
}


    /* return an exit code */

    int
q_runner_dir( char *dir )
{
    syslog( LOG_DEBUG, "q_runner_dir starting" );

    q_runner_d( dir );

    if ( simta_fast_files != 0 ) {
	syslog( LOG_ERR, "q_runner_dir exiting with %d fast_files",
		simta_fast_files );
	return( EXIT_FAST_FILE );
    }

    return( EXIT_OK );
}


    int
q_runner_d( char *dir )
{
    struct host_q		*host_q = NULL;
    struct host_q		*hq;
    struct message		*m;
    struct dirent		*entry;
    DIR				*dirp;
    int				result;
    char			hostname[ MAXHOSTNAMELEN + 1 ];

    /* create NULL host queue for unexpanded messages */
    if ( simta_null_q == NULL ) {
	if (( simta_null_q = host_q_lookup( &host_q, SIMTA_NULL_QUEUE ))
		== NULL ) {
	    syslog( LOG_ERR, "q_runner_dir can't allocate null queue" );
	    return( -1 );
	}
    }

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "q_runner_dir opendir %s: %m", dir );
	return( -1 );
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

	    if (( result = env_info( m, hostname, MAXHOSTNAMELEN )) < 0 ) {
		return( -1 );

	    } else if ( result > 0 ) {
		/* free message */
		message_free( m );
		continue;
	    }

	    if (( hq = host_q_lookup( &host_q, hostname )) == NULL ) {
		return( -1 );
	    }

	    message_queue( hq, m );
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "q_runner_dir readdir %s: %m", dir );
	return( EX_TEMPFAIL );
    }

#ifdef DEBUG
    printf( "q_runner_dir %s:\n", dir );
    q_stab_stdout( host_q );
#endif /* DEBUG */

    if ( q_runner( &host_q ) != 0 ) {
	return( -1 );
    }

    return( 0 );
}


    void
q_deliver( struct host_q *hq )
{
    int                         dfile_fd = 0;
    SNET                        *snet_dfile = NULL;
    SNET                        *snet_smtp = NULL;
    SNET			*snet_lock;
    SNET			*snet_bounce = NULL;
    char                        dfile_fname[ MAXPATHLEN ];
    char                        efile_fname[ MAXPATHLEN ];
    int                         ml_error;
    int                         unlinked;
    int				smtp_error;
    int                         sent;
    char                        *at;
    struct timeval              tv;
    struct message		**mp;
    struct message		*m;
    struct recipient		**r_sort;
    struct recipient		*remove;
    struct envelope		*env_deliver;
    struct envelope		*env_bounce = NULL;
    struct envelope		env_local;
    struct recipient            *r;
    struct stat                 sb;
    static int                  (*local_mailer)(int, char *,
                                        struct recipient *) = NULL;

    if ( hq->hq_status == HOST_LOCAL ) {
        /* figure out what our local mailer is */
        if ( local_mailer == NULL ) {
            if (( local_mailer = get_local_mailer()) == NULL ) {
                syslog( LOG_ALERT, "q_deliver: no local mailer" );
                hq->hq_status = HOST_DOWN;
            }
        }

    } else if ( hq->hq_status == HOST_MX ) {
        /* HOST_MX sent is used to count how many messages have been
         * sent to a SMTP host.
         */
        sent = 0;

    } else if (( hq->hq_status != HOST_BOUNCE ) &&
	    ( hq->hq_status != HOST_DOWN )) {
        syslog( LOG_ERR, "q_deliver fatal error: unreachable code" );
	hq->hq_status = HOST_DOWN;
    }

    mp = &hq->hq_message_first;

    while ( *mp != NULL ) {
	m = *mp;
	*mp = m->m_next;
	hq->hq_entries--;

	if (( env_deliver = m->m_env ) == NULL ) {
	    /* lock & read envelope to deliver */
	    env_deliver = &env_local;
	    if ( env_read( m, &env_local, &snet_lock ) != 0 ) {
		/* message not valid.  disregard */
		if ( strcmp( m->m_dir, simta_dir_fast ) == 0 ) {
		    /* XXX trouble here, we're stranding fast files? */
		    syslog( LOG_ERR, "q_deliver fast_file error 1" );
		    simta_fast_files--;
		}
		message_free( m );
		continue;
	    }

	} else {
	    if ( env_deliver->e_err_text != NULL ) {
		line_file_free( env_deliver->e_err_text );
		env_deliver->e_err_text = NULL;
	    }
	    /* don't need a lock, file is in the fast queue */
	    snet_lock = NULL;
	}

	env_deliver->e_flags = 0;
	env_deliver->e_success = 0;
	env_deliver->e_failed = 0;
	env_deliver->e_tempfail = 0;
	unlinked = 0;

	/* open Dfile to deliver & check to see if it's geriatric */
        sprintf( dfile_fname, "%s/D%s", m->m_dir, m->m_id );

        if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
	    syslog( LOG_WARNING, "q_deliver bad Dfile: %s", dfile_fname );
	    if ( strcmp( m->m_dir, simta_dir_fast ) == 0 ) {
		/* XXX trouble here, we're stranding fast files? */
		syslog( LOG_ERR, "q_deliver fast_file error 2" );
		simta_fast_files--;
	    }
	    goto message_cleanup;
        }

        if ( hq->hq_status == HOST_LOCAL ) {
            /* HOST_LOCAL sent is incremented every time we send
             * a message to a user via. a local mailer.
             */
	    syslog( LOG_INFO, "q_deliver %s: attempting local delivery",
		    env_deliver->e_id );
	    env_deliver->e_flags = ( env_deliver->e_flags | ENV_ATTEMPT );
            sent = 0;
            for ( r = env_deliver->e_rcpt; r != NULL; r = r->r_next ) {
		at = NULL;
		ml_error = EX_TEMPFAIL;

                if ( sent != 0 ) {
                    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                        syslog( LOG_ERR, "q_deliver lseek: %m" );
			goto lseek_fail;
                    }
                }

                for ( at = r->r_rcpt; ; at++ ) {
                    if ( *at == '@' ) {
                        *at = '\0';
                        break;

                    } else if ( *at == '\0' ) {
                        break;
                    }
                }

		syslog( LOG_INFO, "q_deliver %s %s: attempting local delivery",
			env_deliver->e_id, r->r_rcpt );
                ml_error = (*local_mailer)( dfile_fd, env_deliver->e_mail, r );

lseek_fail:
                if ( ml_error == 0 ) {
                    /* success */
                    r->r_delivered = R_DELIVERED;
                    env_deliver->e_success++;
		    syslog( LOG_INFO, "q_deliver %s %s: delivered locally",
			    env_deliver->e_id, r->r_rcpt );

		} else if ( ml_error == EX_TEMPFAIL ) {
		    r->r_delivered = R_TEMPFAIL;
		    env_deliver->e_tempfail++;
		    syslog( LOG_INFO, "q_deliver %s %s: local delivery "
			    "tempfail", env_deliver->e_id, r->r_rcpt );

                } else {
                    /* hard failure */
                    r->r_delivered = R_FAILED;
                    env_deliver->e_failed++;
		    syslog( LOG_INFO, "q_deliver %s %s: local delivery "
			    "hard failure", env_deliver->e_id, r->r_rcpt );
                }

                if ( at != NULL ) {
                    *at = '@';
                }

                sent++;
            }

        } else if ( hq->hq_status == HOST_MX ) {
            if (( snet_dfile = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
                syslog( LOG_ERR, "q_deliver snet_attach: %m" );
		smtp_error = SMTP_ERROR;
		goto smtp_cleanup;
            }

            /* open outbound SMTP connection */
            if ( snet_smtp == NULL ) {
                if (( smtp_error = smtp_connect( &snet_smtp, hq )) !=
			SMTP_OK ) {
		    goto smtp_cleanup;
		}
            }

            if ( sent != 0 ) {
                if (( smtp_error = smtp_rset( snet_smtp, hq )) != SMTP_OK ) {
		    goto smtp_cleanup;
                }
            }

	    env_deliver->e_flags = ( env_deliver->e_flags | ENV_ATTEMPT );
	    syslog( LOG_INFO, "q_deliver %s: attempting delivery via SMTP",
		    env_deliver->e_id );
            if (( smtp_error = smtp_send( snet_smtp, hq, env_deliver,
		    snet_dfile )) != SMTP_OK ) {
smtp_cleanup:
		if ( snet_smtp != NULL ) {
		    switch ( smtp_error ) {
		    default:
		    case SMTP_ERROR:
			smtp_quit( snet_smtp, hq );

		    case SMTP_BAD_CONNECTION:
			if ( snet_close( snet_smtp ) < 0 ) {
			    syslog( LOG_ERR, "snet_close: %m" );
			}
			snet_smtp = NULL;
		    }
		}
	    }
            sent++;

        } else if ( hq->hq_status == HOST_BOUNCE ) {
	    env_deliver->e_flags = ( env_deliver->e_flags | ENV_BOUNCE );
	}

	if ((( env_deliver->e_tempfail > 0 ) ||
		( hq->hq_status == HOST_DOWN )) &&
		( ! ( env_deliver->e_flags & ENV_BOUNCE ))) {
	    /* stat dfile to see if it's old */
	    if ( fstat( dfile_fd, &sb ) != 0 ) {
		syslog( LOG_ERR, "q_deliver snet_attach: %m" );
		goto oldfile_error;
	    }

	    if ( gettimeofday( &tv, NULL ) != 0 ) {
		syslog( LOG_ERR, "q_deliver gettimeofday" );
		goto oldfile_error;
	    }

	    /* consider Dfiles old if they're over 3 days */
	    if (( tv.tv_sec - sb.st_mtime ) > ( 60 * 60 * 24 * 3 )) {
oldfile_error:
		env_deliver->e_flags = ( env_deliver->e_flags | ENV_BOUNCE );
		env_deliver->e_flags = ( env_deliver->e_flags | ENV_OLD );
	    }
	}

	if (( env_deliver->e_flags & ENV_BOUNCE ) ||
		( env_deliver->e_failed > 0 )) {
	    snet_bounce = NULL;

            if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                syslog( LOG_ERR, "q_deliver lseek: %m" );

            } else {
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
	    }

	    /* create bounce message */
	    if (( env_bounce = bounce( hq, env_deliver, snet_bounce ))
		    == NULL ) {
		syslog( LOG_ERR, "q_deliver bounce failed" );
		goto message_cleanup;
            }
	    syslog( LOG_INFO, "q_deliver %s: bounce %s generated",
		    env_deliver->e_id, env_bounce->e_id );
        }

	/*
	 * DELETE ORIGINAL
	 *     - ENV_BOUNCE
	 *     - env_deliver->e_tempfail == 0 && !HOST_DOWN
	 *
	 * REWRITE ORIGINAL
	 *     - if tempfails && ( fails || successes )
	 *
	 * MOVE ORIGINAL
	 *     - if fast_queue
	 *
	 * TOUCH ORIGINAL
	 *     - if ENV_ATTEMPT
	 *
	 * IGNORE ORIGINAL
	 *     - everything else
	 */

        if (( env_deliver->e_flags & ENV_BOUNCE ) ||
		(( env_deliver->e_tempfail == 0 ) &&
		( hq->hq_status != HOST_DOWN ))) {
	    /* no retries, delete Efile then Dfile */

	    sprintf( efile_fname, "%s/E%s", env_deliver->e_dir,
		    env_deliver->e_id );

	    if ( snet_lock != NULL ) {
		if ( ftruncate( snet_fd( snet_lock ), (off_t)0 ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver ftruncate %s: %m",
			    efile_fname );
		}
	    } else {
		if ( truncate( efile_fname, (off_t)0 ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver truncate %s: %m",
			    efile_fname );
		}
	    }

	    if ( env_unlink( env_deliver ) != 0 ) {
		unlinked = 1;
		goto message_cleanup;
	    }

	    syslog( LOG_DEBUG, "q_deliver %s delivered", env_deliver->e_id );

        } else if (( env_deliver->e_success != 0 ) ||
		( env_deliver->e_failed != 0 )) {
	    /* remove any recipients that don't need to be tried later */
	    r_sort = &(env_deliver->e_rcpt);

	    while ( *r_sort != NULL ) {
		if ((*r_sort)->r_delivered != R_TEMPFAIL ) {
		    remove = *r_sort;
		    *r_sort = (*r_sort)->r_next;
		    rcpt_free( remove );

		} else {
		    r_sort = &((*r_sort)->r_next);
		}
	    }

	    /* write out modified envelope */
	    if ( env_outfile( env_deliver, env_deliver->e_dir ) != 0 ) {
		goto message_cleanup;
	    }

	    if ( strcmp( env_deliver->e_dir, simta_dir_fast ) == 0 ) {
		/* overwrote fast file, not created a new one */
		simta_fast_files--;
	    }

	} else if (( env_deliver->e_flags & ENV_ATTEMPT ) &&
		( strcmp( env_deliver->e_dir, simta_dir_fast ) != 0 )) {
	    env_touch( env_deliver );
	}

	if ( env_bounce != NULL ) {
	    if ( env_bounce->e_message != NULL ) {
		message_queue( simta_null_q, env_bounce->e_message );
	    }
	    env_bounce = NULL;
	}

message_cleanup:
	if ( env_bounce != NULL ) {
	    if ( env_bounce->e_message != NULL ) {
		message_free( env_bounce->e_message );
		env_bounce->e_message = NULL;
	    }
	    env_unlink( env_bounce );
	    env_free( env_bounce );
	    env_bounce = NULL;
	}

	if ( m->m_env != NULL ) {
	    if ( unlinked != 0 ) {
		env_slow( m->m_env );
	    }
	    env_free( m->m_env );
	} else {
	    env_reset( env_deliver );
	}

	message_free( m );

        if ( snet_dfile == NULL ) {
	    if ( dfile_fd >= 0 ) {
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
        smtp_quit( snet_smtp, hq );
	if ( snet_close( snet_smtp ) != 0 ) {
	    syslog( LOG_ERR, "q_deliver snet_close: %m" );
	}
    }
}
