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


int	q_deliver ___P(( struct host_q * ));
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
    if ( m->m_env != NULL ) {
	env_free( m->m_env );
	free( m->m_env );
    }

    free( m->m_id );
    free( m );
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

    if (( m->m_next = *mp ) == NULL ) {
	hq->hq_message_last = m;
    }

    hq->hq_entries++;

    *mp = m;
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

    syslog( LOG_DEBUG, "q_runner started" );

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
    struct envelope		env;
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

	    /* lock envelope while we expand */
	    if ( env_read( unexpanded, &env, &snet_lock ) != 0 ) {
		/* free message */
		message_free( unexpanded );
		continue;
	    }

	    /* expand message */
	    result = expand( host_q, &env );

	    /* release lock */
	    if ( snet_close( snet_lock ) != 0 ) {
		syslog( LOG_ERR, "q_run snet_close: %m" );
	    }

	    /* clean up */
	    env_reset( &env );
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


    int
q_deliver( struct host_q *hq )
{
    char                        dfile_fname[ MAXPATHLEN ];
    char                        efile_fname[ MAXPATHLEN ];
    int                         dfile_fd;
    SNET                        *dfile_snet = NULL;
    int                         result;
    int                         sent;
    char                        *at;
    SNET                        *snet = NULL;
    SNET			*snet_lock;
    struct timeval              tv;
    struct message		**mp;
    struct message		*m;
    struct recipient		**r_sort;
    struct recipient		*remove;
    struct envelope		*env;
    struct envelope		*bounce_env;
    struct envelope		env_local;
    struct recipient            *r;
    struct stat                 sb;
    static int                  (*local_mailer)(int, char *,
                                        struct recipient *) = NULL;

    if ( hq->hq_status == HOST_LOCAL ) {
        /* figure out what our local mailer is */
        if ( local_mailer == NULL ) {
            if (( local_mailer = get_local_mailer()) == NULL ) {
                syslog( LOG_ALERT, "q_deliver: no local mailer!" );
                return( -1 );
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
        return( -1 );
    }

    mp = &hq->hq_message_first;

    while ( *mp != NULL ) {
	m = *mp;
	*mp = m->m_next;
	hq->hq_entries--;

	if (( env = m->m_env ) == NULL ) {
	    /* lock & read envelope to deliver */
	    env = &env_local;
	    if ( env_read( m, &env_local, &snet_lock ) != 0 ) {
		/* message not valid.  disregard */
		if ( strcmp( m->m_dir, simta_dir_fast ) == 0 ) {
		    simta_fast_files--;
		}
		message_free( m );
		continue;
	    }
	}

	/* open Dfile to deliver & check to see if it's geriatric */
        errno = 0;
        sprintf( dfile_fname, "%s/D%s", m->m_dir, m->m_id );

        if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
            if ( errno == ENOENT ) {
                errno = 0;
                syslog( LOG_WARNING, "q_deliver missing Dfile: %s",
                        dfile_fname );

		if ( snet_close( snet_lock ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver snet_close: %m" );
		    return( -1 );
		}

		if ( strcmp( m->m_dir, simta_dir_fast ) == 0 ) {
		    simta_fast_files--;
		}

		message_free( m );
                continue;

            } else {
                syslog( LOG_ERR, "q_deliver open %s: %m", dfile_fname );
                return( -1 );
            }
        }

        /* stat dfile to see if it's old */
        if ( fstat( dfile_fd, &sb ) != 0 ) {
            syslog( LOG_ERR, "q_deliver snet_attach: %m" );
            return( -1 );
        }

        if ( gettimeofday( &tv, NULL ) != 0 ) {
            syslog( LOG_ERR, "q_deliver gettimeofday" );
            return( -1 );
        }

        /* consider Dfiles old if they're over 3 days */
        if (( tv.tv_sec - sb.st_mtime ) > ( 60 * 60 * 24 * 3 )) {
            env->e_old_dfile = 1;
        }

        if ( hq->hq_status == HOST_LOCAL ) {
            /* HOST_LOCAL sent is incremented every time we send
             * a message to a user via. a local mailer.
             */
            sent = 0;

            for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
                if ( sent != 0 ) {
                    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                        syslog( LOG_ERR, "q_deliver lseek: %m" );
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

                if (( result = (*local_mailer)( dfile_fd, env->e_mail,
                        r )) < 0 ) {
                    /* syserror */
                    return( -1 );

                } else if ( result == 0 ) {
                    /* success */
                    r->r_delivered = R_DELIVERED;
                    env->e_success++;

		} else if (( result == EX_TEMPFAIL ) &&
			( env->e_old_dfile == 0 )) {
		    r->r_delivered = R_TEMPFAIL;
		    env->e_tempfail++;

                } else {
                    /* hard failure */
                    r->r_delivered = R_FAILED;
                    env->e_failed++;
                }

                if ( at != NULL ) {
                    *at = '@';
                }

                sent++;
            }

        } else if ( hq->hq_status == HOST_MX ) {
            if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
                syslog( LOG_ERR, "q_deliver snet_attach: %m" );
                return( -1 );
            }

            if ( sent != 0 ) {

                if (( result = smtp_rset( snet, hq )) == SMTP_ERR_SYSCALL ) {
                    return( -1 );

                } else if ( result == SMTP_ERR_REMOTE ) {
		    snet = NULL;
		    goto cleanup;
                }
            }

            /* open connection, completely ready to send at least one message */
            if ( snet == NULL ) {
                if (( result = smtp_connect( &snet, hq ))
			== SMTP_ERR_SYSCALL ) {
                    return( -1 );

                } else if ( result == SMTP_ERR_REMOTE ) {
		    goto cleanup;
                }
            }

            if (( result = smtp_send( snet, hq, env, dfile_snet ))
		    == SMTP_ERR_SYSCALL ) {
                return( -1 );

            } else if ( result == SMTP_ERR_REMOTE ) {
		snet = NULL;
		goto cleanup;
	    }

            sent++;
        }

cleanup:
	/* if hq->hq_err_text != NULL, bounce entire message */
	/* if env->e_err_text != NULL, bounce entire message */
	/* if env->e_failed > 0, bounce at least some rcpts */
	/* if hq->hq_status == HOST_DOWN && env->e_old_dfile > 0,
	 *	bounce message */

        if (( hq->hq_err_text != NULL ) ||( env->e_err_text != NULL ) ||
		( env->e_failed > 0 ) || (( hq->hq_status == HOST_DOWN ) &&
		( env->e_old_dfile > 0 ))) {
            if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
                syslog( LOG_ERR, "q_deliver lseek: %m" );
                return( -1 );
            }

            if ( dfile_snet == NULL ) {
                if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 ))
                        == NULL ) {
                    syslog( LOG_ERR, "q_deliver snet_attach: %m" );
                    return( -1 );
                }
            }

	    if ( hq->hq_err_text != NULL ) {
		env->e_err_text = hq->hq_err_text;
	    }

            if (( bounce_env = bounce( env, dfile_snet )) == NULL ) {
                return( -1 );
            }
	    env_free( bounce_env );
	    free( bounce_env );

	    if ( hq->hq_err_text != NULL ) {
		env->e_err_text = NULL;
	    }
        }

        if ( dfile_snet == NULL ) {
            if ( close( dfile_fd ) != 0 ) {
                syslog( LOG_ERR, "q_deliver close: %m" );
                return( -1 );
            }

        } else {
            if ( snet_close( dfile_snet ) != 0 ) {
                syslog( LOG_ERR, "q_deliver snet_close: %m" );
                return( -1 );
            }

	    dfile_snet = NULL;
        }

	/* if hq->hq_status == HOST_BOUNCE, delete message */
	/* if env->e_err_text != NULL, delete message */
	/* if hq->hq_status != HOST_DOWN && env->e_tempfail == 0,
	 *	delete message */
	/* if hq->hq_status == HOST_DOWN && env->e_old_dfile > 0,
	 *	delete message */

        if (( hq->hq_status == HOST_BOUNCE ) || ( env->e_err_text != NULL ) ||
		(( env->e_tempfail == 0 ) && ( hq->hq_status != HOST_DOWN )) ||
		(( hq->hq_status == HOST_DOWN ) && ( env->e_old_dfile > 0 ))) {
	    /* no retries, delete Efile then Dfile */
	    sprintf( efile_fname, "%s/E%s", env->e_dir, env->e_id );

	    if ( ftruncate( snet_fd( snet_lock ), (off_t)0 ) != 0 ) {
		syslog( LOG_ERR, "q_deliver ftruncate %s: %m", efile_fname );
		return( -1 );
	    }

	    if ( env_unlink( env ) != 0 ) {
		return( -1 );
	    }

        } else {
            /* some retries; place in retry list */

            if (( env->e_success != 0 ) || ( env->e_failed != 0 )) {
		/* remove any recipients that don't need to be tried later */
		r_sort = &(env->e_rcpt);

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
                if ( env_outfile( env, env->e_dir ) != 0 ) {
                    return( -1 );
                }

		if ( strcmp( env->e_dir, simta_dir_fast ) == 0 ) {
		    /* overwrote fast file, not created a new one */
		    simta_fast_files--;
		}

            } else if ( hq->hq_status != HOST_DOWN ) {
                /* all retries.  touch envelope */
		if ( env_touch( env ) != 0 ) {
                    return( -1 );
		}
            }

	    /* move message to SLOW if it isn't there already */
	    if ( env_slow( env ) != 0 ) {
		return( -1 );
	    }
        } 

	if ( snet_close( snet_lock ) != 0 ) {
	    syslog( LOG_ERR, "q_deliver snet_close: %m" );
	    return( -1 );
	}

	env_reset( env );
	message_free( m );
    }

    if ( snet != NULL ) {
        if (( result = smtp_quit( snet, hq )) < 0 ) {
            return( -1 );
        }
    }

    return( 0 );
}
