#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#include <sys/time.h>
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
#include "expand.h"
#include "simta.h"
#include "bounce.h"


int	q_deliver ___P(( struct host_q * ));
int	deliver_local ___P(( struct envelope *, int ));


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


    void
message_free( struct message *m )
{
    free( m->m_id );
    free( m );
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

    hq->hq_entries++;

    *mp = m;

    return( 0 );
}


    /* look up a given host in the host_q.  if not found, create */

    struct host_q *
host_q_lookup( struct host_q **host_q, char *hostname ) 
{
    struct host_q		*hq;

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

	if ( strcasecmp( simta_hostname, hq->hq_hostname ) == 0 ) {
	    hq->hq_status = HOST_LOCAL;

	} else if (( hostname == NULL ) || ( *hostname == '\0' )) {
	    hq->hq_status = HOST_NULL;

	} else {
	    hq->hq_status = HOST_MX;
	}
    }

    return( hq );
}


    int
q_runner( struct host_q **host_q )
{
    struct host_q		*hq;
    struct host_q		*deliver_q;
    struct host_q		**dq;
    struct message		*unexpanded;
    SNET			*snet_lock;
    struct envelope		env;
    int				result;

    /* create NULL host queue for unexpanded messages */
    if ( simta_null_q == NULL ) {

#ifdef DEBUG
    printf( "simta_null_q init 2\n" );
#endif /* DEBUG */

	if (( simta_null_q = host_q_lookup( host_q, "\0" )) == NULL ) {
	    return( -1 );
	}
    }

    for ( ; ; ) {
	/* BUILD DELIVER_Q */
	/* sort the deliver_q by number of messages */
	deliver_q = NULL;

	for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	    if (( hq->hq_entries == 0 ) || ( hq == simta_null_q )) {
		hq->hq_deliver = NULL;

	    } else if (( hq->hq_status == HOST_LOCAL ) ||
		    ( hq->hq_status == HOST_MX )) {
		/* hq is expanded and has at least one message */
		dq = &deliver_q;

		for ( ; ; ) {
		    if (( *dq == NULL ) ||
			    ( hq->hq_entries >= (*dq)->hq_entries )) {
			break;
		    }
		}

		hq->hq_deliver = *dq;
		*dq = hq;

	    } else if (( hq->hq_status == HOST_DOWN ) ||
		    ( hq->hq_status == HOST_BOUNCE )) {
		hq->hq_deliver = NULL;

		if ( q_deliver( hq ) != 0 ) {
		    return( -1 );
		}

	    } else {
		syslog( LOG_ERR, "q_runner: host_type out of range" );
	    }
	}

	/* deliver all mail in every expanded queue */
	while ( deliver_q != NULL ) {
	    if ( q_deliver( deliver_q ) != 0 ) {
		return( -1 );
	    }

	    deliver_q = deliver_q->hq_deliver;
	}

	/* EXPAND ONE MESSAGE */
	for ( ; ; ) {

#ifdef DEBUG
    printf( "host_q before expand:\n" );
    q_stab_stdout( *host_q );
    printf( "\n" );
#endif /* DEBUG */

	    /* delivered all expanded mail, check for unexpanded */
	    if (( unexpanded = simta_null_q->hq_message_first ) == NULL ) {
		/* no more unexpanded mail.  we're done */
		return( 0 );
	    }

	    /* pop message off message queue */
	    simta_null_q->hq_message_first = unexpanded->m_next;
	    simta_null_q->hq_entries--;

	    /* lock envelope while we expand */
	    if (( result = env_read( unexpanded, &env, &snet_lock )) < 0 ) {
		return( -1 );

	    } else if ( result > 0 ) {
		/* free message */
		message_free( unexpanded );
		continue;
	    }

	    /* expand message */
	    if (( result = expand( host_q, &env )) != 0 ) {
		/* expand had an unrecoverable system error */
		return( -1 );
	    }

	    /* release lock */
	    if ( snet_close( snet_lock ) != 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( -1 );
	    }

	    /* reset envelope */
	    env_reset( &env );

	    if ( result > 0 ) {
		/* message not expandable, try the next one */
		continue;

	    } else {
		/* at least one address was expanded.  try to deliver it */
		break;
	    }
	}
    }
}


    int
q_runner_dir( char *dir )
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

#ifdef DEBUG
    printf( "simta_null_q init 1\n" );
#endif /* DEBUG */

	if (( simta_null_q = host_q_lookup( &host_q, "\0" )) == NULL ) {
	    exit( EX_TEMPFAIL );
	}
    }

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", dir );
	exit( EX_TEMPFAIL );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* organize a directory's messages by host and timestamp */
    while (( entry = readdir( dirp )) != NULL ) {
	if ( *entry->d_name == 'E' ) {
	    if (( m = message_create( entry->d_name + 1 )) == NULL ) {
		exit( EX_TEMPFAIL );
	    }

	    m->m_dir = dir;

	    if (( result = env_info( m, hostname, MAXHOSTNAMELEN )) < 0 ) {
		exit( EX_TEMPFAIL );

	    } else if ( result > 0 ) {
		/* free message */
		message_free( m );
		continue;
	    }

	    if (( hq = host_q_lookup( &host_q, hostname )) == NULL ) {
		exit( EX_TEMPFAIL );
	    }

	    if ( message_queue( hq, m ) < 0 ) {
		exit( EX_TEMPFAIL );
	    }
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
	exit( EX_TEMPFAIL );
    }

    return( 0 );
}


    int
q_deliver( struct host_q *hq )
{
    char                        dfile_fname[ MAXPATHLEN ];
    char                        dfile_slow[ MAXPATHLEN ];
    char                        efile_fname[ MAXPATHLEN ];
    char                        efile_slow[ MAXPATHLEN ];
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
    struct envelope		env;
    struct recipient            *r;
    struct stat                 sb;
    static int                  (*local_mailer)(int, char *,
                                        struct recipient *) = NULL;

#ifdef DEBUG
    printf( "q_deliver:\n" );
    q_stdout( hq );
    printf( "\n" );
#endif /* DEBUG */

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

	/* lock & read envelope to deliver */
	if (( result = env_read( m, &env, &snet_lock )) < 0 ) {
	    return( -1 );

	} else if ( result > 0 ) {
	    /* message not valid.  disregard */
	    *mp = m->m_next;
	    message_free( m );
	    hq->hq_entries--;
	    continue;
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

		*mp = m->m_next;
		message_free( m );
		hq->hq_entries--;

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
            env.e_old_dfile = 1;
        }

        if ( hq->hq_status == HOST_LOCAL ) {
            /* HOST_LOCAL sent is incremented every time we send
             * a message to a user via. a local mailer.
             */
            sent = 0;

            for ( r = env.e_rcpt; r != NULL; r = r->r_next ) {
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

                if (( result = (*local_mailer)( dfile_fd, env.e_mail,
                        r )) < 0 ) {
                    /* syserror */
                    return( -1 );

                } else if ( result == 0 ) {
                    /* success */
                    r->r_delivered = R_DELIVERED;
                    env.e_success++;

		} else if (( result == EX_TEMPFAIL ) &&
			( env.e_old_dfile == 0 )) {
		    r->r_delivered = R_TEMPFAIL;
		    env.e_tempfail++;

                } else {
                    /* hard failure */
                    r->r_delivered = R_FAILED;
                    env.e_failed++;
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

            if (( result = smtp_send( snet, hq, &env, dfile_snet ))
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
	/* if env.e_err_text != NULL, bounce entire message */
	/* if env.e_failed > 0, bounce at least some rcpts */
	/* if hq->hq_status == HOST_DOWN && env.e_old_dfile > 0,
	 *	bounce message */

        if (( hq->hq_err_text != NULL ) ||( env.e_err_text != NULL ) ||
		( env.e_failed > 0 ) || (( hq->hq_status == HOST_DOWN ) &&
		( env.e_old_dfile > 0 ))) {
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
		env.e_err_text = hq->hq_err_text;
	    }

            if ( bounce( &env, dfile_snet ) < 0 ) {
                return( -1 );
            }

	    if ( hq->hq_err_text != NULL ) {
		env.e_err_text = NULL;
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
	/* if env.e_err_text != NULL, delete message */
	/* if hq->hq_status != HOST_DOWN && env.e_tempfail == 0,
	 *	delete message */
	/* if hq->hq_status == HOST_DOWN && env.e_old_dfile > 0,
	 *	delete message */

        if (( hq->hq_status == HOST_BOUNCE ) || ( env.e_err_text != NULL ) ||
		(( env.e_tempfail == 0 ) && ( hq->hq_status != HOST_DOWN )) ||
		(( hq->hq_status == HOST_DOWN ) && ( env.e_old_dfile > 0 ))) {
	    /* no retries, delete Efile then Dfile */
	    sprintf( efile_fname, "%s/E%s", env.e_dir, env.e_id );

	    if ( ftruncate( snet_fd( snet_lock ), (off_t)0 ) != 0 ) {
		syslog( LOG_ERR, "q_deliver ftruncate %s: %m", efile_fname );
		return( -1 );
	    }

	    if ( unlink( efile_fname ) != 0 ) {
		syslog( LOG_ERR, "q_deliver unlink %s: %m", efile_fname );
		return( -1 );
	    }

            if ( unlink( dfile_fname ) != 0 ) {
                syslog( LOG_ERR, "q_deliver unlink %s: %m", dfile_fname );
                return( -1 );
            }

        } else {
            /* some retries; place in retry list */

            if (( env.e_success != 0 ) || ( env.e_failed != 0 )) {
		/* remove any recipients that don't need to be tried later */
		r_sort = &(env.e_rcpt);

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
                if ( env_outfile( &env, env.e_dir ) != 0 ) {
                    return( -1 );
                }

            } else if ( hq->hq_status != HOST_DOWN ) {
                /* all retries.  touch envelope */
		if ( env_touch( &env ) != 0 ) {
                    return( -1 );
		}
            }

	    /* move message to SLOW if it isn't there already */
	    if ( env.e_dir != SIMTA_DIR_SLOW ) {
		sprintf( efile_fname, "%s/E%s", env.e_dir, env.e_id );
		sprintf( dfile_slow, "%s/D%s", SIMTA_DIR_SLOW, env.e_id );
		sprintf( efile_slow, "%s/E%s", SIMTA_DIR_SLOW, env.e_id );

		if ( link( dfile_fname, dfile_slow ) != 0 ) {
		    syslog( LOG_ERR, "link %s %s: %m", dfile_fname,
			    dfile_slow );
		    return( -1 );
		}

		if ( link( efile_fname, efile_slow ) != 0 ) {
		    syslog( LOG_ERR, "link %s %s: %m", efile_fname,
			    efile_slow );
		    return( -1 );
		}

		if ( unlink( efile_fname ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver unlink %s: %m", efile_fname );
		    return( -1 );
		}

		if ( unlink( dfile_fname ) != 0 ) {
		    syslog( LOG_ERR, "q_deliver unlink %s: %m", dfile_fname );
		    return( -1 );
		}
	    }
        } 

	if ( snet_close( snet_lock ) != 0 ) {
	    syslog( LOG_ERR, "q_deliver snet_close: %m" );
	    return( -1 );
	}

	env_reset( &env );

	*mp = m->m_next;
	message_free( m );
	hq->hq_entries--;
    }

    if ( snet != NULL ) {
        if (( result = smtp_quit( snet, hq )) < 0 ) {
            return( -1 );
        }
    }

    return( 0 );
}
