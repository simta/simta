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
#include "expand.h"

/* GLOBAL VARS */
struct host_q		*simta_null_q;

int	q_deliver ___P(( struct host_q * ));
int	q_read_dir ___P(( char *, struct host_q ** ));
int	bounce ___P(( struct envelope *, SNET * ));


    void
message_stdout( struct message *m )
{
    printf( "\t%s\n", m->m_id );
}


    void
q_stdout( struct host_q *hq )
{
    struct message		*m;

    if (( hq->hq_hostname == NULL ) || ( *hq->hq_hostname == '\0' )) {
	printf( "%d\tNULL:\n", hq->hq_entries );
    } else {
	printf( "%d\t%s:\n", hq->hq_entries, hq->hq_hostname );
    }

    for ( m = hq->hq_message_first; m != NULL; m = m->m_next ) {
	message_stdout( m );
    }
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

    *mp = m;

    return( 0 );
}


    /* look up a given host in the host_q.  if not found, create */

    struct host_q *
host_q_lookup( struct host_q **host_q, char *hostname ) 
{
    struct host_q		*hq;
    char			*localhostname;

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

	if (( localhostname = simta_gethostname()) == NULL ) {
	    return( NULL );
	}

	if ( strcasecmp( localhostname, hq->hq_hostname ) == 0 ) {
	    hq->hq_status = HOST_LOCAL;

	} else if (( hostname == NULL ) || ( *hostname == '\0' )) {
	    hq->hq_status = HOST_NULL;

	} else {
	    hq->hq_status = HOST_REMOTE;
	}
    }

    return( hq );
}


    int
bounce( struct envelope *env, SNET *message )
{
    struct envelope             bounce_env;
    char                        dfile_fname[ MAXPATHLEN ];
    int                         dfile_fd;
    FILE                        *dfile;
    struct recipient            *r;
    struct message		*m;
    struct line                 *l;
    int                         line_no = 0;
    char                        *line;
    time_t                      clock;
    struct tm                   *tm;
    struct timeval		tv;
    char                        daytime[ 35 ];

    memset( &bounce_env, 0, sizeof( struct envelope ));

    env_reset( &bounce_env );

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "gettimeofday: %m" );
	return( -1 );
    }

    sprintf( bounce_env.e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec );

    if (( env->e_mail != NULL ) && ( *env->e_mail != '\0' )) {
        if ( env_recipient( &bounce_env, env->e_mail ) != 0 ) {
            return( -1 );
        }

    } else {
        if ( env_recipient( &bounce_env, SIMTA_POSTMASTER ) != 0 ) {
            return( -1 );
        }
    }

    /* all bounces get created in SLOW */
    bounce_env.e_dir = SIMTA_DIR_SLOW;

    sprintf( dfile_fname, "%s/D%s", bounce_env.e_dir, bounce_env.e_id );

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

    if ( time( &clock ) < 0 ) {
        syslog( LOG_ERR, "time: %m" );
        close( dfile_fd );
        goto cleanup;
    }

    if (( tm = localtime( &clock )) == NULL ) {
        syslog( LOG_ERR, "localtime: %m" );
        close( dfile_fd );
        goto cleanup;
    }

    if ( strftime( daytime, sizeof( daytime ), "%a, %e %b %Y %T", tm )
            == 0 ) {
        syslog( LOG_ERR, "strftime: %m" );
        close( dfile_fd );
        goto cleanup;
    }

    /* XXX From: address */
    fprintf( dfile, "Date: %s\n", daytime );
    fprintf( dfile, "Message-ID: %s\n", env->e_id );

    /* XXX bounce message */
    fprintf( dfile, "Your mail was bounced.\n" );
    fprintf( dfile, "\n" );

    /* XXX mail loop message */
    if ( env->e_mail_loop != 0 ) {
        fprintf( dfile, "There was a mail loop.\n" );
        fprintf( dfile, "\n" );
    }

    /* XXX oldfile message */
    if ( env->e_old_dfile != 0 ) {
        fprintf( dfile, "It was over three days old.\n" );
        fprintf( dfile, "\n" );
    }

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
        if (( r->r_delivered == R_FAILED ) || ( env->e_old_dfile != 0 ) ||
		( env->e_mail_loop != 0 )) {
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

    if ( env_outfile( &bounce_env, bounce_env.e_dir ) != 0 ) {
        goto cleanup;
    }

    if (( m = message_create( bounce_env.e_id )) == NULL ) {
	return( -1 );
    }

    m->m_dir = bounce_env.e_dir;
    m->m_etime.tv_sec = tv.tv_sec;

    if ( message_queue( simta_null_q, m ) != 0 ) {
	return( -1 );
    }

    env_reset( &bounce_env );

    return( 0 );

cleanup:
    unlink( dfile_fname );

    return( -1 );
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

    for ( ; ; ) {
	/* BUILD DELIVER_Q */
	/* sort the hosts in the deliver_q by number of messages */
	deliver_q = NULL;

	for ( hq = *host_q; hq != NULL; hq = hq->hq_next ) {
	    if ((( hq->hq_status == HOST_LOCAL ) ||
		    ( hq->hq_status == HOST_REMOTE )) &&
		    ( hq->hq_entries > 0 )) {
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

	    } else {
		hq->hq_deliver = NULL;

		if ( hq->hq_status == HOST_MAIL_LOOP ) {
		    /* bounce queue */
		    /* XXX BOUNCE */
		}
	    }
	}

	/* DELIVER DELIVER_Q */
	/* deliver all mail in every expanded queue */
	while ( deliver_q != NULL ) {
	    if (( result = q_deliver( deliver_q )) < 0 ) {
		return( -1 );

	    } else if ( result > 0 ) {
		/* XXX error case.  queue down?  move to DIR_SLOW? */
	    }

	    deliver_q = deliver_q->hq_deliver;
	}

	/* EXPAND ONE MESSAGE */
	for ( ; ; ) {
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
q_read_dir( char *dir, struct host_q **host_q )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct host_q		*hq;
    char			hostname[ MAXHOSTNAMELEN + 1 ];
    struct message		*m;
    int				result;

    if (( dirp = opendir( dir )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", dir );
	return( EX_TEMPFAIL );
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

	    if (( result = env_info( m, hostname )) < 0 ) {
		return( -1 );

	    } else if ( result > 0 ) {
		/* free message */
		message_free( m );
		continue;
	    }

	    if (( hq = host_q_lookup( host_q, hostname )) == NULL ) {
		return( -1 );
	    }

	    if ( message_queue( hq, m ) < 0 ) {
		return( -1 );
	    }

	    hq->hq_entries++;
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "readdir: %m" );
	return( EX_TEMPFAIL );
    }

    return( 0 );
}


    int
q_runner_dir( char *dir )
{
    struct host_q		*host_q = NULL;

    /* create NULL host queue for unexpanded messages */
    if (( simta_null_q = host_q_lookup( &host_q, "\0" )) == NULL ) {
	exit( EX_TEMPFAIL );
    }

    /* read dir for efiles, sort by hostname & efile time */
    if ( q_read_dir( dir, &host_q ) != 0 ) {
	exit( EX_TEMPFAIL );
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
    char                        efile_fname[ MAXPATHLEN ];
    int                         dfile_fd;
    SNET                        *dfile_snet = NULL;
    int                         result;
    int                         sent;
    char                        *at;
    SNET                        *snet = NULL;
    SNET			*snet_lock;
    struct timeval              tv;
    struct message		*m;
    struct message		*m_remove;
    struct message		**m_clean;
    struct recipient		**r_sort;
    struct recipient		*remove;
    struct envelope		env;
    struct recipient            *r;
    struct stat                 sb;
    void                        (*logger)(char *) = NULL;
    static int                  (*local_mailer)(int, char *,
                                        struct recipient *) = NULL;

#ifdef DEBUG
    logger = stdout_logger;
    printf( "q_deliver:\n" );
    q_stdout( hq );
    printf( "\n" );
#endif /* DEBUG */

    if ( hq->hq_status == HOST_LOCAL ) {
        /* figure out what our local mailer is */
        if ( local_mailer == NULL ) {
            if (( local_mailer = get_local_mailer()) == NULL ) {
                syslog( LOG_ALERT, "deliver local: no local mailer!" );
                return( -1 );
            }
        }

    } else if ( hq->hq_status == HOST_REMOTE ) {
        /* XXX DEBUG send only to terminator (or alias rsug), for now */
	if (( strcasecmp( hq->hq_hostname, "rsug.itd.umich.edu" ) != 0 ) &&
		( strcasecmp( hq->hq_hostname,
		"terminator.rsug.itd.umich.edu" ) != 0 )) {
            return( 0 );
        }

        /* HOST_REMOTE sent is used to count how many messages have been
         * sent to a SMTP host.
         */
        sent = 0;

    } else {
        syslog( LOG_ERR, "deliver: illega host queue status" );
        return( -1 );
    }

    for ( m = hq->hq_message_first; m != NULL; m = m->m_next ) {
	/* lock & read envelope to deliver */
	if (( result = env_read( m, &env, &snet_lock )) < 0 ) {
	    return( -1 );

	} else if ( result > 0 ) {
	    m->m_action = M_REMOVE;
	    continue;
	}

	/* open Dfile to deliver & check to see if it's geriatric */
        errno = 0;
        sprintf( dfile_fname, "%s/D%s", m->m_dir, m->m_id );

        if (( dfile_fd = open( dfile_fname, O_RDONLY, 0 )) < 0 ) {
            if ( errno == ENOENT ) {
                errno = 0;
                syslog( LOG_WARNING, "deliver: missing Dfile: %s",
                        dfile_fname );
                m->m_action = M_REMOVE;

		if ( snet_close( snet_lock ) != 0 ) {
		    syslog( LOG_ERR, "snet_close: %m" );
		    return( -1 );
		}
                continue;

            } else {
                syslog( LOG_ERR, "open %s: %m", dfile_fname );
                return( -1 );
            }
        }

        /* stat dfile to see if it's old */
        if ( fstat( dfile_fd, &sb ) != 0 ) {
            syslog( LOG_ERR, "snet_attach: %m" );
            return( -1 );
        }

        if ( gettimeofday( &tv, NULL ) != 0 ) {
            syslog( LOG_ERR, "gettimeofday" );
            return( -1 );
        }

        /* consider Dfiles old if they're over 3 days */
        if (( tv.tv_sec - sb.st_mtime ) > ( 60 * 60 * 24 * 3 )) {
            m->m_old_dfile = 1;
        }

        if ( hq->hq_status == HOST_LOCAL ) {
            /* HOST_LOCAL sent is incremented every time we send
             * a message to a user via. a local mailer.
             */
            sent = 0;

            for ( r = env.e_rcpt; r != NULL; r = r->r_next ) {
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

                if (( result = (*local_mailer)( dfile_fd, env.e_mail,
                        r )) < 0 ) {
                    /* syserror */
                    return( -1 );

                } else if ( result == 0 ) {
                    /* success */
                    r->r_delivered = R_DELIVERED;
                    env.e_success++;

                } else if ( result == EX_TEMPFAIL ) {
                    if ( env.e_old_dfile != 0 ) {
                        r->r_delivered = R_FAILED;
                        env.e_failed++;
                    } else {
                        r->r_delivered = R_TEMPFAIL;
                        env.e_tempfail++;
                    }

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

        } else if ( hq->hq_status == HOST_REMOTE ) {
            if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
                syslog( LOG_ERR, "snet_attach: %m" );
                return( -1 );
            }

            if ( sent != 0 ) {
                if (( result = smtp_rset( snet, hq->hq_hostname, logger )) ==
                        SMTP_ERR_SYSCALL ) {
                    return( -1 );

                } else if ( result == SMTP_ERR_SYNTAX ) {
                    break;
                }
            }

            /* open connection, completely ready to send at least one message */
            if ( snet == NULL ) {
                if (( result = smtp_connect( &snet, hq->hq_hostname, 25,
			logger )) == SMTP_ERR_SYSCALL ) {
                    return( -1 );

                } else if ( result == SMTP_ERR_NO_BOUNCE ) {
                    if ( snet_close( dfile_snet ) != 0 ) {
                        syslog( LOG_ERR, "close: %m" );
                        return( -1 );
                    }

                    /* XXX do something if remote host is fucked up? */

		    if ( snet_close( snet_lock ) != 0 ) {
			syslog( LOG_ERR, "snet_close: %m" );
			return( -1 );
		    }

		    return( 0 );

                } else if ( result == SMTP_ERR_BOUNCE_Q ) {
                    if ( snet_close( dfile_snet ) != 0 ) {
                        syslog( LOG_ERR, "close: %m" );
                        return( -1 );
                    }

                    syslog( LOG_ALERT, "Mail loop detected: "
                            "Hostname %s is not a remote host",
                            hq->hq_hostname );

                    hq->hq_status = HOST_MAIL_LOOP;

		    if ( snet_close( snet_lock ) != 0 ) {
			syslog( LOG_ERR, "snet_close: %m" );
			return( -1 );
		    }

                    return( 0 );
                }
            }

            if (( result = smtp_send( snet, hq->hq_hostname, &env, dfile_snet,
		    logger )) == SMTP_ERR_SYSCALL ) {
                return( -1 );

            } else if ( result == SMTP_ERR_SYNTAX ) {
                /* message not sent */
		/* XXX message rejection or down server? */

		if ( env.e_old_dfile == 0 ) {
		    if ( env_touch( &env ) != 0 ) {
			return( -1 );
		    }

		    env.e_tempfail = 1;
		    env.e_success = 0;
		    env.e_failed = 0;

		} else {
		    env.e_tempfail = 0;
		    env.e_success = 0;
		    env.e_failed = 1;
		}
	    }

            sent++;
        }

        if ( env.e_failed > 0 ) {
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

            if (( result = bounce( &env, dfile_snet )) < 0 ) {
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

        if ( env.e_tempfail == 0  ) {
            /* no retries, delete Efile then Dfile */
            m->m_action = M_REMOVE;

	    sprintf( efile_fname, "%s/E%s", env.e_dir, env.e_id );

	    if ( ftruncate( snet_fd( snet_lock ), (off_t)0 ) != 0 ) {
		syslog( LOG_ERR, "ftruncate %s: %m", efile_fname );
		return( -1 );
	    }

	    if ( unlink( efile_fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", efile_fname );
		return( -1 );
	    }

	    env_reset( &env );

            if ( unlink( dfile_fname ) != 0 ) {
                syslog( LOG_ERR, "unlink %s: %m", dfile_fname );
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

            } else {
                /* all retries.  touch envelope */
                if ( env_touch( &env ) != 0 ) {
                    return( -1 );
                }
            }

            m->m_action = M_REORDER;
	    m->m_etime.tv_sec = env.e_etime.tv_sec;
        } 

	if ( snet_close( snet_lock ) != 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}
    }

    if ( snet != NULL ) {
        if (( result = smtp_quit( snet, hq->hq_hostname, logger )) < 0 ) {
            return( -1 );
        }
    }

    /* clean up queue */
    m_clean = &hq->hq_message_first;

    while ( *m_clean != NULL ) {
        if ((*m_clean)->m_action == M_REMOVE ) {

            m_remove = *m_clean;
            *m_clean = m_remove->m_next;

            message_free( m_remove );
            hq->hq_entries--;

        } else if ((*m_clean)->m_action == M_REORDER ) {
	    if ( hq->hq_message_last != *m_clean ) {
		m_remove = *m_clean;
		m_remove->m_action = 0;
		*m_clean = m_remove->m_next;

		hq->hq_message_last->m_next = m_remove;
		hq->hq_message_last = m_remove;
		m_remove->m_next = NULL;
	    }

        } else {
            m_clean = &((*m_clean)->m_next);
        }
    }

    return( 0 );
}
