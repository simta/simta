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

#include "queue.h"
#include "envelope.h"
#include "simta.h"
#include "expand.h"
#include "ll.h"


    /* return 0 on success
     * return -1 on syserror
     * syslog errors
     */

    int
expand( struct host_q **hq_stab, struct envelope *unexpanded_env )
{
    struct message		*m;
    struct host_q		*hq;
    struct timeval		tv;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*hs;
    struct stab_entry		*rs;
    struct host_list		*host;
    struct recipient		*r;
    struct recipient		*remove;
    struct recipient		**r_sort;
    struct envelope		env;
    int				failed_expansions = 0;
    int				expansions = 0;
    char			*local_part;
    char			*destination_host;
    char			*email_address;
    char			e_original[ MAXPATHLEN ];
    char			d_original[ MAXPATHLEN ];
    char			d_slow[ MAXPATHLEN ];
    char			d_fast[ MAXPATHLEN ];
    char			*unexpanded_dir;

    /* XXX dummy variables for commenting purposes only */
    int				expansion_fails;

    /* return 1 until function is completed, for debugging only */
    return( 1 );

    /* expand unexpanded_env->e_rcpt addresses */
    for ( r = unexpanded_env->e_rcpt; r != NULL; r = r->r_next ) {
	/* expand r->rcpt */

	/* if expansion for recipient r fails, we mark it and
	 * note that we've failed at least one expansion.
	 */ 
	/* if expansion fails for r->rcpt */
	if ( expansion_fails ) {
	    failed_expansions++;
	    r->r_delivered = 0;

	} else {
	    expansions++;
	    r->r_delivered = 1;
	}

	/* for each email address you expand out of r->rcpt */
	for ( ; ; ) {
	    /* this segment of code sorts an expanded address
	     * by it's destination host.
	     *
	     * note that it uses the following variables and does no error
	     * checking on them:
	     *
	     * char *destination_host
	     * char *local_part
	     *
	     * The following code  expects the expansion routine to do so,
	     * but does not expect them to be malloc()ed.  It allocates
	     * space for their storage, and does not free the original
	     * values.
	     */

	    /* find or create an entry for this destination host */
	    if (( host = (struct host_list*)ll_lookup( host_stab,
		    destination_host )) == NULL ) {
		if (( host = (struct host_list*)malloc(
			sizeof( struct host_list ))) == NULL ) {
		    syslog( LOG_ERR, "malloc: %m" );
		    return( -1 );
		}

		if (( host->h_name = strdup( destination_host )) == NULL ) {
		    syslog( LOG_ERR, "strdup: %m" );
		    return( -1 );
		}

		host->h_addresses = NULL;

		if ( ll_insert( &host_stab, host->h_name, host, NULL ) != 0 ) {
		    syslog( LOG_ERR, "malloc: %m" );
		    return( -1 );
		}
	    }

	    /* find or create an entry for the local part in destination host */
	    if ( ll_lookup( host->h_addresses, local_part ) == NULL ) {
		if (( local_part = strdup( local_part )) == NULL ) {
		    syslog( LOG_ERR, "strdup: %m" );
		    return( -1 );
		}

		if ( ll_insert( &(host->h_addresses), local_part, local_part,
			NULL ) != 0 ) {
		    syslog( LOG_ERR, "malloc: %m" );
		    return( -1 );
		}
	    }
	}
    }

    memset( &env, 0, sizeof( struct envelope ));

    sprintf( d_original, "%s/D%s", unexpanded_env->e_dir,
	    unexpanded_env->e_id );
    sprintf( e_original, "%s/E%s", unexpanded_env->e_dir,
	    unexpanded_env->e_id );

    /* for each expanded host, write out addresses */
    for ( hs = host_stab; hs != NULL; hs = hs->st_next ) {
	host = (struct host_list*)hs->st_data;
	destination_host = host->h_name;

	for ( rs = host->h_addresses; rs != NULL; rs = rs->st_next ) {
	    local_part = rs->st_key;

	    if (( email_address = (char*)malloc( strlen( destination_host ) +
		    strlen( local_part ) + 2 )) == NULL ) {
		syslog( LOG_ERR, "malloc: %m" );
		return( -1 );
	    }

	    sprintf( email_address, "%s@%s", local_part, destination_host );

	    if ( env_recipient( &env, email_address ) != 0 ) {
		return( -1 );
	    }

	    free( email_address );
	}

	/* fill in env */
	env.e_dir = SIMTA_DIR_FAST;
	env.e_mail = unexpanded_env->e_mail;

	strcpy( env.e_expanded, destination_host );

	if ( gettimeofday( &tv, NULL ) != 0 ) {
	    syslog( LOG_ERR, "gettimeofday: %m" );
	    return( -1 );
	}

	sprintf( env.e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
		    (unsigned long)tv.tv_usec );

	/* Dfile: link Dold_id SIMTA_DIR_FAST/Dnew_id */
	sprintf( d_fast, "%s/D%s", SIMTA_DIR_FAST, env.e_id );

	if ( link( d_original, d_fast ) != 0 ) {
	    syslog( LOG_ERR, "link %s %s: %m", d_original, d_fast );
	    return( -1 );
	}

	/* Efile: write SIMTA_DIR_FAST/Enew_id for all recipients at host */
	if ( env_outfile( &env, SIMTA_DIR_FAST ) != 0 ) {
	    return( -1 );
	}

	/* create message to put in host queue */
	if (( m = message_create( env.e_id )) == NULL ) {
	    return( -1 );
	}

	/* create all messages we are expanding in the FAST queue */
	m->m_dir = SIMTA_DIR_FAST;

	/* env has corrected etime after disk access */
	m->m_etime.tv_sec = env.e_etime.tv_sec;

	/* find / create the expanded host queue */
	if (( hq = host_q_lookup( hq_stab, destination_host )) == NULL ) {
	    return( -1 );
	}

	/* queue message "m" in host queue "hq" */
	if ( message_queue( hq, m ) != 0 ) {
	    return( -1 );
	}

	/* reset env */
	env_reset( &env );
    }

    if ( failed_expansions == 0 ) {
	/* all rcpts expanded */

	/* truncate unexpanded Efile so no other q_runner gets it */
	if ( unexpanded_env->e_dir != SIMTA_DIR_FAST ) {
	    if ( truncate( e_original, (off_t)0 ) != 0 ) {
		syslog( LOG_ERR, "truncate %s: %m", e_original );
		return( -1 );
	    }
	}

	/* unlink original unexpanded Efile */
	if ( unlink( e_original ) != 0 ) {
	    syslog( LOG_ERR, "unlink %s: %m", e_original );
	}

	/* unlink original unexpanded Dfile */
	if ( unlink( d_original ) != 0 ) {
	    syslog( LOG_ERR, "unlink %s: %m", d_original );
	}

    } else {
	unexpanded_dir = unexpanded_env->e_dir;

	if ( unexpanded_dir != SIMTA_DIR_SLOW ) {
	    sprintf( d_slow, "%s/D%s", SIMTA_DIR_SLOW, unexpanded_env->e_id );
	    if ( link( d_original, d_slow ) != 0 ) {
		syslog( LOG_ERR, "link %s %s: %m", d_original, d_slow );
	    }
	}

	if ( expansions > 0 ) {
	    /* remove any recipients that don't need to be tried later */
	    r_sort = &(unexpanded_env->e_rcpt);

	    while ( *r_sort != NULL ) {
		if ((*r_sort)->r_delivered == 0 ) {
		    remove = *r_sort;
		    *r_sort = (*r_sort)->r_next;
		    rcpt_free( remove );

		} else {
		    r_sort = &((*r_sort)->r_next);
		}
	    }
	}

	/* write out env to SLOW */
	if ( env_outfile( unexpanded_env, SIMTA_DIR_SLOW ) != 0 ) {
	    return( -1 );
	}

	if ( unexpanded_dir != SIMTA_DIR_SLOW ) {
	    /* truncate & unlink original Efile */
	    if ( unexpanded_env->e_dir != SIMTA_DIR_FAST ) {
		if ( truncate( e_original, (off_t)0 ) != 0 ) {
		    syslog( LOG_ERR, "truncate %s: %m", e_original );
		    return( -1 );
		}
	    }

	    /* unlink original unexpanded Efile */
	    if ( unlink( e_original ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", e_original );
	    }

	    /* unlink original Dfile */
	    if ( unlink( d_original ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", d_original );
		return( -1 );
	    }
	}
    }

#ifdef DEBUG
    printf( "expand\n" );
    q_stab_stdout( *hq_stab );
#endif /* DEBUG */

    return( 0 );
}
