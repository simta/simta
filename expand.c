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
#include "expand.h"
#include "ll.h"
#include "address.h"
#include "simta.h"

#define	SIMTA_EXPANSION_FAILED		0
#define	SIMTA_EXPANSION_SUCCESS		1

extern int	debug;

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
    struct stab_entry		*expansion = NULL;
    struct stab_entry		*seen = NULL;
    struct stab_entry		*failed = NULL;
    struct stab_entry		*i = NULL;
    struct recipient		*r;
    struct recipient		*remove;
    struct recipient		**r_sort;
    struct envelope		*env_p;
    int				failed_expansions = 0, ret = 0;
    int				expansions = 0;
    char			*domain = NULL;
    char			e_original[ MAXPATHLEN ];
    char			d_original[ MAXPATHLEN ];
    char			d_slow[ MAXPATHLEN ];
    char			d_fast[ MAXPATHLEN ];
    char			*unexpanded_dir;

    /* Create paths */
    sprintf( d_original, "%s/D%s", unexpanded_env->e_dir,
	unexpanded_env->e_id );
    sprintf( e_original, "%s/E%s", unexpanded_env->e_dir,
	unexpanded_env->e_id );

    /* expand unexpanded_env->e_rcpt addresses */
    for ( r = unexpanded_env->e_rcpt; r != NULL; r = r->r_next ) {
	/* expand r->rcpt */
	if ( address_expand( r->r_rcpt, &expansion, &seen ) < 0 ) {
	    /* if expansion for recipient r fails, we mark it and
	     * note that we've failed at least one expansion.
	     */ 
	    failed_expansions++;
	    r->r_delivered = SIMTA_EXPANSION_FAILED;
	    if ( debug ) printf( "expanding %s failed\n", r->r_rcpt );
        } else {
	    expansions++;
	    r->r_delivered = SIMTA_EXPANSION_SUCCESS;
	    if ( debug != 0 ) {
		if ( expansion == NULL ) {
		    printf( "expanding %s succeded ERROR!\n", r->r_rcpt );
		} else {
		    printf( "expanding %s succeded\n", r->r_rcpt );
		}
	    } else if ( debug != 0 ) {
	    }
	}
    }

    for ( i = expansion; i != NULL; i = i->st_next ) {
	ret = address_expand( i->st_key, &expansion, &seen );
	if ( ret < 0 ) {
	    if ( ll_insert( &failed, i->st_key, i->st_key, NULL ) != 0 ) {
		syslog( LOG_ERR, "expand: ll_insert: %m\n" );
		return( -1 );
	    }
	    i->st_data = NULL;
	} else if ( ret > 0 ) {
	    i->st_data = NULL;
	}
    }

    /* Create per host expanded envelopes */
    for ( i = expansion; i != NULL; i = i->st_next ) {
	if ( i->st_data == NULL ) {
	    continue;
	}
	if (( domain = strchr( i->st_key, '@' )) == NULL ) {
	    syslog( LOG_ERR, "expand: no domain" );
	    return( -1 );
	}
	domain++;

	if ( debug ) printf( "%s in host_stab?...", domain );
	if (( env_p = ll_lookup( host_stab, domain )) == NULL ) {
	    /* Create envelope and add it to list */
	    if (( env_p = env_create( NULL )) == NULL ) {
		syslog( LOG_ERR, "expand: env_create: %m" );
		return( -1 );
	    }

	    /* fill in env */
	    env_p->e_dir = SIMTA_DIR_FAST;
	    env_p->e_mail = unexpanded_env->e_mail;
	    /* XXX - is this right? */
	    strcpy( env_p->e_expanded, domain );

	    if ( gettimeofday( &tv, NULL ) != 0 ) {
		syslog( LOG_ERR, "gettimeofday: %m" );
		return( -1 );
	    }
	    sprintf( env_p->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
			(unsigned long)tv.tv_usec );

	    /* Dfile: link Dold_id SIMTA_DIR_FAST/Dnew_id */
	    sprintf( d_fast, "%s/D%s", SIMTA_DIR_FAST, env_p->e_id );

	    if ( link( d_original, d_fast ) != 0 ) {
		syslog( LOG_ERR, "link %s %s: %m", d_original, d_fast );
		return( -1 );
	    }

	    /* Add host */
	    if ( ll_insert( &host_stab, domain, env_p, NULL ) != 0 ) {
		syslog( LOG_ERR, "expand: ll_insert: %m" );
		return( -1 );
	    }
	    if (( env_p = ll_lookup( host_stab, domain )) == NULL ) {
		syslog( LOG_ERR, "epxand: ll_lookup: %m\n" );
		return( -1 );
	    }
	    if ( debug ) printf( "no - added to host_stab\n" );
	} else {
	    if ( debug ) printf( "yes\n" );
	}

	if (( r = (struct recipient *)malloc( sizeof( struct recipient )))
		== NULL ) {
	    syslog( LOG_ERR, "expand: malloc: %m" );
	    return( -1 );
	}
	if (( r->r_rcpt = strdup( i->st_key )) == NULL ) {
	    syslog( LOG_ERR, "expand: strdup: %m" );
	    return( -1 );
	}
	r->r_next = env_p->e_rcpt;
	env_p->e_rcpt = r;

	if ( debug ) {
	    printf( "  added %s\n", r->r_rcpt );
	}
    }

    /* Place all expanded envelopes into host_q */
    for ( i = host_stab; i != NULL; i = i->st_next ) {

	env_p = i->st_data;

	/* Efile: write SIMTA_DIR_FAST/Enew_id for all recipients at host */
	if ( env_outfile( env_p, SIMTA_DIR_FAST ) != 0 ) {
	    return( -1 );
	}

	/* create message to put in host queue */
	if (( m = message_create( env_p->e_id )) == NULL ) {
	    return( -1 );
	}

	/* create all messages we are expanding in the FAST queue */
	m->m_dir = SIMTA_DIR_FAST;

	/* env has corrected etime after disk access */
	m->m_etime.tv_sec = env_p->e_etime.tv_sec;

	/* find / create the expanded host queue */
	if (( hq = host_q_lookup( hq_stab, env_p->e_expanded )) == NULL ) {
	    return( -1 );
	}

	/* queue message "m" in host queue "hq" */
	if ( message_queue( hq, m ) != 0 ) {
	    return( -1 );
	}
    }

    if ( debug ) printf( "envelopes written\n" );

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
		if ((*r_sort)->r_delivered == SIMTA_EXPANSION_SUCCESS ) {
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
    printf( "expanded host_q after:\n" );
    q_stab_stdout( *hq_stab );
    printf( "\n" );
#endif /* DEBUG */

    return( 0 );
}
