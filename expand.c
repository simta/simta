#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

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
#include "bounce.h"
#include "expand.h"
#include "ll.h"
#include "address.h"
#include "simta.h"

struct envelope * new_host_env( struct stab_entry **host_stab, char *domain,
    char *e_mail, char *d_original );

    struct envelope * 
new_host_env( struct stab_entry **host_stab, char *domain, char *e_mail,
    char *d_original )
{
    char			d_fast[ MAXPATHLEN ];
    struct timeval              tv;
    struct envelope		*env_p = NULL;

    /* Create envelope and add it to list */
    if (( env_p = env_create( NULL )) == NULL ) {
	syslog( LOG_ERR, "expand: env_create: %m" );
	return( NULL );
    }

    /* fill in env */
    env_p->e_dir = simta_dir_fast;
    env_p->e_mail = e_mail;
    /* XXX - is this right? */
    strcpy( env_p->e_expanded, domain );

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "gettimeofday: %m" );
	return( NULL );
    }
    sprintf( env_p->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec );

    /* Dfile: link Dold_id simta_dir_fast/Dnew_id */
    sprintf( d_fast, "%s/D%s", simta_dir_fast, env_p->e_id );

    if ( link( d_original, d_fast ) != 0 ) {
	syslog( LOG_ERR, "link %s %s: %m", d_original, d_fast );
	return( NULL );
    }

    /* Add host */
    if ( ll_insert( host_stab, domain, env_p, NULL ) != 0 ) {
	syslog( LOG_ERR, "expand: ll_insert: %m" );
	return( NULL );
    }

    return( env_p );
}

    /* return 0 on success
     * return -1 on syserror
     * syslog errors
     */

    int
expand( struct host_q **hq_stab, struct envelope *unexpanded_env )
{
    struct message		*m;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*expansion = NULL;
    struct stab_entry		*seen = NULL;
    struct stab_entry		*i = NULL;
    struct expn			*expn;
    struct recipient		*r;
    struct envelope		*env_p;
    int				failed_expansions = 0, rc = 0;
    int				expansions = 0, ae_error;
    char			*domain = NULL;
    char			e_original[ MAXPATHLEN ];
    char			d_original[ MAXPATHLEN ];
    SNET			*snet = NULL;

    /* Create paths */
    sprintf( d_original, "%s/D%s", unexpanded_env->e_dir,
	unexpanded_env->e_id );
    sprintf( e_original, "%s/E%s", unexpanded_env->e_dir,
	unexpanded_env->e_id );

    /* convert rcpt list into an expansion list */
    for ( r = unexpanded_env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( add_address( &expansion, r->r_rcpt, r ) != 0 ) {
	    return( -1 );
	}
    }

    if ( simta_debug ) printf( "\nTurn the crank\n" );
    /* Turn the crank on expansion list */
    for ( i = expansion; i != NULL; i = i->st_next ) {
	if ( i->st_data == NULL ) {
	    printf( "die die die\n" );
	}

	if ( simta_debug ) printf( "\n%s:\n", i->st_key );
	expn = (struct expn*)i->st_data;

	rc = address_expand( i->st_key, expn->e_rcpt_parent, &expansion,
		&seen, &ae_error );

	if ( simta_debug ) printf( "\naddress_expand %s: %d\n", i->st_key, rc );

	if ( rc < 0 ) {
	    /* System failure */
	    failed_expansions++;
	    r->r_delivered = SIMTA_EXPANSION_FAILED;
	    if ( simta_debug ) printf( "expanding %s failed\n", r->r_rcpt );

	} else if ( rc == 0 ) {
	    switch( ae_error ) {

	    case SIMTA_EXPAND_ERROR_NONE:
		/* XXX do you want to report an error here? */
#ifdef DEBUG
		printf( "SIMTA_EXPAND_ERROR_NONE\n" );
#endif /* DEBUG */
		break;

	    case SIMTA_EXPAND_ERROR_SYSTEM:
		/* XXX do you want to report an error here? */
#ifdef DEBUG
		printf( "SIMTA_EXPAND_ERROR_SYSTEM\n" );
#endif /* DEBUG */
		break;

	    case SIMTA_EXPAND_ERROR_OFF_HOST:
		/* XXX do you want to report an error here? */
#ifdef DEBUG
		printf( "SIMTA_EXPAND_ERROR_OFF_HOST\n" );
#endif /* DEBUG */
		break;

	    case SIMTA_EXPAND_ERROR_BAD_FORMAT:
		if ( simta_debug ) printf( " bad format - removing\n" );
		failed_expansions++;
		free( i->st_data );
		i->st_data = NULL;
		break;

	    case SIMTA_EXPAND_ERROR_SEEN:
		if ( simta_debug ) printf( " seen - removing\n" );
		/* indicate address already expanded */
		free( i->st_data );
		i->st_data = NULL;
		break;

	    case SIMTA_EXPAND_ERROR_NOT_LOCAL:
		if ( simta_debug ) printf( " not local - removing\n" );
		failed_expansions++;
		free( i->st_data );
		i->st_data = NULL;
		break;

#ifdef NOT_DEF
#ifdef HAVE_LDAP
	    case SIMTA_EXPAND_ERROR_LDAP:
		/* XXX unwind expansion here */
		break;
#endif /* HAVE_LDAP */
#endif /* NOT_DEF */

	    default:
		/* XXX do you want to report an error here? */
#ifdef DEBUG
		printf( "SIMTA_EXPAND_ERROR_default\n" );
#endif /* DEBUG */
		break;
	    }

	} else {
	    /* indicate address expanded */
	    free( i->st_data );
	    i->st_data = NULL;
	}
    }

    if ( simta_debug ) printf( "\ncreating per host queue\n" );

    /* Create per host expanded envelopes */
    for ( i = expansion; i != NULL; i = i->st_next ) {
	if ( i->st_data == NULL ) {
	    if ( simta_debug ) printf( "not adding %s to host queue: NULL\n",
		    (char *)i->st_key );
	    continue;
	}
	if (( domain = strchr( i->st_key, '@' )) == NULL ) {
	    syslog( LOG_ERR, "expand: no domain" );
	    return( -1 );
	}
	domain++;
	if ( simta_debug ) printf( "adding %s to host queue\n",
	    (char *)i->st_key );

	/* If envelope is marked for punt, create one host entry
	 * for punt machine.  Otherwise, create host queue entry.
	 */
	if ( unexpanded_env->e_punt != NULL ) {
	    if ( simta_debug ) printf( "punting to %s\n",
		    unexpanded_env->e_punt );

	    if (( env_p = new_host_env( &host_stab, unexpanded_env->e_punt,
		    unexpanded_env->e_mail, d_original )) == NULL ) {
		return( -1 );
	    }

	} else {
	    if ( simta_debug ) printf( "%s in host_stab?...", domain );
	    if (( env_p = ll_lookup( host_stab, domain )) == NULL ) {
		if (( env_p = new_host_env( &host_stab, domain,
			unexpanded_env->e_mail, d_original )) == NULL ) {
		    return( -1 );
		}
		if ( simta_debug ) printf( "no - added to host_stab\n" );
	    } else {
		if ( simta_debug ) printf( "yes\n" );
	    }
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

	if ( simta_debug ) {
	    printf( "  added %s\n", r->r_rcpt );
	}
    }

    if ( simta_debug ) printf( "\nplace envelopes into host_q\n" );

    /* Place all expanded envelopes into host_q */
    for ( i = host_stab; i != NULL; i = i->st_next ) {

	if ( simta_debug ) printf( "creating env for %s\n", i->st_key );

	env_p = i->st_data;

	/* Efile: write simta_dir_fast/Enew_id for all recipients at host */
	if ( env_outfile( env_p, simta_dir_fast ) != 0 ) {
	    return( -1 );
	}

	/* create message to put in host queue */
	if (( m = message_create( env_p->e_id )) == NULL ) {
	    return( -1 );
	}

	/* create all messages we are expanding in the FAST queue */
	m->m_dir = simta_dir_fast;

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

    if ( failed_expansions ) {
	/* Create bounces */
	if (( snet = snet_open( d_original, O_RDWR, 0, 1024 * 1024 ))
		== NULL ) {
	    syslog( LOG_ERR, "snet_open: %m" );
	    return( -1 );
	}
	if ( bounce( unexpanded_env, snet ) != 0 ) {
	    syslog( LOG_ERR, "bounce failed\n" );
	    return( -1 );
	}
	if ( snet_close( snet ) != 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}
    }

    /* truncate unexpanded Efile so no other q_runner gets it */
    if ( unexpanded_env->e_dir != simta_dir_fast ) {
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

#ifdef DEBUG
    printf( "expanded host_q after:\n" );
    q_stab_stdout( *hq_stab );
    printf( "\n" );
#endif /* DEBUG */

    return( 0 );
}
