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

int				simta_expand_debug = 0;


    /* return 0 on success
     * return 1 on syserror
     * syslog errors
     */

    int
expand( struct host_q **hq_stab, struct envelope *unexpanded_env )
{
    /* XXX variable audit */
    struct message		*m;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*expansion = NULL;
    struct stab_entry		*seen = NULL;
    struct stab_entry		*i = NULL;
    struct expn			*expn;
    struct recipient		*r;
    struct envelope		*env_p;
    struct timeval              tv;
    char			*domain = NULL;
    char			e_original[ MAXPATHLEN ];
    char			d_original[ MAXPATHLEN ];
    char			d_fast[ MAXPATHLEN ];
    SNET			*snet = NULL;

    /* add all of the addresses in the rcpt list into the expansion list */
    for ( r = unexpanded_env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( add_address( &expansion, r->r_rcpt, r ) != 0 ) {
	    /* add_address syslogs errors */
	    return( 1 );
	}
    }

    /* call address_expand on each address in the expansion list.
     *
     * if an address is expandable, the address(es) that it expands to will
     * be added to the expansion list. These non-terminal addresses must
     * have their st_data set to NULL to specify that they are not to be
     * included in the terminal expansion list. 
     *
     * Any address in the expansion list who's st_data is not NULL is
     * considered a terminal address and will be written out as one
     * of the addresses in expanded envelope(s).
     */ 

    simta_rcpt_errors = 0;

    for ( i = expansion; i != NULL; i = i->st_next ) {
	expn = (struct expn*)i->st_data;

	switch ( address_expand( i->st_key, expn->e_rcpt_parent, &expansion,
		&seen )) {

	case ADDRESS_SYSERROR:
	    /* XXX expansion terminal failure */
	    free( i->st_data );
	    i->st_data = NULL;
	    return( 1 );

	case ADDRESS_BAD_FORMAT:
	    if ( rcpt_error( expn->e_rcpt_parent, "bad address format: ",
		    i->st_key, NULL ) != 0 ) {
		/* XXX expansion terminal failure */
		/* rcpt_error syslogs errors */
		free( i->st_data );
		i->st_data = NULL;
		return( 1 );
	    }

	    free( i->st_data );
	    i->st_data = NULL;
	    break;

	case ADDRESS_SEEN:
	    free( i->st_data );
	    i->st_data = NULL;
	    break;

	case ADDRESS_EXTERNAL:
	    /* the address is out of our domain */
	    break;

	case ADDRESS_EXPANDED:
	    /* the address is non-terminal */

	    free( i->st_data );
	    i->st_data = NULL;
	    break;

	case ADDRESS_LOCAL:
	    /* the address is a terminal local address */
	    break;

	case ADDRESS_NOT_FOUND:
	    if ( rcpt_error( expn->e_rcpt_parent, "address not found: ",
		    i->st_key, NULL ) != 0 ) {
		/* XXX expansion terminal failure */
		/* rcpt_error syslogs errors */
		free( i->st_data );
		i->st_data = NULL;
		return( 1 );
	    }

	    free( i->st_data );
	    i->st_data = NULL;
	    break;

	default:
	    /* this should be unreachable code */
	    syslog( LOG_ERR, "expand address_expand switch: unreachable code" );
	    /* XXX expansion terminal failure */
	    free( i->st_data );
	    i->st_data = NULL;
	    break;
	}
    }

    sprintf( d_original, "%s/D%s", unexpanded_env->e_dir,
	    unexpanded_env->e_id );

    /* Create one expanded envelope for every host we expanded address for */
    for ( i = expansion; i != NULL; i = i->st_next ) {
	if ( i->st_data == NULL ) {
	    /* not a terminal expansion, do not add */
	    continue;
	}

	/* If envelope is marked for punt, create one host entry
	 * for punt machine.  Otherwise, create host queue entry.
	 */

	if ( unexpanded_env->e_punt != NULL ) {
	    domain = unexpanded_env->e_punt;

	} else {
	    if (( domain = strchr( i->st_key, '@' )) == NULL ) {
		/* XXX expansion terminal failure */
		syslog( LOG_ERR, "expand strchr: unreachable code" );
		return( 1 );
	    }

	    domain++;
	}

	if (( env_p = (struct envelope*)ll_lookup( host_stab, domain ))
		== NULL ) {
	    if ( strlen( domain ) > MAXHOSTNAMELEN ) {
		syslog( LOG_ERR, "expand strlen: domain too long" );
		/* XXX expansion terminal failure */
		return( 1 );
	    }

	    /* Create envelope and add it to list */
	    if (( env_p = env_create( NULL )) == NULL ) {
		syslog( LOG_ERR, "expand env_create: %m" );
		/* XXX expansion terminal failure */
		return( 1 );
	    }

	    if ( gettimeofday( &tv, NULL ) != 0 ) {
		syslog( LOG_ERR, "expand gettimeofday: %m" );
		free( env_p );
		/* XXX expansion terminal failure */
		return( 1 );
	    }

	    /* fill in env */
	    env_p->e_dir = simta_dir_fast;
	    env_p->e_mail = unexpanded_env->e_mail;
	    strcpy( env_p->e_expanded, domain );
	    sprintf( env_p->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
			(unsigned long)tv.tv_usec );

	    /* Add env to host_stab */
	    if ( ll_insert( &host_stab, domain, env_p, NULL ) != 0 ) {
		syslog( LOG_ERR, "expand ll_insert: %m" );
		free( env_p );
		/* XXX expansion terminal failure */
		return( 1 );
	    }
	}

	if (( r = (struct recipient *)malloc( sizeof( struct recipient )))
		== NULL ) {
	    syslog( LOG_ERR, "expand malloc: %m" );
	    /* XXX expansion terminal failure */
	    return( 1 );
	}

	if (( r->r_rcpt = strdup( i->st_key )) == NULL ) {
	    free( r );
	    syslog( LOG_ERR, "expand strdup: %m" );
	    /* XXX expansion terminal failure */
	    return( 1 );
	}

	r->r_next = env_p->e_rcpt;
	env_p->e_rcpt = r;
    }

    /* Write out all expanded envelopes and place them in to the host_q */
    for ( i = host_stab; i != NULL; i = i->st_next ) {
	env_p = i->st_data;

	if ( simta_expand_debug == 0 ) {
	    /* create message to put in host queue */
	    if (( m = message_create( env_p->e_id )) == NULL ) {
		/* message_create syslogs errors */
		/* XXX expansion terminal failure */
		return( 1 );
	    }

	    /* create all messages we are expanding in the FAST queue */
	    m->m_dir = simta_dir_fast;

	    /* find / create the expanded host queue */
	    if (( hq = host_q_lookup( hq_stab, env_p->e_expanded )) == NULL ) {
		/* host_q_lookup syslogs errors */
		/* XXX expansion terminal failure */
		return( 1 );
	    }

	    /* Dfile: link Dold_id simta_dir_fast/Dnew_id */
	    sprintf( d_fast, "%s/D%s", simta_dir_fast, env_p->e_id );

	    if ( link( d_original, d_fast ) != 0 ) {
		syslog( LOG_ERR, "expand: link %s %s: %m", d_original, d_fast );
		free( env_p );
		/* XXX expansion terminal failure */
		return( 1 );
	    }

	    /* Efile: write simta_dir_fast/Enew_id for all recipients at host */
	    if ( env_outfile( env_p, simta_dir_fast ) != 0 ) {
		/* env_outfile syslogs errors */
		/* XXX expansion terminal failure */
		/* XXX unlink dfile */
		return( 1 );
	    }

	    /* queue message "m" in host queue "hq" */
	    message_queue( hq, m );

	    /* env has corrected etime after disk access */
	    m->m_etime.tv_sec = env_p->e_etime.tv_sec;

	} else {
	    env_stdout( env_p );
	}
    }

    if ( simta_expand_debug != 0 ) {
	return( 0 );
    }

    /* if there were any failed expansions, create a bounce message */
    if ( simta_rcpt_errors != 0 ) {
	/* Create bounces */
	if (( snet = snet_open( d_original, O_RDWR, 0, 1024 * 1024 ))
		== NULL ) {
	    syslog( LOG_ERR, "expand snet_open %s: %m", d_original );
	    /* XXX expansion terminal failure */
	    return( 1 );
	}

	if ( bounce( unexpanded_env, snet ) != 0 ) {
	    if ( snet_close( snet ) != 0 ) {
		syslog( LOG_ERR, "expand snet_close: %m" );
	    }

	    /* XXX expansion terminal failure */
	    return( 1 );
	}

	if ( snet_close( snet ) != 0 ) {
	    syslog( LOG_ERR, "expand snet_close: %m" );
	    /* XXX expansion terminal failure */
	    return( 1 );
	}
    }

    sprintf( e_original, "%s/E%s", unexpanded_env->e_dir,
	    unexpanded_env->e_id );

    /* truncate unexpanded Efile so no other q_runner gets it */
    if ( unexpanded_env->e_dir != simta_dir_fast ) {
	if ( truncate( e_original, (off_t)0 ) != 0 ) {
	    syslog( LOG_ERR, "expand truncate %s: %m", e_original );
	    /* XXX expansion terminal failure */
	    return( 1 );
	}
    }

    if ( env_unlink( unexpanded_env ) != 0 ) {
	/* XXX expansion terminal failure */
	return( 1 );
    }

    /* XXX free host_stab */
    /* XXX free expansion */
    /* XXX free seen */

    return( 0 );
}
