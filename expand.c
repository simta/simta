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

#include <assert.h>
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

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "queue.h"
#include "envelope.h"
#include "expand.h"
#include "ll.h"
#include "simta.h"
#include "line_file.h"
#include "header.h"

#ifdef HAVE_LDAP
#include "simta_ldap.h"
#include "dn.h"
#endif /* HAVE_LDAP */

int				simta_expand_debug = 0;


    /* return EXPAND_OK on success
     * return EXPAND_SYSERROR on syserror
     * return EXPAND_FATAL on fata errors (leaving fast files behind in error)
     * syslog errors
     */

    int
expand_and_deliver( struct envelope *unexpanded_env )
{
    if ( unexpanded_env->e_hostname == NULL ) {
	if ( expand( unexpanded_env ) != 0 ) {
	    env_move( unexpanded_env, simta_dir_slow );
	    return( EXPAND_SYSERROR );
	}
    }

    if ( q_runner() != 0 ) {
	return( EXPAND_SYSERROR );
    }
    return( EXPAND_OK );
}


    struct envelope *
eo_lookup( struct expand_output *eo_list, char *hostname, char *from )
{
    struct expand_output	*e;

    for ( e = eo_list; e != NULL; e = e->eo_next ) {
	if ( strcasecmp( e->eo_hostname, hostname ) != 0 ) {
	    continue;
	}

	if ( strcasecmp( e->eo_from, from ) == 0 ) {
	    return( e->eo_env );
	}
    }

    return( NULL );
}


    int
eo_insert( struct expand_output **eo_list, struct envelope *env )
{
    struct expand_output	*e_new;

    if (( e_new = (struct expand_output*)malloc(
	    sizeof( struct expand_output ))) == NULL ) {
	return( 1 );
    }

    if (( e_new->eo_hostname = env->e_hostname ) == NULL ) {
	e_new->eo_hostname = "";
    }

    e_new->eo_from = env->e_mail;
    e_new->eo_env = env;
    e_new->eo_next = *eo_list;
    *eo_list = e_new;

    return( 0 );
}


    /* return 0 on success
     * return 1 on syserror
     * return -1 on fata errors (leaving fast files behind in error)
     * syslog errors
     */

    int
expand( struct envelope *unexpanded_env )
{
    struct expand		exp;
    struct envelope		*base_error_env;
    struct envelope		*env_dead = NULL;
    struct envelope		*env;
    struct envelope		**env_p;
    struct recipient		*rcpt;
    struct expand_output	*host_stab = NULL;
    struct expand_output	*eo;
    struct expand_output	*eo_free;
    struct exp_addr		*e_addr;
    struct exp_addr		*next_e_addr;
    char			*domain;
    SNET			*snet = NULL;
    int				n_rcpts;
    int				return_value = 1;
    int				env_out = 0;
    int				fast_file_start;
    int				sendermatch;
    char			e_original[ MAXPATHLEN ];
    char			d_original[ MAXPATHLEN ];
    char			d_out[ MAXPATHLEN ];
#ifdef HAVE_LDAP
    int				loop_color = 1;
    struct exp_link		*memonly;
    struct exp_link		*parent;
#endif /* HAVE_LDAP */

    if ( unexpanded_env->e_hostname != NULL ) {
	syslog( LOG_DEBUG, "Expand %s: already expanded for host %s",
		unexpanded_env->e_hostname );
	return_value = 0;
	goto done;
    }

    memset( &exp, 0, sizeof( struct expand ));
    exp.exp_env = unexpanded_env;
    fast_file_start = simta_fast_files;

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

    if (( base_error_env = address_bounce_create( &exp )) == NULL ) {
	syslog( LOG_ERR, "expand.env_create: %m" );
	goto done;
    }

    if ( env_recipient( base_error_env, unexpanded_env->e_mail ) != 0 ) {
	syslog( LOG_ERR, "expand.env_recipient: %m" );
	goto done;
    }

    /* add all of the original recipients to the expansion list */
    for ( rcpt = unexpanded_env->e_rcpt; rcpt != NULL; rcpt = rcpt->r_next ) {
	if ( add_address( &exp, rcpt->r_rcpt, base_error_env,
		ADDRESS_TYPE_EMAIL, exp.exp_env->e_mail ) != 0 ) {
	    /* add_address syslogs errors */
	    goto cleanup1;
	}
    }

    /* process the expansion list */
    for ( exp.exp_addr_cursor = exp.exp_addr_head;
	    exp.exp_addr_cursor != NULL;
	    exp.exp_addr_cursor = exp.exp_addr_cursor->e_addr_next ) {
	switch ( address_expand( &exp )) {
	case ADDRESS_EXCLUDE:
	    exp.exp_addr_cursor->e_addr_terminal = 0;
	    /* the address is not a terminal local address */
	    break;

	case ADDRESS_FINAL:
	    exp.exp_addr_cursor->e_addr_terminal = 1;
	    break;

	case ADDRESS_SYSERROR:
	    goto cleanup1;

	default:
	    panic( "expand: address_expand out of range" );
	}
    }

#ifdef HAVE_LDAP
    /* Members-only processing */
    for ( memonly = exp.exp_memonly; memonly != NULL;
	    memonly = memonly->el_next ) {
	if (( parent_permitted( memonly->el_exp_addr )) ||
		( sender_is_child( memonly->el_exp_addr, loop_color++ ))) {
	    memonly->el_exp_addr->e_addr_ldap_flags =
		    ( memonly->el_exp_addr->e_addr_ldap_flags &
		    ( ~STATUS_LDAP_MEMONLY ));
	    if ( memonly->el_exp_addr->e_addr_env_moderated != NULL ) {
		env_free( memonly->el_exp_addr->e_addr_env_moderated );
		memonly->el_exp_addr->e_addr_env_moderated = NULL;
	    }

	} else {
	    memonly->el_exp_addr->e_addr_ldap_flags |= STATUS_LDAP_SUPRESSOR;
	    supress_addrs( memonly->el_exp_addr->e_addr_children,
		    loop_color++ );
	}
    }
#endif /* HAVE_LDAP */

    sprintf( d_original, "%s/D%s", unexpanded_env->e_dir,
	    unexpanded_env->e_id );

    /* Create one expanded envelope for every host we expanded address for */
    for ( e_addr = exp.exp_addr_head; e_addr != NULL;
	    e_addr = e_addr->e_addr_next ) {

#ifdef HAVE_LDAP
	if ((( e_addr->e_addr_ldap_flags & STATUS_LDAP_SUPRESSED ) != 0 ) &&
		( !unblocked_path_to_root( e_addr, loop_color++ ))) {
	    if ( simta_expand_debug != 0 ) {
		printf( "Supressed: %s\n", e_addr->e_addr );
	    }
	    continue;
	}

	if ( e_addr->e_addr_env_moderated != NULL ) {
	    /* Dfile: link Dold_id env->e_dir/Dnew_id */
	    e_addr->e_addr_env_moderated->e_dir = simta_dir_fast;
	    e_addr->e_addr_env_moderated->e_dinode = unexpanded_env->e_dinode;
	    if ( env_id( e_addr->e_addr_env_moderated ) != 0 ) {
		goto cleanup3;
	    }

	    syslog( LOG_DEBUG, "expand moderation env %s dinode %d",
		    e_addr->e_addr_env_moderated->e_id,
		    (int)e_addr->e_addr_env_moderated->e_dinode );

	    if ( simta_expand_debug != 0 ) {
		printf( "Moderated: %s\n", e_addr->e_addr );
		env_stdout( e_addr->e_addr_env_moderated );
		continue;
	    }

	    sprintf( d_out, "%s/D%s", e_addr->e_addr_env_moderated->e_dir,
		    e_addr->e_addr_env_moderated->e_id );
	    if ( link( d_original, d_out ) != 0 ) {
		syslog( LOG_ERR, "expand: link %s %s: %m", d_original, d_out );
		goto cleanup3;
	    }

	    sendermatch = !strcasecmp( unexpanded_env->e_mail,
		    e_addr->e_addr_env_moderated->e_mail );

	    n_rcpts = 0;
	    for ( rcpt = e_addr->e_addr_env_moderated->e_rcpt; rcpt != NULL;
		    rcpt = rcpt->r_next ) {
		n_rcpts++;
		if ( sendermatch ) {
		    syslog( LOG_INFO, "Expand %s: %s: To <%s> From <%s>",
			    unexpanded_env->e_id,
			    e_addr->e_addr_env_moderated->e_id, rcpt->r_rcpt,
			    e_addr->e_addr_env_moderated->e_mail );
		} else {
		    syslog( LOG_INFO, "Expand %s: %s: To <%s> From <%s> (%s)",
			    unexpanded_env->e_id,
			    e_addr->e_addr_env_moderated->e_id, rcpt->r_rcpt,
			    e_addr->e_addr_env_moderated->e_mail,
			    unexpanded_env->e_mail );
		}

	    }
	    syslog( LOG_INFO,
		    "Expand %s: %s: Expanded %d moderators",
		    unexpanded_env->e_id, e_addr->e_addr_env_moderated->e_id,
		    n_rcpts );

	    if ( env_outfile( e_addr->e_addr_env_moderated ) != 0 ) {
		/* env_outfile syslogs errors */
		if ( unlink( d_out ) != 0 ) {
		    syslog( LOG_ERR, "expand unlink %s: %m", d_out );
		}
		goto cleanup3;
	    }
	    env_out++;
	    queue_envelope( e_addr->e_addr_env_moderated );
	    continue;

	} else if ( e_addr->e_addr_ldap_flags & STATUS_LDAP_SUPRESSOR ) {
	    for ( parent = e_addr->e_addr_parents; parent != NULL;
		    parent = parent->el_next ) {
		if ( parent->el_exp_addr == NULL ) {
		    if ( bounce_text( base_error_env, TEXT_ERROR,
			    "Members only group conditions not met: ",
			    e_addr->e_addr, NULL ) != 0 ) {
			goto cleanup3;
		    }

		    if ( bounce_text( base_error_env, TEXT_ERROR,
	    "If you have any questions, please contact the group owner: ",
			    e_addr->e_addr_owner, NULL ) != 0 ) {
			goto cleanup3;
		    }

		} else if (( e_addr->e_addr_ldap_flags & 
			STATUS_LDAP_PRIVATE ) == 0 ) {
		    if ( bounce_text( parent->el_exp_addr->e_addr_errors,
			    TEXT_ERROR,
			    "Members only group conditions not met: ",
			    e_addr->e_addr, NULL ) != 0 ) {
			goto cleanup3;
		    }

		    if ( bounce_text( parent->el_exp_addr->e_addr_errors, 
			    TEXT_ERROR,
	    "If you have any questions, please contact the group owner: ",
			    e_addr->e_addr_owner, NULL ) != 0 ) {
			goto cleanup3;
		    }
		}
	    }

	    continue;
	}
#endif /* HAVE_LDAP */

	if ( e_addr->e_addr_terminal == 0 ) {
	    if ( simta_expand_debug != 0 ) {
		printf( "Non-terminal: %s\n", e_addr->e_addr );
	    }
	    /* not a terminal expansion, do not add */
	    continue;
	}

	if ( simta_expand_debug != 0 ) {
	    printf( "Terminal: %s\n", e_addr->e_addr );
	}

	switch ( e_addr->e_addr_type ) {
	case ADDRESS_TYPE_EMAIL:
	    if (( domain = strchr( e_addr->e_addr, '@' )) == NULL ) {
		syslog( LOG_ERR, "expand.strchr: unreachable code" );
		goto cleanup3;
	    }
	    domain++;
	    env = eo_lookup( host_stab, domain, e_addr->e_addr_from );
	    break;

	case ADDRESS_TYPE_DEAD:
	    domain = NULL;
	    env = env_dead;
	    break;

	default:
	    panic( "expand: address type out of range" );
	}

	if ( env == NULL ) {
	    /* Create envelope and add it to list */
	    if (( env = env_create( e_addr->e_addr_from,
		    unexpanded_env )) == NULL ) {
		syslog( LOG_ERR, "expand.env_create: %m" );
		goto cleanup3;
	    }

	    if ( env_id( env ) != 0 ) {
		env_free( env );
		goto cleanup3;
	    }

	    env->e_dinode = unexpanded_env->e_dinode;

	    syslog( LOG_DEBUG, "expand expansion env %s dinode %d", env->e_id,
		    (int)env->e_dinode );

	    /* fill in env */
	    if ( domain != NULL ) {
		env->e_dir = simta_dir_fast;
		if ( env_hostname( env, domain ) != 0 ) {
		    env_free( env );
		    goto cleanup3;
		}
	    } else {
		env->e_dir = simta_dir_dead;
		env_dead = env;
	    }

	    /* Add env to host_stab */
	    if ( eo_insert( &host_stab, env ) != 0 ) {
		syslog( LOG_ERR, "expand.ll_insert: %m" );
		env_free( env );
		goto cleanup3;
	    }
	}

	if ( env_recipient( env, e_addr->e_addr ) != 0 ) {
	    goto cleanup3;
	}

	syslog( LOG_NOTICE,
		"expand: recipient <%s> added to env %s for host %s",
		e_addr->e_addr, env->e_id,
		env->e_hostname ? env->e_hostname : "NULL" );
    }

    /* Write out all expanded envelopes and place them in to the host_q */
    for ( eo = host_stab; eo != NULL; eo = eo->eo_next ) {
	env = eo->eo_env;

	if ( simta_expand_debug == 0 ) {
	    /* Dfile: link Dold_id env->e_dir/Dnew_id */
	    sprintf( d_out, "%s/D%s", env->e_dir, env->e_id );

	    if ( link( d_original, d_out ) != 0 ) {
		syslog( LOG_ERR, "expand: link %s %s: %m", d_original, d_out );
		goto cleanup4;
	    }

	    sendermatch = !strcasecmp( unexpanded_env->e_mail, env->e_mail );

	    n_rcpts = 0;
	    for ( rcpt = env->e_rcpt; rcpt != NULL; rcpt = rcpt->r_next ) {
		n_rcpts++;
		if ( sendermatch ) {
		    syslog( LOG_INFO, "Expand %s: %s: To <%s> From <%s>",
			    unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
			    env->e_mail );
		} else {
		    syslog( LOG_INFO, "Expand %s: %s: To <%s> From <%s> (%s)",
			    unexpanded_env->e_id, env->e_id, rcpt->r_rcpt, 
			    env->e_mail, unexpanded_env->e_mail );
		}
	    }

	    syslog( LOG_INFO,
		    "Expand %s: %s: Expanded %d recipients",
		    unexpanded_env->e_id, env->e_id, n_rcpts );

	    /* Efile: write env->e_dir/Enew_id for all recipients at host */
	    syslog( LOG_NOTICE, "expand %s: writing %s %s",
		    unexpanded_env->e_id, env->e_id,
		    env->e_hostname ? env->e_hostname : "NULL" );
	    if ( env_outfile( env ) != 0 ) {
		/* env_outfile syslogs errors */
		if ( unlink( d_out ) != 0 ) {
		    syslog( LOG_ERR, "expand unlink %s: %m", d_out );
		}
		goto cleanup4;
	    }

	    env_out++;
	    queue_envelope( env );

	} else {
	    printf( "\n" );
	    env_stdout( env );
	}
    }

    if ( env_out == 0 ) {
	syslog( LOG_NOTICE, "expand %s: no terminal recipients, "
		"deleting message", unexpanded_env->e_id );
    }

    /* write errors out to disk */
    env_p = &(exp.exp_errors);
    while (( env = *env_p ) != NULL ) {
	if ( simta_expand_debug == 0 ) {
	    if ( env->e_error != 0 ) {
		env_p = &(env->e_next);

		if ( snet == NULL ) {
		    if (( snet = snet_open( d_original, O_RDONLY, 0,
			    1024 * 1024 )) == NULL ) {
			syslog( LOG_ERR, "expand.snet_open %s: %m",
				d_original );
			goto cleanup5;
		    }
		} else {
		    if ( lseek( snet_fd( snet ), (off_t)0, SEEK_SET ) != 0 ) {
			syslog( LOG_ERR, "q_deliver lseek: %m" );
			panic( "q_deliver lseek fail" );
		    }
		}

		/* write out error text, get Dfile inode */
		if (( env->e_dinode = bounce_dfile_out( env, snet )) == 0 ) {
		    if ( snet != NULL ) {
			if ( snet_close( snet ) != 0 ) {
			    syslog( LOG_ERR, "expand.snet_close %s: %m",
				    d_original );
			}
		    }

		    goto cleanup5;
		}

		syslog( LOG_DEBUG, "expand errors env %s dinode %d", env->e_id,
			(int)env->e_dinode );

		line_file_free( env->e_err_text );
		env->e_err_text = NULL;
		env->e_error = 0;

		if ( env_outfile( env ) != 0 ) {
		    /* env_outfile syslogs errors */
		    sprintf( d_out, "%s/D%s", env->e_dir, env->e_id );
		    if ( unlink( d_out ) != 0 ) {
			syslog( LOG_ERR, "expand unlink %s: %m", d_out );
		    }
		    goto cleanup5;
		}

		sendermatch = !strcasecmp( unexpanded_env->e_mail,
			env->e_mail );

		n_rcpts = 0;
		for ( rcpt = env->e_rcpt; rcpt != NULL; rcpt = rcpt->r_next ) {
		    n_rcpts++;
		    if ( sendermatch ) {
			syslog( LOG_INFO, "Expand %s: %s: To <%s> From <%s>",
				unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
				env->e_mail );
		    } else {
			syslog( LOG_INFO,
				"Expand %s: %s: To <%s> From <%s> (%s)",
				unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
				env->e_mail, unexpanded_env->e_mail );
		    }
		}

		syslog( LOG_INFO, "Expand %s: %s: Expanded %d bounces",
			unexpanded_env->e_id, env->e_id, n_rcpts );

		queue_envelope( env );

	    } else {
		*env_p = env->e_next;
		env_free( env );
	    }

	} else {
	    *env_p = env->e_next;
	    bounce_stdout( env );
	    env_free( env );
	}
    }

    if ( snet != NULL ) {
	if ( snet_close( snet ) != 0 ) {
	    syslog( LOG_ERR, "expand.snet_close %s: %m",
		    d_original );
	    sprintf( d_out, "%s/D%s", env->e_dir, env->e_id );
	    if ( unlink( d_out ) != 0 ) {
		syslog( LOG_ERR, "expand unlink %s: %m", d_out );
	    }
	    goto cleanup5;
	}
	snet = NULL;
    }

    if ( simta_expand_debug != 0 ) {
	return_value = 0;
	goto cleanup2;
    }

    if ( utime( d_original, NULL ) != 0 ) {
	syslog( LOG_ERR, "expand.utime %s: %m", d_original );
	goto cleanup5;
    }

    if ( unexpanded_env->e_dir != simta_dir_fast ) {
	/* truncate orignal Efile */
	sprintf( e_original, "%s/E%s", unexpanded_env->e_dir,
		unexpanded_env->e_id );

	if ( truncate( e_original, (off_t)0 ) != 0 ) {
	    syslog( LOG_ERR, "expand.truncate %s: %m", e_original );
	    goto cleanup5;
	}
    }

    /* delete original message */
    if ( env_unlink( unexpanded_env ) != 0 ) {
	syslog( LOG_ERR, "expand env_unlink %s: can't delete original message",
		unexpanded_env->e_id );
    }

    syslog( LOG_INFO, "Expand %s: Message Deleted: Expansion complete", 
	    unexpanded_env->e_id );

    return_value = 0;
    goto cleanup2;

cleanup5:
    while ( exp.exp_errors != NULL ) {
	env = exp.exp_errors;
	exp.exp_errors = exp.exp_errors->e_next;

	/* unlink if written to disk */
	if (( env->e_flags & ENV_FLAG_EFILE ) != 0 ) {
	    queue_remove_envelope( env );
	    if ( env_unlink( env ) == 0 ) {
		syslog( LOG_INFO, "Expand %s: Message Deleted: "
			"System error, unwinding expansion", env->e_id );
	    } else {
		syslog( LOG_INFO, "Expand %s: "
			"System error, can't unwind expansion", env->e_id );
	    }
	}

	env_free( env );
    }

cleanup4:
    for ( eo = host_stab; eo != NULL; eo = eo->eo_next ) {
	env = eo->eo_env;
	eo->eo_env = NULL;

	if (( env->e_flags & ENV_FLAG_EFILE ) != 0 ) {
	    queue_remove_envelope( env );
	    if ( env_unlink( env ) == 0 ) {
		syslog( LOG_INFO, "Expand %s: Message Deleted: "
			"System error, unwinding expansion", env->e_id );
	    } else {
		syslog( LOG_INFO, "Expand %s: "
			"System error, can't unwind expansion", env->e_id );
	    }
	}

	env_free( env );
    }

cleanup3:
#ifdef HAVE_LDAP
    for ( memonly = exp.exp_memonly; memonly != NULL;
	    memonly = memonly->el_next ) {
	if (( memonly->el_exp_addr->e_addr_env_moderated != NULL ) &&
		(( memonly->el_exp_addr->e_addr_env_moderated->e_flags &
		ENV_FLAG_EFILE ) != 0 )) {
	    env_unlink( memonly->el_exp_addr->e_addr_env_moderated );
	    env_free( memonly->el_exp_addr->e_addr_env_moderated );
	    memonly->el_exp_addr->e_addr_env_moderated = NULL;
	}
    }
#endif /* HAVE_LDAP */

    if ( simta_fast_files != fast_file_start ) {
	syslog( LOG_WARNING, "expand: could not unwind expansion" );
	return_value = 1;
    }

cleanup2:
    /* free host_stab */
    eo = host_stab;
    while ( eo != NULL ) {
	eo_free = eo;
	eo = eo->eo_next;
	free( eo_free );
    }

cleanup1:
#ifdef HAVE_LDAP  
    exp_addr_link_free( exp.exp_memonly );
#endif /* HAVE_LDAP */

    /* free the expansion list */
    for ( e_addr = exp.exp_addr_head; e_addr != NULL; e_addr = next_e_addr ) {
	next_e_addr = e_addr->e_addr_next;

#ifdef HAVE_LDAP  
	exp_addr_link_free( e_addr->e_addr_parents );
	exp_addr_link_free( e_addr->e_addr_children );
	permitted_destroy( e_addr );
	if (( e_addr->e_addr_env_moderated != NULL ) &&
		(( e_addr->e_addr_env_moderated->e_flags &
		ENV_FLAG_EFILE ) == 0 )) {
	    env_free( e_addr->e_addr_env_moderated );
	}

	if ( e_addr->e_addr_owner ) {
	    free( e_addr->e_addr_owner );
	}

	if ( e_addr->e_addr_dn ) {
	    free( e_addr->e_addr_dn );
	}
#endif

	free( e_addr->e_addr );
	free( e_addr->e_addr_from );
	free( e_addr );
    }

done:
    if ( return_value != 0 ) {
	syslog( LOG_NOTICE, "Expand %s: Expansion failed",
		unexpanded_env->e_id );
    }

    return( return_value );
}


#ifdef HAVE_LDAP
    void
supress_addrs( struct exp_link *list, int color )
{
    struct exp_link		*el;

    for ( el = list; el != NULL; el = el->el_next ) {
	assert(( el->el_exp_addr->e_addr_ldap_flags &
		STATUS_EMAIL_SENDER ) == 0 );

	if ( el->el_exp_addr->e_addr_anti_loop == color ) {
	    continue;
	}
	el->el_exp_addr->e_addr_anti_loop = color;

	if (( el->el_exp_addr->e_addr_ldap_flags &
		STATUS_LDAP_SUPRESSED ) != 0 ) {
	    continue;
	}

	el->el_exp_addr->e_addr_ldap_flags |= STATUS_LDAP_SUPRESSED;
	supress_addrs( el->el_exp_addr->e_addr_children, color );
    }

    return;
}


    int
sender_is_child( struct exp_addr *e, int color )
{
    struct exp_link		*el;

    if ( e->e_addr_anti_loop == color ) {
	return( 0 );
    }
    e->e_addr_anti_loop = color;

    if (( e->e_addr_ldap_flags & STATUS_EMAIL_SENDER ) != 0 ) {
	return( 1 );
    }

    if (( e->e_addr_ldap_flags & STATUS_NO_EMAIL_SENDER ) != 0 ) {
	return( 0 );
    }

    for ( el = e->e_addr_children; el != NULL; el = el->el_next ) {
	if ( sender_is_child( el->el_exp_addr, color )) {
	    e->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
	    return( 1 );
	}
    }

    e->e_addr_ldap_flags |= STATUS_NO_EMAIL_SENDER;
    return( 0 );
}


    int
unblocked_path_to_root( struct exp_addr *e, int color )
{
    struct exp_link		*el;

    if ( e->e_addr_anti_loop == color ) {
	return( 0 );
    }
    e->e_addr_anti_loop = color;

    if (( e->e_addr_ldap_flags & STATUS_LDAP_MEMONLY ) != 0 ) {
	return( 0 );
    }

    if (( e->e_addr_ldap_flags & STATUS_NO_ROOT_PATH ) != 0 ) {
	return( 0 );
    }

    if (( e->e_addr_ldap_flags & STATUS_ROOT_PATH ) != 0 ) {
	return( 1 );
    }

    for ( el = e->e_addr_parents; el != NULL; el = el->el_next ) {
	if (( el->el_exp_addr == NULL ) ||
		( unblocked_path_to_root( el->el_exp_addr, color ))) {
	    e->e_addr_ldap_flags |= STATUS_ROOT_PATH;
	    return( 1 );
	}
    }

    e->e_addr_ldap_flags |= STATUS_NO_ROOT_PATH;
    return( 0 );
}


    int
permitted_create( struct exp_addr *e_addr, char **permitted )
{
    int		idx;
    char	*namedup;

    if (permitted && *permitted)
    {
	/* 
	** Normalize the permitted group list 
	** normalization happens "in-place"
	*/   
	for (idx = 0;  permitted[idx] != NULL; idx++) {
	    dn_normalize_case (permitted[idx]);

	    if ((namedup = strdup (permitted[idx])) == NULL)
		return (1);

	    if ( ll_insert ( &e_addr->e_addr_ok, namedup, namedup, NULL ) != 0 )
		return (1);
	}		
    }
    return 0;
}


    void
permitted_destroy ( struct exp_addr *e_addr)
{

    struct stab_entry  *pstab;
    struct stab_entry  *nstab;

    pstab = e_addr->e_addr_ok;
    while ( pstab != NULL ) {
        nstab = pstab;
        pstab = pstab->st_next;
        if ( nstab->st_key != NULL ) {
            free( nstab->st_key );
        }
        free( nstab );
    }
    return;
}


    int
parent_permitted( struct exp_addr *memonly )
{
    struct exp_link		*parent;
    struct stab_entry		*ok;

    for ( ok = memonly->e_addr_ok; ok != NULL; ok = ok->st_next ) {
	for ( parent = memonly->e_addr_parents; parent != NULL;
		parent = parent->el_next ) {
	    if ( parent->el_exp_addr == NULL ) {
		continue;
	    }

	    if (( strcmp( ok->st_key, parent->el_exp_addr->e_addr_dn ) == 0 )) {
		return( 1 );
	    }
	}
    }

    return( 0 );
}
#endif /* HAVE_LDAP */
