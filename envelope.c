/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <dirent.h>
#include <assert.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "ll.h"
#include "envelope.h"
#include "line_file.h"
#include "header.h"
#include "simta.h"
#include "queue.h"


    int
env_jail_set( struct envelope *e, int val )
{
    char			*s;

    if ( simta_debug > 1 ) {
	switch ( val ) {
	default:
	    s = "Unknown";
	    break;

	case ENV_JAIL_NO_CHANGE:
	    s = "JAIL_NO_CHANGE";
	    break;

	case ENV_JAIL_PAROLEE:
	    s = "JAIL_PAROLEE";
	    break;

	case ENV_JAIL_PRISONER:
	    s = "JAIL_PRISONER";
	    break;
	}

	syslog( LOG_DEBUG, "Jail %s: value %d (%s)", e->e_id, val, s );
    }

    e->e_jail = val;

    return( 0 );
}

    int
env_jail_status( struct envelope *env, int jail )
{
    SNET			*snet_lock;

    if ( env == NULL ) {
	return( 0 );
    }

    if (( jail != ENV_JAIL_PRISONER ) && ( jail != ENV_JAIL_PAROLEE )) {
	syslog( LOG_ERR, "Syserror %s: env_jail_status: illegal code: %d",
		env->e_id, jail );
	return( 1 );
    }

    if (( env->e_jail != ENV_JAIL_PRISONER ) &&
	    ( env->e_jail != ENV_JAIL_PAROLEE )) {
	syslog( LOG_ERR, "Syserror %s: env_jail_status: illegal env code: %d",
		env->e_id, env->e_jail );
	return( 1 );
    }

    if ( env->e_jail == jail ) {
	return( 0 );
    }

    if ( env->e_hq != NULL ) {
	if ( jail == ENV_JAIL_PRISONER ) {
	    env->e_hq->hq_jail_envs--;
	} else {
	    env->e_hq->hq_jail_envs++;
	}
    }

    if ( env_read( READ_JAIL_INFO, env, &snet_lock ) != 0 ) {
	return( 0 );
    }

    env_jail_set( env, jail );

    if ( env_outfile( env ) != 0 ) {
	return( 1 );
    }

    env_rcpt_free( env );

    return( 0 );
}


    int
env_is_old( struct envelope *env, int dfile_fd )
{
    struct timeval              tv_now;
    struct stat			sb;

    if ( env->e_age == ENV_AGE_UNKNOWN ) {
	if ( fstat( dfile_fd, &sb ) != 0 ) {
	    syslog( LOG_ERR, "env_is_old fstat %s/D%s: %m", env->e_dir,
		    env->e_id );
	    return( 0 );
	}

	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    return( 0 );
	}

	if ( simta_bounce_seconds > 0 ) {
	    if (( tv_now.tv_sec - sb.st_mtime ) > ( simta_bounce_seconds )) {
		env->e_age = ENV_AGE_OLD;
	    } else {
		env->e_age = ENV_AGE_NOT_OLD;
	    }

	}
    }

    if ( env->e_age == ENV_AGE_OLD ) {
	return( 1 );
    }

    return( 0 );
}


    struct envelope *
env_create( char *dir, char *id, char *e_mail, struct envelope *parent )
{
    struct envelope	*env;
    struct timeval		tv_now;
    int				pid;
    /* way bigger than we should ever need */
    char			buf[ 1024 ];

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	syslog( LOG_ERR, "env_create malloc: %m" );
	return( NULL );
    }
    memset( env, 0, sizeof( struct envelope ));

    if (( id == NULL ) || ( *id == '\0' )) {
	if ( simta_gettimeofday( &tv_now ) != 0 ) {
	    env_free( env );
	    return( NULL );
	}

	if (( pid = getpid()) < 0 ) {
	    syslog( LOG_ERR, "env_set_id getpid: %m" );
	    env_free( env );
	    return( NULL );
	}

	snprintf( buf, 1023, "%lX.%lX.%d", (unsigned long)tv_now.tv_sec,
		(unsigned long)tv_now.tv_usec, pid );

	id = buf;
    }

    if (( env->e_id = strdup( id )) == NULL ) {
	syslog( LOG_ERR, "env_create strdup: %m" );
	env_free( env );
	return( NULL );
    }

    if ( e_mail != NULL ) {
	if ( env_sender( env, e_mail ) != 0 ) {
	    env_free( env );
	    return( NULL );
	}
    }

    if ( parent ) {
	env->e_n_exp_level = parent->e_n_exp_level + 1;
	env_jail_set( env, parent->e_jail );
    } else if ( simta_mail_jail != 0 ) {
	env_jail_set( env, ENV_JAIL_PRISONER );
    }

    env->e_dir = dir;

    return( env );
}


    void
rcpt_free( struct recipient *r )
{
    if ( r != NULL ) {
	if ( r->r_rcpt != NULL ) {
	    free( r->r_rcpt );
	    r->r_rcpt = NULL;
	}

	if ( r->r_err_text != NULL ) {
	    line_file_free( r->r_err_text );
	    r->r_err_text = NULL;
	}

	memset( r, 0, sizeof( struct recipient ));
	free( r );
    }
}


    void
env_rcpt_free( struct envelope *env )
{
    struct recipient		*r;
    struct recipient		*r_next;


    for ( r = env->e_rcpt; r != NULL; r = r_next ) {
	r_next = r->r_next;
	rcpt_free( r );
    }

    env->e_rcpt = NULL;
    env->e_n_rcpt = 0;
}


    void
env_clear_errors( struct envelope *env )
{
    struct recipient		*r;

    env->e_error = 0;

    if ( env->e_err_text != NULL ) {
	line_file_free( env->e_err_text );
	env->e_err_text = NULL;
    }

    env->e_flags = ( env->e_flags & ( ~ENV_FLAG_BOUNCE ));
    env->e_flags = ( env->e_flags & ( ~ENV_FLAG_TEMPFAIL ));

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( r->r_err_text != NULL ) {
	    line_file_free( r->r_err_text );
	    r->r_err_text = NULL;
	}
	r->r_status = 0;
    }

    return;
}


    int
env_hostname( struct envelope *env, char *hostname )
{
    if ( env->e_hostname != NULL ) {
	if ( strcasecmp( env->e_hostname, hostname ) != 0 ) {
	    syslog( LOG_WARNING, "Warning env_hostname: %s: "
		    "can't reassign hostname from \"%s\" to \"%s\"",
		    env->e_id, env->e_hostname, hostname );
	}
	return( 0 );
    }

    if (( hostname != NULL ) && ( *hostname != '\0' )) {
	if (( env->e_hostname = strdup( hostname )) == NULL ) {
	    syslog( LOG_ERR, "env_hostname strdup: %m" );
	    return( 1 );
	}
    }

    return( 0 );
}


    int
env_sender( struct envelope *env, char *e_mail )
{
    if ( env->e_mail != NULL ) {
	syslog( LOG_ERR, "env_sender: %s already has a sender", env->e_id );
	return( 1 );
    }
    
    if (( env->e_mail = strdup( e_mail )) == NULL ) {
	syslog( LOG_ERR, "env_sender strdup: %m" );
	return( 1 );
    }

    return( 0 );
}


    void
env_free( struct envelope *env )
{
    if ( env == NULL ) {
	return;
    }

    if ( env->e_mid != NULL ) {
	free( env->e_mid );
    }

    if ( env->e_env_list_entry != NULL ) {
	dll_remove_entry( &simta_env_list, env->e_env_list_entry );
    }

    if ( env->e_mail != NULL ) {
	free( env->e_mail );
    }

    if ( env->e_sender_entry != NULL ) {
	dll_remove_entry( &(env->e_sender_entry->se_list->sl_entries),
		env->e_sender_entry->se_dll );
	env->e_sender_entry->se_list->sl_n_entries--;
	if ( env->e_sender_entry->se_list->sl_entries == NULL ) {
	    dll_remove_entry( &simta_sender_list,
		env->e_sender_entry->se_list->sl_dll );
	    free( env->e_sender_entry->se_list );
	}
	free( env->e_sender_entry );
    }

    if ( env->e_hostname != NULL ) {
	free( env->e_hostname );
    }

    if ( env->e_id != NULL ) {
	free( env->e_id );
    }

    env_rcpt_free( env );
    env_clear_errors( env );
    memset( env, 0, sizeof( struct envelope ));
    free( env );

    return;
}


    void
env_syslog( struct envelope *e )
{
    syslog( LOG_DEBUG, "message %s rcpt %d host %s",
	    e->e_id, e->e_n_rcpt, e->e_hostname ? e->e_hostname : "NULL" );
}


    void
env_stdout( struct envelope *e )
{
    struct recipient		*r;

    if ( e->e_id == NULL ) {
	printf( "Message-Id NULL\n" );
    } else {
	printf( "Message-Id:\t%s\n", e->e_id );
    }

    if ( e->e_hostname == NULL ) {
	printf( "expanded NULL\n" );
    } else {
	printf( "expanded %s\n", e->e_hostname );
    }

    if ( e->e_mail != NULL ) {
	printf( "mail:\t%s\n", e->e_mail );
    } else {
	printf( "mail NULL\n" );
    }

    if ( e->e_dir != NULL ) {
	printf( "dir:\t%s\n", e->e_dir );
    } else {
	printf( "dir NULL\n" );
    }

    for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	printf( "rcpt:\t%s\n", r->r_rcpt );
    }
}


    int
env_recipient( struct envelope *e, char *addr )
{
    struct recipient		*r;

    if (( r = (struct recipient*)malloc( sizeof( struct recipient )))
	    == NULL ) {
	syslog( LOG_ERR, "env_recipient malloc: %m" );
	return( -1 );
    }
    memset( r, 0, sizeof( struct recipient ));

    if (( addr == NULL ) || ( *addr == '\0' )) {
	if (( r->r_rcpt = strdup( "" )) == NULL ) {
	    syslog( LOG_ERR, "env_recipient strdup: %m" );
	    free( r );
	    return( -1 );
	}

    } else {
	if (( r->r_rcpt = strdup( addr )) == NULL ) {
	    syslog( LOG_ERR, "env_recipient strdup: %m" );
	    free( r );
	    return( -1 );
	}
    }

    r->r_next = e->e_rcpt;
    e->e_rcpt = r;
    e->e_n_rcpt++;

    return( 0 );
}


    int
env_outfile( struct envelope *e )
{
    if (( e->e_flags & ENV_FLAG_TFILE ) == 0 ) {
	if ( env_tfile( e ) != 0 ) {
	    return( 1 );
	}
    }

    if ( env_efile( e ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    int
env_dfile_open( struct envelope *env )
{
    char				dfile_fname[ MAXPATHLEN + 1 ];
    int					fd;

    sprintf( dfile_fname, "%s/D%s", env->e_dir, env->e_id );

    if (( fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	syslog( LOG_ERR, "Syserror env_dfile_open: open %s: %m", dfile_fname );
	return( -1 );
    }

    env->e_flags |= ENV_FLAG_DFILE;

    return( fd );
}


    int
env_tfile_unlink( struct envelope *e )
{
    char		tf[ MAXPATHLEN + 1 ];

syslog( LOG_DEBUG, "env_tfile_unlink %s", e->e_id );

    sprintf( tf, "%s/t%s", e->e_dir, e->e_id );

    if ( unlink( tf ) != 0 ) {
	syslog( LOG_ERR, "env_tfile_unlink unlink %s: %m", tf );
	return( -1 );
    }

    e->e_flags = ( e->e_flags & ( ~ENV_FLAG_TFILE ));

    return( 0 );
}


    int
env_tfile( struct envelope *e )
{
    int						fd;
    struct recipient				*r;
    FILE					*tff;
    char					tf[ MAXPATHLEN + 1 ];
    int						version_to_write;

    assert( e->e_dir != NULL );
    assert( e->e_id != NULL );

    sprintf( tf, "%s/t%s", e->e_dir, e->e_id );

    /* make tfile */
    if (( fd = open( tf, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	syslog( LOG_ERR, "env_tfile open %s: %m", tf );
	return( -1 );
    }

    if (( tff = fdopen( fd, "w" )) == NULL ) {
	close( fd );
	syslog( LOG_ERR, "env_tfile fdopen: %m" );
	unlink( tf );
	return( -1 );
    }

    /* VSIMTA_EFILE_VERSION */
    version_to_write = SIMTA_EFILE_VERSION;
#if 0
    if (( !e->e_attributes ) && ( !e->e_jail )) {
	version_to_write = 3;
    }
#endif

    if ( fprintf( tff, "V%d\n", version_to_write ) < 0 ) {
	syslog( LOG_ERR, "env_tfile fprintf: %m" );
	goto cleanup;
    }

    /* Emessage-id */
    if ( fprintf( tff, "E%s\n", e->e_id ) < 0 ) {
	syslog( LOG_ERR, "env_tfile fprintf: %m" );
	goto cleanup;
    }

    /* Idinode */
    if ( e->e_dinode <= 0 ) {
	panic( "env_tfile: bad dinode" );
    }
    if ( fprintf( tff, "I%lu\n", e->e_dinode ) < 0 ) {
	syslog( LOG_ERR, "env_tfile fprintf: %m" );
	goto cleanup;
    }

    syslog( LOG_DEBUG, "env_tfile %s: Dinode %d", e->e_id, (int)e->e_dinode );

    /* Xpansion Level */
    if ( fprintf( tff, "X%d\n", e->e_n_exp_level ) < 0 ) {
	syslog( LOG_ERR, "env_tfile fprintf: %m" );
	goto cleanup;
    }

    /* Jail Level */
    if (( version_to_write < 5 )) {
    } else if ( fprintf( tff, "J%d\n", e->e_jail ) < 0 ) {
	syslog( LOG_ERR, "env_tfile fprintf: %m" );
	goto cleanup;
    }

    /* Hdestination-host */
    if (( e->e_hostname != NULL ) && ( e->e_dir != simta_dir_dead )) {
	if ( fprintf( tff, "H%s\n", e->e_hostname ) < 0 ) {
	    syslog( LOG_ERR, "env_tfile fprintf: %m" );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "H\n" ) < 0 ) {
	    syslog( LOG_ERR, "env_tfile fprintf: %m" );
	    goto cleanup;
	}
    }

    if (( version_to_write < 4 )) {
    } else if ( fprintf( tff, "D%u\n", e->e_attributes ) < 0 ) {
	syslog( LOG_ERR, "env_tfile fprintf: %m" );
	goto cleanup;
    }

    /* Ffrom-addr@sender.com */
    if ( e->e_mail != NULL ) {
	if ( fprintf( tff, "F%s\n", e->e_mail ) < 0 ) {
	    syslog( LOG_ERR, "env_tfile fprintf: %m" );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "F\n" ) < 0 ) {
	    syslog( LOG_ERR, "env_tfile fprintf: %m" );
	    goto cleanup;
	}
    }

    /* Rto-addr@recipient.com */
    if ( e->e_rcpt != NULL ) {
	for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	    if ( fprintf( tff, "R%s\n", r->r_rcpt ) < 0 ) {
		syslog( LOG_ERR, "env_tfile fprintf: %m" );
		goto cleanup;
	    }
	}

    } else {
	syslog( LOG_ERR, "env_tfile %s: no recipients", e->e_id );
	goto cleanup;
    }

    if ( fclose( tff ) != 0 ) {
	syslog( LOG_ERR, "env_tfile fclose: %m" );
	unlink( tf );
	return( -1 );
    }

    e->e_flags |= ENV_FLAG_TFILE;

    return( 0 );

cleanup:
    fclose( tff );
    unlink( tf );
    return( -1 );
}


    int
sender_list_add( struct envelope *e )
{
    struct dll_entry			*sl_dll;
    struct dll_entry			*se_dll;
    struct sender_list			*list;
    struct sender_entry			*entry;

    if (( sl_dll = dll_lookup_or_create( &simta_sender_list,
	e->e_mail, 1 )) == NULL ) {
	return( 1 );
    }

    if (( list = (struct sender_list*)sl_dll->dll_data ) == NULL ) {
	if (( list = (struct sender_list*)malloc(
		sizeof( struct sender_list ))) == NULL ) {
	    syslog( LOG_ERR, "Syserror: env_sender malloc: %m" );
	    return( 1 );
	}
	memset( list, 0, sizeof( struct sender_list ));
	list->sl_dll = sl_dll;
	sl_dll->dll_data = list;
    }

    if (( se_dll = dll_lookup_or_create( &(list->sl_entries),
	    e->e_id, 0 )) == NULL ) {
	return( 1 );
    }

    if ( se_dll->dll_data != NULL ) {
	return( 0 );
    }

    if (( entry = (struct sender_entry*)malloc(
	    sizeof( struct sender_entry ))) == NULL ) {
	syslog( LOG_ERR, "Syserror: env_sender malloc: %m" );
	return( 1 );
    }
    memset( entry, 0, sizeof( struct sender_entry ));
    se_dll->dll_data = entry;
    e->e_sender_entry = entry;
    entry->se_env = e;
    entry->se_list = list;
    entry->se_dll = se_dll;
    list->sl_n_entries++;

    return( 0 );
}


    int
env_efile( struct envelope *e )
{
    char		tf[ MAXPATHLEN + 1 ];
    char		ef[ MAXPATHLEN + 1 ];
    struct timeval	tv_now;
    struct dll_entry	*e_dll;

    sprintf( tf, "%s/t%s", e->e_dir, e->e_id );
    sprintf( ef, "%s/E%s", e->e_dir, e->e_id );

    if ( rename( tf, ef ) < 0 ) {
	syslog( LOG_ERR, "env_efile rename %s %s: %m", tf, ef );
	unlink( tf );
	return( -1 );
    }

    if ( e->e_dir == simta_dir_fast ) {
	simta_fast_files++;
	syslog( LOG_DEBUG, "env_efile %s fast_files increment %d",
		e->e_id, simta_fast_files );
    }

    syslog( LOG_DEBUG, "env_efile %s %s %s", e->e_dir, e->e_id,
	    e->e_hostname ? e->e_hostname : "" );

    e->e_flags = ( e->e_flags & ( ~ENV_FLAG_TFILE ));
    e->e_flags |= ENV_FLAG_EFILE;

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return( -1 );
    }

    e->e_etime.tv_sec = tv_now.tv_sec;

    if ( simta_no_sync == 0 ) {
	sync();
    }

    if ( simta_mid_list_enable != 0 ) {
	if (( e_dll = dll_lookup_or_create( &simta_env_list,
		e->e_id, 0 )) == NULL ) {
	    return( 1 );
	}

	if ( e_dll->dll_data == NULL ) {
	    e_dll->dll_data = e;
	    e->e_env_list_entry = e_dll;
	}
    }

    if ( simta_sender_list_enable != 0 ) {
	if ( sender_list_add( e ) != 0 ) {
	    return( 1 );
	}
    }

    return( 0 );
}


    /* calling this function updates the attempt time */

    int
env_touch( struct envelope *env )
{
    char			fname[ MAXPATHLEN ];
    struct timeval		tv_now;

    sprintf( fname, "%s/E%s", env->e_dir, env->e_id );

    if ( utime( fname, NULL ) != 0 ) {
	syslog( LOG_ERR, "env_touch utime %s: %m", fname );
	return( -1 );
    }

    if ( simta_gettimeofday( &tv_now ) != 0 ) {
	return( -1 );
    }

    env->e_etime.tv_sec = tv_now.tv_sec;

    return( 0 );
}


    /* Version
     * Emessage-id
     * [ Mid ]
     * Inode
     * Xpansion level
     * Jail
     * From
     * Recipients
     */

    int
env_read( int mode, struct envelope *env, SNET **s_lock )
{
    char			*line;
    SNET			*snet;
    char			filename[ MAXPATHLEN + 1 ];
    char			*hostname;
    int				ret = 1;
    ino_t			dinode;
    int				version;
    int				exp_level;
    int				jail;
    int				line_no = 1;
    struct dll_entry		*e_dll;

    switch ( mode ) {
    default:
	syslog( LOG_ERR, "Syserror env_read: unknown mode: %d", mode );
	return( 1 );

    case READ_QUEUE_INFO:
	if ( s_lock != NULL ) {
	    syslog( LOG_ERR,
		    "Syserror env_read: READ_QUEUE_INFO: no lock allowed" );
	    return( 1 );
	}
	break;

    case READ_DELIVER_INFO:
    case READ_JAIL_INFO:
	break;
    }

    sprintf( filename, "%s/E%s", env->e_dir, env->e_id );

    if (( snet = snet_open( filename, O_RDWR, 0, 1024 * 1024 )) == NULL ) {
	if (( errno != ENOENT ) || ( simta_debug != 0 )) {
	    syslog( LOG_ERR, "Syserror env_read: snet_open %s: %m", filename );
	}
	return( 1 );
    }

    switch ( mode ) {
    default:
	syslog( LOG_ERR, "Syserror env_read: mode change: %d", mode );
	goto cleanup;

    case READ_QUEUE_INFO:
	/* test to see if env is locked by a q_runner */
	if ( lockf( snet_fd( snet ), F_TEST, 0 ) != 0 ) {
	    syslog( LOG_ERR, "Syserror env_read: lockf %s: %m", filename );
	    goto cleanup;
	}
	break;

    case READ_DELIVER_INFO:
    case READ_JAIL_INFO:
	if ( s_lock != NULL ) {
	    *s_lock = snet;

	    /* lock envelope fd */
	    if ( lockf( snet_fd( snet ), F_TLOCK, 0 ) != 0 ) {
		if (( errno != EAGAIN ) && ( simta_debug == 0 )) {
		    /* file not locked by a diferent process */
		    syslog( LOG_ERR, "Syserror env_read: lockf %s: %m",
			    filename );
		}
		goto cleanup;
	    }
	}
	break;
    }

    /* Vsimta-version */
    if ((( line = snet_getline( snet, NULL )) == NULL ) || ( *line != 'V' )) {
	syslog( LOG_ERR, "Syserror env_read: %s %d: expected version syntax",
		filename, line_no );
	goto cleanup;
    }
    sscanf( line + 1, "%d", &version );
    if (( version < 1 ) || ( version > SIMTA_EFILE_VERSION )) {
	syslog( LOG_ERR,
		"Syserror env_read: %s %d: unsupported efile version %d",
		filename, line_no, version );
	goto cleanup;
    }

    if ( version >= 2 ) {
	/* Emessage-id */
	line_no++;
	if ((( line = snet_getline( snet, NULL )) == NULL ) || 
		( *line != 'E' )) {
	    syslog( LOG_ERR,
		    "Syserror env_read: %s %d: expected Equeue-id syntax",
		    filename, line_no );
	    goto cleanup;
	}
	if ( strcmp( line + 1, env->e_id ) != 0 ) {
	    syslog( LOG_WARNING,
		    "Syserror env_read: %s %d: queue-id mismatch: %s",
		    filename, line_no, line + 1 );
	    goto cleanup;
	}
    }

    line_no++;
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR,
		"Syserror env_read: %s %d: expected Dinode syntax", filename,
			line_no );
	goto cleanup;
    }

    /* ignore optional M for now */
    if ( *line == 'M' ) {
	line_no++;
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR,
		    "Syserror env_read: %s %d: expected Dinode syntax",
		    filename, line_no );
	    goto cleanup;
	}
    }

    /* Dinode info */
    if ( *line != 'I' ) {
	syslog( LOG_ERR, "Syserror env_read: %s %d: expected Dinode syntax",
		filename, line_no );
	goto cleanup;
    }

    sscanf( line + 1, "%lu", &dinode );

    switch ( mode ) {
    default:
	syslog( LOG_ERR, "Syserror env_read: mode change: %d", mode );
	goto cleanup;

    case READ_JAIL_INFO:
    case READ_DELIVER_INFO:
	if ( dinode != env->e_dinode ) {
	    syslog( LOG_WARNING,
		    "Warning env_read %s %d: Dinode reread mismatch: "
		    "old %d new %d, ignoring", filename, line_no,
		    (int)env->e_dinode, (int)dinode );
	}
	break;

    case READ_QUEUE_INFO:
	if ( dinode == 0 ) {
	    syslog( LOG_WARNING, "Warning env_read %s %d: Dinode is 0",
		    filename, line_no );
	}
	env->e_dinode = dinode;
	break;
    }

    /* expansion info */
    if ( version >= 3 ) {
	line_no++;
	if ((( line = snet_getline( snet, NULL )) == NULL ) ||
		( *line != 'X' )) {
	    syslog( LOG_ERR,
		    "Syserror env_read: %s %d: expected Xpansion syntax",
		    filename, line_no );
	    goto cleanup;
	}

	if ( sscanf( line + 1, "%d", &exp_level) != 1 ) {
	    syslog( LOG_ERR, "Syserror env_read: %s %d: bad Xpansion syntax",
		    filename, line_no );
	    goto cleanup;
	}

	switch ( mode ) {
	default:
	    syslog( LOG_ERR, "env_read error: mode change1: %d", mode );
	    goto cleanup;

	case READ_DELIVER_INFO:
	case READ_JAIL_INFO:
	    if ( exp_level == env->e_n_exp_level ) {
		break;
	    }
	    syslog( LOG_WARNING, "Warning env_read %s %d: Xpansion mismatch: "
		    "old %d new %d, ignoring", filename, line_no,
		    env->e_n_exp_level, exp_level );
	    break;

	case READ_QUEUE_INFO:
	    env->e_n_exp_level = exp_level;
	    break;
	}
    }

    /* Jail info */
    if ( version >= 5 ) {
	line_no++;
	if ((( line = snet_getline( snet, NULL )) == NULL ) ||
		( *line != 'J' )) {
	    syslog( LOG_ERR,
		    "Syserror env_read: %s %d: expected Jail syntax",
		    filename, line_no );
	    goto cleanup;
	}

	if ( sscanf( line + 1, "%d", &jail) != 1 ) {
	    syslog( LOG_ERR, "Syserror env_read: %s %d: bad Jail syntax",
		    filename, line_no );
	    goto cleanup;
	}

	switch ( mode ) {
	default:
	    syslog( LOG_ERR, "env_read error: mode change2: %d", mode );
	    goto cleanup;

	case READ_JAIL_INFO:
	case READ_DELIVER_INFO:
	    if ( env->e_jail == jail ) {
		break;
	    }
	    syslog( LOG_WARNING, "Warning env_read %s %d: Jail mismatch: "
		    "old %d new %d, ignoring", filename, line_no,
		    env->e_jail, jail );
	    break;

	case READ_QUEUE_INFO:
	    env_jail_set( env, jail );
	    break;
	}
    }

    line_no++;
    if ((( line = snet_getline( snet, NULL )) == NULL ) || ( *line != 'H' )) {
	syslog( LOG_ERR,
		"Syserror env_read: %s %d: expected host syntax",
		filename, line_no );
	goto cleanup;
    }

    hostname = line + 1;

    switch ( mode ) {
    default:
	syslog( LOG_ERR, "env_read error: mode change3: %d", mode );
	goto cleanup;

    case READ_DELIVER_INFO:
    case READ_JAIL_INFO:
	if ( env->e_hostname == NULL ) {
	    if ( *hostname != '\0' ) {
		syslog( LOG_ERR,
			"Syserror env_read: %s %d: hostname reread mismatch, "
			"old \"\" new \"%s\"", filename, line_no, hostname );
		goto cleanup;
	    }
	} else if ( strcasecmp( hostname, env->e_hostname ) != 0 ) {
	    syslog( LOG_ERR,
		    "Syserror env_read: %s %d: hostname reread mismatch, "
		    "old \"%s\" new \"%s\"", filename, line_no,
		    env->e_hostname, hostname );
	    goto cleanup;
	}
	break;

    case READ_QUEUE_INFO:
	if ( env_hostname( env, hostname ) != 0 ) {
	    goto cleanup;
	}
	break;
    }

    /* Dattributes */
    if ( version >= 4 ) {
	line_no++;
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR, "env_read %s: unexpected EOF", filename );
	    goto cleanup;
	}

	if ( *line != 'D' ) {
	    syslog( LOG_ERR, "env_read %s: expected Dattributes syntax",
		    filename );
	    goto cleanup;
	}

	if ( sscanf( line + 1, "%d", &exp_level) != 1 ) {
	    syslog( LOG_ERR, "env_read: %s: bad Dattributes syntax", filename );
	    goto cleanup;
	}

	if ( mode == READ_QUEUE_INFO ) {
	    env->e_attributes = exp_level;
	} else if ( exp_level != env->e_attributes ) {
	    syslog( LOG_WARNING, "env_read %s: Dattributes reread mismatch "
		    "old %d new %d", filename, env->e_attributes, exp_level );
	}
    }

    /* Ffrom-address */
    line_no++;
    if ((( line = snet_getline( snet, NULL )) == NULL ) || ( *line != 'F' )) {
	syslog( LOG_ERR, "Syserror env_read: %s %d: expected Ffrom syntax",
		filename, line_no );
	goto cleanup;
    }

    switch ( mode ) {
    default:
	syslog( LOG_ERR, "env_read error: mode change4: %d", mode );
	goto cleanup;

    case READ_QUEUE_INFO:
	if ( env_sender( env, line + 1 ) == 0 ) {
	    ret = 0;
	}
	goto cleanup;

    case READ_JAIL_INFO:
    case READ_DELIVER_INFO:
	if ( strcmp( env->e_mail, line + 1 ) != 0 ) {
	    syslog( LOG_ERR, "Syserror env_read: %s %d: bad sender re-read: "
		    "old \"%s\" new \"%s\"",
		    filename, line_no, env->e_mail, line + 1 );
	    goto cleanup;
	}
	break;
    }

    /* Rto-addresses */
    for ( line_no++; ( line = snet_getline( snet, NULL )) != NULL;
	    line_no++ ) {
	if ( *line != 'R' ) {
	    syslog( LOG_ERR,
		    "Syserror env_read: %s %d: expected Recipient syntax",
		    filename, line_no );
	    goto cleanup;
	}

	if ( env_recipient( env, line + 1 ) != 0 ) {
	    goto cleanup;
	}
    }

    if ( env->e_rcpt == NULL ) {
	syslog( LOG_ERR,
		"Syserror env_read: %s %d: expected Recipient syntax",
		filename, line_no );
	goto cleanup;
    }

    ret = 0;

    /* close snet if no need to maintain lock */
    if ( s_lock == NULL ) {
cleanup:
	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "Syserror env_read: snet_close %s: %m",
		    filename );
	    ret = 1;
	}
    }

    if (( simta_mid_list_enable != 0 ) && ( ret == 0 )) {
	if (( e_dll = dll_lookup_or_create( &simta_env_list,
		env->e_id, 0 )) == NULL ) {
	    return( 1 );
	}

	if ( e_dll->dll_data == NULL ) {
	    e_dll->dll_data = env;
	    env->e_env_list_entry = e_dll;
	}
    }

    if (( simta_sender_list_enable != 0 ) && ( ret == 0 )) {
	if ( sender_list_add( env ) != 0 ) {
	    return( 1 );
	}
    }

    return( ret );
}


    int
env_truncate_and_unlink( struct envelope *env, SNET *snet_lock )
{
    char		efile_fname[ MAXPATHLEN + 1 ];

    if ( snet_lock != NULL ) {
	if ( ftruncate( snet_fd( snet_lock ), (off_t)0 ) == 0 ) {
	    env_unlink( env );
	    return( 0 );
	}

	sprintf( efile_fname, "%s/E%s", env->e_dir, env->e_id );
	syslog( LOG_ERR, "q_deliver ftruncate %s: %m", efile_fname );
    }

    return( env_unlink( env ));
}


    int
env_dfile_unlink( struct envelope *e )
{
    char		df[ MAXPATHLEN + 1 ];

syslog( LOG_DEBUG, "env_dfile_unlink %s ", e->e_id );

    sprintf( df, "%s/D%s", e->e_dir, e->e_id );

    if ( unlink( df ) != 0 ) {
	syslog( LOG_ERR, "env_dfile_unlink unlink %s: %m", df );
	return( -1 );
    }

    e->e_flags = ( e->e_flags & ( ~ENV_FLAG_DFILE ));

    return( 0 );
}


    /* truncate the efile before calling this function */

    int
env_unlink( struct envelope *env )
{
    char		efile_fname[ MAXPATHLEN + 1 ];

    sprintf( efile_fname, "%s/E%s", env->e_dir, env->e_id );

    if ( unlink( efile_fname ) != 0 ) {
	syslog( LOG_ERR, "env_unlink unlink %s: %m", efile_fname );
	return( -1 );
    }

    env->e_flags = ( env->e_flags & ( ~ENV_FLAG_EFILE ));

    if ( env->e_dir == simta_dir_fast ) {
	simta_fast_files--;
	syslog( LOG_DEBUG, "env_unlink %s fast_files decrement %d",
		env->e_id, simta_fast_files );
    }

    env_dfile_unlink( env );

    syslog( LOG_DEBUG, "env_unlink %s %s: unlinked", env->e_dir, env->e_id );

    return( 0 );
}


    int
env_move( struct envelope *env, char *target_dir )
{
    char                        dfile_new[ MAXPATHLEN ];
    char                        efile_new[ MAXPATHLEN ];
    char                        dfile_old[ MAXPATHLEN ];
    char                        efile_old[ MAXPATHLEN ];

    /* only move messages to slow or fast */
    assert(( target_dir == simta_dir_slow ) ||
	    ( target_dir == simta_dir_fast ));

    /* move message to target_dir if it isn't there already */
    if ( env->e_dir != target_dir ) {
	sprintf( efile_old, "%s/E%s", env->e_dir, env->e_id );
	sprintf( dfile_old, "%s/D%s", env->e_dir, env->e_id );
	sprintf( dfile_new, "%s/D%s", target_dir, env->e_id );
	sprintf( efile_new, "%s/E%s", target_dir, env->e_id );

	if ( link( dfile_old, dfile_new ) != 0 ) {
	    syslog( LOG_ERR, "env_move link %s %s: %m", dfile_old,
		    dfile_new );
	    return( -1 );
	}

	if ( link( efile_old, efile_new ) != 0 ) {
	    syslog( LOG_ERR, "env_move link %s %s: %m", efile_old,
		    efile_new );
	    if ( unlink( dfile_new ) != 0 ) {
		syslog( LOG_ERR, "env_move unlink %s: %m", dfile_new );
	    }
	    return( -1 );
	}

	if ( target_dir == simta_dir_fast ) {
	    simta_fast_files++;
	    syslog( LOG_DEBUG, "env_move %s fast_files increment %d",
		    env->e_id, simta_fast_files );
	}

	if ( env_unlink( env ) != 0 ) {
	    if ( unlink( efile_new ) != 0 ) {
		syslog( LOG_ERR, "env_move unlink %s: %m", efile_new );
	    } else {
		if ( target_dir == simta_dir_fast ) {
		    simta_fast_files--;
		    syslog( LOG_DEBUG, "env_move %s fast_files decrement %d",
			    env->e_id, simta_fast_files );
		}

		if ( unlink( dfile_new ) != 0 ) {
		    syslog( LOG_ERR, "env_move unlink %s: %m", dfile_new );
		}
	    }
	    return( -1 );
	}

	env->e_dir = target_dir;
	env->e_flags |= ENV_FLAG_EFILE;

	syslog( LOG_DEBUG, "env_move %s %s: moved", env->e_dir, env->e_id );
    }

    return( 0 );
}


    int
env_string_recipients( struct envelope *env, char *line )
{
    struct string_address		*sa;
    char				*addr;

    if (( sa = string_address_init( line )) == NULL ) {
	syslog( LOG_ERR,
		"env_string_recipients: string_address_init: malloc: %m" );
	return( 1 );
    }

    while (( addr = string_address_parse( sa )) != NULL ) {
	if ( env_recipient( env, addr ) != 0 ) {
	    string_address_free( sa );
	    return( 1 );
	}
    }

    string_address_free( sa );

    return( 0 );
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
