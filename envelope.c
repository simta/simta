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

#include <assert.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <utime.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "line_file.h"
#include "header.h"
#include "simta.h"


    int
env_id( struct envelope *e )
{
    struct timeval		tv;
    int				pid;
    /* way bigger than we should ever need */
    char			buf[ 1024 ];

    assert( e->e_id == NULL );

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "env_id gettimeofday: %m" );
	return( -1 );
    }

    if (( pid = getpid()) < 0 ) {
	syslog( LOG_ERR, "env_id getpid: %m" );
	return( -1 );
    }

    snprintf( buf, 1023, "%lX.%lX.%d", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec, pid );

    if (( e->e_id = strdup( buf )) == NULL ) {
	syslog( LOG_ERR, "env_id strdup: %m" );
	return( -1 );
    }

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

	if ( gettimeofday( &tv_now, NULL ) != 0 ) {
	    syslog( LOG_ERR, "env_is_old gettimeofday: %m" );
	    return( 0 );
	}

	if (( tv_now.tv_sec - sb.st_mtime ) > ( simta_bounce_seconds )) {
	    env->e_age = ENV_AGE_OLD;
	} else {
	    env->e_age = ENV_AGE_NOT_OLD;
	}
    }

    if ( env->e_age == ENV_AGE_OLD ) {
	return( 1 );
    }

    return( 0 );
}


    int
env_set_id( struct envelope *e, char *id )
{
    if (( id == NULL ) || ( *id == '\0' )) {
	syslog( LOG_ERR, "env_set_id: must have valid ID" );
	return( 1 );
    }

    if (( e->e_id = strdup( id )) == NULL ) {
	syslog( LOG_ERR, "env_set_id malloc: %m" );
	return( 1 );
    }

    return( 0 );
}


    struct envelope *
env_dup( struct envelope *env )
{
    struct envelope	*dup;
    struct recipient	*r;

    if (( dup = env_create( env->e_mail, NULL )) == NULL ) {
	return( NULL );
    }

    if ( env_id( dup ) != 0 ) {
	env_free( dup );
	return( NULL );
    }

    dup->e_dir = env->e_dir;
    dup->e_flags = env->e_flags;
    dup->e_n_exp_level = env->e_n_exp_level;

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( env_recipient( dup, r->r_rcpt ) != 0 ) {
	    env_free( dup );
	    return( NULL );
	}
    }

    return( dup );
}


    struct envelope *
env_create( char *e_mail, struct envelope *parent )
{
    struct envelope	*env;

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	syslog( LOG_ERR, "env_create malloc: %m" );
	return( NULL );
    }
    memset( env, 0, sizeof( struct envelope ));

    if ( e_mail != NULL ) {
	if ( env_sender( env, e_mail ) != 0 ) {
	    env_free( env );
	    return( NULL );
	}
    }

    if ( parent ) {
	env->e_n_exp_level = parent->e_n_exp_level + 1;
    }

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
	syslog( LOG_ERR, "env_hostname: %s already has a hostname", env->e_id );
	return( 1 );
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

    if ( e_mail == NULL ) {
	e_mail = "";
    }
    
    if (( env->e_mail = strdup( e_mail )) == NULL ) {
	syslog( LOG_ERR, "env_sender strdup: %m" );
	return( 1 );
    }

    return( 0 );
}


    void
env_reset( struct envelope *env )
{
    if ( env != NULL ) {
	if ( env->e_list_prev == NULL ) {
	    if ( simta_env_queue == env ) {
		simta_env_queue = env->e_list_next;
	    }
	} else {
	    env->e_list_prev->e_list_next = env->e_list_next;
	}

	if ( env->e_list_next != NULL ) {
	    env->e_list_next->e_list_prev = env->e_list_prev;
	}

	env->e_list_next = NULL;
	env->e_list_prev = NULL;

	if ( env->e_mail != NULL ) {
	    free( env->e_mail );
	    env->e_mail = NULL;
	}

	if ( env->e_hostname != NULL ) {
	    free( env->e_hostname );
	    env->e_hostname = NULL;
	}

	if ( env->e_id != NULL ) {
	    free( env->e_id );
	    env->e_id = NULL;
	}

	env_rcpt_free( env );

	env_clear_errors( env );

	env->e_flags = 0;
	return;
    }
}


    void
env_free( struct envelope *env )
{
    if ( env != NULL ) {
	env_reset( env );
	memset( env, 0, sizeof( struct envelope ));
	free( env );
    }
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


    /* Efile syntax:
     *
     * VSIMTA_EFILE_VERSION
     * Emessage-id
     * Idinode
     * Xpansion Level
     * Hdestination-host
     * Ffrom-addr@sender.com
     * Rto-addr@recipient.com
     * Roptional-to-addr@recipient.com
     */

    int
env_outfile( struct envelope *e )
{
    if ( env_tfile( e ) != 0 ) {
	return( 1 );
    }

    if ( env_efile( e ) != 0 ) {
	return( 1 );
    }

    return( 0 );
}


    int
env_tfile_unlink( struct envelope *e )
{
    char		tf[ MAXPATHLEN + 1 ];

    sprintf( tf, "%s/t%s", e->e_dir, e->e_id );

    if ( unlink( tf ) != 0 ) {
	syslog( LOG_ERR, "env_tfile_unlink unlink %s: %m", tf );
	return( -1 );
    }

    return( 0 );
}


    int
env_tfile( struct envelope *e )
{
    struct stat			sb;
    int			fd;
    struct recipient	*r;
    FILE		*tff;
    char		tf[ MAXPATHLEN + 1 ];

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
    if ( fprintf( tff, "V%d\n", SIMTA_EFILE_VERSION ) < 0 ) {
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

    syslog( LOG_DEBUG, "env_read_queue_info %s: Dinode %d",
	    e->e_id, e->e_dinode );

    /* Xpansion Level */
    if ( fprintf( tff, "X%d\n", e->e_n_exp_level ) < 0 ) {
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

    /* get tfile modification time */
    if ( fstat( fd, &sb ) != 0 ) {
	syslog( LOG_ERR, "env_tfile fstat: %m" );
	goto cleanup;
    }

    e->e_etime.tv_sec = sb.st_mtime;

    if ( fclose( tff ) != 0 ) {
	syslog( LOG_ERR, "env_tfile fclose: %m" );
	unlink( tf );
	return( -1 );
    }

    return( 0 );

cleanup:
    fclose( tff );
    unlink( tf );
    return( -1 );
}


    int
env_efile( struct envelope *e )
{
    char		tf[ MAXPATHLEN + 1 ];
    char		ef[ MAXPATHLEN + 1 ];

    sprintf( tf, "%s/t%s", e->e_dir, e->e_id );
    sprintf( ef, "%s/E%s", e->e_dir, e->e_id );

    if ( rename( tf, ef ) < 0 ) {
	syslog( LOG_ERR, "env_efile rename %s %s: %m", tf, ef );
	unlink( tf );
	return( -1 );
    }

    if ( e->e_dir == simta_dir_fast ) {
	simta_fast_files++;
    }

    syslog( LOG_DEBUG, "env_efile %s %s %s", e->e_dir, e->e_id,
	    e->e_hostname ? e->e_hostname : "" );

    e->e_flags |= ENV_FLAG_ON_DISK;

    if ( simta_no_sync == 0 ) {
	sync();
    }

    return( 0 );
}


    /* calling this function updates the attempt time */

    int
env_touch( struct envelope *env )
{
    char			fname[ MAXPATHLEN ];
    struct stat			sb;

    sprintf( fname, "%s/E%s", env->e_dir, env->e_id );

    if ( utime( fname, NULL ) != 0 ) {
	syslog( LOG_ERR, "env_touch utime %s: %m", fname );
	return( -1 );
    }

    if ( stat( fname, &sb ) != 0 ) {
	syslog( LOG_ERR, "env_touch stat %s: %m", fname );
	return( -1 );
    }

    env->e_etime.tv_sec = sb.st_mtime;

    return( 0 );
}


    int
env_read_queue_info( struct envelope *e )
{
    char		*line;
    char		*hostname;
    SNET		*snet;
    char		fname[ MAXPATHLEN + 1 ];
    struct stat		sb;
    int			ret = 1;
    int			version;

    sprintf( fname, "%s/E%s", e->e_dir, e->e_id );

    if (( snet = snet_open( fname, O_RDWR, 0, 1024 * 1024 ))
	    == NULL ) {
	syslog( LOG_ERR, "env_read_queue_info snet_open %s: %m", fname );
	return( 1 );
    }

    /* test to see if env is locked by a q_runner */
    if ( lockf( snet_fd( snet ), F_TEST, 0 ) != 0 ) {
	syslog( LOG_ERR, "env_read_queue_info lockf %s: %m", fname );
	goto cleanup;
    }

    if ( fstat( snet_fd( snet ), &sb ) != 0 ) {
	syslog( LOG_ERR, "env_read_queue_info fstat %s: %m", fname );
	goto cleanup;
    }

    e->e_etime.tv_sec = sb.st_mtime;

    /* Vsimta-version */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_queue_info %s: unexpected EOF", fname );
	goto cleanup;
    }
    if ( *line != 'V' ) {
	syslog( LOG_ERR, "env_read_queue_info %s bad version syntax", fname );
	goto cleanup;
    }
    /* code to deal with v0.1 type version numbers.
     * version 2 and beyond use integer as version not floats.
     */
#ifdef SIMTA_OLD_EFILE_VERSION_1
    if ( strcmp( line + 1, "0.1" ) == 0 ) {
	version = 1;
    } else {
#endif /* SIMTA_OLD_EFILE_VERSION_1 */
	if ( sscanf( line + 1, "%d", &version ) != 1 ) {
	    syslog( LOG_ERR, "env_read_queue_info: %s: bad version syntax",
		fname );
	    goto cleanup;
	}
#ifdef SIMTA_OLD_EFILE_VERSION_1
    }
#endif /* SIMTA_OLD_EFILE_VERSION_1 */
    if (( version > SIMTA_EFILE_VERSION ) || ( version < 1 )) {
	syslog( LOG_ERR, "env_read_queue_info: %s: unsupported version",
	    fname );
	goto cleanup;
    }

    if ( version >= 2 ) {
	/* Emessage-id */
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR, "env_read_queue_info %s: unexpected EOF", fname );
	    goto cleanup;
	}
	if ( *line != 'E' ) {
	    syslog( LOG_ERR, "env_read_queue_info %s: bad Emessage-id syntax",
		fname );
	    goto cleanup;
	}
	if ( strcmp( line + 1, e->e_id ) != 0 ) {
	    syslog( LOG_ERR, "env_read_queue_info %s: message-id mismatch",
		fname );
	    goto cleanup;
	}
    }

    /* Dinode info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_queue_info %s: unexpected EOF", fname );
	goto cleanup;
    }

    if ( *line != 'I' ) {
	syslog( LOG_ERR, "env_read_queue_info %s: bad Dinode syntax", fname );
	goto cleanup;
    }

    sscanf( line + 1, "%lu", &(e->e_dinode));
    if ( e->e_dinode == 0 ) {
	syslog( LOG_ERR, "env_read_queue_info %s: bad Dinode info", fname );
	goto cleanup;
    }

    /* expansion info */
    if ( version >= 3 ) {
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR, "env_read_queue_info %s: unexpected EOF", fname );
	    goto cleanup;
	}

	if ( *line != 'X' ) {
	    syslog( LOG_ERR, "env_read_queue_info %s: bad Xpansion syntax",
		    fname );
	    goto cleanup;
	}

	if ( sscanf( line + 1, "%d", &(e->e_n_exp_level)) != 1 ) {
	    syslog( LOG_ERR, "env_read_queue_info: %s: bad Xpansion syntax",
		fname );
	    goto cleanup;
	}
    }

    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_queue_info %s: unexpected EOF", fname );
	goto cleanup;
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "env_read_queue_info %s: bad host syntax", fname );
	goto cleanup;
    }

    hostname = line + 1;

    if ( env_hostname( e, hostname ) != 0 ) {
	goto cleanup;
    }

    /* Ffrom-address */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_queue_info %s unexpected EOF", fname );
	goto cleanup;
    }

    if ( *line != 'F' ) {
	syslog( LOG_ERR, "env_read_queue_info %s bad from syntax",
		fname );
	goto cleanup;
    }

    if ( env_sender( e, line + 1 ) != 0 ) {
	goto cleanup;
    }

    ret = 0;

cleanup:
    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_ERR, "env_read_queue_info snet_close: %m" );
    }

    return( ret );
}


    int
env_read_delivery_info( struct envelope *env, SNET **s_lock )
{
    char			*line;
    SNET			*snet;
    char			filename[ MAXPATHLEN + 1 ];
    char			*hostname;
    int				ret = 1;
    ino_t			dinode;
    int				version;
    int				exp_level;

    sprintf( filename, "%s/E%s", env->e_dir, env->e_id );

    if (( snet = snet_open( filename, O_RDWR, 0, 1024 * 1024 )) == NULL ) {
	if ( errno != ENOENT ) {
	    syslog( LOG_ERR,
		    "env_read_delivery_info snet_open %s: %m", filename );
	}
	return( 1 );
    }

    if ( s_lock != NULL ) {
	*s_lock = snet;

	/* lock envelope fd for delivery attempt */
	if ( lockf( snet_fd( snet ), F_TLOCK, 0 ) != 0 ) {
	    if ( errno != EAGAIN ) {
		/* file not locked by a diferent process */
		syslog( LOG_ERR, "env_read_delivery_info lockf %s: %m",
			filename );
	    }
	    goto cleanup;
	}
    }

    /* Vsimta-version */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: unexpected EOF",
		filename );
	goto cleanup;
    }
    if ( *line != 'V' ) {
	syslog( LOG_ERR, "env_read_delivery_info %s bad version syntax",
	    filename );
	goto cleanup;
    }
    /* code to deal with v0.1 type version numbers.
     * version 2 and beyond use integer as version not floats.
     */
#ifdef SIMTA_OLD_EFILE_VERSION_1
    if ( strcmp( line + 1, "0.1" ) == 0 ) {
	version = 1;
    } else {
#endif /* SIMTA_OLD_EFILE_VERSION_1 */
	if ( sscanf( line + 1, "%d", &version ) != 1 ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: bad version syntax",
		filename );
	    goto cleanup;
	}
#ifdef SIMTA_OLD_EFILE_VERSION_1
    }
#endif /* SIMTA_OLD_EFILE_VERSION_1 */
    if ( version > SIMTA_EFILE_VERSION ) {
	syslog( LOG_ERR, "env_read_delivery_info: %s: unsupported version",
	    filename );
	goto cleanup;
    }

    if ( version >= 2 ) {
	/* Emessage-id */
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: unexpected EOF",
		filename );
	    goto cleanup;
	}
	if ( *line != 'E' ) {
	    syslog( LOG_ERR,
		"env_read_delivery_info %s: bad Emessage-id syntax", filename );
	    goto cleanup;
	}
	if ( strcmp( line + 1, env->e_id ) != 0 ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: message-id mismatch",
		filename );
	    goto cleanup;
	}
    }

    /* Dinode info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: unexpected EOF",
		filename );
	goto cleanup;
    }

    if ( *line != 'I' ) {
	syslog( LOG_ERR, "env_read_delivery_info %s bad Dinode syntax",
		filename );
	goto cleanup;
    }

    sscanf( line + 1, "%lu", &dinode );
    if ( dinode == 0 ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: bad Dinode info",
	    filename );
	goto cleanup;
    } else if ( dinode != env->e_dinode ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: bad Dinode info re-read: "
		"old %d new %d", filename, env->e_dinode, dinode );
	goto cleanup;
    }

    syslog( LOG_DEBUG, "env_read_queue_info %s: Dinode %d", env->e_id,
	    env->e_dinode );

    /* expansion info */
    if ( version >= 3 ) {
	if (( line = snet_getline( snet, NULL )) == NULL ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: unexpected EOF",
		    filename );
	    goto cleanup;
	}

	if ( *line != 'X' ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: bad Xpansion syntax",
		    filename );
	    goto cleanup;
	}

	if ( sscanf( line + 1, "%d", &exp_level) != 1 ) {
	    syslog( LOG_ERR, "env_read_delivery_info: %s: bad Xpansion syntax",
		filename );
	    goto cleanup;
	}

	if ( exp_level != env->e_n_exp_level ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: Xpansion mismatch",
		filename );
	    goto cleanup;
	}
    }

    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: unexpected EOF",
	    filename );
	goto cleanup;
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: bad host syntax",
	    filename );
	goto cleanup;
    }

    hostname = line + 1;

    if ( env->e_hostname == NULL ) {
	if ( *hostname != '\0' ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: bad hostname re-read",
		    filename );
	    goto cleanup;
	}
    } else {
	if ( strcmp( hostname, env->e_hostname ) != 0 ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s: bad hostname re-read",
		    filename );
	    goto cleanup;
	}
    }

    /* Ffrom-address */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read_delivery_info %s unexpected EOF", filename );
	goto cleanup;
    }

    if ( *line != 'F' ) {
	syslog( LOG_ERR, "env_read_delivery_info %s bad from syntax",
		filename );
	goto cleanup;
    }

    if ( strcmp( env->e_mail, line + 1 ) != 0 ) {
	syslog( LOG_ERR, "env_read_delivery_info %s: bad sender re-read",
		filename );
	goto cleanup;
    }

    /* Rto-addresses */
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( *line != 'R' ) {
	    syslog( LOG_ERR, "env_read_delivery_info %s bad recieved syntax",
		    filename );
	    goto cleanup;
	}

	if ( env_recipient( env, line + 1 ) != 0 ) {
	    return( -1 );
	}
    }

    if ( env->e_rcpt == NULL ) {
	syslog( LOG_ERR, "env_read_delivery_info %s no recipients", filename );
	goto cleanup;
    }

    ret = 0;

    /* close snet if no need to maintain lock */
    if ( s_lock == NULL ) {
cleanup:
	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read_delivery_info snet_close %s: %m",
		    filename );
	    ret = 1;
	}
    }

    return( ret);
}


    int
env_from( struct envelope *env )
{
    if ( env->e_mail == NULL ) {
	return( 0 );
    }

    return( 1 );
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


    /* truncate the efile before calling this function */

    int
env_unlink( struct envelope *env )
{
    char		efile_fname[ MAXPATHLEN + 1 ];
    char		dfile_fname[ MAXPATHLEN + 1 ];

    sprintf( efile_fname, "%s/E%s", env->e_dir, env->e_id );
    sprintf( dfile_fname, "%s/D%s", env->e_dir, env->e_id );

    if ( unlink( efile_fname ) != 0 ) {
	syslog( LOG_ERR, "env_unlink unlink %s: %m", efile_fname );
	return( -1 );
    }

    env->e_flags = ( env->e_flags & ( ~ENV_FLAG_ON_DISK ));

    if ( env->e_dir == simta_dir_fast ) {
	simta_fast_files--;
    }

    if ( unlink( dfile_fname ) != 0 ) {
	syslog( LOG_ERR, "env_unlink unlink %s: %m", dfile_fname );
    }

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
	}


	if ( env_unlink( env ) != 0 ) {
	    if ( unlink( efile_new ) != 0 ) {
		syslog( LOG_ERR, "env_move unlink %s: %m", efile_new );
	    } else {
		if ( target_dir == simta_dir_fast ) {
		    simta_fast_files--;
		}

		if ( unlink( dfile_new ) != 0 ) {
		    syslog( LOG_ERR, "env_move unlink %s: %m", dfile_new );
		}
	    }
	    return( -1 );
	}

	env->e_dir = target_dir;

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
