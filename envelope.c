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

#include <snet.h>

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "line_file.h"
#include "simta.h"


    int
env_gettimeofday_id( struct envelope *e )
{
    struct timeval		tv;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "env_gettimeofday gettimeofday: %m" );
	return( -1 );
    }

    sprintf( e->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec );

    return( 0 );
}


    struct envelope *
env_dup( struct envelope *env )
{
    struct envelope	*dup;
    struct recipient	*r;

    if (( dup = env_create( env->e_mail )) == NULL ) {
	return( NULL );
    }

    if ( env_gettimeofday_id( dup ) != 0 ) {
	env_free( dup );
	return( NULL );
    }

    dup->e_dir = env->e_dir;
    dup->e_flags = env->e_flags;

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( env_recipient( dup, r->r_rcpt ) != 0 ) {
	    env_free( dup );
	    return( NULL );
	}
    }

    return( dup );
}


    struct envelope *
env_create( char *e_mail )
{
    struct envelope	*env;

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	syslog( LOG_ERR, "env_create malloc: %m" );
	return( NULL );
    }
    memset( env, 0, sizeof( struct envelope ));

    if ( e_mail != NULL ) {
	if (( env->e_mail = strdup( e_mail )) == NULL ) {
	    syslog( LOG_ERR, "env_create strdup: %m" );
	    env_free( env );
	    return( NULL );
	}
    }

    return( env );
}


    void
rcpt_free( struct recipient *r )
{
    if ( r != NULL ) {
	if ( r->r_rcpt != NULL ) {
	    free( r->r_rcpt );
	}

	if ( r->r_err_text != NULL ) {
	    line_file_free( r->r_err_text );
	}
    }
}


    void
env_rcpt_free( struct envelope *env )
{
    struct recipient		*r;
    struct recipient		*r_next;

    r = env->e_rcpt;

    while ( r != NULL ) {
	rcpt_free( r );
	r_next = r->r_next;
	free( r );
	r = r_next;
    }

    env->e_rcpt = NULL;
}


    void
env_free( struct envelope *env )
{
    if ( env != NULL ) {
	env_rcpt_free( env );

	if ( env->e_mail != NULL ) {
	    free( env->e_mail );
	}

	if ( env->e_err_text != NULL ) {
	    line_file_free( env->e_err_text );
	}

	free( env );
    }
}


    void
env_reset( struct envelope *env )
{
    if ( env != NULL ) {
	if ( env->e_mail != NULL ) {
	    free( env->e_mail );
	    env->e_mail = NULL;
	}

	if ( env->e_helo != NULL ) {
	    free( env->e_helo );
	    env->e_helo = NULL;
	}

	if ( env->e_err_text != NULL ) {
	    line_file_free( env->e_err_text );
	    env->e_err_text = NULL;
	}

	env_rcpt_free( env );

	env->e_message = NULL;
	*env->e_id = '\0';
	env->e_flags = 0;
	env->e_failed = 0;
	env->e_tempfail = 0;
	env->e_success = 0;
	return;
    }
}


    void
env_syslog( struct envelope *e )
{
    struct recipient		*r;
    int				count = 0;

    for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	count++;
    }

    syslog( LOG_DEBUG, "message %s rcpt %d host %s",
	    e->e_id, count, e->e_expanded );
}

    void
env_stdout( struct envelope *e )
{
    struct recipient		*r;

    if ( *e->e_id == '\0' ) {
	printf( "Message-Id NULL\n" );
    } else {
	printf( "Message-Id:\t%s\n", e->e_id );
    }

    if ( *e->e_expanded == '\0' ) {
	printf( "expanded NULL\n" );
    } else {
	printf( "expanded %s\n", e->e_expanded );
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
	/* if no rcpt, simta_postmaster is default */
	if (( r->r_rcpt = strdup( simta_postmaster )) == NULL ) {
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
    r->r_err_text = NULL;

    return( 0 );
}


    /* Efile syntax:
     *
     * SIMTA_VERSION_STRING
     * Hdestination-host
     * Ffrom-addr@sender.com
     * Rto-addr@recipient.com
     * Roptional-to-addr@recipient.com
     */

    int
env_outfile( struct envelope *e, char *dir )
{
    struct stat			sb;
    int			fd;
    struct recipient	*r;
    FILE		*tff;
    char		tf[ MAXPATHLEN ];
    char		ef[ MAXPATHLEN ];

    e->e_dir = dir;

    sprintf( tf, "%s/t%s", dir, e->e_id );
    sprintf( ef, "%s/E%s", dir, e->e_id );

    /* make E (t) file */
    if (( fd = open( tf, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	syslog( LOG_ERR, "env_outfile open %s: %m", tf );
	return( -1 );
    }

    if (( tff = fdopen( fd, "w" )) == NULL ) {
	close( fd );
	syslog( LOG_ERR, "env_outfile fdopen: %m" );
	goto cleanup;
    }

    /* SIMTA_VERSION_STRING */
    if ( fprintf( tff, "%s\n", SIMTA_VERSION_STRING ) < 0 ) {
	syslog( LOG_ERR, "env_outfile fprintf: %m" );
	fclose( tff );
	goto cleanup;
    }

    /* Hdestination-host */
    if (( e->e_expanded != NULL ) && ( *e->e_expanded != '\0' ) &&
	    ( strcasecmp( dir, simta_dir_dead ) != 0 )) {
	if ( fprintf( tff, "H%s\n", e->e_expanded ) < 0 ) {
	    syslog( LOG_ERR, "env_outfile fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "H\n" ) < 0 ) {
	    syslog( LOG_ERR, "env_outfile fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* Ffrom-addr@sender.com */
    if (( e->e_mail != NULL ) && ( *e->e_mail != '\0' )) {
	if ( fprintf( tff, "F%s\n", e->e_mail ) < 0 ) {
	    syslog( LOG_ERR, "env_outfile fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}

    } else {
	/* XXX NULL From addr OK? */
	if ( fprintf( tff, "F\n" ) < 0 ) {
	    syslog( LOG_ERR, "env_outfile fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* Rto-addr@recipient.com */
    if (( e->e_rcpt != NULL ) && ( *e->e_rcpt->r_rcpt != '\0' )) {
	for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	    if ( fprintf( tff, "R%s\n", r->r_rcpt ) < 0 ) {
		syslog( LOG_ERR, "env_outfile fprintf: %m" );
		fclose( tff );
		goto cleanup;
	    }
	}

    } else {
	/* XXX is it illegal to have no recipients? */
	if ( fprintf( tff, "R\n" ) < 0 ) {
	    syslog( LOG_ERR, "env_outfile fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* get efile modification time */
    if ( fstat( fd, &sb ) != 0 ) {
	syslog( LOG_ERR, "env_outfile fstat: %m" );
	goto cleanup;
    }

    e->e_etime.tv_sec = sb.st_mtime;

    /* sync? */
    if ( fclose( tff ) != 0 ) {
	syslog( LOG_ERR, "env_outfile fclose: %m" );
	goto cleanup;
    }

    if ( rename( tf, ef ) < 0 ) {
	syslog( LOG_ERR, "env_outfile rename %s %s: %m", tf, ef );
	goto cleanup;
    }

    if (( strcasecmp( dir, simta_dir_fast )) == 0 ) {
	simta_fast_files++;
    }

    syslog( LOG_DEBUG, "env_outfile %s %s %s", dir, e->e_id, e->e_expanded );

    return( 0 );

cleanup:
    unlink( tf );

    return( -1 );
}


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


    /* struct message *m has file dir and id info for the envelope file
     *
     * char *hostname is an array of char at least MAXHOSTNAMELEN long.
     * If there is an expanded hostname in the efile, it will be written
     * to hostname.
     */

    /*
     * return 0 if everything went fine
     * return 1 on error
     */

    int
env_info( struct message *m, char *hostname, size_t len )
{
    char		*line;
    SNET		*snet;
    char		fname[ MAXPATHLEN + 1 ];
    struct stat		sb;
    int			ret = 1;

    sprintf( fname, "%s/E%s", m->m_dir, m->m_id );

    if (( snet = snet_open( fname, O_RDWR, 0, 1024 * 1024 ))
	    == NULL ) {
	syslog( LOG_ERR, "env_info snet_open: %m" );
	return( 1 );
    }

    /* test to see if env is locked by a q_runner */
    if ( lockf( snet_fd( snet ), F_TEST, 0 ) != 0 ) {
	syslog( LOG_ERR, "env_info lockf %s: %m", fname );
	goto cleanup;
    }

    if ( fstat( snet_fd( snet ), &sb ) != 0 ) {
	syslog( LOG_ERR, "env_info fstat %s: %m", fname );
	goto cleanup;
    }

    m->m_etime.tv_sec = sb.st_mtime;

    /* first line of an envelope should be version info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_info %s: unexpected EOF", fname );
	goto cleanup;
    }

    if ( strcmp( line, SIMTA_VERSION_STRING ) != 0 ) {
	syslog( LOG_ERR, "env_info %s bad version syntax", fname );
	goto cleanup;
    }

    /* second line of an envelope has expansion info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_info %s: unexpected EOF", fname );
	goto cleanup;
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "env_info %s: bad host syntax", fname );
	goto cleanup;
    }

    if ( *(line + 1 ) != '\0' ) {
	m->m_expanded = 1;
    } else {
	m->m_expanded = 0;
    }

    if (( hostname != NULL ) && ( len > 0 )) {
	strncpy( hostname, line + 1, len );
    }

    /* third line of an envelope has from info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_info %s: unexpected EOF", fname );
	goto cleanup;
    }

    if ( *line != 'F' ) {
	syslog( LOG_ERR, "env_info %s: bad from syntax", fname );
	goto cleanup;
    }

    if (( *(line + 1 ) == '\0' ) || ( strcasecmp( (line + 1),
	    simta_postmaster ) == 0 )) {
	m->m_from = 0;
    } else {
	m->m_from = 1;
    }

    ret = 0;

cleanup:
    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_ERR, "env_info snet_close: %m" );
    }

    return( ret );
}


    /* struct message *m has file info for the envelope
     *
     * struct envelope *e will have envelpe info written to it
     *
     * if s_lock != NULL, Efile will be locked and *s_lock will point
     * to it's SNET.
     */

    /* return 0 on success
     * return 1 on syntax error
     * return -1 on sys error
     * syslog errors
     */

    int
env_read( struct message *m, struct envelope *env, SNET **s_lock )
{
    char			*line;
    SNET			*snet;
    char			filename[ MAXPATHLEN + 1 ];

    memset( env, 0, sizeof( struct envelope ));

    sprintf( filename, "%s/E%s", m->m_dir, m->m_id );

    strcpy( env->e_id, m->m_id );
    env->e_dir = m->m_dir;

    if (( snet = snet_open( filename, O_RDWR, 0, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "env_read snet_open %s: %m", filename );
	return( 1 );
    }

    if ( s_lock != NULL ) {
	*s_lock = snet;

	/* lock envelope fd for delivery attempt */
	if ( lockf( snet_fd( snet ), F_TLOCK, 0 ) != 0 ) {
	    if ( errno == EAGAIN ) {
		/* file locked by a diferent process */
		if ( snet_close( snet ) < 0 ) {
		    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
		    return( -1 );
		}

		return( 1 );

	    } else {
		syslog( LOG_ERR, "env_read lockf %s: %m", filename );
		return( -1 );
	    }
	}
    }

    /* SIMTA_VERSION_STRING */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read %s unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}

	return( 1 );
    }

    if ( strcmp( line, SIMTA_VERSION_STRING ) != 0 ) {
	syslog( LOG_ERR, "env_read %s bad version syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}

	return( 1 );
    }

    /* Hdestination-host */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read %s unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "env_read %s bad host syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}

	return( 1 );
    }

    /* Ffrom-address */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "env_read %s unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'F' ) {
	syslog( LOG_ERR, "env_read %s bad from syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *(line + 1) != '\0' ) {
	if (( env->e_mail = strdup( line + 1 )) == NULL ) {
	    syslog( LOG_ERR, "env_read strdup: %m" );
	    return( -1 );
	}

    } else {
	/* XXX no from address */
    }

    /* Rto-addresses */
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( *line != 'R' ) {
	    syslog( LOG_ERR, "env_read %s bad recieved syntax", filename );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
		return( -1 );
	    }

	    /* free previously allocated recipients */
	    env_rcpt_free( env );

	    return( 1 );
	}

	if ( env_recipient( env, line + 1 ) != 0 ) {
	    return( -1 );
	}
    }

    if ( env->e_rcpt == NULL ) {
	/* XXX no recipients.  Illegal message? */
    }

    /* close snet if no need to maintain lock */
    if ( s_lock == NULL ) {
	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "env_read snet_close %s: %m", filename );
	    return( -1 );
	}
    }

    return( 0 );
}


    int
env_from( struct envelope *env )
{
    if ( env->e_mail == NULL ) {
	return( 0 );
    }

    if ( strcasecmp( env->e_mail, simta_postmaster ) == 0 ) {
	return( 0 );
    }

    return( 1 );
}


    /* truncate the efile before calling this function */

    int
env_unlink( struct envelope *env )
{
    sprintf( simta_ename, "%s/E%s", env->e_dir, env->e_id );
    sprintf( simta_dname, "%s/D%s", env->e_dir, env->e_id );

    if ( unlink( simta_ename ) != 0 ) {
	syslog( LOG_ERR, "env_unlink unlink %s: %m", simta_ename );
	return( -1 );
    }

    if ( strcmp( simta_dir_fast, env->e_dir ) == 0 ) {
	simta_fast_files--;
    }

    if ( unlink( simta_dname ) != 0 ) {
	syslog( LOG_ERR, "env_unlink unlink %s: %m", simta_dname );
    }

    syslog( LOG_DEBUG, "env_unlink %s %s: unlinked", env->e_dir, env->e_id );

    return( 0 );
}


    int
env_slow( struct envelope *env )
{
    char                        dfile_slow[ MAXPATHLEN ];
    char                        efile_slow[ MAXPATHLEN ];
    char                        dfile_fname[ MAXPATHLEN ];
    char                        efile_fname[ MAXPATHLEN ];

    /* move message to SLOW if it isn't there already */
    if ( strcasecmp( env->e_dir, simta_dir_slow ) != 0 ) {
	sprintf( efile_fname, "%s/E%s", env->e_dir, env->e_id );
	sprintf( dfile_fname, "%s/D%s", env->e_dir, env->e_id );
	sprintf( dfile_slow, "%s/D%s", simta_dir_slow, env->e_id );
	sprintf( efile_slow, "%s/E%s", simta_dir_slow, env->e_id );

	if ( link( dfile_fname, dfile_slow ) != 0 ) {
	    syslog( LOG_ERR, "env_slow link %s %s: %m", dfile_fname,
		    dfile_slow );
	    return( -1 );
	}

	if ( link( efile_fname, efile_slow ) != 0 ) {
	    syslog( LOG_ERR, "env_slow link %s %s: %m", efile_fname,
		    efile_slow );
	    return( -1 );
	}

	if ( env_unlink( env ) != 0 ) {
	    return( -1 );
	}

	syslog( LOG_DEBUG, "env_slow %s %s: moved", env->e_dir, env->e_id );
    }

    return( 0 );
}
