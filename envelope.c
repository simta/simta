/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

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

#include "simta.h"
#include "queue.h"
#include "envelope.h"
#include "line_file.h"


    int
env_gettimeofday_id( struct envelope *e )
{
    struct timeval		tv;

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "gettimeofday: %m" );
	return( -1 );
    }

    sprintf( e->e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec );

    return( 0 );
}


    struct envelope *
env_create( char *id )
{
    struct envelope	*env;
    static char		localhostname[ MAXHOSTNAMELEN ] = "\0";

    /* XXX divine local host name with gethostname */
    if ( *localhostname == '\0' ) {
	if ( gethostname( localhostname, MAXHOSTNAMELEN ) != 0 ) {
	    syslog( LOG_ERR, "gethostname: %m" );
	    return( NULL );
	}
    }

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	syslog( LOG_ERR, "malloc: %m" );
	return( NULL );
    }
    memset( env, 0, sizeof( struct envelope ));

    /* XXX overflow */
    if ( id != NULL ) {
	strcpy( env->e_id, id );
    } else {
	*env->e_id = '\0';
    }

    env->e_hostname = localhostname;

    env->e_sin = NULL;
    env->e_helo = NULL;
    env->e_mail = NULL;
    env->e_rcpt = NULL;
    env->e_flags = 0;

    return( env );
}


    void
rcpt_free( struct recipient *r )
{
    if ( r != NULL ) {
	rcpt_free( r->r_next );
	free( r->r_rcpt );
	line_file_free( r->r_text );
	free( r );
    }
}


    void
env_free( struct envelope *env )
{
    rcpt_free( env->e_rcpt );
    free( env );
}


    void
env_reset( struct envelope *env )
{
    struct recipient	*r, *rnext;

    if ( env->e_mail != NULL ) {
	free( env->e_mail );
	env->e_mail = NULL;
    }

    if ( env->e_rcpt != NULL ) {
	for ( r = env->e_rcpt; r != NULL; r = rnext ) {
	    rnext = r->r_next;
	    free( r->r_rcpt );
	    free( r );
	}
	env->e_rcpt = NULL;
    }

    *env->e_id = '\0';
    env->e_flags = 0;
    return;
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

    if ( *e->e_hostname == '\0' ) {
	printf( "hostname NULL\n" );
    } else {
	printf( "hostname %s\n", e->e_hostname );
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
	syslog( LOG_ERR, "malloc: %m" );
	return( -1 );
    }
    memset( r, 0, sizeof( struct recipient ));

    if (( r->r_rcpt = strdup( addr )) == NULL ) {
	syslog( LOG_ERR, "strdup: %m" );
	return( -1 );
    }

    r->r_next = e->e_rcpt;
    e->e_rcpt = r;

    return( 0 );
}


    int
env_fstat( struct envelope *e, int fd )
{
    struct stat			sb;

    if ( fstat( fd, &sb ) != 0 ) {
	syslog( LOG_ERR, "fstat: %m" );
	return( -1 );
    }

    e->e_etime.tv_sec = sb.st_mtime;

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

     /* call env_create( id ) before this function */

     /* return 0 on success
      * return 1 on syntax error
      * return -1 on sys error
      * syslog errors
      */

    int
env_infile( struct envelope *e, char *dir )
{
    char			*line;
    SNET			*snet;
    char			filename[ MAXPATHLEN ];

    sprintf( filename, "%s/E%s", dir, e->e_id );

    e->e_dir = dir;

    if (( snet = snet_open( filename, O_RDONLY, 0, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_open %s: %m", filename );
	return( 1 );
    }

    /* get efile modification time */
    if ( env_fstat( e, snet_fd( snet )) != 0 ) {
	return( -1 );
    }

    /* SIMTA_VERSION_STRING */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( strcmp( line, SIMTA_VERSION_STRING ) != 0 ) {
	syslog( LOG_ERR, "%s bad version syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    /*** Hdestination-host ***/
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", filename, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "%s: bad host syntax", filename, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *(line + 1) != '\0' ) {
	strcpy( e->e_expanded, line + 1 );
    }

    /*** Ffrom-address ***/
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", filename, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'F' ) {
	syslog( LOG_ERR, "%s: bad from syntax", filename, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *(line + 1) != '\0' ) {
	if (( e->e_mail = strdup( line + 1 )) == NULL ) {
	    syslog( LOG_ERR, "strdup: %m" );
	    return( -1 );
	}
    }

    /* XXX require 1 to-address? */
    /*** Rto-addresses ***/
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( *line != 'R' ) {
	    syslog( LOG_ERR, "%s: bad recipient syntax", filename, line );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( -1 );
	    }

	    return( 1 );
	}

	if ( env_recipient( e, line + 1 ) != 0 ) {
	    return( -1 );
	}
    }

    if ( snet_close( snet ) < 0 ) {
	syslog( LOG_ERR, "snet_close: %m" );
	return( -1 );
    }

    return( 0 );
}


    /* remove any recipients that don't need to be tried later */

    void
env_cleanup( struct envelope *e )
{
    struct recipient	**r;
    struct recipient	*remove;

    r = &(e->e_rcpt);

    while ( *r != NULL ) {
	if ((*r)->r_delivered != R_TEMPFAIL ) {
	    remove = *r;
	    *r = (*r)->r_next;
	    free( remove->r_rcpt );
	    free( remove );
	} else {
	    r = &((*r)->r_next);
	}
    }
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
	syslog( LOG_ERR, "open %s: %m", tf );
	return( -1 );
    }

    if (( tff = fdopen( fd, "w" )) == NULL ) {
	close( fd );
	syslog( LOG_ERR, "fdopen: %m" );
	goto cleanup;
    }

    /* SIMTA_VERSION_STRING */
    if ( fprintf( tff, "%s\n", SIMTA_VERSION_STRING ) < 0 ) {
	syslog( LOG_ERR, "fprintf: %m" );
	fclose( tff );
	goto cleanup;
    }

    /* Hdestination-host */
    if (( e->e_expanded != NULL ) && ( *e->e_expanded != '\0' )) {
	if ( fprintf( tff, "H%s\n", e->e_expanded ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "H\n" ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* Ffrom-addr@sender.com */
    if (( e->e_mail != NULL ) && ( *e->e_mail != '\0' )) {
	if ( fprintf( tff, "F%s\n", e->e_mail ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "F\n" ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* Rto-addr@recipient.com */
    /* XXX is it illegal to have no recipients? */
    if (( e->e_rcpt != NULL ) && ( *e->e_rcpt->r_rcpt != '\0' )) {
	for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	    if ( fprintf( tff, "R%s\n", r->r_rcpt ) < 0 ) {
		syslog( LOG_ERR, "fprintf: %m" );
		fclose( tff );
		goto cleanup;
	    }
	}

    } else {
	if ( fprintf( tff, "R\n" ) < 0 ) {
	    syslog( LOG_ERR, "fprintf: %m" );
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* get efile modification time */
    if ( env_fstat( e, fd ) != 0 ) {
	goto cleanup;
    }

    if ( fclose( tff ) != 0 ) {
	syslog( LOG_ERR, "fclose: %m" );
	goto cleanup;
    }

    if ( rename( tf, ef ) < 0 ) {
	syslog( LOG_ERR, "rename %s %s: %m", tf, ef );
	goto cleanup;
    }

    return( 0 );

cleanup:
    unlink( tf );

    return( -1 );
}


    /*
     * return 0 if everything went fine
     * return -1 on syscall error
     * return 1 on syntax error
     *
     * unexpanded = 0 if envelope is expanded
     * unexpanded = 1 if envelope is not expanded
     * unexpanded = -1 on error
     */

    int
/* XXX not vetted */
env_unexpanded( char *fname, int *unexpanded )
{
    char		*line;
    SNET		*snet;

    *unexpanded = -1;

    if (( snet = snet_open( fname, O_RDONLY, 0, 1024 * 1024 ))
	    == NULL ) {
	syslog( LOG_ERR, "snet_open: %m" );
	return( -1 );
    }

    /* first line of an envelope should be version info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", fname, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    /* XXX Version check? */

    /* second line of an envelope has expansion info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", fname, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'H' ) {
	return( 1 );
    }

    /* check to see if envelope has been expanded */
    if ( *(line + 1) == '\0' ) {
	*unexpanded = 1;
    } else {
	*unexpanded = 0;
    }

    if ( snet_close( snet ) != 0 ) {
	*unexpanded = -1;
	syslog( LOG_ERR, "snet_close: %m" );
	return( -1 );
    }

    return( 0 );
}


    int
env_unlink( struct envelope *env )
{
    char			fname[ MAXPATHLEN ];

    sprintf( fname, "%s/E%s", env->e_dir, env->e_id );

    /* XXX truncate */

    if ( unlink( fname ) != 0 ) {
	syslog( LOG_ERR, "unlink %s: %m", fname );
	return( -1 );
    }

    env_free( env );

    return( 0 );
}


    int
env_touch( struct envelope *env )
{
    char			fname[ MAXPATHLEN ];
    struct stat			sb;

    sprintf( fname, "%s/E%s", env->e_dir, env->e_id );

    if ( utime( fname, NULL ) != 0 ) {
	syslog( LOG_ERR, "utime %s: %m", fname );
	return( -1 );
    }

    if ( stat( fname, &sb ) != 0 ) {
	syslog( LOG_ERR, "stat %s: %m", fname );
	return( -1 );
    }

    env->e_etime.tv_sec = sb.st_mtime;

    return( 0 );
}


    /*
     * return 0 if everything went fine
     * return -1 on syscall error
     * return 1 on syntax error
     */

    int
env_info( struct message *m, char *hostname )
{
    char		*line;
    SNET		*snet;
    char		fname[ MAXPATHLEN + 1 ];
    struct stat		sb;

    *hostname = '\0';

    sprintf( fname, "%s/E%s", m->m_dir, m->m_id );

    if (( snet = snet_open( fname, O_RDONLY, 0, 1024 * 1024 ))
	    == NULL ) {
	syslog( LOG_ERR, "snet_open: %m" );
	return( -1 );
    }

    if ( fstat( snet_fd( snet ), &sb ) != 0 ) {
	syslog( LOG_ERR, "fstat %s: %m", fname );
	return( -1 );
    }

    m->m_etime.tv_sec = sb.st_mtime;

    /* first line of an envelope should be version info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", fname, line );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( strcmp( line, SIMTA_VERSION_STRING ) != 0 ) {
	syslog( LOG_ERR, "%s bad version syntax", fname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    /* second line of an envelope has expansion info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s: unexpected EOF", fname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "%s: bad host syntax", fname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( strlen( line + 1 ) > MAXHOSTNAMELEN ) {
	syslog( LOG_ERR, "%s hostname too long", fname );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    strcpy( hostname, line + 1 );

    if ( snet_close( snet ) != 0 ) {
	syslog( LOG_ERR, "snet_close: %m" );
	return( -1 );
    }

    return( 0 );
}



    int
env_lock( struct message *m, struct envelope *env, SNET **s )
{
    char			*line;
    SNET			*snet;
    char			filename[ MAXPATHLEN + 1 ];

    memset( env, 0, sizeof( struct envelope ));

    sprintf( filename, "%s/E%s", m->m_dir, m->m_id );

    if (( snet = snet_open( filename, O_RDONLY, 0, 1024 * 1024 )) == NULL ) {
	syslog( LOG_ERR, "snet_open %s: %m", filename );
	return( 1 );
    }

    *s = snet;

    /* lock envelope fd for delivery attempt */
    if ( lockf( snet_fd( snet ), F_TLOCK, 0 ) != 0 ) {
	if ( errno == EAGAIN ) {
	    /* file locked by a diferent process */
	    return( 1 );

	} else {
	    syslog( LOG_ERR, "lockf %s: %m", filename );
	    return( -1 );
	}
    }

    /* SIMTA_VERSION_STRING */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( strcmp( line, SIMTA_VERSION_STRING ) != 0 ) {
	syslog( LOG_ERR, "%s bad version syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    /* Hdestination-host */
    /* XXX already have destination host, check that it hasn't changed? */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'H' ) {
	syslog( LOG_ERR, "%s bad host syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    /* Ffrom-address */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	syslog( LOG_ERR, "%s unexpected EOF", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *line != 'F' ) {
	syslog( LOG_ERR, "%s bad from syntax", filename );

	if ( snet_close( snet ) < 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    return( -1 );
	}

	return( 1 );
    }

    if ( *(line + 1) != '\0' ) {
	if (( env->e_mail = strdup( line + 1 )) == NULL ) {
	    syslog( LOG_ERR, "strdup: %m" );
	    return( -1 );
	}
    }

    /* Rto-addresses */
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( *line != 'R' ) {
	    syslog( LOG_ERR, "%s bad recieved syntax", filename );

	    if ( snet_close( snet ) < 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		return( -1 );
	    }

	    /* XXX free previously allocated recipients */

	    return( 1 );
	}

	if ( env_recipient( env, line + 1 ) != 0 ) {
	    return( -1 );
	}
    }

    /* close snet after deliver attempt to maintain lock */

    return( 0 );
}
