/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sysexits.h>

#include <snet.h>

#include "envelope.h"

    struct envelope *
env_create( char *id )
{
    struct envelope	*env;

    if (( env = (struct envelope *)malloc( sizeof( struct envelope ))) ==
	    NULL ) {
	return( NULL );
    }
    memset( env, 0, sizeof( struct envelope ));

    /* XXX overflow */
    if ( id != NULL ) {
	strcpy( env->e_id, id );
    } else {
	*env->e_id = '\0';
    }

    env->e_sin = NULL;
    *env->e_hostname = '\0';
    env->e_helo = NULL;
    env->e_mail = NULL;
    env->e_rcpt = NULL;
    env->e_flags = 0;

    return( env );
}


    void
rcpt_free( struct recipient *r ) {
    rcpt_free( r->r_next );
    free( r->r_rcpt );
    free( r );
}


    void
env_free ( struct envelope *env )
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
	return( -1 );
    }
    memset( r, 0, sizeof( struct recipient ));

    if (( r->r_rcpt = strdup( addr )) == NULL ) {
	return( -1 );
    }

    r->r_next = e->e_rcpt;
    e->e_rcpt = r;

    return( 0 );
}


    /* Efile syntax:
     *
     * Vversion
     * Hdestination-host
     * Ffrom-addr@sender.com
     * Rto-addr@recipient.com
     * Roptional-to-addr@recipient.com
     */

     /* return 0 on success
      * return 1 on syntax error
      * return -1 on sys error
      */

    int
env_infile( struct envelope *e, char *filename )
{
    char			*line;
    SNET			*snet;

    if (( snet = snet_open( filename, O_RDONLY, 0, 1024 * 1024 )) == NULL ) {
	return( -1 );
    }

    /*** Vversion ***/
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	return( 1 );
    }

    /* XXX better version checking */
    if ( *line != 'V' ) {
	return( 1 );
    }

    /*** Hdestination-host ***/
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	return( 1 );
    }

    if ( *line != 'H' ) {
	return( 1 );
    }

    if ( *(line + 1) != '\0' ) {
	strcpy( e->e_expanded, line + 1 );
    }

    /*** Ffrom-address ***/
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	return( 1 );
    }

    if ( *line != 'F' ) {
	return( 1 );
    }

    if ( *(line + 1) != '\0' ) {
	if (( e->e_mail = strdup( line + 1 )) == NULL ) {
	    return( -1 );
	}
    }

    /* XXX require 1 to-address? */
    /*** Rto-addresses ***/
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	if ( *line != 'R' ) {
	    return( 1 );
	}

	if ( env_recipient( e, line + 1 ) != 0 ) {
	    return( -1 );
	}
    }

    if ( snet_close( snet ) < 0 ) {
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
	if ((*r)->r_exit != EX_TEMPFAIL ) {
	    remove = *r;
	    *r = (*r)->r_next;
	    free( remove->r_rcpt );
	    free( remove );
	} else {
	    r = &((*r)->r_next);
	}
    }
}


    struct recipient	*r;

    /* Efile syntax:
     *
     * Vversion
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

    sprintf( tf, "%s/t%s", dir, e->e_id );
    sprintf( ef, "%s/E%s", dir, e->e_id );

    /* make E (t) file */
    if (( fd = open( tf, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
	return( 1 );
    }

    if (( tff = fdopen( fd, "w" )) == NULL ) {
	close( fd );
	goto cleanup;
    }

    /* Vversion */
    /* XXX better version info needed */
    if ( fprintf( tff, "V0\n" ) < 0 ) {
	fclose( tff );
	goto cleanup;
    }

    /* Hdestination-host */
    if (( e->e_expanded != NULL ) && ( *e->e_expanded != '\0' )) {
	if ( fprintf( tff, "H%s\n", e->e_expanded ) < 0 ) {
	    fclose( tff );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "H\n" ) < 0 ) {
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* Ffrom-addr@sender.com */
    /* XXX can e->e_mail be NULL? */
    if (( e->e_mail != NULL ) && ( *e->e_mail != '\0' )) {
	if ( fprintf( tff, "F%s\n", e->e_mail ) < 0 ) {
	    fclose( tff );
	    goto cleanup;
	}

    } else {
	if ( fprintf( tff, "F\n" ) < 0 ) {
	    fclose( tff );
	    goto cleanup;
	}
    }

    /* Rto-addr@recipient.com */
    /* XXX is it illegal to have no recipients? */
    if (( e->e_rcpt != NULL ) && ( *e->e_rcpt->r_rcpt != '\0' )) {
	for ( r = e->e_rcpt; r != NULL; r = r->r_next ) {
	    if ( fprintf( tff, "R%s\n", r->r_rcpt ) < 0 ) {
		fclose( tff );
		goto cleanup;
	    }
	}

    } else {
	if ( fprintf( tff, "R\n" ) < 0 ) {
	    fclose( tff );
	    goto cleanup;
	}
    }

    if ( fclose( tff ) != 0 ) {
	goto cleanup;
    }

    if ( rename( tf, ef ) < 0 ) {
	goto cleanup;
    }

    return( 0 );

cleanup:
    unlink( tf );

    return( 1 );
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
env_unexpanded( char *fname, int *unexpanded )
{
    char		*line;
    SNET		*snet;

    *unexpanded = -1;

    if (( snet = snet_open( fname, O_RDONLY, 0, 1024 * 1024 ))
	    == NULL ) {
	return( -1 );
    }

    /* first line of an envelope should be version info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
	return( 1 );
    }

    /* second line of an envelope has expansion info */
    if (( line = snet_getline( snet, NULL )) == NULL ) {
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
	return( -1 );
    }

    return( 0 );
}
