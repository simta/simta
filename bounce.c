#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/stat.h>

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

#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "ml.h"
#include "line_file.h"
#include "smtp.h"
#include "expand.h"
#include "simta.h"


    int
bounce_text( struct envelope *bounce_env, char *t1, char *t2, char *t3 )
{
    char			*text;
    size_t			len;

    if ( bounce_env->e_err_text == NULL ) {
	if (( bounce_env->e_err_text = line_file_create()) == NULL ) {
	    syslog( LOG_ERR, "bounce_text line_file_create: %m" );
	    return( -1 );
	}
    }

    if ( t3 != NULL ) {
	len = strlen( t1 ) + strlen( t2 ) + strlen( t3 ) + 1;

	if (( text = (char*)malloc( len )) == NULL ) {
	    syslog( LOG_ERR, "bounce_text malloc: %m" );
	    return( -1 );
	}
	sprintf( text, "%s%s%s", t1, t2, t3 );

	if ( line_append( bounce_env->e_err_text, text, NO_COPY ) == NULL ) {
	    syslog( LOG_ERR, "bounce_text line_append: %m" );
	    free( text );
	    return( -1 );
	}

    } else if ( t2 != NULL ) {
	len = strlen( t1 ) + strlen( t2 ) + 1;

	if (( text = (char*)malloc( len )) == NULL ) {
	    syslog( LOG_ERR, "bounce_text malloc: %m" );
	    return( -1 );
	}
	sprintf( text, "%s%s", t1, t2 );

	if ( line_append( bounce_env->e_err_text, text, NO_COPY ) == NULL ) {
	    syslog( LOG_ERR, "bounce_text line_append: %m" );
	    free( text );
	    return( -1 );
	}

    } else {
	if ( line_append( bounce_env->e_err_text, t1, COPY ) == NULL ) {
	    syslog( LOG_ERR, "bounce_text line_append: %m" );
	    return( -1 );
	}
    }

    return( 0 );
}


    void
bounce_stdout( struct envelope *bounce_env )
{
    struct line                 *l;
    struct recipient		*r;

    if (( bounce_env->e_err_text == NULL ) ||
	    (( l = bounce_env->e_err_text->l_first ) == NULL )) {
	return;
    }

    printf( "***   Bounce Message %s  ***\n", bounce_env->e_id );

    /* dfile message headers */
    printf(  "From: mailer-daemon@%s\n", simta_hostname );
    for ( r = bounce_env->e_rcpt; r != NULL; r = r->r_next ) {
	printf(  "To: <%s>\n", r->r_rcpt );
    }
    printf(  "\n" );

    while ( l != NULL ) {
	printf(  "%s\n", l->line_data );
	l = l->line_next;
    }
}


    ino_t
bounce_dfile_out( struct envelope *bounce_env, SNET *message )
{
    int				ret = 0;
    char                        dfile_fname[ MAXPATHLEN ];
    int                         dfile_fd;
    FILE                        *dfile;
    struct line                 *l;
    char                        *line;
    time_t                      clock;
    struct tm                   *tm;
    char                        daytime[ 35 ];
    struct stat			sbuf;
    struct recipient		*r;

    sprintf( dfile_fname, "%s/D%s", bounce_env->e_dir, bounce_env->e_id );

    if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 ))
            < 0 ) {
        syslog( LOG_ERR, "bounce_dfile_out open %s: %m", dfile_fname );
	return( 0 );
    }

    if (( dfile = fdopen( dfile_fd, "w" )) == NULL ) {
	syslog( LOG_ERR, "bounce_dfile_out fdopen %s: %m", dfile_fname );
        if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "bounce_dfile_out fclose %s: %m", dfile_fname );
	}
	return( 0 );
    }

    if ( time( &clock ) < 0 ) {
        syslog( LOG_ERR, "bounce_dfile_out time: %m" );
        goto cleanup;
    }

    if (( tm = localtime( &clock )) == NULL ) {
        syslog( LOG_ERR, "bounce_dfile_out localtime: %m" );
        goto cleanup;
    }

    if ( strftime( daytime, sizeof( daytime ), "%a, %e %b %Y %T", tm )
            == 0 ) {
        syslog( LOG_ERR, "bounce_dfile_out strftime: %m" );
        goto cleanup;
    }

    /* dfile message headers */
    if ( *(bounce_env->e_mail) == '\0' ) {
	fprintf( dfile, "From: mailer-daemon@%s\n", simta_hostname );
    } else {
	fprintf( dfile, "From: %s\n", bounce_env->e_mail );
    }
    for ( r = bounce_env->e_rcpt; r != NULL; r = r->r_next ) {
	printf(  "To: <%s>\n", r->r_rcpt );
    }
    fprintf( dfile, "Date: %s\n", daytime );
    fprintf( dfile, "Message-ID: %s\n", bounce_env->e_id );
    fprintf( dfile, "Subject: undeliverable mail\n" );
    fprintf( dfile, "\n" );

    for ( l = bounce_env->e_err_text->l_first; l != NULL; l = l->line_next ) {
	fprintf( dfile, "%s\n", l->line_data );
    }
    fprintf( dfile, "\n" );

    if ( message != NULL ) {
	fprintf( dfile, "\n" );
	fprintf( dfile, "Bounced message:\n" );
	fprintf( dfile, "\n" );

	while (( line = snet_getline( message, NULL )) != NULL ) {
	    fprintf( dfile, "%s\n", line );
	}
    }

    if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	syslog( LOG_ERR, "bounce_dfile_out fstat %s: %m", dfile_fname );
        goto cleanup;
    }

    ret = 1;

cleanup:
    if ( fclose( dfile ) != 0 ) {
	syslog( LOG_ERR, "bounce_dfile_out fclose %s: %m", dfile_fname );
	ret = 0;
    }

    if ( ret != 0 ) {
	return( sbuf.st_ino );
    }

    if ( unlink( dfile_fname ) != 0 ) {
	syslog( LOG_ERR, "bounce_dfile_out unlink %s: %m", dfile_fname );
    }

    return( 0 );
}


    struct envelope *
bounce( struct host_q *hq, struct envelope *env, SNET *message )
{
    struct envelope             *bounce_env;
    char                        dfile_fname[ MAXPATHLEN ];
    int                         dfile_fd;
    FILE                        *dfile;
    struct recipient            *r;
    struct line                 *l;
    char                        *line;
    time_t                      clock;
    struct tm                   *tm;
    struct stat			sbuf;
    char                        daytime[ 35 ];

    if (( bounce_env = env_create( NULL )) == NULL ) {
	return( NULL );
    }

    if ( env_gettimeofday_id( bounce_env ) != 0 ) {
	goto cleanup1;
    }

    if ( env_sender( bounce_env, NULL ) != 0 ) {
	goto cleanup1;
    }

    bounce_env->e_dir = simta_dir_fast;

    /* if the postmaster is a failed recipient,
     * we need to put the bounce in the dead queue.
     */
    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ((( env->e_flags & ENV_BOUNCE ) ||
		( r->r_status == R_FAILED ))) {
	    if ( *(r->r_rcpt) == '\0' ) {
		bounce_env->e_dir = simta_dir_dead;
		break;
	    }
	}
    }

    if ( env_recipient( bounce_env, env->e_mail ) != 0 ) {
	goto cleanup1;
    }

    sprintf( dfile_fname, "%s/D%s", bounce_env->e_dir, bounce_env->e_id );
    if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 ))
            < 0 ) {
        syslog( LOG_ERR, "bounce %s open %s: %m", env->e_id, dfile_fname );
        goto cleanup2;
    }
    if (( dfile = fdopen( dfile_fd, "w" )) == NULL ) {
        syslog( LOG_ERR, "bounce %s fdopen %s: %m", env->e_id, dfile_fname );
        if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "bounce %s close %s: %m", env->e_id, dfile_fname );
	}
        goto cleanup3;
    }
    if ( time( &clock ) < 0 ) {
        syslog( LOG_ERR, "bounce %s time: %m", env->e_id );
        if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "bounce %s close %s: %m", env->e_id, dfile_fname );
	}
        goto cleanup3;
    }
    if (( tm = localtime( &clock )) == NULL ) {
        syslog( LOG_ERR, "bounce %s localtime: %m", env->e_id );
        if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "bounce %s close %s: %m", env->e_id, dfile_fname );
	}
        goto cleanup3;
    }
    if ( strftime( daytime, sizeof( daytime ), "%a, %e %b %Y %T", tm )
            == 0 ) {
        syslog( LOG_ERR, "bounce %s strftime: %m", env->e_id );
        if ( close( dfile_fd ) != 0 ) {
	    syslog( LOG_ERR, "bounce %s close %s: %m", env->e_id, dfile_fname );
	}
        goto cleanup3;
    }

    if ( env->e_mail == '\0' ) {
	fprintf( dfile, "From: <mailer-daemon@%s>\n", simta_hostname );
    } else {
	fprintf( dfile, "From: <%s>\n", env->e_mail );
    }
    for ( r = bounce_env->e_rcpt; r != NULL; r = r->r_next ) {
	printf(  "To: <%s>\n", r->r_rcpt );
    }
    fprintf( dfile, "Date: %s\n", daytime );
    fprintf( dfile, "Message-ID: %s\n", bounce_env->e_id );
    fprintf( dfile, "Subject: undeliverable mail\n" );
    fprintf( dfile, "\n" );
    fprintf( dfile, "Your mail was bounced.\n" );
    fprintf( dfile, "\n" );

    if ( *(env->e_hostname) == '\0' ) {
        fprintf( dfile, "There was a local error in expanding the "
		"recipients of your message\n\n" );
    }

    if ( env->e_flags & ENV_OLD ) {
        fprintf( dfile, "This message is old and undeliverable.\n\n" );
    }

    if ( hq->hq_err_text != NULL ) {
	fprintf( dfile, "The following error occured during delivery to "
		"host %s:\n", hq->hq_hostname );
	for ( l = hq->hq_err_text->l_first; l != NULL; l = l->line_next ) {
	    fprintf( dfile, "%s\n", l->line_data );
	}
	fprintf( dfile, "\n" );
    } else {
	fprintf( dfile, "An error occured during delivery to host %s.\n\n",
		hq->hq_hostname );
    }

    if ( env->e_err_text != NULL ) {
	fprintf( dfile, "The following error occured during delivery of "
		"message %s:\n", env->e_id );
	for ( l = env->e_err_text->l_first; l != NULL; l = l->line_next ) {
	    fprintf( dfile, "%s\n", l->line_data );
	}

	fprintf( dfile, "\n" );
    }

    syslog( LOG_INFO, "Bounce %s: %s: From <>", env->e_id, bounce_env->e_id );
    syslog( LOG_INFO, "Bounce %s: %s: To <%s>", env->e_id, bounce_env->e_id,
	    bounce_env->e_rcpt->r_rcpt );

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if (( env->e_flags & ENV_BOUNCE ) || ( r->r_status == R_FAILED )) {
	    syslog( LOG_INFO, "Bounce %s: %s: Bouncing address <%s>",
		    env->e_id, bounce_env->e_id, r->r_rcpt );
            fprintf( dfile, "address %s\n", r->r_rcpt );
            if ( r->r_err_text != NULL ) {
                for ( l = r->r_err_text->l_first; l != NULL;
			l = l->line_next ) {
                    fprintf( dfile, "%s\n", l->line_data );
                }
            }
            fprintf( dfile, "\n" );
        }
    }

    fprintf( dfile, "Bounced message:\n" );
    fprintf( dfile, "\n" );
    while (( line = snet_getline( message, NULL )) != NULL ) {
	fprintf( dfile, "%s\n", line );
    }

    if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	syslog( LOG_ERR, "bounce %s fstat %s: %m", env->e_id, dfile_fname );
        goto cleanup4;
    }
    bounce_env->e_dinode = sbuf.st_ino;

    if ( fclose( dfile ) != 0 ) {
	syslog( LOG_ERR, "bounce %s fclose %s: %m", env->e_id, dfile_fname );
        goto cleanup4;
    }

    if ( env_outfile( bounce_env ) != 0 ) {
	goto cleanup4;
    }

    syslog( LOG_INFO, "Bounce %s: %s: Message Completed", env->e_id,
	    bounce_env->e_id );

    return( bounce_env );

cleanup4:
    syslog( LOG_INFO, "Bounce %s: Message Deleted: System Error",
	    bounce_env->e_id );
cleanup3:
    if ( unlink( dfile_fname ) != 0 ) {
	syslog( LOG_ERR, "bounce %s unlink %s: %m", env->e_id, dfile_fname );
    }
cleanup2:
    env_reset( bounce_env );
cleanup1:
    free( bounce_env );
    return( NULL );
}
