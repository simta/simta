#include "config.h"

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

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
#include "bounce.h"


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

	if ( line_append( bounce_env->e_err_text, text ) == NULL ) {
	    syslog( LOG_ERR, "bounce_text line_append: %m" );
	    free( text );
	    return( -1 );
	}

	free( text );

    } else if ( t2 != NULL ) {
	len = strlen( t1 ) + strlen( t2 ) + 1;

	if (( text = (char*)malloc( len )) == NULL ) {
	    syslog( LOG_ERR, "bounce_text malloc: %m" );
	    return( -1 );
	}
	sprintf( text, "%s%s", t1, t2 );

	if ( line_append( bounce_env->e_err_text, text ) == NULL ) {
	    syslog( LOG_ERR, "bounce_text line_append: %m" );
	    free( text );
	    return( -1 );
	}

	free( text );

    } else {
	if ( line_append( bounce_env->e_err_text, t1 ) == NULL ) {
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
	printf(  "To: %s\n", r->r_rcpt );
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
    int				return_value = 0;
    int				line_no = 0;
    char                        dfile_fname[ MAXPATHLEN ];
    int                         dfile_fd;
    FILE                        *dfile;
    struct line                 *l;
    char                        *line;
    time_t                      clock;
    struct tm                   *tm;
    char                        daytime[ 35 ];
    struct stat			sbuf;

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
    fprintf( dfile, "From: mailer-daemon@%s\n", simta_hostname );
    if (( bounce_env->e_mail == NULL ) || ( *bounce_env->e_mail == '\0' )) {
	/* XXX ERROR */
	fprintf( dfile, "To: %s\n", simta_postmaster );
    } else {
	fprintf( dfile, "To: %s\n", bounce_env->e_mail );
    }
    fprintf( dfile, "Date: %s\n", daytime );
    fprintf( dfile, "Message-ID: %s\n", bounce_env->e_id );
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
	    line_no++;
	    if ( line_no > SIMTA_BOUNCE_LINES ) {
		break;
	    }

	    fprintf( dfile, "%s\n", line );
	}
    }

    if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	syslog( LOG_ERR, "bounce_dfile_out fstat %s: %m", dfile_fname );
        goto cleanup;
    }

    return_value = 1;

cleanup:
    if ( fclose( dfile ) != 0 ) {
	syslog( LOG_ERR, "bounce_dfile_out fclose %s: %m", dfile_fname );
	return_value = 0;
    }

    if ( return_value != 0 ) {
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
    struct message		*m;
    struct line                 *l;
    int                         line_no = 0;
    char                        *line;
    time_t                      clock;
    struct tm                   *tm;
    struct timeval		tv;
    struct stat			sbuf;
    char                        daytime[ 35 ];

    if (( bounce_env = env_create( NULL )) == NULL ) {
	return( NULL );
    }

    if ( env_gettimeofday_id( bounce_env ) != 0 ) {
	goto cleanup1;
    }

    bounce_env->e_dir = simta_dir_fast;

    if (( env->e_mail == NULL ) || ( *env->e_mail == '\0' ) ||
	    ( strcasecmp( env->e_mail, simta_postmaster ) == 0 )) {
        if ( env_recipient( bounce_env, simta_postmaster ) != 0 ) {
            goto cleanup1;
        }

	/* if the postmaster is a recipient,
	 * we need to put the bounce in the dead queue.
	 */
	for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	    if ((( env->e_flags & ENV_BOUNCE ) ||
		    ( r->r_delivered == R_FAILED )) &&
		    ( strcasecmp( simta_postmaster, r->r_rcpt ) == 0 )) {
		bounce_env->e_dir = simta_dir_dead;
		break;
	    }
	}

    } else {
        if ( env_recipient( bounce_env, env->e_mail ) != 0 ) {
            goto cleanup1;
        }
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

    fprintf( dfile, "From: mailer-daemon@%s\n", simta_hostname );
    if (( env->e_mail == NULL ) || ( *env->e_mail == '\0' )) {
	fprintf( dfile, "To: %s\n", simta_postmaster );
    } else {
	fprintf( dfile, "To: %s\n", env->e_mail );
    }
    fprintf( dfile, "Date: %s\n", daytime );
    fprintf( dfile, "Message-ID: %s\n", bounce_env->e_id );
    fprintf( dfile, "\n" );
    fprintf( dfile, "Your mail was bounced.\n" );
    fprintf( dfile, "\n" );

    if ( env->e_flags & ENV_UNEXPANDED ) {
        fprintf( dfile, "There was a local error in processing the "
		" recipients of your message\n" );
    }

    if ( env->e_flags & ENV_OLD ) {
        fprintf( dfile, "This message has been undeliverable for at least "
		"three days.\n" );
    }

    if ( hq->hq_err_text != NULL ) {
	fprintf( dfile, "The following error occured during delivery to "
		"host %s:\n", hq->hq_hostname );
	for ( l = hq->hq_err_text->l_first; l != NULL; l = l->line_next ) {
	    fprintf( dfile, "%s\n", l->line_data );
	}

    } else if ( env->e_err_text != NULL ) {
	fprintf( dfile, "The following error occured during delivery to "
		"host %s:\n", hq->hq_hostname );
	for ( l = env->e_err_text->l_first; l != NULL; l = l->line_next ) {
	    fprintf( dfile, "%s\n", l->line_data );
	}

    } else {
	fprintf( dfile, "An error occured during delivery to host %s.\n",
		hq->hq_hostname );
    }

    fprintf( dfile, "\n" );

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if (( env->e_flags & ENV_BOUNCE ) || ( r->r_delivered == R_FAILED )) {
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

    if ( message != NULL ) {
	fprintf( dfile, "Bounced message:\n" );
	fprintf( dfile, "\n" );
	while (( line = snet_getline( message, NULL )) != NULL ) {
	    line_no++;
	    if ( line_no > SIMTA_BOUNCE_LINES ) {
		break;
	    }
	    fprintf( dfile, "%s\n", line );
	}
    }

    if ( fstat( dfile_fd, &sbuf ) != 0 ) {
	syslog( LOG_ERR, "bounce %s fstat %s: %m", env->e_id, dfile_fname );
        goto cleanup3;
    }
    bounce_env->e_dinode = sbuf.st_ino;

    if ( fclose( dfile ) != 0 ) {
	syslog( LOG_ERR, "bounce %s fclose %s: %m", env->e_id, dfile_fname );
        goto cleanup3;
    }

    /* if it's not going to the DEAD queue, add it to our work list */
    if ( bounce_env->e_dir != simta_dir_dead ) {
	if (( m = message_create( bounce_env->e_id )) == NULL ) {
	    goto cleanup3;
	}
	m->m_dir = bounce_env->e_dir;
	m->m_etime.tv_sec = tv.tv_sec;
	m->m_env = bounce_env;
	if ( env_outfile( bounce_env ) != 0 ) {
	    goto cleanup4;
	}
	bounce_env->e_message = m;

    } else {
	if ( env_outfile( bounce_env ) != 0 ) {
	    goto cleanup3;
	}
    }

    return( bounce_env );

cleanup4:
    message_free( m );
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
