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
bounce( struct envelope *env, SNET *message )
{
    struct envelope             bounce_env;
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
    char                        daytime[ 35 ];

    memset( &bounce_env, 0, sizeof( struct envelope ));

    env_reset( &bounce_env );

    if ( gettimeofday( &tv, NULL ) != 0 ) {
	syslog( LOG_ERR, "gettimeofday: %m" );
	return( -1 );
    }

    sprintf( bounce_env.e_id, "%lX.%lX", (unsigned long)tv.tv_sec,
	    (unsigned long)tv.tv_usec );

    bounce_env.e_dir = SIMTA_DIR_FAST;
    bounce_env.e_mail = simta_postmaster;

    if (( env->e_mail == NULL ) || ( *env->e_mail == '\0' ) ||
	    ( strcasecmp( env->e_mail, simta_postmaster ) == 0 )) {
        if ( env_recipient( &bounce_env, simta_postmaster ) != 0 ) {
            return( -1 );
        }

	for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	    if (( r->r_delivered == R_FAILED ) &&
		    ( strcasecmp( simta_postmaster, r->r_rcpt ) == 0 )) {

		bounce_env.e_dir = SIMTA_DIR_DEAD;
		break;
	    }
	}

    } else {
        if ( env_recipient( &bounce_env, env->e_mail ) != 0 ) {
            return( -1 );
        }
    }

    sprintf( dfile_fname, "%s/D%s", bounce_env.e_dir, bounce_env.e_id );

    if (( dfile_fd = open( dfile_fname, O_WRONLY | O_CREAT | O_EXCL, 0600 ))
            < 0 ) {
        syslog( LOG_ERR, "open %s: %m", dfile_fname );
        return( -1 );
    }

    if (( dfile = fdopen( dfile_fd, "w" )) == NULL ) {
        syslog( LOG_ERR, "fdopen %s: %m", dfile_fname );
        close( dfile_fd );
        goto cleanup;
    }

    if ( time( &clock ) < 0 ) {
        syslog( LOG_ERR, "time: %m" );
        close( dfile_fd );
        goto cleanup;
    }

    if (( tm = localtime( &clock )) == NULL ) {
        syslog( LOG_ERR, "localtime: %m" );
        close( dfile_fd );
        goto cleanup;
    }

    if ( strftime( daytime, sizeof( daytime ), "%a, %e %b %Y %T", tm )
            == 0 ) {
        syslog( LOG_ERR, "strftime: %m" );
        close( dfile_fd );
        goto cleanup;
    }

    /* XXX From: address */
    fprintf( dfile, "From: mailer-daemon@%s\n", simta_hostname );
    fprintf( dfile, "To: %s\n", bounce_env.e_mail );
    fprintf( dfile, "Date: %s\n", daytime );
    fprintf( dfile, "Message-ID: %s\n", bounce_env.e_id );
    fprintf( dfile, "\n" );

    /* XXX bounce message */
    fprintf( dfile, "Your mail was bounced.\n" );
    fprintf( dfile, "\n" );

    /* XXX oldfile message */
    if ( env->e_old_dfile != 0 ) {
        fprintf( dfile, "It was over three days old.\n" );
        fprintf( dfile, "\n" );
    }

    if ( env->e_err_text != NULL ) {
	fprintf( dfile, "The following error occured:\n" );

	for ( l = env->e_err_text->l_first; l != NULL; l = l->line_next ) {
	    fprintf( dfile, "%s\n", l->line_data );
	}

	fprintf( dfile, "\n" );
    }

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
        if (( env->e_err_text != NULL ) || ( env->e_old_dfile != 0 ) || 
		( r->r_delivered == R_FAILED ) || ( r->r_text != NULL )) {
            fprintf( dfile, "address %s\n", r->r_rcpt );

            if ( r->r_text != NULL ) {
                for ( l = r->r_text->l_first; l != NULL; l = l->line_next ) {
                    fprintf( dfile, "%s\n", l->line_data );
                }
            }

            fprintf( dfile, "\n" );
        }
    }

    fprintf( dfile, "Bounced message:\n" );
    fprintf( dfile, "\n" );

    while (( line = snet_getline( message, NULL )) != NULL ) {
        line_no++;

        if ( line_no > SIMTA_BOUNCE_LINES ) {
            break;
        }

        fprintf( dfile, "%s\n", line );
    }

    if ( fclose( dfile ) != 0 ) {
        goto cleanup;
    }

    if ( env_outfile( &bounce_env, bounce_env.e_dir ) != 0 ) {
        goto cleanup;
    }

    /* if it's not going to the DEAD queue, add it to our work list */
    if ( bounce_env.e_dir != SIMTA_DIR_DEAD ) {
	if (( m = message_create( bounce_env.e_id )) == NULL ) {
	    return( -1 );
	}

	m->m_dir = bounce_env.e_dir;
	m->m_etime.tv_sec = tv.tv_sec;

	if ( message_queue( simta_null_q, m ) != 0 ) {
	    return( -1 );
	}
    }

    /* make sure to reset to clean up any memory */
    env_reset( &bounce_env );

    return( 0 );

cleanup:
    unlink( dfile_fname );

    return( -1 );
}

