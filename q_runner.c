#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <sysexits.h>
#include <utime.h>

#include <snet.h>

#include "ll.h"
#include "envelope.h"
#include "queue.h"
#include "message.h"
#include "ml.h"
#include "smtp.h"

/* XXX default postmaster? */
#define	SIMTA_POSTMASTER	"postmaster"
#define	BOUNCE_LINES		100

struct host_q		*null_queue;


void	host_stab_stdout ___P(( void * ));
void	q_file_stab_stdout ___P(( void * ));
void	deliver_remote ___P(( struct host_q * ));
int	deliver_local ___P(( struct host_q * ));
int	bounce ___P(( struct envelope *, SNET * ));


    int
bounce( struct envelope *env, SNET *message )
{
    struct envelope		*bounce_env;
    char			dfile_fname[ MAXPATHLEN ];
    int				dfile_fd;
    FILE			*dfile;
    struct recipient		*r;
    struct line			*l;
    int				line_no = 0;
    char			*line;
    struct q_file		*q;

    if (( bounce_env = env_create( NULL )) == NULL ) {
	syslog( LOG_ERR, "env_create: %m" );
	return( -1 );
    }

    if ( env_gettimeofday_id( bounce_env ) != 0 ) {
	syslog( LOG_ERR, "env_gettimeofday_id: %m" );
	return( -1 );
    }

    sprintf( dfile_fname, "%s/D%s", FAST_DIR, bounce_env->e_id );

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

    if (( env->e_mail != NULL ) && ( *env->e_mail != '\0' )) {
	if ( env_recipient( bounce_env, env->e_mail ) != 0 ) {
	    syslog( LOG_ERR, "env_recipient: %m" );
	    fclose( dfile );
	    goto cleanup;
	}

    } else {
	if ( env_recipient( bounce_env, SIMTA_POSTMASTER ) != 0 ) {
	    syslog( LOG_ERR, "env_recipient: %m" );
	    fclose( dfile );
	    goto cleanup;
	}
    }

    fprintf( dfile, "Headers\n" );
    fprintf( dfile, "\n" );

    fprintf( dfile, "Your mail was bounced.\n" );
    fprintf( dfile, "\n" );

    for ( r = env->e_rcpt; r != NULL; r = r->r_next ) {
	if ( r->r_delivered == R_FAILED ) {
	    fprintf( dfile, "address %s:\n", r->r_rcpt );

	    for ( l = r->r_text->l_first; l != NULL; l = l->line_next ) {
		fprintf( dfile, "%s:\n", l->line_data );
	    }

	    fprintf( dfile, "\n" );
	}
    }

    fprintf( dfile, "Bounced message:\n" );
    fprintf( dfile, "\n" );

    while (( line = snet_getline( message, NULL )) != NULL ) {
	line_no++;

	if ( line_no > BOUNCE_LINES ) {
	    break;
	}

	fprintf( dfile, "%s\n", line );
    }

    if ( fclose( dfile ) != 0 ) {
	goto cleanup;
    }

    if ( env_outfile( bounce_env, FAST_DIR ) != 0 ) {
	goto cleanup;
    }

    /* XXX add to NULL queue, update q->q_etime */
    if (( q = q_file_env( bounce_env )) == NULL ) {
	syslog( LOG_ERR, "q_file_env: %m" );
	exit( 1 );
    }

    q->q_env = bounce_env;
    q->q_expanded = q->q_env->e_expanded;
    q->q_etime = &(q->q_env->e_etime);

    if ( ll__insert( &(null_queue->hq_qfiles), q, efile_time_compare ) != 0 ) {
	syslog( LOG_ERR, "ll__insert: %m" );
	exit( 1 );
    }

    return( 0 );

cleanup:
    unlink( dfile_fname );

    return( -1 );
}


    void
q_file_stab_stdout( void *data )
{
    struct q_file		*q;

    q = (struct q_file*)data;

    q_file_stdout( q );
}


    void
host_stab_stdout( void *data )
{
    struct host_q		*hq;

    hq = (struct host_q*)data;

    host_q_stdout( hq );

    ll_walk( hq->hq_qfiles, q_file_stab_stdout );

    printf( "\n" );
}


    /* 1. For each efile:
     *      -organize by host
     *      -organize under host in reverse chronological order
     *
     * 2. For each host:
     *      -try to send messages
     *      -if there is a failure, stat all the d files to see if a bounce
     *           needs to be generated.
     */

    int
main( int argc, char *argv[] )
{
    DIR				*dirp;
    struct dirent		*entry;
    struct q_file		*q;
    struct envelope		*env;
    struct host_q		*hq;
    struct stab_entry		*host_stab = NULL;
    struct stab_entry		*hs;
    int				result;
    char			fname[ MAXPATHLEN ];

    openlog( argv[ 0 ], LOG_NDELAY, LOG_SIMTA );

    /* create and preserve NULL queue for bunced messages later on */
    if (( null_queue = host_q_lookup( &host_stab, "\0" )) == NULL ) {
	syslog( LOG_ERR, "host_q_create: %m" );
	exit( 1 );
    }

    if (( dirp = opendir( SLOW_DIR )) == NULL ) {
	syslog( LOG_ERR, "opendir %s: %m", SLOW_DIR );
	exit( 1 );
    }

    /* clear errno before trying to read */
    errno = 0;

    /* examine a directory */
    while (( entry = readdir( dirp )) != NULL ) {

	/* ignore '.' and '..' */
	if ( entry->d_name[ 0 ] == '.' ) {
	    if ( entry->d_name[ 1 ] == '\0' ) {
		continue;
	    } else if ( entry->d_name[ 1 ] == '.' ) {
		if ( entry->d_name[ 2 ] == '\0' ) {
		    continue;
		}
	    }
	}

	/* organize Efiles by host and modification time */
	if ( *entry->d_name == 'E' ) {
	    if (( env = env_create( entry->d_name + 1 )) == NULL ) {
		syslog( LOG_ERR, "env_create: %m" );
		exit( 1 );
	    }

	    sprintf( fname, "%s/%s", SLOW_DIR, entry->d_name );

	    if (( result = env_infile( env, fname )) < 0 ) {
		/* syserror */
		syslog( LOG_ERR, "env_infile %s: %m", fname );
		exit( 1 );

	    } else if ( result > 1 ) {
		/* syntax error */
		env_free( env );
		/* XXX env_infile should syslog errors */
		syslog( LOG_WARNING, "env_infile %s: syntax error", fname );
		continue;
	    }

	    if (( q = q_file_env( env )) == NULL ) {
		syslog( LOG_ERR, "q_file_env: %m" );
		exit( 1 );
	    }

	    /* XXX DNS lookup if q->q_expanded == NULL? */

	    if (( hq = host_q_lookup( &host_stab, q->q_expanded )) == NULL ) {
		exit( 1 );
	    }

	    if ( ll__insert( &(hq->hq_qfiles), q, efile_time_compare ) != 0 ) {
		syslog( LOG_ERR, "ll__insert: %m" );
		exit( 1 );
	    }
	}
    }

    /* did readdir finish, or encounter an error? */
    if ( errno != 0 ) {
	syslog( LOG_ERR, "readdir: %m" );
	exit( 1 );
    }

#ifdef DEBUG
    ll_walk( host_stab, host_stab_stdout );
#endif /* DEBUG */

    /*
     * 2. For each host:
     *      -try to send messages
     *      -if there is a failure, stat all the d files to see if a bounce
     *           needs to be generated.
     */

    for ( hs = host_stab; hs != NULL; hs = hs->st_next ) {
	hq = (struct host_q*)hs->st_data;

	if ( hq->hq_status == HOST_NULL ) {
	    /* XXX NULL host queue.  Add DNS code */

	} else if ( hq->hq_status == HOST_LOCAL ) {
	    deliver_local( hq );

	} else if ( hq->hq_status == HOST_REMOTE ) {
	    deliver_remote( hq );

	} else if ( hq->hq_status == HOST_BOUNCE ) {
	    /* XXX deliver_bounce( hq ); */

	} else {
	    /* big error */
	    syslog( LOG_ERR, "q_runner: unreachable code" );
	    exit( 1 );
	}
    }

#ifdef DEBUG
    ll_walk( host_stab, host_stab_stdout );
#endif /* DEBUG */

    return( 0 );
}


    int
deliver_local( struct host_q *hq )
{
    struct q_file		*q;
    struct stab_entry		*qs;
    struct recipient		*r;
    int				sent;
    int				result;
    int				dfile_fd;
    char			*at;
    char			fname[ MAXPATHLEN ];
    static int			(*local_mailer)(int, char *, char *) = NULL;
    struct stat			sb;
    SNET			*dfile_snet;

    if ( local_mailer == NULL ) {
	if (( local_mailer = get_local_mailer()) == NULL ) {
	    syslog( LOG_ALERT, "deliver local: no local mailer!" );
	    exit( 1 );
	}
    }

    for ( qs = hq->hq_qfiles; qs != NULL; qs = qs->st_next ) {
	q = (struct q_file*)qs->st_data;

	/* get message_data */
	errno = 0;
	sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	if (( dfile_fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	    if ( errno == ENOENT ) {
		errno = 0;
		syslog( LOG_WARNING, "Missing Dfile: %s", fname );
		q->q_action = Q_REMOVE;
		continue;

	    } else {
		syslog( LOG_ERR, "open %s: %m", fname );
		exit( 1 );
	    }
	}

	sent = 0;
	q->q_env->e_failed = 0;
	q->q_env->e_tempfail = 0;
	q->q_env->e_success = 0;

	if ( fstat( dfile_fd, &sb ) != 0 ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    exit( 1 );
	}

	/* XXX if old dfile set env->e_old_dfile */

	for ( r = q->q_env->e_rcpt; r != NULL; r = r->r_next ) {
	    if ( sent != 0 ) {
		if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
		    syslog( LOG_ERR, "lseek: %m" );
		    exit( 1 );
		}
	    }

	    for ( at = r->r_rcpt; ; at++ ) {
		if ( *at == '@' ) {
		    *at = '\0';
		    break;

		} else if ( *at == '\0' ) {
		    at = NULL;
		    break;
		}
	    }

	    if (( result = (*local_mailer)( dfile_fd, q->q_env->e_mail,
		    r->r_rcpt )) < 0 ) {
		/* syserror */
		exit( 1 );

	    } else if ( result == 0 ) {
		/* success */
		r->r_delivered = R_DELIVERED;
		q->q_env->e_success++;

	    } else if ( result == EX_TEMPFAIL ) {
		if ( q->q_env->e_old_dfile != 0 ) {
		    r->r_delivered = R_FAILED;
		    q->q_env->e_failed++;

		} else {
		    r->r_delivered = R_TEMPFAIL;
		    q->q_env->e_tempfail++;
		}

	    } else {
		/* hard failure */
		r->r_delivered = R_FAILED;
		q->q_env->e_failed++;
	    }

	    sent++;

	    if ( at != NULL ) {
		*at = '@';
	    }
	}

	if ( q->q_env->e_failed > 0 ) {
	    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
		syslog( LOG_ERR, "lseek: %m" );
		exit( 1 );
	    }

	    if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
		syslog( LOG_ERR, "snet_attach: %m" );
		exit( 1 );
	    }

	    if (( result = bounce( q->q_env, dfile_snet )) < 0 ) {
		exit( 1 );
	    }

	    if ( snet_close( dfile_snet ) != 0 ) {
		syslog( LOG_ERR, "snet_close: %m" );
		exit( 1 );
	    }

	} else {
	    if ( close( dfile_fd ) != 0 ) {
		syslog( LOG_ERR, "close: %m" );
		exit( 1 );
	    }
	}

	if ( q->q_env->e_tempfail == 0  ) {
	    /* no retries, only successes and bounces */
	    /* delete Efile then Dfile */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }

	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }

	    q->q_action = Q_REMOVE;

	} else {
	    /* some retries.  touch efile */
	    /* XXX update q->q_etime */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( utime( fname, NULL ) != 0 ) {
		syslog( LOG_ERR, "utime %s: %m", fname );
		exit( 1 );
	    }

	    q->q_action = Q_REORDER;

	    if (( q->q_env->e_success != 0 ) || ( q->q_env->e_failed != 0 )) {

		/* some retries, and some sent.  re-write envelope */
		env_cleanup( q->q_env );

		if ( env_outfile( q->q_env, SLOW_DIR ) != 0 ) {
		    syslog( LOG_ERR, "utime %s: %m", fname );
		    exit( 1 );
		}
	    }
	} 
    }

    host_q_cleanup( hq );

    return( 0 );
}


    void
deliver_remote( struct host_q *hq )
{
    struct q_file		*q;
    struct stab_entry		*qs;
    struct stat			sb;
    int				result;
    int				dfile_fd;
    SNET			*dfile_snet;
    int				sent = 0;
    char			fname[ MAXPATHLEN ];
    SNET			*snet = NULL;
    void                        (*logger)(char *) = NULL;

#ifdef DEBUG
    logger = stdout_logger;
#endif /* DEBUG */

    /* XXX send only to terminator (or alias rsug), for now */
    if (( strcasecmp( hq->hq_name, "terminator.rsug.itd.umich.edu" ) != 0 ) &&
	    ( strcasecmp( hq->hq_name, "rsug.itd.umich.edu" ) != 0 )) {
	return;
    }

    for ( qs = hq->hq_qfiles; qs != NULL; qs = qs->st_next ) {
	q = (struct q_file*)qs->st_data;

	/* get message_data */
	errno = 0;
	sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	if (( dfile_fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	    if ( errno == ENOENT ) {
		errno = 0;
		syslog( LOG_WARNING, "Missing Dfile: %s", fname );
		q->q_action = Q_REMOVE;
		continue;

	    } else {
		syslog( LOG_ERR, "open %s: %m", fname );
		exit( 1 );
	    }
	}

	if ( fstat( dfile_fd, &sb ) != 0 ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    exit( 1 );
	}

	/* XXX if old dfile set env->e_old_dfile */

	if (( dfile_snet = snet_attach( dfile_fd, 1024 * 1024 )) == NULL ) {
	    syslog( LOG_ERR, "snet_attach: %m" );
	    exit( 1 );
	}

	if ( sent != 0 ) {
	    if (( result = smtp_rset( snet, logger )) == SMTP_ERR_SYSCALL ) {
		exit( 1 );

	    } else if ( result == SMTP_ERR_SYNTAX ) {
		break;
	    }
	}

	/* open connection, completely ready to send at least one message */
	if ( snet == NULL ) {
	    if (( snet = smtp_connect( hq->hq_name, 25 )) == NULL ) {
		exit( 1 );
	    }

	    if (( result = smtp_helo( snet, logger )) == SMTP_ERR_SYSCALL ) {
		exit( 1 );

	    } else if ( result == SMTP_ERR_SYNTAX ) {
		if ( snet_close( dfile_snet ) != 0 ) {
		    syslog( LOG_ERR, "close: %m" );
		    exit( 1 );
		}

		return;

	    } else if ( result == SMTP_ERR_MAIL_LOOP ) {
		/* mail loop */
		if ( snet_close( dfile_snet ) != 0 ) {
		    syslog( LOG_ERR, "close: %m" );
		    exit( 1 );
		}

		syslog( LOG_ALERT, "Hostname %s is not a remote host",
			hq->hq_name );

		hq->hq_status = HOST_BOUNCE;
		/* XXX deliver_bounce( hq ); */
		return;
	    }
	}

	if (( result = smtp_send( snet, q->q_env, dfile_snet, logger ))
		== SMTP_ERR_SYSCALL ) {
	    exit( 1 );

	} else if ( result == SMTP_ERR_SYNTAX ) {
	    /* XXX error case? */
	}

	sent++;

	if ( q->q_env->e_failed > 0 ) {
	    if ( lseek( dfile_fd, (off_t)0, SEEK_SET ) != 0 ) {
		syslog( LOG_ERR, "lseek: %m" );
		exit( 1 );
	    }

	    if (( result = bounce( q->q_env, dfile_snet )) < 0 ) {
		exit( 1 );
	    }
	}

	if ( snet_close( dfile_snet ) != 0 ) {
	    syslog( LOG_ERR, "snet_close: %m" );
	    exit( 1 );
	}

	if ( q->q_env->e_tempfail == 0  ) {
	    /* no retries, only successes and bounces */
	    /* delete Efile then Dfile */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }

	    sprintf( fname, "%s/D%s", SLOW_DIR, q->q_id );

	    if ( unlink( fname ) != 0 ) {
		syslog( LOG_ERR, "unlink %s: %m", fname );
		exit( 1 );
	    }

	    q->q_action = Q_REMOVE;

	} else {
	    /* some retries.  touch efile */
	    /* XXX update q->q_etime */
	    sprintf( fname, "%s/E%s", SLOW_DIR, q->q_id );

	    if ( utime( fname, NULL ) != 0 ) {
		syslog( LOG_ERR, "utime %s: %m", fname );
		exit( 1 );
	    }

	    q->q_action = Q_REORDER;

	    if (( q->q_env->e_success != 0 ) || ( q->q_env->e_failed != 0 )) {

		/* some retries, and some sent.  re-write envelope */
		env_cleanup( q->q_env );

		if ( env_outfile( q->q_env, SLOW_DIR ) != 0 ) {
		    syslog( LOG_ERR, "utime %s: %m", fname );
		    exit( 1 );
		}
	    }
	} 
    }

    if ( snet != NULL ) {
	if (( result = smtp_quit( snet, logger )) < 0 ) {
	    exit( 1 );
	}
    }

    host_q_cleanup( hq );

    return;
}
