/*
 * Copyright (c) 1995,2001 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <inttypes.h>
#include <syslog.h>

#include <netinet/in.h>

#ifdef __STDC__
#include <stdarg.h>
#else /* __STDC__ */
#include <varargs.h>
#endif /* __STDC__ */

#include "snet.h"

#define SNET_BUFLEN	4096

/*
 * BOL is beginning of line, FUZZY is after a CR but before a possible LF,
 * IN is past BOL, but before the end of a line.
 */
#define SNET_BOL	0
#define SNET_FUZZY	1
#define SNET_IN		2

static ssize_t snet_read0 ___P(( SNET *, char *, size_t, struct timeval * ));
static ssize_t snet_read1 ___P(( SNET *, char *, size_t, struct timeval * ));
static ssize_t snet_write0 ___P(( SNET *, char *, size_t, struct timeval * ));

/*
 * This routine is necessary, since snet_getline() doesn't differentiate
 * between NULL => EOF and NULL => connection dropped (or some other error).
 */
    int
snet_eof( SNET *sn )
{
    return ( sn->sn_flag & SNET_EOF );
}

    SNET *
snet_attach( fd, max )
    int		fd;
    int		max;
{
    SNET		*sn;

    if (( sn = (SNET *)malloc( sizeof( SNET ))) == NULL ) {
	return( NULL );
    }
    sn->sn_fd = fd;
    if (( sn->sn_rbuf = (char *)malloc( SNET_BUFLEN )) == NULL ) {
	free( sn );
	return( NULL );
    }
    sn->sn_rbuflen = SNET_BUFLEN;
    sn->sn_rstate = SNET_BOL;
    sn->sn_rcur = sn->sn_rend = sn->sn_rbuf;
    sn->sn_maxlen = max;

    if (( sn->sn_wbuf = (char *)malloc( SNET_BUFLEN )) == NULL ) {
	free( sn->sn_rbuf );
	free( sn );
	return( NULL );
    }
    sn->sn_wbuflen = SNET_BUFLEN;

    sn->sn_flag = 0;

    return( sn );
}

    SNET *
snet_open( path, flags, mode, max )
    char	*path;
    int		flags;
    int		mode;
{
    int		fd;

    if (( fd = open( path, flags, mode )) < 0 ) {
	return( NULL );
    }
    return( snet_attach( fd, max ));
}

    int
snet_close( SNET *sn )
{
    int			fd;

    fd = snet_fd( sn );
    free( sn->sn_wbuf );
    free( sn->sn_rbuf );
    free( sn );
    if ( close( fd ) < 0 ) {
	return( -1 );
    }
    return( 0 );
}

    void
snet_timeout( SNET *sn, int flag, struct timeval *tv )
{
    if ( flag & SNET_READ_TIMEOUT ) {
	sn->sn_flag |= SNET_READ_TIMEOUT;
	memcpy( &(sn->sn_read_timeout), tv, sizeof( struct timeval ));
    }
    if ( flag & SNET_WRITE_TIMEOUT ) {
	sn->sn_flag |= SNET_WRITE_TIMEOUT;
	memcpy( &(sn->sn_write_timeout), tv, sizeof( struct timeval ));
    }
    if ( flag & SNET_SSL_ACCEPT_TIMEOUT ) {
	sn->sn_flag |= SNET_SSL_ACCEPT_TIMEOUT;
	memcpy( &(sn->sn_ssl_accept_timeout), tv, sizeof( struct timeval ));
    }
    if ( flag & SNET_SSL_CONNECT_TIMEOUT ) {
	sn->sn_flag |= SNET_SSL_CONNECT_TIMEOUT;
	memcpy( &(sn->sn_ssl_connect_timeout), tv, sizeof( struct timeval ));
    }
    return;
}

#ifdef HAVE_LIBSSL
/*
 * Returns 0 on success, and all further communication is through
 * the OpenSSL layer.  Returns -1 on failure, check the OpenSSL error
 * stack for specific errors.
 */
    int
snet_starttls( SNET *sn, SSL_CTX *sslctx, int sslaccept )
{
    struct timeval	default_tv;

    if (( sslaccept != 0 ) && ( sn->sn_flag & SNET_SSL_ACCEPT_TIMEOUT )) {
	default_tv = sn->sn_ssl_accept_timeout;
	return( snet_starttls_tv( sn, sslctx, sslaccept, &default_tv ));
    } else if (( sslaccept == 0 ) &&
	    ( sn->sn_flag & SNET_SSL_CONNECT_TIMEOUT )) {
	default_tv = sn->sn_ssl_connect_timeout;
	return( snet_starttls_tv( sn, sslctx, sslaccept, &default_tv ));
    } else {
	return( snet_starttls_tv( sn, sslctx, sslaccept, NULL ));
    }
}


    int
snet_starttls_tv( SNET *sn, SSL_CTX *sslctx, int sslaccept, struct timeval *tv )
{
    int			rc;
    int			oflags = 0;

    if (( sn->sn_ssl = SSL_new( sslctx )) == NULL ) {
	return( -1 );
    }

    if (( rc = SSL_set_fd( sn->sn_ssl, snet_fd( sn ))) != 1 ) {
	return( rc );
    }

    if ( tv != NULL ) {
	if (( oflags = fcntl( snet_fd( sn ), F_GETFL )) < 0 ) {
	    return( -1 );
	}
	if (( oflags & O_NONBLOCK ) == 0 ) {
	    if ( fcntl( snet_fd( sn ), F_SETFL, oflags | O_NONBLOCK ) < 0 ) {
		return( -1 );
	    }
	}
    }

    for ( ; ; ) {
	int		err;
	fd_set		fd_read;
	fd_set		fd_write;

	if ( sslaccept ) {
	    rc = SSL_accept( sn->sn_ssl );
	} else {
	    rc = SSL_connect( sn->sn_ssl );
	}

	if ( rc == 1 ) {
	    sn->sn_flag |= SNET_TLS;
	    break;
	}

	if ( rc == 0 ) {
	    break;
	}

	if ( tv == NULL ) {
	    break;
	}

        if ( tv->tv_sec == 0 && tv->tv_usec == 0 ) {
            break;
        }

	err = SSL_get_error( sn->sn_ssl, rc );

	if ( err == SSL_ERROR_WANT_READ ) {
	    FD_ZERO( &fd_read );
	    FD_ZERO( &fd_write );
	    FD_SET( snet_fd( sn ), &fd_read );

	} else if ( err == SSL_ERROR_WANT_WRITE ) {
	    FD_ZERO( &fd_read );
	    FD_ZERO( &fd_write );
	    FD_SET( snet_fd( sn ), &fd_write );

	} else {
	    break;
	}

	if ( snet_select( snet_fd( sn ) + 1, &fd_read, &fd_write, NULL,
		tv ) < 0 ) {
	    break;
	}
    }

    if (( tv != NULL ) && (( oflags & O_NONBLOCK ) == 0 )) {
	if ( fcntl( snet_fd( sn ), F_SETFL, oflags ) < 0 ) {
	    return( -1 );
	}
    }

    return( rc );
}
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
    int
snet_setsasl( sn, conn )
    SNET	*sn;
    sasl_conn_t	*conn;
{

    const int		*ssfp;
    unsigned int	*maxp;
    int		rc;

    /* XXX - flush cache */

    /* security layer security strength factor.  If 0, call to sasl_encode,
     * sasl_decode unnecessary
     */
    if (( rc = sasl_getprop( conn, SASL_SSF, (const void **) &ssfp))
	    != SASL_OK ) {
	return( -1 );
    }
    sn->sn_saslssf = *ssfp;

    /* security layer max output buf unsigned */
    if (( rc = sasl_getprop( conn, SASL_MAXOUTBUF, (const void **) &maxp))
	    != SASL_OK ) {
	return( -1 );
    }
    sn->sn_saslmaxout = *maxp;

    sn->sn_conn = conn;
    sn->sn_flag |= SNET_SASL;

    return( 0 );
}
#endif /* HAVE_LIBSASL */

/*
 * Just like fprintf, only use the SNET header to get the fd, and use
 * snet_write() to move the data.
 *
 * Todo: %f, *, . and, -
 */
    ssize_t
#ifdef __STDC__
snet_writeftv( SNET *sn, struct timeval *tv, char *format, ... )
#else /* __STDC__ */
snet_writeftv( sn, tv, format, va_alist )
    SNET		*sn;
    struct timeval	*tv;
    char		*format;
    va_dcl
#endif /* __STDC__ */
{
    va_list		vl;
    char		dbuf[ 128 ], *p;
    char		*dbufoff;
    int			d, len;
    long		l;
    long long		ll;
    unsigned int	u_d;
    unsigned long	u_l;
    unsigned long long	u_ll;
    int			is_long, is_longlong, is_unsigned, is_negative;
    char		*cur, *end;

#ifdef __STDC__
    va_start( vl, format );
#else /* __STDC__ */
    va_start( vl );
#endif /* __STDC__ */

#define SNET_WBUFGROW(x)						\
	    while ( cur + (x) > end ) {					\
		if (( sn->sn_wbuf = (char *)realloc( sn->sn_wbuf,	\
			sn->sn_wbuflen + SNET_BUFLEN )) == NULL ) {	\
		    abort();						\
		}							\
		cur = sn->sn_wbuf + sn->sn_wbuflen - ( end - cur );	\
		sn->sn_wbuflen += SNET_BUFLEN;				\
		end = sn->sn_wbuf + sn->sn_wbuflen;			\
	    }		

    cur = sn->sn_wbuf;
    end = sn->sn_wbuf + sn->sn_wbuflen;

    for ( ; *format; format++ ) {

	if ( *format != '%' ) {
	    SNET_WBUFGROW( 1 );
	    *cur++ = *format;
	} else {
	    is_long = 0;
	    is_longlong = 0;
	    is_unsigned = 0;

modifier:

	    switch ( *++format ) {
	    case 's' :
		p = va_arg( vl, char * );
		len = strlen( p );
		SNET_WBUFGROW( len );
		memcpy( cur, p, len );
		cur += len;
		break;

	    case 'c' :
		SNET_WBUFGROW( 1 );
		*cur++ = va_arg( vl, int );
		break;

	    case 'l' :
		if ( is_long ) {
		    is_longlong = 1;
		} else {
		    is_long = 1;
		}
		goto modifier;

	    case 'u' :
		is_unsigned = 1;
		goto modifier;

	    case 'd' :
		p = dbufoff = dbuf + sizeof( dbuf );

#define SNET_WF_D(x)						\
		if ( (x) < 0 ) {				\
		    is_negative = 1;				\
		    (x) = - (x);				\
		} else {					\
		    is_negative = 0;				\
		}						\
		do {						\
		    if ( --dbufoff < dbuf ) {			\
			abort();				\
		    }						\
		    *dbufoff = '0' + ( (x) % 10 );		\
		    (x) /= 10;					\
		} while ( (x) );				\
		if ( !is_unsigned && is_negative ) {		\
		    if ( --dbufoff < dbuf ) {			\
			abort();				\
		    }						\
		    *dbufoff = '-';				\
		}

		if ( is_unsigned ) {
		    if ( is_longlong ) {
			u_ll = va_arg( vl, unsigned long long );
			SNET_WF_D( u_ll );
		    } else if ( is_long ) {
			u_l = va_arg( vl, unsigned long );
			SNET_WF_D( u_l );
		    } else {
			u_d = va_arg( vl, unsigned int );
			SNET_WF_D( u_d );
		    }
		} else {
		    if ( is_longlong ) {
			ll = va_arg( vl, long long );
			SNET_WF_D( ll );
		    } else if ( is_long ) {
			l = va_arg( vl, long );
			SNET_WF_D( l );
		    } else {
			d = va_arg( vl, int );
			SNET_WF_D( d );
		    }
		}

		len = p - dbufoff;
		SNET_WBUFGROW( len );
		memcpy( cur, dbufoff, len );
		cur += len;
		break;

	    case 'o' :
		p = dbufoff = dbuf + sizeof( dbuf );

#define SNET_WF_O(x)						\
		do {						\
		    if ( --dbufoff < dbuf ) {			\
			abort();				\
		    }						\
		    *dbufoff = '0' + ( (x) & 0007 );		\
		    (x) = (x) >> 3;				\
		} while ( (x) );

		if ( is_longlong ) {
		    u_ll = va_arg( vl, unsigned long long );
		    SNET_WF_O( u_ll );
		} else if ( is_long ) {
		    u_l = va_arg( vl, unsigned long );
		    SNET_WF_O( u_l );
		} else {
		    u_d = va_arg( vl, unsigned int );
		    SNET_WF_O( u_d );
		}

		len = p - dbufoff;
		SNET_WBUFGROW( len );
		memcpy( cur, dbufoff, len );
		cur += len;
		break;

	    case 'x' :
		p = dbufoff = dbuf + sizeof( dbuf );

#define SNET_WF_X(x)						\
		do {						\
		    char	hexalpha[] = "0123456789abcdef";\
		    if ( --dbufoff < dbuf ) {			\
			abort();				\
		    }						\
		    *dbufoff = hexalpha[ (x) & 0x0f ];		\
		    (x) = (x) >> 4;				\
		} while ( (x) );

		if ( is_longlong ) {
		    u_ll = va_arg( vl, unsigned long long );
		    SNET_WF_X( u_ll );
		} else if ( is_long ) {
		    u_l = va_arg( vl, unsigned long );
		    SNET_WF_X( u_l );
		} else {
		    u_d = va_arg( vl, unsigned int );
		    SNET_WF_X( u_d );
		}

		len = p - dbufoff;
		SNET_WBUFGROW( len );
		memcpy( cur, dbufoff, len );
		cur += len;
		break;

	    case 'X' :
		p = dbufoff = dbuf + sizeof( dbuf );

#define SNET_WF_XX(x)						\
		do {						\
		    char	hexalpha[] = "0123456789ABCDEF";\
		    if ( --dbufoff < dbuf ) {			\
			abort();				\
		    }						\
		    *dbufoff = hexalpha[ (x) & 0x0f ];		\
		    (x) = (x) >> 4;				\
		} while ( (x) );

		if ( is_longlong ) {
		    u_ll = va_arg( vl, unsigned long long );
		    SNET_WF_XX( u_ll );
		} else if ( is_long ) {
		    u_l = va_arg( vl, unsigned long );
		    SNET_WF_XX( u_l );
		} else {
		    u_d = va_arg( vl, unsigned int );
		    SNET_WF_XX( u_d );
		}

		len = p - dbufoff;
		SNET_WBUFGROW( len );
		memcpy( cur, dbufoff, len );
		cur += len;
		break;

	    default :
		SNET_WBUFGROW( 2 );
		*cur++ = '%';
		*cur++ = 'E';
		break;
	    }
	}
    }

    va_end( vl );

    return( snet_write( sn, sn->sn_wbuf, cur - sn->sn_wbuf, tv ));
}

/*
 * select that updates the timeout structure.
 *
 * We could define snet_select to just be select on platforms that update
 * the timeout structure.
 */
    int
snet_select( int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
	struct timeval *tv )
{
#ifndef linux
    struct timeval	tv_begin, tv_end;
#endif /* linux */
    int			rc;

#ifndef linux
    if ( gettimeofday( &tv_begin, NULL ) < 0 ) {
	return( -1 );
    }
#endif /* linux */

    rc = select( nfds, rfds, wfds, efds, tv );

#ifndef linux
    if ( gettimeofday( &tv_end, NULL ) < 0 ) {
	return( -1 );
    }

    if ( tv_begin.tv_usec > tv_end.tv_usec ) {
	tv_end.tv_usec += 1000000;
	tv_end.tv_sec -= 1;
    }
    if (( tv->tv_usec -= ( tv_end.tv_usec - tv_begin.tv_usec )) < 0 ) {
	tv->tv_usec += 1000000;
	tv->tv_sec -= 1;
    }

    /*
     * If we've gone negative, we don't generate an additional error.  Instead,
     * we just zero tv and return whatever select() returned.  The caller
     * must inspect the fd_sets to determine that nothing was set.
     */
    if (( tv->tv_sec -= ( tv_end.tv_sec - tv_begin.tv_sec )) < 0 ) {
	tv->tv_sec = 0;
	tv->tv_usec = 0;
    }
#endif /* linux */

    return( rc );
}

    static ssize_t
snet_write0( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    size_t		len;
    struct timeval	*tv;
{
    fd_set		fds;
    int			rc, oflags;
    size_t		rlen = 0;
    struct timeval	default_tv;

#ifdef HAVE_LIBSASL
    if (( sn->sn_flag & SNET_SASL ) && ( sn->sn_saslssf )) {
	const char		*ebuf;
	unsigned		elen;

	/* Encode if SASL needs it */
	if (( sasl_encode( sn->sn_conn, buf, len, &ebuf, &elen )) != SASL_OK ) {
	    return( -1 );
	}
	buf = (char*)ebuf;
	len = elen;
    }
#endif /* HAVE_LIBSASL */

    if (( tv == NULL ) && ( sn->sn_flag & SNET_WRITE_TIMEOUT )) {
	default_tv = sn->sn_write_timeout;
	tv = &default_tv;
    }

    if ( tv == NULL ) {
	if ( sn->sn_flag & SNET_TLS ) {
#ifdef HAVE_LIBSSL
	    /*
	     * If SSL_MODE_ENABLE_PARTIAL_WRITE has been set, this routine
	     * can (abnormally) return less than a full write.
	     */
	    return( SSL_write( sn->sn_ssl, buf, len ));
#else
	    return( -1 );
#endif /* HAVE_LIBSSL */
	} else {
	    return( write( snet_fd( sn ), buf, len ));
	}
    }

    if (( oflags = fcntl( snet_fd( sn ), F_GETFL )) < 0 ) {
	return( -1 );
    }
    if (( oflags & O_NONBLOCK ) == 0 ) {
	if ( fcntl( snet_fd( sn ), F_SETFL, oflags | O_NONBLOCK ) < 0 ) {
	    return( -1 );
	}
    }

    while ( len > 0 ) {
	FD_ZERO( &fds );
	FD_SET( snet_fd( sn ), &fds );

	if ( snet_select( snet_fd( sn ) + 1, NULL, &fds, NULL, tv ) < 0 ) {
	    goto restoreblocking;
	}
	if ( FD_ISSET( snet_fd( sn ), &fds ) == 0 ) {
	    errno = ETIMEDOUT;
	    goto restoreblocking;
	}

	if ( sn->sn_flag & SNET_TLS ) {
#ifdef HAVE_LIBSSL
	    /*
	     * Make sure we ARE allowing partial writes.  This can't
	     * be turned off!!!
	     */
	    SSL_set_mode( sn->sn_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE );

	    if (( rc = SSL_write( sn->sn_ssl, buf, len )) <= 0 ) {
		switch ( SSL_get_error( sn->sn_ssl, rc )) {
		case SSL_ERROR_WANT_READ :
		    FD_ZERO( &fds );
		    FD_SET( snet_fd( sn ), &fds );

		    if ( snet_select( snet_fd( sn ) + 1,
			    &fds, NULL, NULL, tv ) < 0 ) {
			goto restoreblocking;
		    }
		    if ( FD_ISSET( snet_fd( sn ), &fds ) == 0 ) {
			errno = ETIMEDOUT;
			goto restoreblocking;
		    }

		case SSL_ERROR_WANT_WRITE :
		    continue;

		default :
		    goto restoreblocking;
		}
	    }
#else
	    goto restoreblocking;
#endif /* HAVE_LIBSSL */
	} else {
	    if (( rc = write( snet_fd( sn ), buf, len )) < 0 ) {
		if ( errno == EAGAIN ) {
		    continue;
		}
		goto restoreblocking;
	    }
	}

	buf += rc;
	rlen += rc;
	len -= rc;
    }

    if (( oflags & O_NONBLOCK ) == 0 ) {
	if ( fcntl( snet_fd( sn ), F_SETFL, oflags ) < 0 ) {
	    return( -1 );
	}
    }
    return( rlen );

restoreblocking:
    if (( oflags & O_NONBLOCK ) == 0 ) {
	if ( fcntl( snet_fd( sn ), F_SETFL, oflags ) < 0 ) {
	    return( -1 );
	}
    }
    return( -1 );
}

/* Start compression on the link. "opt" allows option parameters to be set
 * for the compression chosen by "type".
 *
 * Returns -1 for error, 0 in other cases
 */
    int
snet_setcompression( sn, type, level )
    SNET	*sn;
    int		type;
    int		level;
{
#ifdef HAVE_ZLIB
    int		len = 0;

    if ( sn->sn_flag & SNET_ZLIB ) {
	return( -1 );
    }

    if ( type != SNET_ZLIB ) {
	return( -1 );
    }

    memset( &sn->sn_zistream, 0, sizeof( sn->sn_zistream ));
    if ( inflateInit( &sn->sn_zistream ) != Z_OK ) {
	return( -1 );
    }

    memset( &sn->sn_zostream, 0, sizeof( sn->sn_zostream ));
    if ( deflateInit( &sn->sn_zostream, level ) != Z_OK ) {
	return( -1 );
    }

    if ( snet_hasdata( sn )) {
	len = sn->sn_rend - sn->sn_rcur;
    }
	
#ifndef max
#define max(a,b)	(((a)<(b))?(b):(a))
#endif /* max */
    sn->sn_zbuflen = max( SNET_BUFLEN, len );
    if (( sn->sn_zbuf = malloc( sn->sn_zbuflen )) == NULL ) {
	return( -1 );
    }

    sn->sn_zistream.next_in = (unsigned char *)sn->sn_zbuf;
    if ( len ) {
	memcpy( sn->sn_zbuf, sn->sn_rcur, len );
	sn->sn_zistream.avail_in = len;
	sn->sn_rcur = sn->sn_rend = sn->sn_rbuf;
    } else {
	sn->sn_zistream.avail_in = 0;
    }

    sn->sn_flag |= type;
    return( 0 );

#else /* HAVE_ZLIB */
    return( -1 );
#endif /* HAVE_ZLIB */
}

    static ssize_t
snet_read0( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    size_t		len;
    struct timeval	*tv;
{
#ifdef HAVE_ZLIB
    ssize_t rr;
#endif /* HAVE_ZLIB */

    if (( sn->sn_flag & SNET_ZLIB ) == 0 ) {
	return snet_read1( sn, buf, len, tv );
    }

#ifdef HAVE_ZLIB
    sn->sn_zistream.avail_out = len;
    sn->sn_zistream.next_out  = (unsigned char *)buf;

    do {
	if ( sn->sn_zistream.avail_in == 0 ) {
	    if (( rr = snet_read1( sn, sn->sn_zbuf, sn->sn_zbuflen, tv )) < 0) {
		return( -1 );
	    }
	    if ( rr == 0 ) {
		break; /* EOF */
	    }
	    sn->sn_zistream.avail_in = rr;
	    sn->sn_zistream.next_in = (unsigned char *)sn->sn_zbuf;
	}
	if ( inflate( &sn->sn_zistream, Z_SYNC_FLUSH ) != Z_OK ) {
	    return( -1 );
	}
    } while ( sn->sn_zistream.avail_out == len );
    return( len - sn->sn_zistream.avail_out );

#else /* HAVE_ZLIB */
    return( -1 );
#endif /* HAVE_ZLIB */
}

    ssize_t
snet_write( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    size_t		len;
    struct timeval	*tv;
{
#ifdef HAVE_ZLIB
    char		cobuf[ 8192 ];
    size_t		zlen;
#endif /* HAVE_ZLIB */

    if (( sn->sn_flag & SNET_ZLIB ) == 0 ) {
	return snet_write0( sn, buf, len, tv );
    }

#ifdef HAVE_ZLIB
    /* XXX What if len == 0 ? */
    sn->sn_zostream.avail_in = len;
    sn->sn_zostream.next_in  = (unsigned char *)buf;

    /* Continue until buf is at end */
    do {
	sn->sn_zostream.avail_out = sizeof( cobuf );
	sn->sn_zostream.next_out = (unsigned char *)cobuf;

	if ( deflate( &sn->sn_zostream, Z_SYNC_FLUSH ) != Z_OK ) {
	    /* ZZZ */
	    return( -1 );
	}

	zlen = sizeof( cobuf ) - sn->sn_zostream.avail_out;
	if ( zlen > 0 ) {
	    if ( snet_write0( sn, cobuf, zlen, tv ) != zlen ) {
		/* ZZZ */
		return( -1 );
	    }
	}
    } while ( sn->sn_zostream.avail_in > 0 || sn->sn_zostream.avail_out == 0 );
    return( len );
#else /* HAVE_ZLIB */

    return( -1 );
#endif /* HAVE_ZLIB */
}

    static ssize_t
snet_read1( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    size_t		len;
    struct timeval	*tv;
{
    fd_set		fds;
    ssize_t		rc;
    struct timeval	default_tv;
    extern int		errno;
    int			oflags = 0, dontblock = 0;

    if (( tv == NULL ) && ( sn->sn_flag & SNET_READ_TIMEOUT )) {
	default_tv = sn->sn_read_timeout;
	tv = &default_tv;
    }

    if ( tv ) {
	dontblock = 1;
#ifdef HAVE_LIBSSL
	/* Check to see if there is already data in SSL buffer */
	if ( sn->sn_flag & SNET_TLS ) {
	    dontblock = ! SSL_pending( sn->sn_ssl );
	}
#endif /* HAVE_LIBSSL */
    }

    if ( dontblock ) {
	if (( oflags = fcntl( snet_fd( sn ), F_GETFL )) < 0 ) {
	    return( -1 );
	}
	if (( oflags & O_NONBLOCK ) == 0 ) {
	    if (( fcntl( snet_fd( sn ), F_SETFL, oflags | O_NONBLOCK )) < 0 ) {
		return( -1 );
	    }
	}

retry:
	FD_ZERO( &fds );
	FD_SET( snet_fd( sn ), &fds );

	/* time out case? */
	if ( select( snet_fd( sn ) + 1, &fds, NULL, NULL, tv ) < 0 ) {
	    goto restoreblocking;
	}
	if ( FD_ISSET( snet_fd( sn ), &fds ) == 0 ) {
	    errno = ETIMEDOUT;
	    goto restoreblocking;
	}
    }

    if ( sn->sn_flag & SNET_TLS ) {
#ifdef HAVE_LIBSSL
	if (( rc = SSL_read( sn->sn_ssl, buf, len )) < 0 ) {
	    switch ( SSL_get_error( sn->sn_ssl, rc )) {
	    case SSL_ERROR_WANT_WRITE :
		FD_ZERO( &fds );
		FD_SET( snet_fd( sn ), &fds );

		if ( snet_select( snet_fd( sn ) + 1,
			NULL, &fds, NULL, tv ) < 0 ) {
		    goto restoreblocking;
		}
		if ( FD_ISSET( snet_fd( sn ), &fds ) == 0 ) {
		    errno = ETIMEDOUT;
		    goto restoreblocking;
		}

	    case SSL_ERROR_WANT_READ :
		goto retry;

	    default :
		goto restoreblocking;
	    }
	}
#else /* HAVE_LIBSSL */
	rc = -1;
#endif /* HAVE_LIBSSL */
    } else {
	rc = read( snet_fd( sn ), buf, len );
    }
    if ( rc == 0 ) {
	sn->sn_flag |= SNET_EOF;
    }

    if ( dontblock && (( oflags & O_NONBLOCK ) == 0 )) {
	if (( fcntl( snet_fd( sn ), F_SETFL, oflags )) < 0 ) {
	    return( -1 );
	}
    }

#ifdef HAVE_LIBSASL
    if (( sn->sn_flag & SNET_SASL ) && ( sn->sn_saslssf )) {
	/* Decode via SASL */
	const char	*dbuf;
	unsigned	dbuf_len;

	if ( sasl_decode( sn->sn_conn, buf, rc, &dbuf, &dbuf_len )
		!= SASL_OK ) {
	    return( -1 );
	}
	if ( dbuf_len > len ) {
	    /* XXX - resize buf */
	}
	memcpy( buf, dbuf, dbuf_len );
	rc = dbuf_len;
    }
#endif /* HAVE_LIBSASL */

    return( rc );

restoreblocking:
    if ( dontblock && (( oflags & O_NONBLOCK ) == 0 )) {
	if (( fcntl( snet_fd( sn ), F_SETFL, oflags )) < 0 ) {
	    return( -1 );
	}
    }
    return( -1 );
}

    int
snet_hasdata( sn )
    SNET		*sn;
{
    if ( sn->sn_rcur < sn->sn_rend ) {
	if ( sn->sn_rstate == SNET_FUZZY ) {
	    if ( *sn->sn_rcur == '\n' ) {
		sn->sn_rcur++;
	    }
	    sn->sn_rstate = SNET_BOL;
	}
	if ( sn->sn_rcur < sn->sn_rend ) {
	    return( 1 );
	}
    }
    return( 0 );
}

/*
 * External entry point for reading with the snet library.  Compatible
 * with snet_getline()'s buffering.
 */
    ssize_t
snet_read( sn, buf, len, tv )
    SNET		*sn;
    char		*buf;
    size_t		len;
    struct timeval	*tv;
{
    ssize_t		rc;

    /*
     * If there's data already buffered, make sure it's not left over
     * from snet_getline(), and then return whatever's left.
     * Note that snet_getline() calls snet_read0().
     */
    if ( snet_hasdata( sn )) {
#ifndef min
#define min(a,b)	(((a)<(b))?(a):(b))
#endif /* min */
	rc = min( sn->sn_rend - sn->sn_rcur, len );
	memcpy( buf, sn->sn_rcur, rc );
	sn->sn_rcur += rc;
	return( rc );
    }

    rc = snet_read0( sn, buf, len, tv );
    if (( rc > 0 ) && ( sn->sn_rstate == SNET_FUZZY )) {
	sn->sn_rstate = SNET_BOL;
	if ( *buf == '\n' ) {
	    if ( --rc <= 0 ) {
		rc = snet_read0( sn, buf, len, tv );
	    } else {
		memmove( buf, buf + 1, rc );
	    }
	}
    }

    return( rc );
}

/*
 * Get a null-terminated line of input, handle CR/LF issues.
 * Note that snet_getline() returns information from a common area which
 * may be overwritten by subsequent calls.
 */
    char *
snet_getline( sn, tv )
    SNET		*sn;
    struct timeval	*tv;
{
    char		*eol, *line;
    ssize_t		rc;
    extern int		errno;

    for ( eol = sn->sn_rcur; ; eol++ ) {
	if ( eol >= sn->sn_rend ) {				/* fill */
	    /* pullup */
	    if ( sn->sn_rcur > sn->sn_rbuf ) {
		if ( sn->sn_rcur < sn->sn_rend ) {
		    memmove( sn->sn_rbuf, sn->sn_rcur,
			    (unsigned)( sn->sn_rend - sn->sn_rcur ));
		}
		eol = sn->sn_rend = sn->sn_rbuf + ( sn->sn_rend - sn->sn_rcur );
		sn->sn_rcur = sn->sn_rbuf;
	    }

	    /* expand */
	    if ( sn->sn_rend == sn->sn_rbuf + sn->sn_rbuflen ) {
		if ( sn->sn_maxlen != 0 && sn->sn_rbuflen >= sn->sn_maxlen ) {
		    errno = ENOMEM;
		    return( NULL );
		}
		if (( sn->sn_rbuf = (char *)realloc( sn->sn_rbuf,
			sn->sn_rbuflen + SNET_BUFLEN )) == NULL ) {
		    exit( 1 );
		}
		sn->sn_rbuflen += SNET_BUFLEN;
		eol = sn->sn_rend = sn->sn_rbuf + ( sn->sn_rend - sn->sn_rcur );
		sn->sn_rcur = sn->sn_rbuf;
	    }

	    if (( rc = snet_read0( sn, sn->sn_rend,
		    sn->sn_rbuflen - ( sn->sn_rend - sn->sn_rbuf ),
		    tv )) < 0 ) {
		return( NULL );
	    }
	    if ( rc == 0 ) {	/* EOF */
		/*
		 * When we did the read, we made sure we had space to
		 * read, so when we place the '\0' below, we have space
		 * for that.
		 */
		if ( sn->sn_rcur < sn->sn_rend ) {
		    break;
		}
		return( NULL );
	    }
	    sn->sn_rend += rc;
	}

	if ( *eol == '\r' || *eol == '\0' ) {
	    sn->sn_rstate = SNET_FUZZY;
	    break;
	}
	if ( *eol == '\n' ) {
	    if ( sn->sn_rstate == SNET_FUZZY ) {
		sn->sn_rstate = SNET_BOL;
		sn->sn_rcur = eol + 1;
		continue;
	    }
	    sn->sn_rstate = SNET_BOL;
	    break;
	}
	sn->sn_rstate = SNET_IN;
    }

    *eol = '\0';
    line = sn->sn_rcur;
    sn->sn_rcur = eol + 1;
    return( line );
}

    char * 
snet_getline_multi( sn, logger, tv )
    SNET		*sn;
    void		(*logger)( char * );
    struct timeval	*tv;
{
    char		*line; 

    do {
	if (( line = snet_getline( sn, tv )) == NULL ) {
	    return ( NULL );
	}

	if ( logger != NULL ) {
	    (*logger)( line );
	}

	if ( strlen( line ) < 3 ) {
	    errno = EINVAL;
	    return( NULL );
	}

	if ( !isdigit( (int)line[ 0 ] ) ||
		!isdigit( (int)line[ 1 ] ) ||
		!isdigit( (int)line[ 2 ] )) {
	    errno = EINVAL;
	    return( NULL );
	}

	if ( line[ 3 ] != '\0' &&
		line[ 3 ] != ' ' &&
		line [ 3 ] != '-' ) {
	    errno = EINVAL;
	    return ( NULL );
	}

    } while ( line[ 3 ] == '-' );

    return( line );
}
