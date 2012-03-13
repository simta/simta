#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "denser.h"
#include "internal.h"

struct _error {
    int		e_errno;
    char	*e_string;
};

static struct _error _dnsr_error_txt[ DNSR_MAX_ERRNO + 2 ] = {
    { DNSR_ERROR_NONE, "no error" },
    { DNSR_ERROR_FORMAT, "format error" },
    { DNSR_ERROR_SERVER, "server failure" },
    { DNSR_ERROR_NAME, "domain name does not exist" },
    { DNSR_ERROR_NOT_IMPLEMENTED, "query not supported" },
    { DNSR_ERROR_REFUSED, "refused" },
    { 6, "reserved" },
    { 7, "reserved" },
    { DNSR_ERROR_CONFIG, "config file" },
    { DNSR_ERROR_NO_QUERY, "no query sent" },
    { DNSR_ERROR_TIMEOUT, "timeout" },
    { DNSR_ERROR_ID_WRONG, "wrong response ID" },
    { DNSR_ERROR_NOT_RESPONSE, "no response" },
    { DNSR_ERROR_NO_RECURSION, "recursion not available" },
    { DNSR_ERROR_QUESTION_WRONG, "invalid question in result" },
    { DNSR_ERROR_NO_ANSWER, "no answer" },
    { DNSR_ERROR_TRUNCATION, "message truncated" },
    { DNSR_ERROR_SYSTEM, "system error" },
    { DNSR_ERROR_SIZELIMIT_EXCEEDED, "sizelimit exceeded" },
    { DNSR_ERROR_NS_INVALID, "invalid name server" },
    { DNSR_ERROR_NS_DEAD, "name server down" },
    { DNSR_ERROR_TV, "invalid time value" },
    { DNSR_ERROR_FD_SET, "wrong FD set" },
    { DNSR_ERROR_PARSE, "parse failed" },
    { DNSR_ERROR_STATE, "unknown state" },
    { DNSR_ERROR_TYPE, "unknown type" },
    { DNSR_ERROR_RCODE, "unknown rcode" },
    { DNSR_ERROR_TOGGLE, "unknown toggle" },
    { DNSR_ERROR_FLAG, "unknown flag" },
    { DNSR_ERROR_CLASS, "unknown class" },
    { DNSR_ERROR_Z, "Z code not zero" },
    { DNSR_ERROR_CONNECTION_CLOSED, "connection closes" },
    { DNSR_ERROR_UNKNOWN, "unknown" }
};

    int
dnsr_errno( DNSR *dnsr )
{
    return( dnsr->d_errno );
}

    void
dnsr_errclear( DNSR *dnsr )
{
    dnsr->d_errno = DNSR_ERROR_NONE;
    return;
}

    char *
dnsr_err2string( int dnsr_errno )
{
    /* check if < 0 or > max, and then just return as offest */
    if ( dnsr_errno < 0 || dnsr_errno > DNSR_MAX_ERRNO ) {
	return( _dnsr_error_txt[ DNSR_ERROR_UNKNOWN ].e_string );
    } else {
	return( _dnsr_error_txt[ dnsr_errno ].e_string );
    }
}

    void
dnsr_perror( DNSR *dnsr, const char *s )
{
    if ( dnsr->d_errno == DNSR_ERROR_SYSTEM ) {
	perror( s );
    } else {
	fprintf( stderr, "%s: %s\n", s, dnsr_err2string( dnsr->d_errno ));
    }
}
