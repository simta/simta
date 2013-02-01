#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "denser.h"
#include "internal.h"
#include "argcargv.h"
#include "timeval.h"
#include "bprint.h"

static int _dnsr_parse_resolv( DNSR *dnsr );
static int _dnsr_nameserver_add( DNSR *dnsr, char *nameserver, int index );
static void _dnsr_nameserver_reset( DNSR *dnsr );

static char *dnsr_resolvconf_path = _DNSR_RESOLV_CONF_PATH;

/*
 * TODO:  accept an auth section to configure name servers
 * Limit of 4 name servers
 * expects a UNIX resolv.conf ( XXX - posix? )
 */

    int
dnsr_nameserver( DNSR *dnsr, char *server )
{
    int			rc;

    /* Clear any existing nameservers */
    _dnsr_nameserver_reset( dnsr );

    if ( server == NULL ) {
	if (( rc = _dnsr_parse_resolv( dnsr )) != 0 ) {
	    return( rc );
	}
    } else {
	if (( rc = _dnsr_nameserver_add( dnsr, server, 0 )) != 0 ) {
	    return( rc );
	}
	dnsr->d_nscount++;
    }

    /* Set default NS */
    if ( dnsr->d_nscount == 0 ) {
	if (( rc = _dnsr_nameserver_add( dnsr, "INADDR_LOOPBACK", 0 )) != 0 ) {
	    return( rc );
	}
	dnsr->d_nscount++;
    }

    return( 0 );
}

    int
dnsr_config( DNSR *dnsr, int flag, int toggle )
{
    switch( flag ) {
    case DNSR_FLAG_RECURSION:
	switch( toggle ) {
	case DNSR_FLAG_ON:
	    dnsr->d_flags = dnsr->d_flags | DNSR_RECURSION_DESIRED;
	    break;

	case DNSR_FLAG_OFF:
	    dnsr->d_flags = dnsr->d_flags & ~DNSR_RECURSION_DESIRED;
	    break;

	default:
	    DEBUG( fprintf( stderr, "dnsr_config: %d: unknown toggle\n",
		toggle ));
	    dnsr->d_errno = DNSR_ERROR_TOGGLE;
	    return( -1 );
	}
	break;

    default:
	DEBUG( fprintf( stderr, "dnsr_config: %d: unknown flag\n", flag ));
	dnsr->d_errno = DNSR_ERROR_FLAG;
	return( -1 );
    }

    return( 0 );
}

/* An empty file, or one without any valid nameservers defaults to local host
 * Can only add one server by hand, that will use default port
 */

    static int
_dnsr_parse_resolv( DNSR *dnsr )
{
    int				len, rc;
    uint			linenum = 0;
    char			buf[ DNSR_MAX_LINE ];
    char			**argv;
    int				argc;
    FILE			*f;

    if (( f = fopen( dnsr_resolvconf_path, "r" )) == NULL ) {
	DEBUG( perror( dnsr_resolvconf_path ));
	/* Not an error if DNSR_RESOLVECONF_PATH missing - not required */
	if ( errno == ENOENT ) {
	    errno = 0;
	    return( 0 );
	} else {
	    dnsr->d_errno = DNSR_ERROR_SYSTEM;
	    return( -1 );
	}
    }

    while ( fgets( (char*)&buf, DNSR_MAX_LINE, f ) != 0 ) {
	linenum++;

	len = strlen( buf );
	if ( buf[ len - 1] != '\n' ) {
	    DEBUG( fprintf( stderr, "parse_resolve: %s: %d: line too long\n",
		dnsr_resolvconf_path, linenum ));
	    continue;
	}

	if (( argc = acav_parse( NULL, buf, &argv )) < 0 ) {
	    DEBUG( perror( "parse_resolve: acav_parse" ));
	    dnsr->d_errno = DNSR_ERROR_SYSTEM;
	    return( -1 );
	}

	if (( argc == 0 ) || ( *argv[ 0 ] == '#' )) {
	    continue;
	}

	if ( strcmp( argv[ 0 ], "nameserver" ) == 0 ) {
	    if ( dnsr->d_nscount < DNSR_MAX_NS ) {
		if (( rc = _dnsr_nameserver_add( dnsr, argv[ 1 ],
			dnsr->d_nscount ) != 0 )) {
		    return( rc );
		}
		dnsr->d_nscount++;
	    } else {
		DEBUG( fprintf( stderr,
		    "parse_resolve: nameserver %s not added: too many\n",
		    argv[ 1 ] ));
	    }
	}
    }
    if ( ferror( f )) {
	DEBUG( perror( "fgets" ));
	dnsr->d_errno = DNSR_ERROR_SYSTEM;
	return( -1 );
    }
    if ( fclose( f ) != 0 ) {
	DEBUG( perror( "fclose" ));
	dnsr->d_errno = DNSR_ERROR_SYSTEM;
	return( -1 );
    }

    return( 0 );
}

    static int
_dnsr_nameserver_add( DNSR *dnsr, char *nameserver, int index )
{
    if (( index < 0 ) || ( index > DNSR_MAX_NS )) {
	DEBUG( fprintf( stderr, "%d: index out of range\n", index ));
	dnsr->d_errno = DNSR_ERROR_CONFIG;
	return( 1 );
    }
    DEBUG( fprintf( stderr, "name server %d: %s\n", index, nameserver ));

    dnsr->d_nsinfo[ index ].ns_id = rand( ) & 0xffff;
    dnsr->d_nsinfo[ index ].ns_sa.sin_family = AF_INET;
    dnsr->d_nsinfo[ index ].ns_sa.sin_port = htons( DNSR_DEFAULT_PORT );

    /* move up if error */
    if (( dnsr->d_nsinfo[ index ].ns_sa.sin_addr.s_addr =
	    inet_addr( nameserver )) == INADDR_NONE ) {
	DEBUG( fprintf( stderr,
	    "inet_addr: %s: malformed hostname\n", nameserver ));
	dnsr->d_errno = DNSR_ERROR_CONFIG;
	return( 1 );
    }

    return ( 0 );
}

    void
_dnsr_nameserver_reset( DNSR *dnsr )
{
    int		i;

    for ( i = 0; i < dnsr->d_nscount; i++ ) {
	dnsr->d_nsinfo[ i ].ns_id = 0;
    }
    dnsr->d_nscount = 0;
}
