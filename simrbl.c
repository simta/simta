#include "config.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* HAVE_LIBSSL */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <arpa/inet.h>

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

#include "denser.h"
#include "envelope.h"
#include "mx.h"
#include "ll.h"
#include "simta.h"

#define SIMRBL_EXIT_NOT_BLOCKED	0
#define SIMRBL_EXIT_BLOCKED	1
#define SIMRBL_EXIT_ERROR	2


    int
main( int argc, char *argv[])
{
    extern int          optind;
    extern char         *optarg;
    char		*error_txt;
    char		c;
    char		*server = NULL;
    int			rc;
    int			err = 0;
    int			quiet = 0;

    struct in_addr	addr;


    while(( c = getopt( argc, argv, "dl:s:q" )) != -1 ) {
	switch( c ) {
	case 'd':
	    simta_debug++;
	    break;

	case 'l':
	    simta_rbl_domain = optarg;
	    break;

	case 'q':
	    quiet++;
	    break;

	case 's':
	    server = optarg;
	    break;

	default:
	    err++;
	    break;
	}
    }

    if (( argc - optind ) != 1 ) {
	err++;
    }

    if ( err ) {
	fprintf( stderr, "Usage: %s [ -dq ] [ -l rbl-doman ] ", argv[ 0 ] );
	fprintf( stderr, "[ -s server ] " );
	fprintf( stderr, "address\n" );
	exit( EX_USAGE );
    }

    if ( server != NULL ) {
	if (( simta_dnsr = dnsr_new( )) == NULL ) {
	    perror( "dnsr_new" );
	    exit( SIMRBL_EXIT_ERROR );
	}
	if (( rc = dnsr_nameserver( simta_dnsr, optarg )) != 0 ) {
	    dnsr_perror( simta_dnsr, "dnsr_nameserver" );
	    exit( SIMRBL_EXIT_ERROR );
	}
	if ( simta_debug ) fprintf( stderr, "using nameserver: %s\n", server );
    }

    if ( simta_rbl_domain == NULL ) {
	simta_rbl_domain = "rbl.mail.umich.edu";
    }

    if ( simta_user_rbl_domain == NULL ) {
	simta_user_rbl_domain = "rbl-plus.mail-abuse.org";
    }

    rc = inet_pton( AF_INET, argv[ optind ], &addr );
    if ( rc < 0 ) {
	perror( "inet_pton" );
	exit( SIMRBL_EXIT_ERROR );
    } else if ( rc == 0 ) {
	fprintf( stderr, "%s: invalid address\n", argv[ optind ] );
	exit( SIMRBL_EXIT_ERROR );
    }

    if (( rc = check_rbl( &addr, simta_rbl_domain, &error_txt )) < 0 ) {
	if ( !quiet ) fprintf( stderr, "check_rbl failed\n" );
	exit( SIMRBL_EXIT_ERROR );
    }

    if ( rc == 0 ) {
	if ( !quiet ) printf( "blocked\n" );
	if ( error_txt != NULL ) {
	    if ( !quiet ) printf( "%s\n", error_txt );
	    free( error_txt );
	}
	exit( SIMRBL_EXIT_BLOCKED );
    } else {
	if ( !quiet ) printf( "not blocked\n" );
	exit( SIMRBL_EXIT_NOT_BLOCKED );
    }
}
