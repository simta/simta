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

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include <snet.h>

#include "denser.h"
#include "envelope.h"
#include "ll.h"
#include "mx.h"
#include "simta.h"

#define SIMRBL_EXIT_NOT_BLOCKED	0
#define SIMRBL_EXIT_BLOCKED	1
#define SIMRBL_EXIT_ERROR	2


    int
main( int argc, char *argv[])
{
    extern int          optind;
    extern char         *optarg;
    char		c;
    char		*server = NULL;
    char		*block_domain = "rbl.mail.umich.edu";
    char		*rbl_msg = NULL;
    int			rc;
    int			err = 0;
    int			quiet = 0;
    int			nolog = 0;

    struct in_addr	addr;
    struct rbl		*rbl_found;

    while(( c = getopt( argc, argv, "dl:ns:q" )) != -1 ) {
	switch( c ) {
	case 'd':
	    simta_debug++;
	    break;

	case 'l':
	    block_domain = optarg;
	    break;

	case 'n':
	    nolog = 1;
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
	fprintf( stderr, "Usage: %s [ -dq ] [ -l rbl-domain ] ", argv[ 0 ] );
	fprintf( stderr, "[ -s server ] " );
	fprintf( stderr, "address\n" );
	exit( EX_USAGE );
    }

    if ( server != NULL ) {
	if (( simta_dnsr = dnsr_new( )) == NULL ) {
	    perror( "dnsr_new" );
	    exit( SIMRBL_EXIT_ERROR );
	}
	if (( rc = dnsr_nameserver( simta_dnsr, server )) != 0 ) {
	    dnsr_perror( simta_dnsr, "dnsr_nameserver" );
	    exit( SIMRBL_EXIT_ERROR );
	}
	if ( simta_debug ) fprintf( stderr, "using nameserver: %s\n", server );
    }

    if ( nolog == 0 ) {
	simta_openlog( 0 );
	simta_rbl_verbose_logging = 1;
    }

    if ( rbl_add( &simta_rbls, RBL_BLOCK, block_domain, "none" ) != 0 ) {
        perror( "malloc" );
        exit( SIMRBL_EXIT_ERROR );
    }     

    rc = inet_pton( AF_INET, argv[ optind ], &addr );
    if ( rc < 0 ) {
	perror( "inet_pton" );
	exit( SIMRBL_EXIT_ERROR );
    } else if ( rc == 0 ) {
	fprintf( stderr, "%s: invalid address\n", argv[ optind ] );
	exit( SIMRBL_EXIT_ERROR );
    }

    simta_rbl_verbose_logging = 1;
    if (( rc = rbl_check( simta_rbls, &addr, NULL, &rbl_found, &rbl_msg ))
	    == RBL_ERROR ) {
	if ( !quiet ) fprintf( stderr, "check_rbl failed\n" );
	exit( SIMRBL_EXIT_ERROR );
    }

    if ( rc == RBL_BLOCK ) {
	if ( !quiet ) printf( "found in %s: %s\n", rbl_found->rbl_domain,
		rbl_msg );
	exit( SIMRBL_EXIT_BLOCKED );
    } else {
	if ( !quiet ) printf( "not found\n" );
	exit( SIMRBL_EXIT_NOT_BLOCKED );
    }
}
