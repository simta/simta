#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif TLS

#include <snet.h>

char	*host = "rsug";

void	logger( char * );

    void
logger( char *p )
{
    puts( p );
    return;
}

    int
main( int ac, char *av[] )
{
    int			i, c, err = 0, s;
    unsigned short	port = 0;
    struct hostent	*hp;
    struct timeval	timeout = { 10, 0 }, tv;
    struct sockaddr_in	sin;
    SNET		*snet, *stty;
    SSL_CTX		*ctx = NULL;
    char		*line, *cryptofile = NULL;
    fd_set		fdset;
    int			starttls = 0, use_randfile = 0;

    while (( c = getopt( ac, av, "C:rp:" )) != EOF ) {
	switch ( c ) {
	case 'p' :
	    port = htons( atoi( optarg ));
	    break;

	case 'r' :
	    use_randfile = 1;
	    break;

	case '?' :
	default :
	    err++;
	    break;
	}
    }

    if (( port == 0 ) || err || ( optind == ac )) {
	fprintf( stderr, "Usage:\t%s -p port hostname\n", av[ 0 ] );
	exit( 1 );
    }

    SSL_load_error_strings();
    SSL_library_init();

    if ( use_randfile ) {
	char	randfile[ MAXPATHLEN ];

	if ( RAND_file_name( randfile, sizeof( randfile )) == NULL ) {
	    fprintf( stderr, "RAND_file_name: %s\n",
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	if ( RAND_load_file( randfile, -1 ) <= 0 ) {
	    fprintf( stderr, "RAND_load_file: %s: %s\n", randfile,
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
	if ( RAND_write_file( randfile ) < 0 ) {
	    fprintf( stderr, "RAND_write_file: %s: %s\n", randfile,
		    ERR_error_string( ERR_get_error(), NULL ));
	    exit( 1 );
	}
    }

    if (( ctx = SSL_CTX_new( SSLv23_client_method())) == NULL ) {
	fprintf( stderr, "SSL_CTX_new: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }

#ifdef notdef
    if ( SSL_CTX_use_PrivateKey_file( ctx, "CERT.pem", SSL_FILETYPE_PEM )
	    != 1 ) {
	fprintf( stderr, "SSL_CTX_use_PrivateKey_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_use_certificate_chain_file( ctx, "CERT.pem" ) != 1 ) {
	fprintf( stderr, "SSL_CTX_use_certificate_chain_file: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
    if ( SSL_CTX_check_private_key( ctx ) != 1 ) {
	fprintf( stderr, "SSL_CTX_check_private_key: %s\n",
		ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }
#endif notdef

    if ( SSL_CTX_load_verify_locations( ctx, "CA.pem", NULL ) != 1 ) {
	fprintf( stderr, "SSL_CTX_load_verify_locations: %s: %s\n",
		cryptofile, ERR_error_string( ERR_get_error(), NULL ));
	exit( 1 );
    }

    SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, NULL );

    host = av[ optind ];

    if (( hp = gethostbyname( host )) == NULL ) {
	fprintf( stderr, "%s: Unknown\n", host );
	exit( 1 );
    }

    for ( i = 0; hp->h_addr_list[ i ] != NULL; i++ ) {
	if (( s = socket( PF_INET, SOCK_STREAM, NULL )) < 0 ) {
	    perror( "socket" );
	    exit( 1 );
	}
	memset( &sin, 0, sizeof( struct sockaddr_in ) );
	sin.sin_family = AF_INET;
	sin.sin_port = port;
	memcpy( &sin.sin_addr.s_addr, hp->h_addr_list[ i ],
		(unsigned int)hp->h_length );
	fprintf( stderr, "Trying %s...", inet_ntoa( sin.sin_addr ));
	fflush( stderr );
	if ( connect( s, ( struct sockaddr *)&sin,
		sizeof( struct sockaddr_in ) ) != 0 ) {
	    perror( "connect" );
	    (void)close( s );
	    continue;
	}
	fprintf( stderr, "ok.\n" );
	if (( snet = snet_attach( s, 1024 * 1024 )) == NULL ) {
	    perror( "snet_attach" );
	    exit( 1 );
	}
	tv = timeout;
	if (( line = snet_getline_multi( snet, logger, &tv )) == NULL ) {
	    perror( "snet_getline_multi" );
	    if ( snet_close( snet ) != 0 ) {
		perror( "snet_close" );
	    }
	    continue;
	}
	if ( *line !='2' ) {
	    fprintf( stderr, "%s\n", line );
	    if ( snet_close( snet ) != 0 ) {
		perror( "snet_close" );
	    }
	    continue;
	}
	break;
    }
    if ( hp->h_addr_list[ i ] == NULL ) {
	fprintf( stderr, "Connection failed\n" );
	exit( 1 );
    }

    if (( stty = snet_attach( 0, 1024 * 1024 )) == NULL ) {
	perror( "snet_attach" );
	exit( 1 );
    }

    FD_ZERO( &fdset );
    for (;;) {
	FD_SET( snet_fd( stty ), &fdset );
	FD_SET( snet_fd( snet ), &fdset );

	if ( select( snet_fd( snet ) + 1, &fdset, NULL, NULL, NULL ) < 0 ) {
	    perror( "select" );
	    exit( 1 );
	}

	if ( FD_ISSET( snet_fd( stty ), &fdset )) {
	    tv = timeout;
	    if (( line = snet_getline( stty, &tv )) == NULL ) {
		printf( "QUIT\n" );
		line = "QUIT";
	    }
	    /* check commands */
	    snet_writef( snet, "%s\r\n", line );
	    if ( strcasecmp( line, "STARTTLS" ) == 0 ) {
		starttls = 1;
	    }
	}

	if ( FD_ISSET( snet_fd( snet ), &fdset )) {
	    tv = timeout;
	    if (( line = snet_getline_multi( snet, logger, &tv )) == NULL ) {
		if ( snet_eof( snet )) {
		    /* This is the only way out */
		    fprintf( stderr, "Connection closed\n" );
		    exit( 0 );
		} else {
		    perror( "XXX snet_getline_multi" );
		    exit( 1 );
		}
	    }
	    if ( starttls ) {
		starttls = 0;
		if ( *line == '2' )  {
		    X509	*peer;
		    char	buf[ 1024 ];

		    if ( snet_starttls( snet, ctx, 0 ) != 1 ) {
			fprintf( stderr, "snet_starttls: %s\n",
				ERR_error_string( ERR_get_error(), NULL ) );
			continue;
		    }
		    if (( peer = SSL_get_peer_certificate( snet->sn_ssl ))
			    == NULL ) {
			fprintf( stderr, "no certificate\n" );
			continue;
		    }
		    fprintf( stderr, "CERT Subject: %s\n", X509_NAME_oneline( X509_get_subject_name( peer ), buf, sizeof( buf )));
		    X509_free( peer );
		}
	    }
	}
    }
}
