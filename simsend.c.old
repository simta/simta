/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <pwd.h>


#include <krb.h>

#include <snet.h>
#include "rfc822.h"
#include "rcptlist.h"
#include "simsend.h"
#include "base64.h"

char            *host = "smtp";

#define OPT_IGNOREDOTS		( 1 << 0 )
#define OPT_RCPTHEADERS		( 1 << 1 )
#define OPT_VERBOSE		( 1 << 2 )

    int
transmit_headers( net, d_head, options )
    SNET			*net;
    struct datalines	*d_head;
    int			options;
{
    char 		*line;

    if ( snet_writef( net, "DATA\r\n" ) < 0 ) {
	perror( "snet_writef" );
	exit( EX_IOERR );
    }

    if (( line = snet_getline( net, NULL )) == NULL ) {
	perror( "snet_getline" );
	exit( EX_IOERR );
    }
    if ( options & OPT_VERBOSE ) printf("<<< %s\n", line );

    dl_output( d_head, net );

    return( 0 );
}

void	(*logger)( char * );

    SNET	*
smtp_connect( port, ourhostname, options )
    unsigned short	port;
    int			options;
    char		*ourhostname;
{

    char		hostname[ MAXHOSTNAMELEN ], *line;
    struct sockaddr_in	sin;
    int 		i, s;
    struct hostent	*hp;
    struct servent	*se;
    SNET			*net;
    
    if ( port == 0 ) {
	if (( se = getservbyname( "smtp", "tcp" )) == NULL ) {
	    fprintf( stderr, "can't find smtp service\n continuing...\n" );
	    port = htons( 25 );
	} else {
	    port = se->s_port;
	}
    }

    if (( hp = gethostbyname( host )) == NULL ) {
	fprintf( stderr, "%s: Can't find address.\n", host );
	exit( 1 );
    }
    strcpy( hostname, hp->h_name );

    memset( &sin, 0, sizeof( struct sockaddr_in ));
    sin.sin_family = AF_INET;
    sin.sin_port = port;
    for ( i = 0; hp->h_addr_list[ i ] != NULL; i++ ) {
        if (( s = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
            perror( "socket" );
            exit( EX_TEMPFAIL );
        }
        /* address in sin, for later */
        memcpy( &sin.sin_addr.s_addr, hp->h_addr_list[ i ],
                (unsigned)hp->h_length );
        if ( connect( s, (struct sockaddr *)&sin,
                sizeof( struct sockaddr_in )) < 0 ) {

            perror( inet_ntoa( *(struct in_addr *)hp->h_addr_list[ i ] ) );
            close( s );
            continue;
        }

        if (( net = snet_attach( s, 1024 * 1024 )) == NULL ) {
            perror( "snet_attach" );
            exit( EX_OSERR );
        }

        if (( line = snet_getline_multi( net, logger, NULL )) == NULL ) {
            perror( "snet_getline_multi" );
            exit( EX_IOERR );
        }

        if ( *line != '2' ) {
            fprintf( stderr, "%s\n", line );
	    snet_close( net );
            continue;
        } else {
            break;
        }
    }

    if ( snet_writef( net, "EHLO %s\r\n", ourhostname ) < 0 ) {
	perror( "snet_writef" );
	exit( EX_IOERR );
    }
    if ( options & OPT_VERBOSE )  printf( ">>> EHLO %s\n", ourhostname);

    /*
     * To do AUTH, we need to send EHLO and parse the extended response.
     * We can check the banner for ESMTP, right?  If we are talking to
     * an ESMTP server, and the server supports AUTH with a protocol we
     * know, then we should AUTH.
     */

    if (( line = snet_getline_multi( net, logger , NULL)) == NULL ) {
	perror( "snet_getline" );
	exit( EX_IOERR );
    }
    if ( *line != '2' ) {
	/* XXX if EHLO has failed, try HELO */
	fprintf( stderr, "%s\n", line );
	snet_close( net );
	exit( 1 );
    }

    auth_krb4( net, ( options & OPT_VERBOSE ) != 0 );

    return( net );
}

    int
read_headers( d_head, rcpthead, sender, options )
    struct datalines	**d_head;
    struct rcptlist	**rcpthead;
    char		*sender;
    int			options;
{
    struct datalines    **d_tail;
    struct datalines	**d_to;
    struct datalines	**d_cc;
    int 		dot, state;
    int 		keyheaders=0;
    char 		buf[ 8192 ], *to_field;
    struct rcptlist	*r;
    int			h_to = 0;
    int			h_cc = 0;
    unsigned int	rcptlist_items, rcptlist_len;

    /* taken pretty much directly from beep.c and command.c in beepage-0.9 */
#define ST_BEGIN        0
#define ST_TRUNC        1

    state = ST_BEGIN;

    /* Intercept the line before sending it to the smtp server.
       We want to insure the integrity of the headers. No Illegal
       mail from simsend!

       The DATA part will take place in two phases. In the headers phase,
       each alleged header will be examined to see if it complies with
       rfc822 until a blank line separating the headers from the body
       has been received. The collected list of headers will then be
       examined, and missing required headers will be added.

       In the body phase, each line will be sent to the smtp server
       without examination, until an EOF or \n.\n is encountered.
    */

    dot = 0;
    /*
     * We're calling fgets() here, but we're not doing line too long checking.
     * Either we should check for that case, or we should use snet_getline()
     * to avoid the issue.  XXX
     */
    while ( fgets( buf, sizeof( buf ), stdin ) != NULL ) {
        if ( ! ( options & OPT_IGNOREDOTS ) ) {
            if ( *buf == '.' ) {
                if ( strcmp( buf, ".\n" ) == 0 ) {
                    dot = 1;
                    break;  /* same as EOF */
                }
            }
        }
        if ( dl_append( &d_head, &d_tail, "%s", buf ) < 0 ) {
            fprintf( stderr, "Fuck...\n" );
            return( -1 );
        }
        if ( *buf == '\n' ) {
            break;
        }
        if ( parse_header( buf, &keyheaders, &h_to, &h_cc ) < 0 ) {
            keyheaders = h_to = h_cc = 0;
            break;
        }
	 
	if ( h_to == 1 ) {
	    d_to = d_tail;
	    h_to = 0;
	} else if ( h_cc == 1 ) {
	    d_cc = d_tail;
	    h_cc = 0;
	}
    }

    /*  If there is no recipient specified in the headers, add the members of
        the recipient list.
    */
    if ( ! ( keyheaders & IH_TO ) ) {
        if ( options & OPT_RCPTHEADERS ) {
	    fprintf( stderr, "No recipient addresses found in header\n" );
	    return( -1 );
	}

	rcptlist_items = rcptlist_len = 0;

        for ( r = *rcpthead; r != NULL; r = r->r_next ) {
	    rcptlist_items++;
	    rcptlist_len += strlen( r->r_rcpt );
	}

	/*  each rcptlist item plus a space, a comma, minus the space and comma
	    for the ending guy, plus the "To: "  plus the null char */
	if (( to_field = (char *)malloc( rcptlist_len + 
				( 2 * rcptlist_items ) + 3 ) ) == NULL ) {
	    perror( "malloc" );
	    return( -1 );
	}

	sprintf( to_field, "To: %s", (*rcpthead)->r_rcpt );
	for ( r = (*rcpthead)->r_next; r!= NULL; r = r->r_next ) {
	    strcat( to_field, ", " );
	    strcat( to_field, r->r_rcpt );
	}

	if ( dl_prepend( &d_head, "%s\n", to_field ) < 0 ) {
	    printf( "Fuck...\n");
            return( -1 );
	}

    } else {
	/* TODO */
	/* if there was a -t flag, populate the rcptlist with the ppl here */
    }

    if ( ! ( keyheaders & IH_FROM ) ) {
        if (dl_prepend(&d_head, "From: %s\n", sender ) < 0 ) {
            printf( "Fuck...\n");
            return( -1 );
        }
    }
    return( 0 );
}

    int
transmit_envelope( net, rcpthead, sender, options )
    SNET			*net;
    struct rcptlist	*rcpthead;
    char		*sender;
    int			options;
{

    struct rcptlist	*r;
    char		*line;


    /* do the MAIL FROM and RCPT TO transactions. */

    if ( snet_writef( net, "MAIL FROM:<%s>\r\n", sender ) < 0 ) {
	perror( "snet_writef" );
	exit( EX_IOERR );
    }
    if ( options & OPT_VERBOSE )  printf( ">>> MAIL FROM: %s\n", sender );
    
    if (( line = snet_getline( net, NULL )) == NULL ) {
	perror( "snet_getline" );
	exit( EX_IOERR );
    }
    if ( options & OPT_VERBOSE )  printf( "<<< %s\n", line );

    if ( *line != '2' ) { 
        fprintf( stderr, "%s\n", line );
	return( -1 );
    }

    for ( r = rcpthead; r != NULL; r = r->r_next ) {
	if ( snet_writef( net, "RCPT TO: %s\r\n", r->r_rcpt ) < 0 ) {
	    perror( "snet_writef" );
	    exit( EX_IOERR );
	}
	if ( options & OPT_VERBOSE )  printf( ">>> RCPT TO:<%s>\n", r->r_rcpt );

	if (( line = snet_getline( net, NULL )) == NULL ) {
	    perror( "snet_getline" );
	    exit( EX_IOERR );
	}
	if ( options & OPT_VERBOSE )  printf( "<<< %s\n", line );

	if ( *line != '2' ) { 
	    fprintf( stderr, "%s\n", line );
	    return( -1 );
	}
    }
    return( 0 );
}

    int
read_body( net, options )
    SNET		*net;
    int		options;
{

    char	buf[ 1024 ];
    int		state;

#define ST_BEGIN	0
#define ST_TRUNC	1

    state = ST_BEGIN;

    /*
     * Here we *do* check for line that are too long.  This code should match
     * the read code in read_headers().  If that changes to snet_getline(),
     * then this should, too.  XXX
     */
    while ( fgets( buf, sizeof( buf ), stdin ) != NULL ) {
	if ( ( state == ST_BEGIN ) && ( ! ( options & OPT_IGNOREDOTS ) ) ) {
	    if ( *buf == '.' ) {
		if ( strcmp( buf, ".\n" ) == 0 ) {
		    break;
		} else {
		    /* Hidden dot algorithm */
		    if ( snet_writef( net, "." ) < 0 ) {
		       perror( "snet_writef" );
		       exit( EX_IOERR );
		    }
		}
	    }
	}

	if ( buf[ strlen( buf ) - 1 ] == '\n' ) {
	    state = ST_BEGIN;
	    buf[ strlen( buf ) - 1 ] = '\0';
	    if ( snet_writef( net, "%s\r\n", buf ) < 0 ) {
	        perror( "snet_writef" );
		exit( EX_IOERR );
	    }
	} else {
	    state = ST_TRUNC;
	    if ( snet_writef( net, "%s", buf ) < 0 ) {
	        perror( "snet_writef" );
		exit( EX_IOERR );
	    }
	}
    }
    if ( snet_writef( net, "\r\n.\r\n" ) < 0 ) {
	perror( "snet_writef" );
	exit( EX_IOERR );
    }
    if ( options & OPT_VERBOSE )  printf( ">>> .\n" );

    return( 0 );
}


    void
smtp_logger( char *msg )
{
    printf( "<<< %s\n", msg );
    return;
}

    int
main( argc, argv )
    int		argc;
    char	*argv[];
{

    int		 	options = 0;
    int			err = 0;
    unsigned short	port = 0;
    int 		c;
    char		ourhostname[ MAXHOSTNAMELEN ];
    char		*sender = NULL;
    struct datalines	*d_head = NULL;
    struct passwd	*pw;
    struct rcptlist	*rcpthead = NULL;
    struct rcptlist	*rcpttail = NULL;
    SNET			*net;


    while (( c = getopt( argc, argv, "f:h:ip:tVv" )) != -1 ) {
        switch ( c ) {
        case 'f':
	    if ( ( sender = (char *)malloc( strlen( optarg ) + 1 ) ) == NULL ) {
		perror( "malloc" );
		exit( EX_TEMPFAIL );
	    }
            strcpy( sender, optarg );
            break;
        case 'h':
            host = optarg;
            break;
        case 'i':
            options |= OPT_IGNOREDOTS;
            break;
        case 'p':
            port = htons( atoi( optarg ) );
            break;
	case 't':
	    options |= OPT_RCPTHEADERS;
	    break;
        case 'V':
            printf( "Version 0\n");
            exit( EX_OK );
	case 'v':
	    options |= OPT_VERBOSE;
	    logger = smtp_logger;
	    break;
        default:
            err++;
            break;
        }
    }

    /*
     * If we're given -t, is it legal to still have command line
     * rcpts?  XXX
     */
    if ( ( !(options & OPT_RCPTHEADERS ) ) && ( optind == argc ) ) {
	err++;
    }

    if ( err ) {
        fprintf( stderr, "Usage: %s [ -i ] [ -t ] [ -v ] [ -V ]\n", argv[ 0 ] );
	fprintf( stderr, "\t[ -h host ] [ -p port ]\n" );
	fprintf( stderr, "\t[ -f from-address ] to-address ...\n" );
        exit( EX_USAGE );
    }

    /*
     * Really, this should be a config file, so that we can configure
     * a "masqurade" hostname.
     */
    if ( gethostname( ourhostname, MAXHOSTNAMELEN ) < 0 ) {
	/* Should I really exit here?? */
        perror( "gethostname" );
	exit( EX_TEMPFAIL );
    }

    /*
     * Do this by UID, not by login name, since we can be called by, for
     * instance, cron.  XXX Might try both.
     */
    if (( pw = getpwuid( getuid() )) == NULL ) {
	fprintf( stderr, "Who are you?\n" );
	exit( EX_CONFIG );
    }

    if ( sender == NULL ) {
	if (( sender = (char *)malloc( strlen( pw->pw_name ) + 
		strlen( ourhostname ) + 1 + 1 )) == NULL ) {
	    perror( "malloc" );
	    exit( EX_TEMPFAIL );
	}
	strcpy( sender, pw->pw_name );
    }

    /*
     * This is not right.  In the getopt code, we only allocate enough
     * space for optarg, not for optarg@ourhostname.  XXX
     */
    strcat( sender, "@" );
    strcat( sender, ourhostname );

    /* get rcpts from command line */
    for (; optind < argc; optind++ ) {
        if ( r_append( argv[ optind ], &rcpthead, &rcpttail ) < 0 ) {
	    perror( "r_append" );
	    exit( 1 );
	}
    }

    /*
     * This routine does error checking and returns error to the caller,
     * however, the return value is not checked.
     *
     * This code is supposed to be used as simsendmail *and* as subroutines
     * for simta to send mail.  As such, it needs to have an error reporting
     * scheme that matches both.  For most daemons (i.e. simta), that means
     * that nothing gets printed to stderr, all errors are reported only to
     * the caller.  For simsendmail, all errors are reported to the user on
     * stderr.  Discuss.  XXX
     */
    read_headers( &d_head, &rcpthead, sender, options );

    if ( ( net = smtp_connect( port, ourhostname, options ) ) < 0 ) { 
        /* syslog */
	exit( EX_TEMPFAIL );
    }

    if ( transmit_envelope( net, rcpthead, sender, options ) < 0 ) {
        /* syslog */
	exit( 1 ); /* ??? */
    }

    if ( transmit_headers( net, d_head, options ) < 0 ) {
        /* syslog */
	exit( 1 );
    }
    
    if ( read_body( net, options ) < 0 ) {
        /* syslog */
	exit( EX_IOERR );
    }
    exit( EX_OK );
}
