#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sysexits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __STDC__
#include <stdarg.h>
#else __STDC__
#include <varargs.h>
#endif __STDC__

#include <snet.h>
#include "rfc822.h"

struct ih   integral_headers[ ] = { 
    { "From:", IH_FROM }, 
    { "Subject:", IH_SUBJ }, 
    { "To:", IH_TO }, 
    { "Cc:", IH_TO },
    { "Bcc:", IH_TO } 
};

    int
parse_header( line, keyheaders, h_to, h_cc )
    char 	*line;
    int		*keyheaders, *h_to, *h_cc; 
{
    unsigned char 	*i;
    char		a;
    int			ih_a;

    if ( isspace( (int)*line ) ) {
	if ( ! ( *keyheaders & FIRST ) ) {
	    return( 0 );
	} else {
	    *keyheaders |= FIRST;
	    return( -1 );
	}
    }
    /* look at each character, looking for a : before I get a ' ', then, check
       if the header I got is in the integral_headers array */
	 
    /*RFC822 "a  line  beginning a [header] field starts with a printable 
		character which is not a colon." */

    if ( ( *line == ':' ) || ( isprint( ( int )*line ) == 0 ) ) {
	return( -1 );
    }
    for ( i = (unsigned char *)line; i != '\0'; i++ ) {
	/* rfc822 Section B.1. no cntrl chars in a field-name */ 
	if ( iscntrl( *i ) != 0 ) {
	    return( -1 );
	} else if ( *i == ':' ) {
	    if ( ( *(i + 1)  != '\0' ) && ( isspace( *(i + 1) ) == 0 ) ) {
	        continue;
	    } else {
	        a = *(i + 1);
	        *(i + 1) = '\0';
		for ( ih_a = 0; ih_a < 5; ih_a++ ) {
		    if ( strcasecmp( integral_headers[ ih_a ].ih_name, line ) 
									== 0 ) {
			*keyheaders |= integral_headers[ ih_a ].ih_bit;
			if ( ih_a == 2 ) {
			    *h_to = 1;
			} else if ( ih_a == 3 ) {
			    *h_cc = 1;
			}
			break;
		    }
		}
		*(i + 1) = a;
		return( 0 );
	    }
	} else if ( isspace( *i ) != 0 ) {
	    return( -1 );
	}
    }
    return( -1 );
}

    struct datalines *
dl_alloc( line ) 
    char *line;
{

    struct datalines *i;

    if (( i = (struct datalines *)malloc(sizeof(struct datalines))) == NULL ) {
	perror( "malloc" );
	return( NULL );
    }

    if (( i->d_line = strdup( line )) == NULL ) {
	perror( "malloc" );
	return( NULL );
    }

    return( i );
}
    

    int
#ifdef __STDC__
dl_append( struct datalines ***d_head, struct datalines ***d_tail, 
		char *format, ... )
#else __STDC__
dl_append( d_head, d_tail, format, va_alist )
    char	*format;
    struct datalines ***d_head;
    struct datalines ***d_tail;
#endif __STDC__
{
    va_list val;
    struct datalines *i;
    char line[ 1024 ];

#ifdef __STDC__
    va_start( val, format );
#else __STDC__
    va_start( val );
#endif __STDC__

    vsprintf( line, format, val );
    if ( ( i = dl_alloc( line ) ) == NULL ) {
        return( -1 );
    }
    va_end( val );

    i->d_next = NULL;
     
    if ( **d_head == NULL ) {
	**d_head = **d_tail = i;
    } else {
	(**d_tail)->d_next = i;
	**d_tail = i;
    }
    return( 0 );
}

    int
#ifdef __STDC__
dl_prepend( struct datalines ***d_head, char *format, ... )
#else __STDC__
dl_prepend( d_head, format, va_alist )
    char	*format;
    struct datalines ***d_head;
#endif __ STDC__
{
    va_list val;
    struct datalines *t;
    char line[1024];


#ifdef __STDC__
    va_start( val, format );
#else __STDC__
    va_start( val );
#endif __STDC__

    vsprintf( line, format, val );
    if ( ( t = dl_alloc( line ) ) == NULL ) {
        return( -1 );
    }

    t->d_next = **d_head;
    **d_head = t;
    va_end( val );
    return( 0 );
}

    int
dl_output( d_head, net )
    struct datalines	*d_head;
    SNET			*net;
{
    struct datalines *i;

    for ( i = d_head; i != NULL; i = i->d_next ) {
	if ( snet_writef( net, "%s", i->d_line ) < 0 ) {
	    perror( "net_writef" );
	    exit( EX_IOERR );
	}
printf("%s", i->d_line );
    }
    return( 0 );
}
						     
    void
dl_free( d_head )
    struct datalines	***d_head;
{
    struct datalines *i, *j;
    i = **d_head;
    while ( i != NULL ) {
        free( i->d_line );
	j = i->d_next;
	free( i );
	i = j;
    }
    **d_head = NULL;
    return;
}
