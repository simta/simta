/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     ldap.c     *****/

#include "config.h"

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <sys/time.h>		/* struct timeval */
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "simta.h"
#include "expand.h"
#include "bounce.h"
#include "argcargv.h"
#include "ldap.h"
#include "dn.h"

#define	SIMTA_LDAP_CONF		"./simta_ldap.conf"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define MAIL500_MAXAMBIGUOUS	10
#define MAIL500_TIMEOUT		180

/* MAXADDRESSLENGTH -- maximum length email address we're gonna process */
#define MAXADDRESSLENGTH	1024
/* ERRORFMTBUFLEN -- Error buffer length process max buffer size. */
#define ERRORFMTBUFLEN		2048

/* XXX somehow get these into the config file */
static char	*noattrs[] = {LDAP_NO_ATTRS, NULL};

static char     *attrs[] = { "objectClass", "title", "postaladdress",
			"mailForwardingAddress", "rfc822Mail",
			"telephoneNumber", "description", "owner",
			"errorsTo", "rfc822ErrorsTo", "requestsTo",
			"rfc822RequestsTo", "cn", "member",
			"moderator", "onVacation", "uid",
			"suppressNoEmailError", "associateddomain", 
			"membersonly", "permittedgroup", NULL };

struct ldap_search_list		*ldap_searches = NULL;
struct list			*ldap_people = NULL;
struct list			*ldap_groups = NULL;
LDAP				*ld = NULL;

static char			*ldap_host;
static int			ldap_port;
static int			starttls;
static char			*binddn;
static char			*bindpw;

static int			ldapdebug;

static char			*vacationhost;
static char			*vacationattr;
/*
** Prototypes
*/
int simta_ldap_value __P(( LDAPMessage *e, char *attr, struct list *master ));
int simta_ldap_expand __P(( struct expand *exp, struct exp_addr *e_addr ));

static int simta_ldap_dn_search __P ((struct expand *exp,
		 struct exp_addr *e_addr));
static int simta_ldap_process_entry __P ((struct expand *exp, 
	struct exp_addr *e_addr, int type, LDAPMessage *entry, char * addr));
static int simta_ldap_expand_group __P (( struct expand *exp, 
		struct exp_addr *e_addr, int type, LDAPMessage *entry));
static void do_ambiguous __P ((struct exp_addr *e_addr, char *email_addr, 
		LDAPMessage *res));
static void do_noemail __P((struct exp_addr *e_addr, char *addr, 
		LDAPMessage *res));
int    simta_ldap_message_stdout __P(( LDAPMessage *m ));
static int simta_local_search __P( ( char ** attrs, char * user, 
				char * domain, int * count));
static int simta_address_type __P ((char * address));
static int simta_ldap_name_search __P (( struct expand *exp, 
	struct exp_addr *e_addr, char * addr, char * domain, int addrtype));

static void simta_ldapuser __P ((char * buf, char ** user, char ** domain));
static void simta_ldapdomain __P ((char * buf, char ** domain));
static char * simta_splitit __P ((char * start, char ** next,  int splitval));
static int add_errdnvals __P((struct expand *exp, struct exp_addr *e_addr, 
		char ** errmailvals));
static int add_errmailvals __P((struct exp_addr *exp, char ** errmailvals, 
		char * dn));
static int simta_group_err_env __P((struct expand *exp, 
		struct exp_addr *e_addr, LDAPMessage *entry, char *dn));
static int simta_ldap_permitted __P(( struct exp_addr *e_addr,char **pgroup, 
			char *dn));
/*
**
*/
static void
simta_ldap_unbind ()
{
    ldap_unbind( ld );
    ld = NULL;
    return;
}

static int
simta_ldap_init ()
{
    int	maxambiguous = MAIL500_MAXAMBIGUOUS;
    int ldaprc;
    int protocol = LDAP_VERSION3;

    if ( ldapdebug ) {
	if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ldapdebug )
                    != LBER_OPT_SUCCESS ) {
	    fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", ldapdebug );
	}
	if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &ldapdebug )
			!= LDAP_OPT_SUCCESS ) {
	    fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", ldapdebug );
	}
    }

    if ( ld == NULL ) {
	
	if (( ld = ldap_init( ldap_host, ldap_port )) == NULL ) {
	    syslog( LOG_ERR, "ldap_init: %m" );
	    return( LDAP_SYSERROR );
	}
	ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	ldap_set_option( ld, LDAP_OPT_SIZELIMIT, (void *) &maxambiguous);
	if( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &protocol )
		!= LDAP_OPT_SUCCESS )
	{
	    fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
			protocol );
	    exit( EXIT_FAILURE );
	}

	if ( starttls &&
	   ( (ldaprc = ldap_start_tls_s( ld, NULL, NULL )) != LDAP_SUCCESS )) {
                fprintf( stderr, "ldap_start_tls_s: %s (%d)\n",
                        ldap_err2string( ldaprc  ), ldaprc );

		syslog( LOG_ERR, "ldap_start_tls: %s", ldap_err2string(ldaprc));
		if ( starttls > 1 ) {
		    return( LDAP_SYSERROR );
		}
	}
	if (binddn) {
	    if ( ldap_bind_s( ld, binddn, bindpw, LDAP_AUTH_SIMPLE)
		 != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		return( LDAP_SYSERROR );
	    }
	}
    }
    return (0);
}

    /* return a statically allocated string if all goes well, NULL if not.
     *
     *     - Build search string where:
     *         + %s -> username
     *         + %h -> hostname
     */

char *
simta_ldap_string( char *filter, char *user, char *domain )
{
    size_t		len;
    static size_t	buf_len = 0;
    static char		*buf = NULL;
    char		*c;
    char		*d;
    char		*insert;
    int			whiteout;
    size_t		place;

    /* make sure buf is big enough search url */
    if (( len = strlen( filter ) + 1 ) > buf_len ) {
	if (( buf = (char*)realloc( buf, len )) == NULL ) {
	    syslog( LOG_ERR, "realloc: %m" );
	    return( NULL );
	}

	buf_len = len;
    }

    d = buf;
    c = filter;

    while ( *c != '\0' ) {

	if ( *c != '%' ) {
	    /* raw character, copy to data buffer */
	    *d = *c;

	    /* advance cursors */
	    d++;
	    c++;

	} else if ( *( c + 1 ) == '%' ) {
	    /* %% -> copy single % to data buffer */
	    *d = *c;

	    /* advance cursors */
	    c += 2;
	    d++;

	} else {
	    if (( *( c + 1 ) == 's' ) ||  ( *( c + 1 ) == 'h' )) {
		/* we currently support %s -> username, %h -> hostname */
		if ( *( c + 1 ) == 's' ) {
		    insert = user;
		    whiteout = 1;

		} else {
		    insert = domain;
		    whiteout = 0;
		}

		/* if needed, resize buf to handle upcoming insert */
		if (( len += strlen( insert )) > buf_len ) {
		    place = d - buf;

		    if (( buf = (char*)realloc( buf, len )) == NULL ) {
			syslog( LOG_ERR, "realloc: %m" );
			return( NULL );
		    }

		    d = buf + place;
		    buf_len = len;
		}

		/* insert word */
		while ( *insert != '\0' ) {
		    if ((( *insert == '.' ) || ( *insert == '_' ))
			    && ( whiteout != 0 )) {
			*d = ' ';
		    } else {
			*d = *insert;
		    }

		    insert++;
		    d++;
		}

		/* advance read cursor */
		c += 2;

	    } else {
		/* XXX unknown/unsupported sequence, copy & warn for now */
		syslog( LOG_WARNING, "unknown ldap print sequence: %c\n",
			*( c + 1 ));
		*d = *c;
		c++;
	    }
	}
    }

    *d = '\0';

    return( buf );
}


    /* this function should return:
     *     LDAP_SYSERROR if there is an error
     *     LDAP_LOCAL if addr is found in the db
     *     LDAP_NOT_LOCAL if addr is not found in the db
     */

    int
simta_local_search (char ** attrs, char * user, char * domain, int *count)
{
    char		*search_string;
    struct ldap_search_list *lds;
    LDAPMessage		*res;
    struct timeval	timeout = {MAIL500_TIMEOUT, 0};
    int			rc;

    *count = 0;
    /* for each base string in ldap_searches:
     *     - Build search string
     *     - query the LDAP db with the search string
     */
    for ( lds = ldap_searches; lds != NULL; lds = lds->lds_next ) {
	search_string = simta_ldap_string( lds->lds_plud->lud_filter, 
			user, domain);
	if ( search_string == NULL ) 
	    return( LDAP_SYSERROR );

	res = NULL;
	rc = ldap_search_st( ld, lds->lds_plud->lud_dn, 
			lds->lds_plud->lud_scope, search_string, attrs, 0, 
			&timeout, &res );
	if ( rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
	    syslog( LOG_ERR, 
	"simta_local_search: ldap_search_st Failed: %s", ldap_err2string(rc ));
		
	    ldap_msgfree( res );

	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}

	*count = ldap_count_entries( ld, res );
	ldap_msgfree( res );
	if (*count)
	    break;
    }
    return (0);
}

/*
** Looks at the incoming email address
** looking for "-errors", "-requests", "-members", or "-owners"
**
** DO WE WANT THIS ROUTINE TO MODIFY THE INCOMING ADDRESS???
** i.e. remove the "-errors", "-requests", "-members", or "-owners"?
*/
static int 
simta_address_type (char * address)
{
    int    addrtype;
    char   *paddr = address;

    
    addrtype = LDS_USER;  /* default */
    if ( (paddr = strrchr ( address, '-')) != NULL )
    {
        paddr++;
        if ((strcasecmp(paddr, ERROR) == 0) ||
            (strcasecmp(paddr, ERRORS) == 0)) {
            addrtype = LDS_GROUP_ERRORS;
            *(--paddr) = '\0';
        } else if ((strcasecmp(paddr, REQUEST) == 0) ||
                   (strcasecmp(paddr, REQUESTS) == 0)) {
            addrtype = LDS_GROUP_REQUEST;
            *(--paddr) = '\0';
        } else if ( strcasecmp( paddr, MEMBERS ) == 0 ) {
            addrtype = LDS_GROUP_MEMBERS;
            *(--paddr) = '\0';
        } else if ((strcasecmp(paddr, OWNER) == 0) ||
                   (strcasecmp(paddr, OWNERS) == 0)) {
            addrtype = LDS_GROUP_OWNER;
            *(--paddr) = '\0';
        }
    }

    return (addrtype);
}
    /* this function should return:
     *     LDAP_SYSERROR if there is an error
     *     LDAP_LOCAL if addr is found in the db
     *     LDAP_NOT_LOCAL if addr is not found in the db
     */

    int
simta_ldap_address_local( char *name, char *domain )
{

    int		count = 0;
    int		rc;
    char	*dup_name;

    if ( ld == NULL ) {
	if ( (rc = simta_ldap_init( )) != 0 ) 
	    return( rc );
    }

    rc = simta_local_search (noattrs, name, domain, &count);
    if (rc != 0 )       
	return (rc);
    
    if ( count == 0 ) {
	dup_name = strdup (name);
	if ( simta_address_type(dup_name ) != LDS_USER) {
	    rc = simta_local_search (noattrs, dup_name, domain, &count);
	}
	free (dup_name);
    }

    return( (count > 0) ? LDAP_LOCAL : LDAP_NOT_LOCAL );
}

    /*
     * given a config filename, this function sets up the search strings,
     * etc, that ldap needs later on.  This function is called *before*
     * simta becomes a daemon, so errors on stderr are ok.  Note that
     * we should still syslog all errors.
     */

    int
simta_ldap_config( char *fname )
{
    int			lineno = 0;
    int			fd;
    char		*line;
    char		*linecopy	= NULL;
    SNET		*snet;
    char		*c;
    struct ldap_search_list **lds;
    struct list		*l_new;
    struct list		**add;

    ACAV		*acav;		/* config file tokenizing stuff */
    char		**av;
    int			ac;
    int			acidx;

    int			intval;

    LDAPURLDesc		*plud;		/* a parsed ldapurl */
    int			rdnpref;	
    int			search_type;
    int			rc;		/* universal return code */

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	if ( errno == ENOENT ) {
	    errno = 0;
	    /* XXX file not found, error? */
	    return( 0 );

	} else {
	    fprintf( stderr, "conf_read open %s: ", fname );
	    perror( NULL );
	    return( -1 );
	}
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	perror( "conf_read snet_attach" );
	return( -1 );
    }

    if (( acav = acav_alloc( )) == NULL ) {
	fprintf (stderr, "acav_alloc error:\n" );
	return ( -1 );
    }	

    for ( lds = &ldap_searches; *lds != NULL; lds = &((*lds)->lds_next))
    	    ;

    
    while (( line = snet_getline( snet, NULL )) != NULL ) {
	lineno++;
	if ( line[0] == '#' || line[0] == '\0' ) {
	    continue;
	}
	if (linecopy) {
	    free (linecopy);
	    linecopy = NULL;
	}

        linecopy = strdup (line);

	if (( ac = acav_parse( acav, line, &av )) < 0 ) {
	    acav_free (acav);
	    fprintf( stderr, "acav_parse returned -1");
	    return (-1);
	}	    

	if (( strncasecmp( av[ 0 ], "uri", 3 ) == 0 ) ||
	    ( strncasecmp( av[ 0 ], "url", 3 ) == 0 )) {
	    if (ac < 2) {
		fprintf( stderr, "Missing uri: %s\n", linecopy );
		continue;
	    }

 	    if ( ldap_is_ldap_url( av[ 1 ] ) != 0 ) {

                /* Parse the URL */
		rc = ldap_url_parse( av[ 1 ], &plud );

		if (rc != LDAP_URL_SUCCESS)
		{
		    fprintf (stderr, 
		"ldap_url_parse parse error: %d for line: %s\n", rc, linecopy);
		    continue;
		}

		
		rdnpref = FALSE;
		search_type = 0;
		acidx = 2;
		while (acidx < ac)
		{
		    if (strncasecmp ( av[acidx], "rdnpref", 7) == 0) {
			    rdnpref = TRUE;
		    } else if (strncasecmp  
			      ( av[acidx], "searchtype=", 11) == 0){

			c = &av[acidx][11];
			if (strncasecmp (c, "ALL", 3) == 0)  {
			    search_type = LDS_ALL;
			} else if (strncasecmp (c, "GROUP", 5) == 0 ) {
			    search_type = LDS_GROUP;
			} else if (strncasecmp (c, "USER", 4) == 0 ) {
			    search_type = LDS_USER;
			}
			else
			    fprintf (stderr,
				"Unknown Searchtype in url: %d\n", lineno);
		    }
		    else 
		        fprintf (stderr,
				    "Unknown extension in URL: %d\n", lineno);
		    acidx++;
		}

		if (( *lds = (struct ldap_search_list *)malloc
			    ( sizeof( struct ldap_search_list ))) == NULL ) { 
		    perror( "malloc" ); 
		    acav_free( acav );
		    ldap_free_urldesc (plud);
		    return( -1 );
		}
		memset( *lds, 0, sizeof( struct ldap_search_list ));

		if (((*lds)->lds_string = strdup( av[ 1 ] )) == NULL ) {
		    perror( "strdup" );
   		    acav_free( acav );
		    ldap_free_urldesc (plud);
		    return( -1 );
		}

		(*lds)->lds_plud = plud;
		(*lds)->lds_rdn_pref = rdnpref;
		(*lds)->lds_search_type = search_type;
		(*lds)->lds_next = NULL;

		lds = &((*lds)->lds_next);

	    } else {
		fprintf( stderr, "uri not an ldap uri: %s\n", linecopy );
	    }
	} else if ( strncasecmp( av[ 0 ], "ldapdebug", 9 ) == 0 ) {
	    if (ac < 2) {
		fprintf( stderr, "Missing ldapdebug value: %s\n", linecopy );
		continue;
	    }
	    intval = atoi (av[ 1 ]);
	    ldapdebug = intval;
	    
	} else if ( strncasecmp( av[ 0 ], "starttls", 8 ) == 0 ) {
	    if (ac < 2) {
		fprintf( stderr, "Missing starttls value: %s\n", linecopy );
		continue;
	    }
	    intval = atoi (av[ 1 ]);
	    if (intval < 0 || intval > 2) {
		fprintf( stderr, "Invalid starttls value: %s\n", linecopy );
		continue;
	    }
	    starttls = intval;
	    
	} else if (( strncasecmp( av[ 0 ], "bindpw", 6 ) == 0 ) ||
		   ( strncasecmp( av[ 0 ], "bindpassword", 12 ) == 0 )) {
	    if (ac < 2) {
		fprintf( stderr, "Missing bindpw/bindpassword value: %s\n", linecopy );
		continue;
	    }
	    bindpw = strdup ( av[ 1 ] );

	} else if ( strncasecmp( av[ 0 ], "binddn", 6 ) == 0 ) {
	
	    if (ac < 2) {
		fprintf( stderr, "Missing binddn value: %s\n", linecopy );
		continue;
	    }
	    binddn = strdup ( av[ 1 ] );
	    
	} else if (( strncasecmp( av[ 0 ], "oc", 2 ) == 0 ) ||
		   ( strncasecmp( av[ 0 ], "objectclass", 11 ) == 0 )) {
	    
	    if (ac < 3) {
		fprintf( stderr, "Missing objectclass parameter: %s\n", linecopy );
		continue;
	    }

	    add = NULL;

	    if ( strncasecmp( av[ 1 ], "person", 6 ) == 0 ) {
		add = &ldap_people;

	    } else if ( strncasecmp( av[ 1 ], "group", 5 ) == 0 ) {
		add = &ldap_groups;
	    }

	    if ( add != NULL ) {
		/* av [ 2] is a objectclass name */

		if (( l_new = (struct list*)
			malloc( sizeof( struct list ))) == NULL ) {
		    perror( "malloc" );
    		    acav_free( acav );
		    return( -1 );
		}
		memset( l_new, 0, sizeof( struct list ));

		if (( l_new->l_string = (char*)strdup (av [ 2 ])) == NULL ) {
		    perror( "strdup" );
    		    acav_free( acav );
		    return( -1 );
		}
	
		l_new->l_next = *add;
		*add = l_new;

	    } else {
		fprintf( stderr, "Unknown objectclass type: %s\n", linecopy );
	    }

	} else if ( strncasecmp( av[ 0 ], "vacationhost", 12 ) == 0 ) {

	    if (ac < 2) {
		fprintf( stderr, "Missing vacationhost value: %s\n", linecopy );
		continue;
	    }
		  
	    if (vacationhost) {
		fprintf( stderr, 
			"Overwriting previous vacation host: %s with %s\n",
			vacationhost, av [ 1 ]);

		free (vacationhost); 
	    }

	    if (( vacationhost = (char*)strdup (av [ 1 ])) == NULL ) {
		perror( "strdup" );
		acav_free( acav );
		return( -1 );
	    }
	} else if ( strncasecmp( av[ 0 ], "vacationattr", 12 ) == 0 ) {

	    if (ac < 2) {
		fprintf( stderr, "Missing vacationattr value: %s\n", linecopy );
		continue;
	    }
		  
	    if (vacationattr) {
		fprintf( stderr, 
		"Overwriting previous vacation attribute name: %s with %s\n",
			vacationattr, av [ 1 ]);

		free (vacationattr); 
	    }

	    if (( vacationattr = (char*)strdup (av [ 1 ])) == NULL ) {
		perror( "strdup" );
		acav_free( acav );
		return( -1 );
	    }
	} else {
	    fprintf( stderr, "Unknown simta/ldap config option: %s\n", linecopy );
	}
    }
    if (linecopy) 	
	free (linecopy);

    acav_free( acav );

    if ( snet_close( snet ) != 0 ) {
	perror( "nlist snet_close" );
	return( -1 );
    }

    /* XXX check to see that ldap is configured correctly */

    if ( ldap_people == NULL ) {
	fprintf( stderr, "%s: No ldap people\n", fname );
	return( 1 );
    }

    if ( ldap_searches == NULL ) {
	fprintf( stderr, "%s: No ldap searches\n", fname );
	return( 1 );
    }
    if (! ldap_searches ->lds_plud->lud_host) {
        fprintf( stderr, "No ldap server specified in initial uri\n");
	return (1);
    }
    ldap_host = strdup (ldap_searches ->lds_plud->lud_host);
    ldap_port = ldap_searches ->lds_plud->lud_port;
    if (ldap_port == 0)
	ldap_port = 389;

    return( 0 );
}

/*
** This function looks thru the attribute "attr" values 
** for the first matching value in the "master" list
*/
    int
simta_ldap_value( LDAPMessage *e, char *attr, struct list *master )
{
    int			idx;
    char		**values;
    struct list		*l;

    if (( values = ldap_get_values( ld, e, attr )) != NULL ) {

	for ( idx = 0; values[ idx ] != NULL; idx++ ) {
	    for ( l = master ; l != NULL; l = l->l_next ) {
		if ( strcasecmp( values[ idx ], l->l_string ) == 0 ) {
		    ldap_value_free( values );
		    return( 1 );
		}
	    }
	}
	ldap_value_free( values );
    }
    return( 0 );
}


    /* this function should return:
     *     LDAP_NOT_FOUND if addr is not found in the database
     *     LDAP_FINAL if addr is a terminal expansion
     *     LDAP_EXCLUDE if addr is an error, and/or expands to other addrs.
     *     LDAP_SYSERROR if there is a system error
     *
     * XXX is LDAP_FINAL useless?  if its in the db, it can never be terminal?
     *
     * struct expand *exp->exp_env->e_mail
     *     - is the sender of the message
     *
     * expansion (not system) errors should be reported back to the sender
     * using bounce_text(...);
     *
     * bounce_text ( e_addr->e_addr_rcpt, char*, char*, char* );
     *     - used to create a bounce for an address
     *
     * add_address( exp, char *new_addr, e_addr->e_addr_rcpt, TYPE );
     *     - used to add new_addr to the expansion list
     *     - TYPE can be either ADDRESS_TYPE_EMAIL or ADDRESS_TYPE_LDAP
     */

    int
simta_ldap_expand( struct expand *exp, struct exp_addr *e_addr )
{
    char	*domain;	/* points to domain in address */
    char	*name;		/* clone of incoming name */
    char	*pname;		/* pointer for traversing name */
    int		nametype;	/* Type of Groupname -- owner, member... */
    int		rc;		/* Universal return code */

    if ( e_addr->e_addr_type == ADDRESS_TYPE_LDAP ) {
	rc = simta_ldap_dn_search (exp, e_addr);
	return (rc);
    }

    /* addr should be somename@somedomain */
    if (strchr( e_addr->e_addr, '@' ) == NULL ) {
	bounce_text( e_addr->e_addr_errors, "bad address format: ",
		e_addr->e_addr, NULL );
	return( LDAP_SYSERROR );
    }

    if ( ld == NULL ) {
	if ( (rc = simta_ldap_init( )) != 0 ) 
	    return( rc );
    }

    name = strdup (e_addr->e_addr);
    if (!name) {
	syslog( LOG_ERR, "simta_ldap_expand: strdup failed" );
	return( LDAP_SYSERROR );
    }
    pname = strchr( name, '@' );
    *pname = '\0';

    domain = pname + 1;

    /*
    ** Do we still want to strip . and _
    */
    for (pname = name; *pname; pname++)
    {
	if (*pname == '.' || *pname == '_')
	    *pname = ' ';
    }
    
    rc = simta_ldap_name_search (exp, e_addr, name, domain, LDS_USER);
    if (rc != LDAP_NOT_FOUND )
    {   /*
	** Either we found the name and processed it,
	** or we got some error that will keep us from going on.
	*/
	free (name);
	return (rc);
    }

    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    nametype = simta_address_type(name );
    if ( nametype != LDS_USER) 
	rc = simta_ldap_name_search (exp, e_addr, name, domain, nametype);

    free (name);
    return (rc);
}

static int
simta_ldap_name_search ( struct expand *exp, struct exp_addr *e_addr,
			char * addr, char * domain, int addrtype)
{
    int			rc;
    int			match = 0;
    char		*search_string;
    LDAPMessage		*res;
    LDAPMessage		*entry;
    struct ldap_search_list             *lds;
    struct timeval      timeout = {MAIL500_TIMEOUT, 0};


    /* for each base string in ldap_searches:
     *    If this search string is of the specified addrtype:
     *       - Build search string
     *       - query the LDAP db with the search string
     */
    for ( lds = ldap_searches; lds != NULL; lds = lds->lds_next ) {

        if (! (lds->lds_search_type & addrtype))
	    continue; 

	/* Fill in the filter string w/ these address and domain strings */
	if (( search_string = simta_ldap_string(  lds->lds_plud->lud_filter, 
		addr, domain )) == NULL ) {
	    return( LDAP_SYSERROR );
	}
	res = NULL;
	rc = ldap_search_st( ld, lds->lds_plud->lud_dn,
			lds->lds_plud->lud_scope, search_string, attrs, 0, 
			&timeout, &res );

	if ( rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {

	    syslog( LOG_ERR, "simta_ldap_name_addr: ldap_search_st Failed: %s",
		    ldap_err2string(rc ));

	    ldap_msgfree( res ); 

	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}

	if (( match = ldap_count_entries( ld, res )) != 0 ) 
	    break;

	ldap_msgfree( res );
    }

    if ( match == 0 ) 
	return( LDAP_NOT_FOUND ); /* no entries found */

    if ( match == -1) {
	syslog( LOG_ERR, 
  "simta_ldap_name_addr:Error parsing result from LDAP server for address: %s",
			e_addr->e_addr);
	simta_ldap_unbind (ld);
	return( LDAP_SYSERROR );
    }
    
    if ( match > 1) {
	LDAPMessage     *tmpres = NULL;
	char            *dn;
	char            **xdn;

	/*
	** More than one match -- if no rdn preference 
        ** then bounce w/ ambiguous user 
        */
  
	if (! lds->lds_rdn_pref) {

	    do_ambiguous (e_addr, addr, res);

            ldap_msgfree( res );
	    return LDAP_EXCLUDE;
	}
	/*
	 * giving rdn preference - see if any entries were matched
	 * because of their rdn.  If so, collect them to deal with
	 * later (== 1 we deliver, > 1 we bounce).
	*/

	for ( entry = ldap_first_entry( ld, res ); 
		entry != NULL; 
		entry = ldap_next_entry( ld, entry ) ){
	    dn = ldap_get_dn( ld, entry );
	    xdn = ldap_explode_dn( dn, 1 );

	    /* XXX bad, but how else can we do it? XXX */
	    if ( strcasecmp( xdn[0], addr ) == 0 ) {
		ldap_delete_result_entry( &res, entry );
		ldap_add_result_entry( &tmpres, entry );
	    }

	    ldap_value_free( xdn );
	    free( dn );
	}

	/* nothing matched by rdn - go ahead and bounce */
	if ( tmpres == NULL ) {
	    do_ambiguous (e_addr, addr, res);

            ldap_msgfree( res );
	    return LDAP_EXCLUDE;

	/* more than one matched by rdn - bounce with rdn matches */
	} else if ( (match = ldap_count_entries( ld, tmpres )) > 1 ) {
	    do_ambiguous (e_addr, addr, res);

            ldap_msgfree( res );
            ldap_msgfree( tmpres );
	    return LDAP_EXCLUDE;

	/* trouble... */
	} else if ( match < 0 ) {
	    syslog( LOG_ERR, 
	"simta_ldap_name_addr: Error parsing result from LDAP server for address: %s",
			e_addr->e_addr);
            ldap_msgfree( res );
            ldap_msgfree( tmpres );
	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}

	/* otherwise one matched by rdn - send to it */
	ldap_msgfree( res );
	res = tmpres;
    }

    /*
    ** Only have one entry now that matches our address.
    */
    if (( entry = ldap_first_entry( ld, res )) == NULL ) {
	syslog( LOG_ERR, "simta_ldap_name_addr: ldap_first_entry: %s",
		ldap_err2string( ldap_result2error( ld, res, 1 )));
	return( LDAP_SYSERROR );
    }

    rc = simta_ldap_process_entry (exp, e_addr, addrtype, entry, addr);

    /* XXX need to do more than just return */
    ldap_msgfree( res );

    return( rc );
}
static int
simta_ldap_dn_search (struct expand *exp, struct exp_addr *e_addr )
{
    char		*search_dn;
    int			rc;
    int			match;
    LDAPMessage		*res;
    LDAPMessage		*entry;
    struct timeval      timeout = {MAIL500_TIMEOUT, 0};

    search_dn = e_addr->e_addr;
    res = NULL;
    rc = ldap_search_st( ld, search_dn, LDAP_SCOPE_BASE, "(objectclass=*)", 
			attrs, 0, &timeout, &res );

    if ( rc != LDAP_SUCCESS 
    &&   rc != LDAP_SIZELIMIT_EXCEEDED 
    &&   rc != LDAP_NO_SUCH_OBJECT ) {

	syslog( LOG_ERR, "simta_ldap_dn_search: ldap_search_st Failed: %s",
		    ldap_err2string(rc ));
	ldap_msgfree( res ); 

	simta_ldap_unbind (ld);
	return( LDAP_SYSERROR );
    }
    match = ldap_count_entries (ld, res );
    if ( match == -1) {
	syslog( LOG_ERR, 
    "simta_ldap_dn_search: Error parsing result from LDAP server for dn: %s",
			search_dn);
	ldap_msgfree( res );
	simta_ldap_unbind (ld);
	return( LDAP_SYSERROR );
    }

    if ( match == 0 ) {
	ldap_msgfree( res );

    	if ( (bounce_text( e_addr->e_addr_errors, search_dn,
		" : Group member does not exist\n" , NULL ) != 0 ) 
    	||   (bounce_text( e_addr->e_addr_errors, 
   "This could be because the distinguished name of the person has changed\n" , 
   "If this is the case, the problem can be solved by removing and\n",
   "then re-adding the person to the group\n" ) != 0 )  ) {

	    syslog( LOG_ERR, 
	"simta_ldap_dn_search: Failed building bounce message -- no member: %s",
				search_dn);
	    return( LDAP_SYSERROR );
	}
	return( LDAP_NOT_FOUND ); /* no entries found */
    }
    
    if (( entry = ldap_first_entry( ld, res )) == NULL ) {
	syslog( LOG_ERR, "simta_ldap_dn_entry: ldap_first_entry: %s",
		ldap_err2string( ldap_result2error( ld, res, 1 )));
	ldap_msgfree( res );
	return( LDAP_SYSERROR );
    }

    rc = simta_ldap_process_entry (exp, e_addr, LDS_USER, entry, search_dn);

    ldap_msgfree( res );
    return (rc);
}
static int
simta_ldap_process_entry (struct expand *exp, struct exp_addr *e_addr, 
			int type, LDAPMessage *entry, char * addr)
{
    char	**values;
    char	**uid;
    char	**onvacation;
    int		idx;
    int		result;
    char	*attrval;
    char	*nextval;

    if ( ldap_groups
    &&  (simta_ldap_value( entry, "objectClass", ldap_groups ) == 1 ) ) {
	result = simta_ldap_expand_group (exp, e_addr, type, entry);
	return (result);
    }

    /* it wasn't a group  -- check if it's a people */
    if ( ldap_people
    &&  (simta_ldap_value( entry, "objectClass", ldap_people ) == 1 ) ) {

	/* get individual's email address(es) */
	if (( values = ldap_get_values( ld, entry, 
				"mailForwardingAddress" )) == NULL ) {
	    /*
	    ** This guy has no mailforwardingaddress	
	    ** Depending on if we're expanding a group
	    ** Bounce it with the appropriate message.
	    */
	    if ( e_addr->e_addr_type != ADDRESS_TYPE_LDAP ) 
		do_noemail (e_addr, addr, entry);
	    else {
		if ((e_addr->e_addr_errors->e_flags & SUPPRESSNOEMAILERROR) == 0) {
	
		    if ( bounce_text( e_addr->e_addr_errors, addr,
		" : Group member exists but does not have an email address" , 
			NULL ) != 0 ) {

			syslog( LOG_ERR, 
    "simta_ldap_process_entry: Failed building bounce message -- no email: %s",
				e_addr->e_addr);
			return( LDAP_SYSERROR );
		    }
		}
	    }
#if 0
	    if (simta_expand_debug)
		syslog( LOG_ERR,
		 "simta_ldap_process_entry: %s has no mailforwardingaddress\n",
			 addr);
#endif
	} else {

	    for ( idx = 0; values[ idx ] != NULL; idx++ ) {

		attrval = values[ idx ];
        	while ( attrval && *attrval )
		{
		    attrval = simta_splitit (attrval, &nextval, ',');
		    if (strchr (attrval, '@') ) {

			if ( add_address( exp, attrval,
			   e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL ) != 0 ) {
				syslog (LOG_ERR, 
	"simta_ldap_process_entry: failed adding mailforwardingaddress: %s", 
			    		 addr);
				ldap_value_free( values );
				return( LDAP_SYSERROR );
			}
		    }
		    attrval = nextval;
		}
	    }

	    ldap_value_free( values );
	    /*
	    * If the user is on vacation, send a copy of the mail to
	    * the vacation server.  The address is constructed from
 	    * the vacationhost (specified in the config file) and
	    * the uid (XXX this should be more general XXX).
	    */
	    onvacation = NULL;
	    if ( vacationhost != NULL && vacationattr != NULL
            && (onvacation = ldap_get_values( ld, entry, vacationattr)) != NULL 
	    && strcasecmp( onvacation[0], "TRUE" ) == 0 ) {

		char    buf[1024];

		if ( (uid = ldap_get_values( ld, entry, "uid" )) != NULL ) {
		    sprintf( buf, "%s@%s", uid[0], vacationhost );
		    if ( add_address( exp, buf,
			  e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL ) != 0 ) {
			syslog (LOG_ERR, 
		"simta_ldap_process_entry: failed adding vacation address: %s", buf);
		    }
		    ldap_value_free( uid);
	    	} else {
		    syslog( LOG_ALERT, "user without a uid on vacation (%s)",
				 addr );
	    	}
	    }
	    if (onvacation)
		ldap_value_free( onvacation );
	}

	return (LDAP_EXCLUDE);

    } else {
	/* Neither a rfc822mailgroup, nor a person */
	syslog( LOG_ERR, "Entry: %s is neither person or rfc822mailgroup ",
		e_addr->e_addr);
	return( LDAP_SYSERROR );
    }
}

static int 
simta_ldap_expand_group ( struct expand *exp, struct exp_addr *e_addr,
 		int type, LDAPMessage *entry)
{
    int		valfound = 0;
    char	**dnvals;
    char	**mailvals;
    char	*dn;
    char	*errmsg;
    int		idx;		/* universal iterator */

    char	**memonly;	/* Members Only attribute values */
    char	**moderator;	/* Moderator attribute values */
    char	**permitted;	/* permittedgroup attribute values */
    char	*sender_name;	/* Name of sender -- upto '@' */
    char	*sender_domain;	/* sender domain -- last 2 components */
    char	*mod_name;	/* moderator name -- upto '@' */
    char	*mod_domain;	/* moderator domain -- last 2 components */

    char	*attrval;
    char	*nextval;
    char	*ndn;		/* a "normalized dn" */

    int		rc;

    dn = ldap_get_dn( ld, entry );
    
    switch ( type ) 
    {
    case LDS_GROUP_ERRORS:
	
	dnvals = ldap_get_values( ld, entry, "errorsto");
	mailvals = ldap_get_values( ld, entry, "rfc822errorsto");
	errmsg = ": Group exists but has no errors-to address\n";
	break;

    case LDS_GROUP_REQUEST:

	dnvals = ldap_get_values( ld, entry, "requeststo");
	mailvals = ldap_get_values( ld, entry, "rfc822requeststo");
	errmsg = ": Group exists but has no requests-to address\n";
	break;

    case LDS_GROUP_OWNER:

	dnvals = ldap_get_values( ld, entry, "owner");
	mailvals = NULL;
	errmsg = ": Group exists but has no owners\n";
	break;

    default:
	dnvals = ldap_get_values( ld, entry, "member");
	mailvals = ldap_get_values( ld, entry, "rfc822mail");
	errmsg = ": Group exists but has no members\n";

	/*
	** Moderated group?
	** If sender matches moderator
	** then send message to the group
	** else send message to the moderator
	*/
	moderator = ldap_get_values( ld, entry, "moderator");
	if (moderator) 
	{
	    simta_ldapuser (exp->exp_env->e_mail, &sender_name, &sender_domain);

	    for (idx = 0; moderator[idx]; idx++)
	    {
		simta_ldapuser (moderator[idx], &mod_name, &mod_domain);
		if ((strcasecmp (sender_name, mod_name) == 0)
		&&  (strcasecmp (sender_domain, mod_domain) == 0) ) 
		{   /*
		    ** This is the moderator.
		    ** send the message to the group.
		    */	
		    free (mod_name);
		    free (mod_domain);
		    break;
		}
		free (mod_name);
		free (mod_domain);
	    }
	    free (sender_name);
	    free (sender_domain);
	    /* 
	    ** If the sender was not found in the moderator list
	    ** then
	    **     Blow away the member and mailvals value lists
	    ** 	   and send this on to the moderators.
	    */

	    if (! moderator[idx]) {
		ldap_value_free (dnvals);
		dnvals = NULL;
		ldap_value_free (mailvals);
		mailvals = moderator;
	    }
	    else
		ldap_value_free (moderator);
	}
	/*
	** MembersOnly group?
	*/
	memonly = ldap_get_values( ld, entry, "membersonly");
	if (memonly) 
	{
	    if(strcasecmp (memonly[0], "TRUE") == 0) 
	    {
		e_addr->e_addr_status |= STATUS_LDAP_EXCLUSIVE;
		permitted = ldap_get_values( ld, entry, "permittedgroup");
		if (permitted ) {
		    rc = simta_ldap_permitted ( e_addr, permitted, dn);

		    if (rc != 0) {
			ldap_value_free (permitted);
			ldap_value_free ( memonly );
		    
			if (dnvals )
			    ldap_value_free( dnvals);
			if (mailvals )
			    ldap_value_free(mailvals );

			ldap_memfree (dn);
			return (rc);
		    }
		    ldap_value_free (permitted);
		}
	    }
	    ldap_value_free ( memonly );
	}
	/* If needed, Create a new error envelope */
	rc = simta_group_err_env (exp, e_addr, entry, dn);
	if (rc != 0) {
	    if (dnvals )
		ldap_value_free( dnvals);
	    if (mailvals )
		ldap_value_free(mailvals );
	    ldap_memfree (dn);
	    return (rc);
	}

	break;
    }   /* end of switch */

    if (dnvals ) {
	valfound++;

	for ( idx = 0; dnvals[ idx ] != NULL; idx++ ) {
	    ndn = dn_normalize_case (dnvals[ idx ]); 
	    if ( add_address( exp, ndn,
			e_addr->e_addr_errors, ADDRESS_TYPE_LDAP) != 0 ) {
		syslog (LOG_ERR,
			"simta_ldap_expand_group: %s failed adding: %s", dn,
			mailvals[ idx ]);
		break;
	    }
	}
	ldap_value_free( dnvals);
    }
    if (mailvals ) {
	valfound++;

	for ( idx = 0; mailvals[ idx ] != NULL; idx++ ) {

	    /*
	    ** If this mail attr has a comma 
	    ** then split it on the comma.
	    ** Verify that each value has a '@'
	    */
	    attrval = mailvals[ idx ];
	    while ( attrval && *attrval )
	    {
		attrval = simta_splitit (attrval, &nextval, ',');

		if (strchr (attrval, '@') ) {		
		    if ( add_address( exp, attrval,
			e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL) != 0 ) {
			syslog (LOG_ERR, 
			    "simta_ldap_expand_group: %s failed adding: %s", dn,
				attrval);
			break;
		    }
		}
		attrval = nextval;
	    }
	}
	ldap_value_free( mailvals);
    }
    if (valfound == 0) {
	bounce_text( e_addr->e_addr_errors, dn, errmsg, NULL);
    }	
    ldap_memfree (dn);
    return LDAP_EXCLUDE;
}

    int
simta_ldap_message_stdout( LDAPMessage *m )
{
    LDAPMessage		*entry;
    LDAPMessage		*message;
    char		*dn;
    char		*attribute;
    BerElement		*ber;
    char		**values;
    int			idx;

    if (( entry = ldap_first_entry( ld, m )) == NULL ) {
	ldap_perror( ld, "ldap_first_entry" );
	return( -1 );
    }

    if (( message = ldap_first_message( ld, m )) == NULL ) {
	ldap_perror( ld, "ldap_first_message" );
	return( -1 );
    }

    if (( dn = ldap_get_dn( ld, message )) == NULL ) {
	ldap_perror( ld, "ldap_get_dn" );
	return( -1 );
    }

    printf( "dn: %s\n", dn );
    ldap_memfree( dn );

    for ( attribute = ldap_first_attribute( ld, message, &ber );
          attribute != NULL;
          attribute = ldap_next_attribute( ld, message, ber )   ) {
    
	printf( "%s:\n", attribute );

	if (( values = ldap_get_values( ld, entry, attribute )) == NULL ) {
	    ldap_perror( ld, "ldap_get_values" );
	    return( -1 );
	}

	for ( idx = 0; values[ idx ] != NULL; idx++ ) {
	    printf( "	%s\n", values[ idx ] );
	}

	ldap_value_free( values );
    }

    ber_free( ber, 0 );

    return( 0 );
}
static void
do_ambiguous (struct exp_addr *e_addr, char *addr, LDAPMessage *res)
{

    int		cnt;
    int		last;
    int		idx;
    char	*dn; 
    char	*rdn;
    char	**ufn;
    char	**vals;
    LDAPMessage	*e;
    char	*errfmt;

    errfmt = (char *) malloc (strlen (addr) + 100);
    if (! errfmt) {
	syslog( LOG_ERR, "do_ambiguous: Failed allocating initial errfmt");
	return;
    }
    
    cnt = ldap_result2error( ld, res, 0 );
    sprintf( errfmt, "%s: Ambiguous user.  %s %d matches found:\n\n",
            addr, cnt == LDAP_SIZELIMIT_EXCEEDED ? "First " : "",
            ldap_count_entries( ld, res ) );

    free (errfmt);
    if ( bounce_text( e_addr->e_addr_errors, errfmt, NULL, NULL ) != 0 )
	return;

    for ( e = ldap_first_entry( ld, res ); e != NULL;
	  e = ldap_next_entry( ld, e ) ) {
	dn = ldap_get_dn( ld, e );
	ufn = ldap_explode_dn( dn, 1 );
	rdn = strdup( ufn[0] );
	ldap_value_free( ufn );
	free( dn );

	if ( strcasecmp( rdn, addr ) == 0 ) {
	    if ( (vals = ldap_get_values( ld, e, "cn" )) != NULL ) {
		for ( idx = 0; vals[idx]; idx++ ) {
		    last = strlen( vals[idx] ) - 1;
		    if (isdigit((unsigned char) vals[idx][last ])) {
			free (rdn);
			rdn = strdup( vals[idx] );
			break;
		    }
		}
		ldap_value_free( vals );
	    }
	}
	if (ldap_groups 
	&& ( simta_ldap_value( e, "objectClass", ldap_groups) > 0 )) {
	    vals = ldap_get_values( ld, e, "description" );
	} else {
	    vals = ldap_get_values( ld, e, "title" );
	}

	errfmt = (char *) malloc (strlen (rdn) + 26);
	if (! errfmt) {
	    syslog( LOG_ERR, "do_ambiguous: Failed allocating errfmtbuf");
	    return;
	}

	sprintf (errfmt, "    %-20s ", rdn);
	bounce_text( e_addr->e_addr_errors, errfmt, vals[0], NULL );
	free (errfmt);

	for ( idx = 1; vals && vals[idx] != NULL; idx++ ) {
	    bounce_text( e_addr->e_addr_errors, "                         ",
			vals[idx], NULL );    /* 1234567890123456789012345 */
	}

	free( rdn );
	if ( vals != NULL )
	    ldap_value_free( vals );
    }
}

static void
do_noemail (struct exp_addr *e_addr, char *addr, LDAPMessage *res)
{

    char	*errfmtbuf;
    size_t	errfmtlen;
    size_t	addrnamelen;
    int		last;
    int		idx;
    char	*dn; 
    char	*rdn;
    char	**ufn;
    char	**vals;

    char	*blankbuf;	/* Buffer of blanks for formatting */

    addrnamelen = strlen (addr);
    if (addrnamelen > MAXADDRESSLENGTH)
	addrnamelen = MAXADDRESSLENGTH;

    errfmtlen = ERRORFMTBUFLEN + addrnamelen;
    errfmtbuf = (char *) malloc (errfmtlen);
    if (! errfmtbuf) {
	syslog( LOG_ERR, "do_noemail: Failed allocating errfmtbuf");
	return;
    }
 
    if ( bounce_text( e_addr->e_addr_errors, addr,
		": User has no email address registered.\n" , NULL ) != 0 ) {
	free (errfmtbuf);
	return;
    }
  
    sprintf( errfmtbuf, 
		"%*s  Name, title, postal address and phone for '%s':\n",
		addrnamelen, " ", addr );

    if ( bounce_text( e_addr->e_addr_errors, errfmtbuf, NULL, NULL ) != 0 ) {
	free (errfmtbuf);
	return;
    }
    free (errfmtbuf);

    /* name */
    dn = ldap_get_dn( ld, res );
    ufn = ldap_explode_dn( dn, 1 );
    rdn = strdup( ufn[0] );
    if ( strcasecmp( rdn, addr ) == 0 ) {
	if ( (vals = ldap_get_values( ld, res, "cn" )) != NULL ) {
	    for ( idx = 0; vals[idx]; idx++ ) {
		last = strlen( vals[idx] ) - 1;
		if ( isdigit((unsigned char) vals[idx][last]) ) {
		    free (rdn);
		    rdn = strdup( vals[idx] );
		    break;
		}
	    }
	    ldap_value_free( vals );
	}
    }
    blankbuf = (char *) malloc (addrnamelen + 10);
    sprintf( blankbuf, "%*s  ", addrnamelen, ""); 

    if ( bounce_text( e_addr->e_addr_errors, blankbuf, rdn, NULL ) != 0 ) {
	free (blankbuf);
	return;
    }

    free( dn );
    free( rdn );
    ldap_value_free( ufn );

    /* titles or descriptions */
    if ( (vals = ldap_get_values( ld, res, "title" )) == NULL &&
         (vals = ldap_get_values( ld, res, "description" )) == NULL ) {

	if ( bounce_text( e_addr->e_addr_errors, blankbuf, 
			"No title or description registered" , NULL ) != 0 ){
	    free (blankbuf);
	    return;
	}
    } else {
	for ( idx = 0; vals[idx] != NULL; idx++ ) {
	    if ( bounce_text( e_addr->e_addr_errors, 
				blankbuf, vals[idx], NULL ) != 0 ) {
		free (blankbuf);
		return;
	    }
	}
	ldap_value_free( vals );
    }
    /* postal address*/
    if ( (vals = ldap_get_values( ld, res, "postaladdress" )) == NULL ) {
	if ( bounce_text( e_addr->e_addr_errors, blankbuf, 
			"No postaladdress registered", NULL ) != 0 ){
	    free (blankbuf);
	    return;
	}
    } else {
	for ( idx = 0; vals[idx] != NULL; idx++ ) {
	    if ( bounce_text( e_addr->e_addr_errors, 
				blankbuf, vals[idx], NULL ) != 0 ) {
	        free (blankbuf);
		return;
	    }
	}
	ldap_value_free( vals );
    }
    /* telephone number */
    if ( (vals = ldap_get_values( ld, res, "telephoneNumber" )) == NULL ) {
	if ( bounce_text( e_addr->e_addr_errors, blankbuf, 
				"No phone number registered", NULL ) != 0 ){
	    free (blankbuf);
	    return;
	}
    } else {
	for ( idx = 0; vals[idx] != NULL; idx++ ) {
	    if ( bounce_text( e_addr->e_addr_errors, 
				blankbuf, vals[idx], NULL ) != 0 ) {
	        free (blankbuf);
		return;
	    }
	}
	ldap_value_free( vals );
    }
    free (blankbuf);
    return;
}
int
simta_mbx_compare ( char * firstemail, char * secondemail)
{
    char *first_name;
    char *first_domain;
    char *second_name;
    char *second_domain;

    int	 rc = -1;

    if (firstemail && *firstemail && secondemail && *secondemail) {
	simta_ldapuser (firstemail, &first_name, &first_domain);
	simta_ldapuser (secondemail, &second_name, &second_domain);

	if ((rc = strcasecmp (first_name, second_name)) == 0) 
	    rc = strcasecmp (first_domain, second_domain);

	free (first_name);
	free (first_domain);
	free (second_name);
	free (second_domain);
    }
    return rc;
}
static int
simta_ldap_permitted ( struct exp_addr *e_addr, char **permitted, char *dn)
{
    int			idx;

    if (permitted && *permitted)
    {
	/* 
	** Normalize the permitted group list 
	** normalization happens "in-place"
	*/   
	for (idx = 0;  permitted[idx] != NULL; idx++) {
	    dn_normalize_case (permitted[idx]);

	    if (ll_insert_tail(&e_addr->e_addr_ok, strdup(" "), 
			strdup (permitted[idx])))
		return (LDAP_SYSERROR);

	}		
    }
    return 0;
}

static void 
simta_ldapuser (char * buf, char ** user, char ** domain)
{
    char  *puser;

    *domain = NULL;
    *user = strdup (buf);

    puser = strchr(*user , '@');
    if (puser)
    {
	*puser = '\0';
	puser++;
	simta_ldapdomain (puser, domain);
    }
    else
	*domain = strdup("");  
    return;
}

static void 
simta_ldapdomain (char * buf, char ** domain)
{
    char *pbuf;
    int	 dotcnt = 0;

    pbuf = &buf [ strlen (buf) - 1 ];

    while (pbuf > buf)
    {
	if (*pbuf == '.')
	{
	    if (dotcnt == 1)
	    {
		pbuf++;
		break;
	    }
	    dotcnt++;
	}
	pbuf--;
    }
    *domain = strdup(pbuf);
    return;
}

static int
simta_group_err_env (struct expand *exp, struct exp_addr *e_addr, 
			LDAPMessage *entry, char *dn)
{

    char **vals;

    int suppressnoemail = 0;
    char ** errdnvals;
    char ** errmailvals;

    int rc = 0;

    vals = ldap_get_values( ld, entry, "suppressNoEmailError");
    if (vals) 
    {
	if (strcasecmp ( vals[0], "TRUE") == 0)	
	    suppressnoemail = TRUE;
	ldap_value_free (vals);
    }

    errdnvals = ldap_get_values( ld, entry, "errorsto");
    errmailvals = ldap_get_values( ld, entry, "rfc822errorsto");

    if (errdnvals || errmailvals || suppressnoemail) {
	if (errdnvals || errmailvals) {
	    if ((e_addr->e_addr_errors = address_bounce_create( exp )) == NULL ) {
		syslog (LOG_ERR,
	  	    "simta_group_err_env: failed creating error env: %s", dn);
		ldap_memfree (dn);
		if (errdnvals)
		    ldap_value_free ( errmailvals );
		if (errmailvals)
		    ldap_value_free ( errdnvals);
		return LDAP_SYSERROR;
	    }
	
	    if (errmailvals) {
		add_errmailvals (e_addr, errmailvals, dn);
		ldap_value_free ( errmailvals );
	    }
	    if (errdnvals) {
		rc = add_errdnvals (exp, e_addr, errdnvals);
		ldap_value_free ( errdnvals );
	    }

	    if (suppressnoemail) 
		e_addr->e_addr_errors->e_flags = SUPPRESSNOEMAILERROR;
	}
	else
	{   /*
	    ** Else SuppressNoEmail must be true -- clone the current envelope
	    */
	    e_addr->e_addr_errors = env_dup (e_addr->e_addr_errors);
	    if ( e_addr->e_addr_errors == NULL ) {
		 syslog (LOG_ERR,
                	"simta_group_err_env: Failed env_dup: %s", dn);
		rc = LDAP_SYSERROR;
	    }
	    else
	        e_addr->e_addr_errors->e_flags = SUPPRESSNOEMAILERROR;
	}
    }

    return (rc);
}
/*
** Expands each value in the dn array "expdnvals"
** For each person it stuff the mailforwardingaddress into the 
** error envelopement.  For each group it stuff the rdn@associatedomain
** into the error envelopement.
*/
static int
add_errdnvals (struct expand *exp, struct exp_addr *e_addr, char ** expdnvals)
{
    int		idx;

    char	*search_dn;    
    LDAPMessage *res;
    LDAPMessage	*entry;
    struct timeval timeout = {MAIL500_TIMEOUT, 0};

    char	*dn;
    char	**vals;
    char	**ufn;
    char	*errmailbuf;
    int		match;
    int		rc;


    for (idx = 0; expdnvals[idx]; idx++)
    {
	search_dn = expdnvals[idx];
	res = NULL;
	rc = ldap_search_st( ld, search_dn, LDAP_SCOPE_BASE, "(objectclass=*)",
                        attrs, 0, &timeout, &res );
     
	if ( rc != LDAP_SUCCESS
	&&   rc != LDAP_SIZELIMIT_EXCEEDED
	&&   rc != LDAP_NO_SUCH_OBJECT ) {
      
	    syslog( LOG_ERR, "add_errdnvals: ldap_search_st Failed: %s",
                    ldap_err2string(rc ));
	    ldap_msgfree( res );
        
	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}

	match = ldap_count_entries (ld, res );
	if (match == -1) {
	    syslog( LOG_ERR,
    "add_errdnvals: Error parsing result from LDAP server for dn: %s",
                        search_dn);
	    ldap_msgfree( res );
	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}
	/*
        ** If not found -- Who cares!
        */
	if ( match == 0 ) {
	    ldap_msgfree( res );
	    continue;
	}

	if (( entry = ldap_first_entry( ld, res )) == NULL ) {
	    syslog( LOG_ERR, "add_errdnvals: ldap_first_entry: %s",
                ldap_err2string( ldap_result2error( ld, res, 1 )));
	    ldap_msgfree( res );
	    return( LDAP_SYSERROR );
	}

	dn = ldap_get_dn (ld, entry );

	if ( ldap_people
	&&  (simta_ldap_value( entry, "objectClass", ldap_people ) == 1 ) ) {
	    if (( vals = ldap_get_values( ld, entry,
                                "mailForwardingAddress" )) != NULL ) {
		add_errmailvals (e_addr, vals, dn);
		ldap_value_free( vals );
	    }
	}

	if ( ldap_groups
	&&  (simta_ldap_value( entry, "objectClass", ldap_groups ) == 1 ) ) {
	    /*
	    ** add rdn@associateddomain to env_recipient list
	    */
	    if (( vals = ldap_get_values( ld, entry,
					 "associateddomain" )) != NULL ) {

		ufn = ldap_explode_dn( dn, 1 );
		errmailbuf = (char *) malloc
				(strlen(ufn[0]) + strlen (vals[0]) + 2);
		if (! errmailbuf) {
		    syslog (LOG_ERR, 
		"simta_add_errmailvals: Failed allocating errmailbuf: %s", dn);
		    ldap_memfree (dn);
		    ldap_msgfree( res );
		    ldap_value_free( vals );
		    ldap_value_free( ufn );
		    return (LDAP_SYSERROR);
		}
		
		sprintf (errmailbuf, "%s@%s", ufn[0], vals[0]); 
	
		ldap_value_free( vals );
		ldap_value_free( ufn );

		rc = env_recipient( e_addr->e_addr_errors, errmailbuf);
	
		if( rc != 0 ) {
		    syslog (LOG_ERR, 
	"simta_add_errmailvals: %s failed adding error recipient: %s", dn,
				errmailbuf);
		    free (errmailbuf);
		    ldap_memfree (dn);
		    ldap_msgfree( res );
		    return (LDAP_SYSERROR);
		}
		free (errmailbuf);
	    }
	}
	ldap_memfree (dn);
	ldap_msgfree( res );
    }
    return (0);
}
/*
** Adds an array of email addresses "errmailvals" to the current
** error envelope.
*/
static int
add_errmailvals (struct exp_addr *e_addr, char ** errmailvals, char * dn)
{

    int		idx;
    char	*attrval;
    char	*nextval;

    for (idx = 0; errmailvals[idx]; idx++)
    {
	attrval = errmailvals[ idx ];
	while ( attrval && *attrval )
	{
	    attrval = simta_splitit (attrval, &nextval, ',');

	    if (strchr (attrval, '@') ) {		
		if( env_recipient( e_addr->e_addr_errors, attrval) != 0 ) {
		    syslog (LOG_ERR, 
	"simta_add_errmailvals: %s failed adding error recipient: %s", dn,
				attrval);
		    break;
		}
	    }
	    attrval = nextval;
	}
    }
    return (0);
}
/*
** Given a string,  it will return the string upto the
** next break character splitval.  It also sets next
** to point to the next character after splitval.
*/
static char *
simta_splitit (char * start, char ** next, int splitval)
{
    *next = strchr (start,  splitval);
    if (*next ) {
	**next = '\0';
	(*next)++;
    }

    return (start);
}
