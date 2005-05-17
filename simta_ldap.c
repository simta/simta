/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     simta_ldap.c     *****/

#include "config.h"

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */


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
#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <snet.h>
#include "denser.h"
#include "ll.h"
#include "queue.h"
#include "envelope.h"
#include "simta.h"
#include "expand.h"
#include "argcargv.h"
#include "simta_ldap.h"
#include "dn.h"

#define	SIMTA_LDAP_CONF		"./simta_ldap.conf"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define MAXRETRIES		5

#define MAXAMBIGUOUS		10
#define LDAP_TIMEOUT_VAL	180

/* MAXADDRESSLENGTH -- maximum length email address we're gonna process */
#define MAXADDRESSLENGTH	1024
/* ERRORFMTBUFLEN -- Error buffer length process max buffer size. */
#define ERRORFMTBUFLEN		2048

/* 
e* LDAP attribute names
** noattrs -- is a attribute list when no attributes are needed.
** allattrs -- is a attribute list when all attributes are wanted.  It
**             It is also the default attribute list if no attribute
**             config file directive found.
*/
static char	*allattrs[] = {"*", NULL};

static char     **attrs     = NULL;

/*
** ldap_search_list -- Contains a parsed uri from the config file.
*/
struct ldap_search_list {
    LDAPURLDesc			*lds_plud;	/* url parsed description */
    int				lds_rdn_pref;	/* TRUE / FALSE */
    int				lds_search_type;/* one of USER, GROUP, ALL */
    char			*lds_string;	/* uri string */
    struct ldap_search_list     *lds_next;	/* next uri */
};

struct ldap_search_list		*ldap_searches = NULL;
struct list			*ldap_people = NULL;
struct list			*ldap_groups = NULL;
LDAP				*ld = NULL;

static char			*ldap_host;
static int			ldap_port;
static time_t			ldap_timeout = LDAP_TIMEOUT_VAL;
static int			starttls;
static char			*tls_cert;
static char			*tls_key;
static char			*tls_cacert;
static char			*binddn;
static char			*bindpw;

static int			ldapdebug;

static char			*vacationhost;
static char			*vacationattr;
static char			*mailfwdattr;
static char			*mailattr;

static int			ndomaincomponent = 2;
/*
** simta_ldap_message_stdout -- Dumps an entry to stdout
*/
    static int
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
simta_ldapdomain (char * buf, char ** domain)
{
    char *pbuf;
    int	 dotcnt = 0;

    pbuf = &buf [ strlen (buf) - 1 ];

    while (pbuf > buf) {
	if (*pbuf == '.') {
	    if (dotcnt == (ndomaincomponent - 1)) {
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

    static void 
simta_ldapuser (char * buf, char ** user, char ** domain)
{
    char  *puser;

    *domain = NULL;
    *user = strdup (buf);

    puser = strchr(*user , '@');
    if (puser) {
	*puser = '\0';
	puser++;
	simta_ldapdomain (puser, domain);
    }
    else
	*domain = strdup("");  
    return;
}

/*
** Unbind from the directory.
*/
    static void
simta_ldap_unbind ()
{
    ldap_unbind( ld );
    ld = NULL;
    return;
}
/*
** SASL Call Back
** This SASL callback only works for "EXTERNAL" 
*/
    static int
simta_ldap_sasl_interact(
        LDAP *ld,
        unsigned flags,
        void *defaults,
        void *in )
{
   
    sasl_interact_t *interact = in;

    while( interact->id != SASL_CB_LIST_END ) {

	interact->result = NULL;
	interact->len = 0;

	interact++;
    } 
    return LDAP_SUCCESS;
}
    static int
simta_ldap_init ()
{
    int ldaprc;
    int	maxambiguous = MAXAMBIGUOUS;
    int protocol = LDAP_VERSION3;

    if ( ld == NULL ) {
	if (( ld = ldap_init( ldap_host, ldap_port )) == NULL ) {
	    syslog( LOG_ERR, "ldap_init: %m" );
	    return( LDAP_SYSERROR );
	}
	if ( ldapdebug ) {
	    ldaprc = ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ldapdebug );
	    if( ldaprc != LBER_OPT_SUCCESS ) {
		syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LBER_OPT_DEBUG_LEVEL=%d\n", ldapdebug);
	    }
	    ldaprc = ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &ldapdebug );
	    if( ldaprc != LDAP_OPT_SUCCESS ) {
		syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LDAP_OPT_DEBUG_LEVEL=%d\n", ldapdebug);
	    }
	}
	ldaprc = ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	if (ldaprc != LDAP_OPT_SUCCESS ) {
	    syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LDAP_OPT_REFERRALS to LDAP_OPT_OFF");
	    return( LDAP_SYSERROR );
	}
	ldaprc = ldap_set_option(ld, LDAP_OPT_SIZELIMIT, (void *)&maxambiguous);
	if (ldaprc != LDAP_OPT_SUCCESS ) {
	    syslog( LOG_ERR, 
		"simta_ldap_init: Failed setting LDAP_OPT_SIZELIMIT = %d\n",
		maxambiguous);
	    return( LDAP_SYSERROR );
	}
	ldaprc = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &protocol );
	if( ldaprc != LDAP_OPT_SUCCESS ) {
	    syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LDAP_OPT_PROTOCOL_VERSION = %d\n",
		protocol );
	    return( LDAP_SYSERROR );
	}
        if (tls_cacert) {
	    ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, tls_cacert);
	    if( ldaprc != LDAP_OPT_SUCCESS ) {
		syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LDAP_OPT_X_TLS_CACERTFILE = %s\n",
		ldap_err2string( ldaprc ) );
		return( LDAP_SYSERROR );
	    }
	}
        if (tls_cert) {
	    ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, tls_cert);
	    if( ldaprc != LDAP_OPT_SUCCESS ) {
		syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LDAP_OPT_X_TLS_CERTFILE = %s\n",
		ldap_err2string( ldaprc ));
		return( LDAP_SYSERROR );
	    }
	}
        if (tls_key) {
	    ldaprc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, tls_key);
	    if( ldaprc != LDAP_OPT_SUCCESS ) {
		syslog( LOG_ERR, 
	"simta_ldap_init: Failed setting LDAP_OPT_X_TLS_KEYFILE = %s\n",
		 ldap_err2string( ldaprc ));
		return( LDAP_SYSERROR );
	    }
	}

	if ( starttls &&
	   ((ldaprc = ldap_start_tls_s( ld, NULL, NULL )) != LDAP_SUCCESS )) {
	    syslog( LOG_ERR, "ldap_start_tls: %s", ldap_err2string(ldaprc));
	    if ( starttls > 1 ) {
		return( LDAP_SYSERROR );
	    }
	}
    }
    /* If a client-side cert specified,  then do a SASL EXTERNAL bind */
    if (tls_cert) {
	ldaprc = ldap_sasl_interactive_bind_s( ld, binddn,
			"EXTERNAL", NULL, NULL,
			LDAP_SASL_QUIET, simta_ldap_sasl_interact, NULL );
	if( ldaprc != LDAP_SUCCESS ) {
	    syslog( LOG_ERR, "ldap_sasl_interactive_bind_s: %s", 
                        ldap_err2string(ldaprc));
	    return ( LDAP_SYSERROR );
	}
    }
    else if (binddn) {
	if ((ldaprc = ldap_bind_s( ld, binddn, bindpw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS){
	    syslog( LOG_ERR, "ldap_bind: %s", ldap_err2string(ldaprc));
	    return( LDAP_SYSERROR );
	}
    }
    return (0);
}
/*
** This function looks thru the attribute "attr" values 
** for the first matching value in the "master" list
*/
    static  int
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
		    return ( 1 );
		}
	    }
	}
	ldap_value_free( values );
    }
    return( 0 );
}

    /* return a statically allocated string if all goes well, NULL if not.
     *
     *     - Build search string where:
     *         + %s -> username
     *         + %h -> hostname
     */

    static char *
simta_ldap_string( char *filter, char *user, char *domain )
{
    size_t		len;
    static size_t	buf_len = 0;
    static char		*buf = NULL;
    char		*c;
    char		*d;
    char		*insert;
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
	switch ( *c ) {
	case '%':
	    switch ( * ( c + 1 )) {
		case 's':
		    /* if needed, resize buf to handle upcoming insert */
		    if (( len += (2 * strlen( user ))) > buf_len ) {
			place = d - buf;
			if (( buf = (char*)realloc( buf, len )) == NULL ) {
			    syslog( LOG_ERR, "realloc: %m" );
			    return( NULL );
			}
			d = buf + place;
			buf_len = len;
		    }

		    /* insert word */
		    for ( insert = user; *insert != '\0'; insert++ ) {
			switch ( *insert ) {

			case '.':
			case '_':
			    *d = ' ';
			    break;

			case '(':
			case ')':
			case '*':
			    *d++ = '\\';    /*  Fall Thru */
			
			default:
			    *d = *insert;
			}
			d++;
		    }

		    /* advance read cursor */
		    c += 2;
		    break;

		case 'h':
		    /* if needed, resize buf to handle upcoming insert */
		    if (( len += strlen( domain )) > buf_len ) {
			place = d - buf;
			if (( buf = (char*)realloc( buf, len )) == NULL ) {
			    syslog( LOG_ERR, "realloc: %m" );
			    return( NULL );
			}
			d = buf + place;
			buf_len = len;
		    }

		    /* insert word */
		    for ( insert = domain; *insert != '\0'; insert++ ) {
			*d = *insert;
			d++;
		    }

		    /* advance read cursor */
		    c += 2;
		    break;

		case '%':
		    /* %% -> copy single % to data buffer */
		    *d = *c;
		    /* advance cursors */
		    c += 2;
		    d++;
		    break;

		default:
		    c++;
		    break;
	    }
	    break;

	default:
	    /* raw character, copy to data buffer */
	    *d = *c;

	    /* advance cursors */
	    d++;
	    c++;
	    break;
	}
    }

    *d = '\0';

    return( buf );
}

/*
** Looks at the incoming email address
** looking for "-errors", "-requests", or "-owners"
**
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
        } else if ((strcasecmp(paddr, OWNER) == 0) ||
                   (strcasecmp(paddr, OWNERS) == 0)) {
            addrtype = LDS_GROUP_OWNER;
            *(--paddr) = '\0';
        }
    }

    return (addrtype);
}

    static void
do_ambiguous (struct exp_addr *e_addr, char *addr, LDAPMessage *res)
{

    int		idx;
    char	*dn; 
    char	*rdn;
    char	**ufn;
    char	**vals;
    LDAPMessage	*e;

    if ( bounce_text( e_addr->e_addr_errors, addr, 
				": Ambiguous user", NULL ) != 0 ) {
	return;
    }

    for ( e = ldap_first_entry( ld, res ); e != NULL;
	  e = ldap_next_entry( ld, e ) ) {
	dn = ldap_get_dn( ld, e );
	ufn = ldap_explode_dn( dn, 1 );
	rdn = strdup( ufn[0] );
	ldap_value_free( ufn );
	free( dn );

	if ( strcasecmp( rdn, addr ) == 0 ) {
	    if ( (vals = ldap_get_values( ld, e, "cn" )) != NULL ) {
		rdn = strdup( vals[0] );
		ldap_value_free( vals );
	    }
	}
	if (ldap_groups 
	&& ( simta_ldap_value( e, "objectClass", ldap_groups) > 0 )) {
	    vals = ldap_get_values( ld, e, "description" );
	} else {
	    vals = ldap_get_values( ld, e, "title" );
	}
	if (vals && vals[0]) {
	    if (bounce_text( e_addr->e_addr_errors, rdn, "\t", vals[0] ) != 0) {
		return;
	    }

	    for ( idx = 1; vals && vals[idx] != NULL; idx++ ) {
		if (bounce_text( e_addr->e_addr_errors, "\t\t", vals[idx], NULL)
			!= 0) {
		    return;
		}
	    }
	    ldap_value_free( vals );
	} else {
	    if (bounce_text( e_addr->e_addr_errors, rdn, NULL, NULL ) != 0) {
		return;
	    }
	}
	free( rdn );
    }
}

    static void
do_noemail (struct exp_addr *e_addr, char *addr, LDAPMessage *res)
{

    int		idx;
    char	*dn; 
    char	*rdn;
    char	**ufn;
    char	**vals;

    char	*pnl;
    char	*pstart;

    if ( bounce_text( e_addr->e_addr_errors, addr,
		": User has no email address registered.\n" , NULL ) != 0 ) {
	return;
    }
  
    if ( bounce_text( e_addr->e_addr_errors, 
"\tName, title, postal address and phone for: ",  addr, NULL ) != 0 ) {
	return;
    }

    /* name */
    dn = ldap_get_dn( ld, res );
    ufn = ldap_explode_dn( dn, 1 );
    rdn = strdup( ufn[0] );
    if ( strcasecmp( rdn, addr ) == 0 ) {
	if ( (vals = ldap_get_values( ld, res, "cn" )) != NULL ) {
	    free (rdn);
	    rdn = strdup( vals[0] );
	    ldap_value_free( vals );
	}
    }

    if ( bounce_text( e_addr->e_addr_errors, "\t", rdn, NULL ) != 0 ) {
	return;
    }

    free( dn );
    free( rdn );
    ldap_value_free( ufn );

    /* titles or descriptions */
    if ( (vals = ldap_get_values( ld, res, "title" )) == NULL &&
         (vals = ldap_get_values( ld, res, "description" )) == NULL ) {

	if ( bounce_text( e_addr->e_addr_errors, "\t", 
			"No title or description registered" , NULL ) != 0 ){
	    ldap_value_free( vals );
	    return;
	}
    } else {
	for ( idx = 0; vals[idx] != NULL; idx++ ) {
	    if ( bounce_text( e_addr->e_addr_errors, 
				"\t", vals[idx], NULL ) != 0 ) {
		ldap_value_free( vals );
		return;
	    }
	}
	ldap_value_free( vals );
    }
    /* postal address*/
    if ( (vals = ldap_get_values( ld, res, "postaladdress" )) == NULL ) {
	if ( bounce_text( e_addr->e_addr_errors, "\t", 
			"No postaladdress registered", NULL ) != 0 ){
	    ldap_value_free( vals );
	    return;
	}
    } else {
        for (pstart = vals[0]; pstart; pstart = pnl) {
	    pnl = strchr (pstart, '$');
	    if (pnl) {
		*pnl = '\0';
		pnl++;
	    }
	    if (strlen (pstart)) {	
		if ( bounce_text( e_addr->e_addr_errors, 
				"\t", pstart, NULL ) != 0 ) {
		    ldap_value_free( vals );
		    return;
		}
	    }
	}
	ldap_value_free( vals );
    }
    /* telephone number */
    if ( (vals = ldap_get_values( ld, res, "telephoneNumber" )) == NULL ) {
	if ( bounce_text( e_addr->e_addr_errors, "\t", 
				"No phone number registered", NULL ) != 0 ){
	    ldap_value_free( vals );
	    return;
	}
    } else {
	for ( idx = 0; vals[idx] != NULL; idx++ ) {
	    if ( bounce_text( e_addr->e_addr_errors, 
				"\t", vals[idx], NULL ) != 0 ) {
		ldap_value_free( vals );
		return;
	    }
	}
	ldap_value_free( vals );
    }
    return;
}

    /* this function should return:
     *     LDAP_SYSERROR if there is an error
     *     LDAP_LOCAL if addr is found in the db
     *     LDAP_NOT_LOCAL if addr is not found in the db
     */

    int
simta_ldap_address_local( char *name, char *domain )
{
    char	*dup_name;
    char	*pname;
    int		nametype;
    int		rc;
    int		count = 0;		/* Number of ldap entries found */

    char			*search_string;
    struct ldap_search_list	*lds;
    LDAPMessage			*res = NULL;
    LDAPMessage			*entry;
    struct timeval		timeout;
    char			**vals;

    if ( ld == NULL ) {
	if ( (rc = simta_ldap_init( )) != 0 ) {
	    return( rc );
	}
    }

    dup_name = strdup (name);
    /*
    ** Strip . and _                 
    */
    for (pname = dup_name; *pname; pname++) {
	if (*pname == '.' || *pname == '_')
	    *pname = ' ';
    }

    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    nametype = simta_address_type(dup_name );

    /* for each base string in ldap_searches:
     *     - Build search string
     *     - query the LDAP db with the search string
     */
    for ( lds = ldap_searches; lds != NULL; lds = lds->lds_next ) {
	search_string = simta_ldap_string( lds->lds_plud->lud_filter, 
			dup_name, domain);
	if ( search_string == NULL ) {
	    free (dup_name);
	    return (LDAP_SYSERROR);
	}

	timeout.tv_sec = ldap_timeout;
	timeout.tv_usec = 0;

	rc = ldap_search_st( ld, lds->lds_plud->lud_dn, 
			lds->lds_plud->lud_scope, search_string, attrs, 0, 
			&timeout, &res );
	if ( rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
	    syslog( LOG_ERR, 
	"simta_ldap_address_local: ldap_search_st Failed: %s", ldap_err2string(rc ));
		
	    ldap_msgfree( res );

	    simta_ldap_unbind (ld);
	    free (dup_name);
	    return (LDAP_SYSERROR);
	}

	if ((count = ldap_count_entries( ld, res ))) {
	    break;
	}
	ldap_msgfree( res );
	res = NULL;
    }

    free (dup_name);

    if (count == 0) {
	rc = LDAP_NOT_LOCAL;
    } else {
	rc = LDAP_LOCAL;
	entry = ldap_first_entry( ld, res );
	if ((vals = ldap_get_values( ld, entry, "realtimeblocklist")) != NULL) {
	    if (strcasecmp ( vals[0], "TRUE") == 0) {
		rc = LDAP_LOCAL_RBL;
	    }
	    ldap_value_free (vals);
	}
    }
    if (res) {
	ldap_msgfree( res );
    }
	
    return ( rc );
}


    static int 
simta_ldap_expand_group ( struct expand *exp, struct exp_addr *e_addr,
 		int type, LDAPMessage *entry)
{
    int		valfound = 0;
    int		moderator_error = 0;
    char	**dnvals;
    char	**mailvals;
    char	*dn;
    char	*errmsg;
    int		idx;		/* universal iterator */

    char	**memonly;	/* Members Only attribute values */
    char	**private;	/* Private Members Only attribute value */
    char	**moderator;	/* Moderator attribute values */
    char	**permitted;	/* permittedgroup attribute values */

    char	*attrval;
    char	*ndn;		/* a "normalized dn" */

    int		rc;
    char	**vals;
    char	**rdns;
    char	*senderbuf;
    char	*psender;
    int		suppressnoemail = 0;
    int		mo_group = 0;
    struct recipient	*r = NULL;

    dn = ldap_get_dn( ld, entry );
   
    if (e_addr->e_addr_dn == NULL) {
	dn_normalize_case(dn);
	e_addr->e_addr_dn = strdup (dn);
    }
    if ((vals = ldap_get_values( ld, entry, "suppressNoEmailError")) != NULL) {
	if (strcasecmp ( vals[0], "TRUE") == 0) {
	    suppressnoemail = 1;
        }
	ldap_value_free (vals);
    }

    if (( vals = ldap_get_values (ld, entry, "associateddomain")) == NULL ){
	return( LDAP_EXCLUDE );
    }
    rdns = ldap_explode_dn (dn, 1);

    if (( e_addr->e_addr_owner = (char*)malloc( strlen( rdns[0] ) +
	    strlen( vals[0] ) + 8 )) == NULL ) {
	ldap_memfree (dn);
	ldap_value_free( vals );
	ldap_value_free( rdns );
	return( LDAP_SYSERROR );
    }
    sprintf( e_addr->e_addr_owner, "%s-owner@%s", rdns[0], vals[0]);

    for (psender = e_addr->e_addr_owner; *psender; psender++) {
	if (*psender == ' ') {
	    *psender = '.';
	}
    }

    if ( *(e_addr->e_addr_from) == '\0' ) {
        senderbuf = strdup ("");
    } else {
	/*
	* You can't send mail to groups that have no associatedDomain.
	*/
	senderbuf = (char *) malloc (strlen(rdns[0]) + strlen (vals[0]) + 12);
	if (! senderbuf ) {
	    syslog (LOG_ERR,
                "simta_ldap_expand_group: Failed allocating senderbuf: %s", dn);
	    ldap_memfree (dn);
	    ldap_value_free( vals );
	    ldap_value_free( rdns );
	    return (LDAP_SYSERROR);
	}
	sprintf (senderbuf, "%s-errors@%s", rdns[0], vals[0]);
	for (psender = senderbuf; *psender; psender++) {
	    if (*psender == ' ') {
		*psender = '.';
	    }
	}

	if ((e_addr->e_addr_errors = address_bounce_create( exp )) == NULL ) {
	    syslog (LOG_ERR,
                  "simta_ldap_expand_group: failed creating error env: %s", dn);
	    free ( senderbuf );
	    ldap_memfree (dn);
	    ldap_value_free( vals );
	    ldap_value_free( rdns );
	    return LDAP_SYSERROR;
	} 

	if (env_recipient( e_addr->e_addr_errors, senderbuf) != 0) {
       	    syslog (LOG_ERR,
               "simta_ldap_expand_group: failed setting error recip: %s", dn);
	    free (senderbuf);
	    ldap_memfree (dn);
	    ldap_value_free( vals );
	    ldap_value_free( rdns );
	    return LDAP_SYSERROR;
	}
    } 

    ldap_value_free( vals );
    ldap_value_free( rdns );

    switch ( type ) {
    case LDS_GROUP_ERRORS:
	
	dnvals = ldap_get_values( ld, entry, "errorsto");
	mailvals = ldap_get_values( ld, entry, "rfc822errorsto");
	errmsg = ": Group exists but has no errors-to address\n";

	if (dnvals == NULL &&  mailvals == NULL) {
	    dnvals = ldap_get_values( ld, entry, "owner");
	}
	    
	break;

    case LDS_GROUP_REQUEST:

	dnvals = ldap_get_values( ld, entry, "requeststo");
	mailvals = ldap_get_values( ld, entry, "rfc822requeststo");
	errmsg = ": Group exists but has no requests-to address\n";

	if (dnvals == NULL &&  mailvals == NULL) {
	    dnvals = ldap_get_values( ld, entry, "owner");
	}
	break;

    case LDS_GROUP_OWNER:

	dnvals = ldap_get_values( ld, entry, "owner");
	mailvals = NULL;
	errmsg = ": Group exists but has no owners\n";
	break;

    default:
	dnvals = NULL;
	mailvals = NULL;
	errmsg = NULL;

	if (( memonly = ldap_get_values( ld, entry, "membersonly" )) != NULL ) {
	    if ( strcasecmp( memonly[0], "TRUE" ) == 0 ) {
		mo_group = 1;
	    }
	    ldap_value_free( memonly );
	}

	if (( moderator = ldap_get_values( ld, entry, "moderator" )) != NULL ) {
	    if ( exp->exp_env->e_n_exp_level < simta_exp_level_max ) {
		if (( e_addr->e_addr_env_moderated =
			env_create( exp->exp_env->e_mail,
			exp->exp_env )) == NULL ) {
		    ldap_value_free( moderator );
		    ldap_memfree( dn );
		    free( senderbuf );
		    return( LDAP_SYSERROR );
		}

		for ( idx = 0; moderator[ idx ] != NULL; idx++ ) {
		    if ( env_string_recipients( e_addr->e_addr_env_moderated,
			    moderator[ idx ]) != 0 ) {
			env_free( e_addr->e_addr_env_moderated );
			e_addr->e_addr_env_moderated = NULL;
			ldap_value_free( moderator );
			ldap_memfree( dn );
			free( senderbuf );
			return( LDAP_SYSERROR );
		    }
		}

		ldap_value_free( moderator );

		if (( r = e_addr->e_addr_env_moderated->e_rcpt ) == NULL ) {
		    /* no valid email addresses */
		    env_free( e_addr->e_addr_env_moderated );
		    e_addr->e_addr_env_moderated = NULL;
		    moderator_error = 1;
		    bounce_text( e_addr->e_addr_errors, "bad moderator: ", dn,
			    NULL );
		}

		for ( ; r != NULL; r = r->r_next ) {
		    if ( simta_mbx_compare( r->r_rcpt,
			    exp->exp_env->e_mail ) == 0 ) {
			/* sender matches moderator in moderator env */
			break;
		    }
		}

	    } else {
		bounce_text( e_addr->e_addr_errors, "moderator mail loop: ", dn,
			NULL );
		break;
	    }
	}

	if ( r != NULL ) {
	    /* sender matches moderator in moderator env */
	    env_free( e_addr->e_addr_env_moderated );
	    e_addr->e_addr_env_moderated = NULL;

	} else if ( mo_group ) {
	    e_addr->e_addr_ldap_flags |= STATUS_LDAP_MEMONLY;

	    if (( private = ldap_get_values( ld, entry, "rfc822private" ))
		    != NULL ) {
		if ( strcasecmp( private[0], "TRUE" ) == 0 ) {
		    e_addr->e_addr_ldap_flags |= STATUS_LDAP_PRIVATE;
		}
		ldap_value_free( private );
	    }

	    if ( exp_addr_link( &(exp->exp_memonly), e_addr ) != 0 ) {
		ldap_memfree( dn );
		free( senderbuf );
		return( LDAP_SYSERROR );
	    }

	    if (( permitted = ldap_get_values( ld, entry,
		    "permittedgroup")) != NULL ) {
		if ( permitted_create( e_addr, permitted ) != 0 ) {
		    ldap_value_free( permitted );
		    free( senderbuf );
		    ldap_memfree( dn );
		    return( LDAP_SYSERROR );
		}
		ldap_value_free( permitted );
	    }
	}

	if ((( e_addr->e_addr_env_moderated == NULL ) &&
		( moderator_error == 0 )) ||
		( e_addr->e_addr_ldap_flags & STATUS_LDAP_MEMONLY )) {
	    dnvals = ldap_get_values( ld, entry, "member");
	    mailvals = ldap_get_values( ld, entry, "rfc822mail");
	}

	if ( suppressnoemail ) {
	    e_addr->e_addr_errors->e_flags |= ENV_FLAG_SUPRESS_NO_EMAIL;
	}
	break;
    }   /* end of switch */

    if (dnvals ) {
	valfound++;

	for ( idx = 0; dnvals[ idx ] != NULL; idx++ ) {
	    ndn = dn_normalize_case (dnvals[ idx ]); 

	    /* If sending to group members 
	    ** -- change from address to be: group-errors@associateddomaon
	    ** -- otherwise use the original sender.
	    */
	    if (( type == LDS_GROUP_MEMBERS ) || ( type == LDS_USER )) {
		rc =  add_address( exp, ndn, e_addr->e_addr_errors, 
			    ADDRESS_TYPE_LDAP, senderbuf );
	    } else {
		rc =  add_address( exp, ndn, e_addr->e_addr_errors,    
			    ADDRESS_TYPE_LDAP, e_addr->e_addr_from );       
	    }
	    if (rc != 0 ) {
		syslog (LOG_ERR,
		    "simta_ldap_expand_group: %s failed adding: %s", dn,
		    dnvals[ idx ]);
		break;
	    }
	}
	ldap_value_free( dnvals);
    }

    if (mailvals ) {
	valfound++;

	for ( idx = 0; mailvals[ idx ] != NULL; idx++ ) {

	    attrval = mailvals[ idx ];

	    if (strchr (attrval, '@') ) {		
		if (( type == LDS_GROUP_MEMBERS ) || ( type == LDS_USER )) {
		    rc = address_string_recipients( exp, attrval,
			    e_addr, senderbuf );
		} else {
		    rc = address_string_recipients( exp, attrval,
			    e_addr, e_addr->e_addr_from );
                }
		if (rc != 0 ) {
		    syslog (LOG_ERR,
			"simta_ldap_expand_group: %s failed adding: %s", dn,
			attrval);
		    break;
		}
	    }
	}
	ldap_value_free( mailvals);
    }
    if ((valfound == 0) && (errmsg != NULL)) {
	bounce_text( e_addr->e_addr_errors, dn, errmsg, NULL);
    }	
    free( senderbuf );
    ldap_memfree (dn);
    return LDAP_EXCLUDE;
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

    char	buf[1024];

    if ( ldap_groups
    &&  (simta_ldap_value( entry, "objectClass", ldap_groups ) == 1 ) ) {
	result = simta_ldap_expand_group (exp, e_addr, type, entry);
	return (result);
    }

    /* it wasn't a group  -- check if it's a people */
    if ( ldap_people
    &&  (simta_ldap_value( entry, "objectClass", ldap_people ) == 1 ) ) {

	/* get individual's email address(es) */
	if (( values = ldap_get_values( ld, entry, mailfwdattr)) == NULL ) {
	    /*
	    ** This guy has no mailforwardingaddress	
	    ** Depending on if we're expanding a group
	    ** Bounce it with the appropriate message.
	    */
	    if ( e_addr->e_addr_type != ADDRESS_TYPE_LDAP ) {
		do_noemail (e_addr, addr, entry);
	    } else {
		if (( e_addr->e_addr_errors->e_flags &
			ENV_FLAG_SUPRESS_NO_EMAIL ) == 0 ) {
		    if ( bounce_text( e_addr->e_addr_errors, addr,
		" : Group member exists but does not have an email address" , 
			"\n" ) != 0 ) {
			syslog( LOG_ERR, 
    "simta_ldap_process_entry: Failed building bounce message -- no email: %s",
				e_addr->e_addr);
			return( LDAP_SYSERROR );
		    }
		}
	    }
	} else {

	    for ( idx = 0; values[ idx ] != NULL; idx++ ) {
		attrval = values[ idx ];
		if ( address_string_recipients( exp, attrval,
			e_addr, e_addr->e_addr_from ) != 0 ) {
		    syslog (LOG_ERR, 
    "simta_ldap_process_entry: failed adding mailforwardingaddress: %s", addr);
		    ldap_value_free( values );
		    return( LDAP_SYSERROR );
		}
	    }
	    ldap_value_free( values );

	    if (( values = ldap_get_values( ld, entry, mailattr)) != NULL ) {
		if ( simta_mbx_compare( values[ 0 ],
			exp->exp_env->e_mail ) == 0 ) {
		    e_addr->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
		}
		ldap_value_free( values );
	    }

	    /*
	    * If the user is on vacation, send a copy of the mail to
	    * the vacation server.  The address is constructed from
 	    * the vacationhost (specified in the config file) and
	    * the uid (XXX this this attr should be configurable XXX).
	    */
	    onvacation = NULL;
	    if ( vacationhost != NULL && vacationattr != NULL
            && (onvacation = ldap_get_values( ld, entry, vacationattr)) != NULL 
	    && strcasecmp( onvacation[0], "TRUE" ) == 0 ) {

		if ( (uid = ldap_get_values( ld, entry, "uid" )) != NULL ) {
		    snprintf( buf, sizeof (buf), "%s@%s", uid[0], vacationhost);
		    if ( add_address( exp, buf,
			  e_addr->e_addr_errors, ADDRESS_TYPE_EMAIL,
			  e_addr->e_addr_from ) != 0 ) {
			syslog (LOG_ERR, 
	"simta_ldap_process_entry: failed adding vacation address: %s", buf);
		    }
		    ldap_value_free( uid);
	    	} else {
		    syslog( LOG_ERR, "user without a uid on vacation (%s)",
				 addr );
	    	}
	    }
	    if ( onvacation ) {
		ldap_value_free( onvacation );
	    }
	}

	return (LDAP_EXCLUDE);

    } else {
	/* Neither a group, or a person */
	syslog( LOG_ERR, "Entry: %s is neither person or group ",
                e_addr->e_addr);
        bounce_text( e_addr->e_addr_errors, addr,
	" : Entry exists but is neither a group or person", NULL );
	return( LDAP_EXCLUDE );
    }
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

    LDAPMessage		*tmpres = NULL;
    char		*dn;
    char		**xdn;
    struct timeval	timeout;
    int			retrycnt = 0;

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
startsearch:
	timeout.tv_sec = ldap_timeout;
	timeout.tv_usec = 0;
	res = NULL;
	rc = ldap_search_st( ld, lds->lds_plud->lud_dn,
			lds->lds_plud->lud_scope, search_string, 
			attrs, 0, &timeout, &res );

	/*
	** After a long idle time,  the connection can be closed 
	** by the ldap server.  A long idle time can result if we
	** are processing a really long queue of mail.
	** If connection timeout, restart the connection.
        */
	if (rc == LDAP_SERVER_DOWN) {
	    ldap_msgfree( res );
	    simta_ldap_unbind (ld);

	    retrycnt++;
	    if (retrycnt > MAXRETRIES) {
		return( LDAP_SYSERROR );
	    }
		
	    if ((rc = simta_ldap_init () )) {
		return( LDAP_SYSERROR );
	    }
	    goto startsearch;
	}



	if ( rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED 
	&&   rc != LDAP_TIMELIMIT_EXCEEDED) {
	    syslog( LOG_ERR, "simta_ldap_name_search: ldap_search_st error: %s",
		    ldap_err2string(rc ));
	    ldap_msgfree( res ); 
	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}

	if (( match = ldap_count_entries( ld, res )) != 0 ) 
	    break;

	ldap_msgfree( res );

        /* Search timeout w/ no matches -- generate a temporary failure */
	if (rc ==  LDAP_TIMELIMIT_EXCEEDED) {
	    return( LDAP_SYSERROR );
	}
    }

    switch (match) {

    case 0:
	return( LDAP_NOT_FOUND ); /* no entries found */

    case -1:
	syslog( LOG_ERR, 
 "simta_ldap_name_search:Error parsing result from LDAP server for address: %s",
			e_addr->e_addr);
	ldap_msgfree( res );
	simta_ldap_unbind (ld);
	return( LDAP_SYSERROR );
    
    default:

	/*
	** More than one match -- if no rdn preference 
        ** then bounce w/ ambiguous user 
        */
	if (! lds->lds_rdn_pref) {
	    do_ambiguous (e_addr, addr, res);

            ldap_msgfree( res );
	    return ( LDAP_EXCLUDE );
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

	/* if nothing matched by rdn - go ahead and bounce */
	if ( tmpres == NULL ) {
	    do_ambiguous (e_addr, addr, res);

            ldap_msgfree( res );
	    return ( LDAP_EXCLUDE );

	/* if more than one matched by rdn - bounce with rdn matches */
	} else if ( (match = ldap_count_entries( ld, tmpres )) > 1 ) {
	    do_ambiguous (e_addr, addr, res);

            ldap_msgfree( res );
            ldap_msgfree( tmpres );
	    return ( LDAP_EXCLUDE );

	/* trouble --  tmpres hosed? */
	} else if ( match < 0 ) {
	    syslog( LOG_ERR, 
	"simta_ldap_name_search: Error parsing LDAP result for address: %s",
			e_addr->e_addr);
            ldap_msgfree( res );
            ldap_msgfree( tmpres );
	    simta_ldap_unbind (ld);
	    return( LDAP_SYSERROR );
	}

	/* otherwise one matched by rdn - send to it */
	ldap_msgfree( res );
	res = tmpres;
        /*  
        ** we've sorted this ambiguity out, 
	** so fall thru to next case and process this entry.
        */
    
    case 1:
	/*
	** One entry now that matches our address.
	*/
	if (( entry = ldap_first_entry( ld, res )) == NULL ) {
	    syslog( LOG_ERR, "simta_ldap_name_search: ldap_first_entry: %s",
		ldap_err2string( ldap_result2error( ld, res, 1 )));
	    return( LDAP_SYSERROR );
        }
    }

    rc = simta_ldap_process_entry (exp, e_addr, addrtype, entry, addr);

    ldap_msgfree( res );
    return( rc );
}

    static int
simta_ldap_dn_expand (struct expand *exp, struct exp_addr *e_addr )
{
    char		*search_dn;
    int			rc;
    int			match;
    LDAPMessage		*res;
    LDAPMessage		*entry;
    struct timeval	timeout;

    search_dn = e_addr->e_addr;
    timeout.tv_sec = ldap_timeout;
    timeout.tv_usec = 0;
    res = NULL;
    rc = ldap_search_st( ld, search_dn, LDAP_SCOPE_BASE, "(objectclass=*)", 
			attrs, 0, &timeout, &res );

    if ( rc != LDAP_SUCCESS 
    &&   rc != LDAP_SIZELIMIT_EXCEEDED 
    &&   rc != LDAP_TIMELIMIT_EXCEEDED
    &&   rc != LDAP_NO_SUCH_OBJECT ) {

	syslog( LOG_ERR, "simta_ldap_dn_expand: ldap_search_st Failed: %s",
		    ldap_err2string(rc ));
	ldap_msgfree( res ); 
	simta_ldap_unbind (ld);
	return( LDAP_SYSERROR );
    }
    match = ldap_count_entries (ld, res );
    if ( match == -1) {
	syslog( LOG_ERR, 
    "simta_ldap_dn_expand: Error parsing result from LDAP server for dn: %s",
			search_dn);
	ldap_msgfree( res );
	simta_ldap_unbind (ld);
	return( LDAP_SYSERROR );
    }

    if ( match == 0 ) {
	ldap_msgfree( res );

    	if (bounce_text( e_addr->e_addr_errors, search_dn,
		" : Group member does not exist" , NULL ) != 0 ) {
	    syslog( LOG_ERR, 
	"simta_ldap_dn_expand: Failed building bounce message -- no member: %s",
				search_dn);
	    return( LDAP_SYSERROR );
	}
	return( LDAP_EXCLUDE ); /* no entries found */
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




    /* this function should return:
     *     LDAP_NOT_FOUND if addr is not found in the database
     *     LDAP_FINAL if addr is a terminal expansion
     *     LDAP_EXCLUDE if addr is an error, and/or expands to other addrs.
     *     LDAP_SYSERROR if there is a system error
     *
     * expansion (not system) errors should be reported back to the sender
     * using bounce_text(...);
     *
     */

    int
simta_ldap_expand( struct expand *exp, struct exp_addr *e_addr )
{
    char	*domain;	/* points to domain in address */
    char	*name;		/* clone of incoming name */
    char	*pname;		/* pointer for traversing name */
    int		nametype;	/* Type of Groupname -- owner, member... */
    int		rc;		/* Universal return code */

    if ( ld == NULL ) {
	if ( (rc = simta_ldap_init( )) != 0 ) {
	    return( rc );
	}
    }
    if ( e_addr->e_addr_type == ADDRESS_TYPE_LDAP ) {
	rc = simta_ldap_dn_expand (exp, e_addr);
	return (rc);
    }

    if ( e_addr->e_addr_at == NULL ) {
	panic( "simta_ldap_expand: e_addr->e_addr_at is NULL");
    }

    *e_addr->e_addr_at = '\0';
    name = strdup (e_addr->e_addr);
    *e_addr->e_addr_at = '@';
    if (!name) {
	syslog( LOG_ERR, "simta_ldap_expand: strdup failed" );
	return( LDAP_SYSERROR );
    }

    domain = e_addr->e_addr_at + 1;

    /*
    ** We still want to strip . and _
    */
    for (pname = name; *pname; pname++) {
	if (*pname == '.' || *pname == '_')
	    *pname = ' ';
    }
    /*
    ** Strip off any "-owners", or "-otherstuff"
    ** and search again
    */
    nametype = simta_address_type(name );
    rc = simta_ldap_name_search (exp, e_addr, name, domain, nametype);

    free (name);
    return (rc);
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
    int			fd = 0;
    char		*line;
    char		*linecopy	= NULL;
    SNET		*snet		= NULL;
    char		*c;
    struct ldap_search_list **lds;
    struct list		*l_new;
    struct list		**add;

    ACAV		*acav	= NULL;	/* config file tokenizing stuff */
    char		**av;
    int			ac;
    int			acidx;
    int			attridx;

    int			intval;

    LDAPURLDesc		*plud;		/* a parsed ldapurl */
    int			rdnpref;	
    int			search_type;
    int			ldaprc;		/* ldap return code */
    int			ret = -1;	/* Default to error */

    /* open fname */
    if (( fd = open( fname, O_RDONLY, 0 )) < 0 ) {
	syslog ( LOG_ERR, "simta_ldap_config open %s: %m", fname );
	goto errexit;
    }

    if (( snet = snet_attach( fd, 1024 * 1024 )) == NULL ) {
	syslog ( LOG_ERR, "simta_ldap_config: snet_attach: %m" );
	goto errexit;
    }

    if (( acav = acav_alloc( )) == NULL ) {
	syslog ( LOG_ERR, "simta_ldap_config: acav_alloc error" );
	goto errexit;
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
	    syslog ( LOG_ERR, "simta_ldap_config: acav_parse returned -1");
	    goto errexit;
	}	    

	if (( strcasecmp( av[ 0 ], "uri" ) == 0 ) ||
	    ( strcasecmp( av[ 0 ], "url" ) == 0 )) {
	    if (ac < 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "simta_ldap_config: Missing uri\n" );
		goto errexit;
	    }

 	    if ( ldap_is_ldap_url( av[ 1 ] ) == 0 ) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "uri not an ldap uri\n" );
		goto errexit;
	    } else {

                /* Parse the URL */
		if ((ldaprc = ldap_url_parse( av[ 1 ], &plud )) != LDAP_URL_SUCCESS){ 
		    syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		    syslog ( LOG_ERR, "ldap_url_parse parse error: %d\n", ldaprc);
		    goto errexit;
		}
		
		rdnpref = FALSE;
		search_type = 0;
		acidx = 2;
		while (acidx < ac) {
		    if (strcasecmp ( av[acidx], "rdnpref") == 0) {
			    rdnpref = TRUE;
		    } else if (strncasecmp  
			      ( av[acidx], "searchtype=", 11) == 0){

			c = &av[acidx][11];
			if (strcasecmp (c, "ALL") == 0)  {
			    search_type = LDS_ALL;
			} else if (strcasecmp (c, "GROUP") == 0 ) {
			    search_type = LDS_GROUP;
			} else if (strcasecmp (c, "USER") == 0 ) {
			    search_type = LDS_USER;
			} else {
		    	    ldap_free_urldesc (plud);
		    	    syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		    	    syslog ( LOG_ERR, "Unknown Searchtype in url\n");
		    	    goto errexit;
			}
		    }
		    else {
			ldap_free_urldesc (plud);
		    	syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		    	syslog ( LOG_ERR, "Unknown extension in url\n");
		    	goto errexit;
		    }
		    acidx++;
		}

		if (( *lds = (struct ldap_search_list *)malloc
			    ( sizeof( struct ldap_search_list ))) == NULL ) { 
		    syslog ( LOG_ERR, "ldap_search_list malloc error: %m" ); 
		    ldap_free_urldesc (plud);
		    goto errexit;
		}
		memset( *lds, 0, sizeof( struct ldap_search_list ));

		if (((*lds)->lds_string = strdup( av[ 1 ] )) == NULL ) {
		    syslog ( LOG_ERR, "ldap_search_list strdup error: %m" ); 
		    ldap_free_urldesc (plud);
		    goto errexit;
		}

		(*lds)->lds_plud = plud;
		(*lds)->lds_rdn_pref = rdnpref;
		(*lds)->lds_search_type = search_type;
		(*lds)->lds_next = NULL;

		lds = &((*lds)->lds_next);

	    }
	} else if ( strcasecmp( av[ 0 ], "attributes" ) == 0 ) {
	    if (ac < 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing attribute value(s)\n");
		goto errexit;
	    }
            if ((attrs = (char **) calloc ( (unsigned) ac , sizeof (char *))) == NULL) { 
		syslog ( LOG_ERR, "ac calloc error: %m" ); 
		goto errexit;
	    }
	    
	    for (acidx = 1, attridx = 0; acidx < ac; acidx++, attridx++) {
		attrs[attridx] = strdup (av[ acidx ]);
		if (attrs[attridx] == NULL) {
		    syslog ( LOG_ERR, "ac calloc error: %m" ); 
		    goto errexit;
		}
	    }
	} else if ( strcasecmp( av[ 0 ], "host" ) == 0 ) { 
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing host value\n");
		goto errexit;
	    }
	    if ((ldap_host = strdup ( av[ 1 ] )) == NULL) {
		syslog ( LOG_ERR, "host strdup error: %m" ); 
		goto errexit;
	    } 

	} else if ( strcasecmp( av[ 0 ], "port" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing port value\n");
		goto errexit;
	    }
	    ldap_port = atoi (av[ 1 ]);
	    
	} else if ( strcasecmp( av[ 0 ], "timeout" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing timeout value\n");
		goto errexit;
	    }
	    ldap_timeout = (time_t) atoi (av[ 1 ]);
	    
	} else if ( strcasecmp( av[ 0 ], "ldapdebug" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing ldapdebug value\n");
		goto errexit;
	    }
	    ldapdebug = atoi (av[ 1 ]);
	    
	} else if ( strcasecmp( av[ 0 ], "starttls" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing starttls value\n");
		goto errexit;
	    }
	    intval = atoi (av[ 1 ]);
	    if (intval < 0 || intval > 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Invalid starttls value\n");
		goto errexit;
	    }
	    starttls = intval;
	    
	} else if ( strcasecmp( av[ 0 ], "TLS_CACERT" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing TLS_CACERT value\n");
		goto errexit;
	    }
	    if ((tls_cacert = strdup (av[ 1 ])) == NULL) {
		syslog ( LOG_ERR, "tls_cacert strdup error: %m" ); 
		goto errexit;
	    } 

	} else if ( strcasecmp( av[ 0 ], "TLS_CERT" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing TLS_CERT value\n");
		goto errexit;
	    }
	    if ((tls_cert = strdup (av[ 1 ])) == NULL) {
		syslog ( LOG_ERR, "tls_cert strdup error: %m" ); 
		goto errexit;
	    } 
	} else if ( strcasecmp( av[ 0 ], "TLS_KEY" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing TLS_KEY value\n");
		goto errexit;
	    }
	    if ((tls_key = strdup (av[ 1 ])) == NULL) {
		syslog ( LOG_ERR, "tls_key strdup error: %m" ); 
		goto errexit;
	    } 

	} else if ( strcasecmp( av[ 0 ], "domaincomponentcount" ) == 0 ) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing domaincomponentcount value\n");
		goto errexit;
	    }
	    ndomaincomponent = atoi (av[ 1 ]);
	    
	} else if (( strcasecmp( av[ 0 ], "bindpw" ) == 0 ) ||
		   ( strcasecmp( av[ 0 ], "bindpassword" ) == 0 )) {
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing bindpw/bindpassword value\n");
		goto errexit;
	    }
	    if ((bindpw = strdup ( av[ 1 ] )) == NULL) {
		syslog ( LOG_ERR, "bindpw strdup error: %m" ); 
		goto errexit;
	    } 

	} else if ( strcasecmp( av[ 0 ], "binddn" ) == 0 ) {
	
	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing binddn/bindpassword value\n");
		goto errexit;
	    }
	    if ((binddn = strdup ( av[ 1 ] )) == NULL) {
		syslog ( LOG_ERR, "binddn strdup error: %m" ); 
		goto errexit;
	    } 
	    
	} else if (( strcasecmp( av[ 0 ], "oc" ) == 0 ) ||
		   ( strcasecmp( av[ 0 ], "objectclass" ) == 0 )) {
	    
	    if (ac != 3) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing objectclass value\n");
		goto errexit;
	    }


	    if ( strcasecmp( av[ 1 ], "person" ) == 0 ) {
		add = &ldap_people;
	    } else if ( strcasecmp( av[ 1 ], "group" ) == 0 ) {
		add = &ldap_groups;
	    } else {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Unknown objectclass type\n");
		goto errexit;
	    }

	    /* av [ 2] is a objectclass name */

	    if (( l_new = (struct list*) malloc( sizeof( struct list ))) == NULL ) {
		syslog ( LOG_ERR, "list malloc error: %m" ); 
		goto errexit;
	    }
	    memset( l_new, 0, sizeof( struct list ));

	    if (( l_new->l_string = (char*)strdup (av [ 2 ])) == NULL ) {
		syslog ( LOG_ERR, "list strdup error: %m" ); 
		goto errexit;
	    }
	
	    l_new->l_next = *add;
	    *add = l_new;

	} else if ( strcasecmp( av[ 0 ], "mail" ) == 0 ) {

	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing mail value\n");
		goto errexit;
	    }
		  
	    if (mailattr) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Multiple mail attributes\n");
		goto errexit;
	    }

	    if (( mailattr = (char*)strdup (av [ 1 ])) == NULL ) {
		syslog ( LOG_ERR, "mailattr strdup error: %m" ); 
		goto errexit;
	    }
	} else if ( strcasecmp( av[ 0 ], "mailforwardingattr" ) == 0 ) {

	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing mailforwardingattr value\n");
		goto errexit;
	    }
		  
	    if (mailfwdattr) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Multiple mailforwarding attributes\n");
		goto errexit;
	    }

	    if (( mailfwdattr = (char*)strdup (av [ 1 ])) == NULL ) {
		syslog ( LOG_ERR, "mailfwdattr strdup error: %m" ); 
		goto errexit;
	    }
	} else if ( strcasecmp( av[ 0 ], "vacationhost" ) == 0 ) {

	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing vacationhost value\n");
		goto errexit;
	    }
		  
	    if (vacationhost) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Multiple vacationhost attributes\n");
		goto errexit;
	    }

	    if (( vacationhost = (char*)strdup (av [ 1 ])) == NULL ) {
		syslog ( LOG_ERR, "vacationhost strdup error: %m" ); 
		goto errexit;
	    }
	} else if ( strcasecmp( av[ 0 ], "vacationattr" ) == 0 ) {

	    if (ac != 2) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Missing vacationattr value\n");
		goto errexit;
	    }
		  
	    if (vacationattr) {
		syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
		syslog ( LOG_ERR, "Multiple vacationattr attributes\n");
		goto errexit;
	    }

	    if (( vacationattr = (char*)strdup (av [ 1 ])) == NULL ) {
		syslog ( LOG_ERR, "vacationattr strdup error: %m" ); 
		goto errexit;
	    }
	} else {
	    syslog ( LOG_ERR, "%s:%d:%s", fname, lineno, linecopy);
	    syslog ( LOG_ERR, "Unknown simta/ldap config option\n");
	    goto errexit;
	}
    }
    /* check to see that ldap is configured correctly */

    if ( ldap_people == NULL ) {
        syslog ( LOG_ERR, "No ldap people objectclass specified\n");
	goto errexit;
    }
    if ( ldap_searches == NULL ) {
        syslog ( LOG_ERR, "No ldap searches specified\n");
	goto errexit;
    }
    if (! ldap_host) {
        syslog ( LOG_ERR, "No ldap server specified\n");
	goto errexit;
    }
    if (ldap_port <= 0) {
	ldap_port = 389;
    }
    if (ldap_timeout <= 0) {
	ldap_timeout = LDAP_TIMEOUT_VAL;
    }
    if (!mailattr) {
	mailattr = strdup ("mail");
	syslog ( LOG_ERR, "Defaulting mail attribute to \'mail\'" ); 
    }
    if (!mailfwdattr) {
	mailfwdattr = strdup ("mail");
	syslog ( LOG_ERR, "Defaulting mailforwardingaddress to \'mail\'" ); 
    }
    if (tls_cert || tls_key ) {
	if (! tls_cert) {
	    syslog ( LOG_ERR, "missing TLS_CERT parameter");
	    goto errexit;
	}
	if (! tls_key) {
	    syslog ( LOG_ERR, "missing TLS_KEY parameter");
	    goto errexit;
	}
    }
    if (attrs == NULL)
	attrs = allattrs;

    ret = 0;

errexit:    
    if (linecopy) {
	free (linecopy);
    }
    if ( acav ){
	acav_free( acav );
    }
    if (snet ) {
	if (snet_close( snet ) != 0 ) {
	    syslog(LOG_ERR, "simta_ldap_config: snet_close %m" );
	}
	fd = 0;
    }
    if (fd) {
	if (close (fd)) {
	    syslog(LOG_ERR, "simta_ldap_config: Config file close %m" );
	}
    }    
    return( ret );
}
