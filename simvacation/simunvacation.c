/*
 * unvacate.c - clean up database files for people who are no longer
 * "on vacation".
 *
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#include <stdio.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/param.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>

#include <lber.h>
#include <ldap.h>

#ifndef VDBDIR
#define VDBDIR		"/var/vacationdb" /* dir for vacation databases */
#endif

#define	LDAP_HOST	"ldap.itd.umich.edu"
#define	BIND_DN		NULL
#define BIND_METHOD	NULL
#define SEARCHBASE	"ou=People,dc=umich,dc=edu"
#define	ATTR_ONVAC	"onVacation"
#define ATTRS		{ ATTR_ONVAC, NULL }

typedef struct uniq_list {
    char *un_name;
    struct uniq_list *un_next;
} uniq_list;

main( int argc, char **argv)
{
    extern int optind, opterr;
    extern char *optarg;

    char ch;

    LDAP *ld;
    char *ldap_host = LDAP_HOST;
    char *searchbase = SEARCHBASE;
    int ldap_port = LDAP_PORT;

    int rc;
    int err = 0;
    static struct timeval timeout;
    static char *attrs[] = ATTRS;
    char filter[64];LDAPMessage *result, *e;
    char **vac;

    char *vdbpath = VDBDIR;
    char vdbdir[MAXPATHLEN];
    char buf[MAXPATHLEN];
    int matches;
    DIR *dirp;
    struct dirent *dire;
    struct uniq_list *u, *uniqnames = NULL;
    struct uniq_list **unp = &uniqnames;
    char *perr;

    openlog( "unvacate", LOG_PID, LOG_LOCAL6 );
    /*
     * Timeout values for LDAP searches
     */
    timeout.tv_sec = 30L;
    timeout.tv_usec = 0L;

    while (( ch = getopt( argc, argv, "s:h:p:v:" )) != EOF ) {
	switch( (char) ch ) {
	case 's':		/* seachbase */
	    searchbase = optarg;
	    break;

	case 'h':		/* ldap server */
	    ldap_host = optarg;
	    break;

	case 'p':		/* ldap port */
	    if ( isdigit( *optarg )) {
		ldap_port = atoi( optarg );
	    }
	    break;

	case 'v':		/* dir for vacation db files */
	    vdbpath = optarg;
	    break;

	case '?':
	default:
	    usage();
	}
    }

    /*
     * Connect to ldap server and bind
     */
    if (( ld = ldap_open( ldap_host, ldap_port )) == NULL ) {
	syslog( LOG_ALERT, "cannot conenct to host %s, port %d",
		ldap_host, ldap_port );
	exit( 1 );
    }
    if (( rc = ldap_simple_bind_s( ld, BIND_DN, BIND_METHOD ))
	  != LDAP_SUCCESS ) {
	ldap_get_option ( ld, LDAP_OPT_ERROR_STRING, &perr);
	syslog( LOG_ALERT, "ldap_simple_bind failed: %s",perr);
	free (perr);
	exit( 1 );
    }


    if ( access( vdbpath, F_OK )) {
	syslog( LOG_ALERT, "cannot open directory %s", vdbpath );
	exit( 1 );
    }

    /*
     * Build a linked list of candidate uniqnames.
     */
    for ( ch = 'a'; ch <= 'z'; ch++ ) {
	sprintf( vdbdir, "%s/%c", vdbpath, ch );
	if ((dirp = opendir( vdbdir )) == NULL) {
	    syslog( LOG_ALERT, "cannot open directory %s", vdbdir );
	    err++;
	    continue;
	}

	while (( dire = readdir( dirp )) != NULL ) {
	    int		len;

	    /* is this a dbm file? */

	    len = strlen( dire->d_name );
	    if ( len > 4 ) {
		if ( !strncmp( &dire->d_name[len - 4],
			      ".ddb", 4 )) {
		    strncpy( buf, dire->d_name, len - 4);
		    buf[len - 4] = '\0';
		    ( *unp ) = ( struct uniq_list *)
			       malloc( sizeof ( struct uniq_list ));
		    ( *unp )->un_name = strdup( buf );
		    unp = &(( *unp )->un_next );
		}
	    }
	}
    }
    ( *unp ) = NULL;

    /*
     * For each candidate uniqname, check to see if user is
     * still on vacation.  If not, remove the .dir and .pag files.
     */
     for ( u = uniqnames; u; u = u->un_next ) {
	sprintf( filter, "uid=%s", u->un_name );
	rc = ldap_search_st( ld, searchbase, LDAP_SCOPE_SUBTREE,
			     filter, attrs, 0, &timeout, &result );
	if ( rc != LDAP_SUCCESS ) {
#if 0
	    syslog( LOG_ALERT, "error in ldap_search: %s",
		    ldap_err2string( ld->ld_errno ));
#endif
	    ldap_get_option ( ld, LDAP_OPT_ERROR_STRING, &perr);
	    syslog( LOG_ALERT, "error in ldap_search: %s",perr);
	    free (perr);
	    err++;
	    continue;
	}
	matches = ldap_count_entries( ld, result );
	if ( matches > 1 ) {
	    syslog( LOG_ALERT, "ambiguous: %s", u->un_name );
	    err++;
	} else {
	    if ( matches == 0 ) {
		/* I don't consider this an error */
		syslog( LOG_INFO, "%s not in UMOD", u->un_name );
	    } else {
		e = ldap_first_entry( ld, result );
		vac = ldap_get_values( ld, e, ATTR_ONVAC );
	    }

	    /*
	     * If (1) user was not in LDAP Directory, or (2) no "onVacation"
	     * attribute was retrieved, or (3) the user is not on
	     * vacation, remove the dbm files.
	     */
	    if ( !matches || !vac || strcasecmp( *vac, "TRUE" )) {
		syslog( LOG_INFO, "removing %s's db files", u->un_name );
		sprintf( buf, "%s/%c/%s.ddb", vdbpath, u->un_name[0],
			 u->un_name );
		if ( unlink( buf ) < 0 ) {
		    syslog( LOG_ALERT, "cannot remove file %s (%m)", buf );
		    err++;
		}
	    } else {
		syslog( LOG_DEBUG, "user %s still on vacation", u->un_name );
	    }
	}
    }
    if ( err ) {
	exit( 1 );
    } else {
	exit( 0 );
    }
}

usage()
{
    fprintf( stderr, "usage: unvacate [-v vbdir] [-s searchbase]\n" );
    fprintf( stderr, "                [-h ldap_host] [-p ldap_port]\n" );
    exit( 1 );
}
