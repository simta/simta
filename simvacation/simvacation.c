/*
 * Copyright (c) 2004 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 *
 * Copyright (c) 1983, 1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1983, 1987 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
/*static char sccsid[] = "from: @(#)vacation.c	5.19 (Berkeley) 3/23/91";*/
static char rcsid[] = "$Id: simvacation.c,v 1.3 2007/05/16 19:17:46 pturgyan Exp $";
#endif /* not lint */

/*
**  Vacation
**  Copyright (c) 1983  Eric P. Allman
**  Berkeley, California
*/

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pwd.h>

#define DB_DBM_HSEARCH    1
#include <db.h>
#include <limits.h>
#include <sysexits.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <lber.h>
#include <ldap.h>

/*
 *  VACATION -- return a message to the sender when on vacation.
 *
 *	This program is invoked as a message receiver.  It returns a
 *	message specified by the user to whomever sent the mail, taking
 *	care not to return a message too often to prevent "I am on
 *	vacation" loops.
 */

void bdb_err_log (const char *errpfx, char *msg);
DB * initialize( char *f );
int  setinterval( DB *dbp, time_t interval );
char *makevdbpath();


#define	MAXLINE	1024			/* max line from mail header */
#define	VDBDIR	"/var/vacationdb"	/* dir for vacation databases */

#ifndef _PATH_SENDMAIL
#define _PATH_SENDMAIL	"/usr/sbin/sendmail"
#endif

/* From tzfile.h */
#define SECSPERMIN      60
#define MINSPERHOUR     60
#define HOURSPERDAY     24
#define DAYSPERWEEK     7
#define DAYSPERNYEAR    365
#define DAYSPERLYEAR    366
#define SECSPERHOUR     (SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY      ((time_t) SECSPERHOUR * HOURSPERDAY)
#define MONSPERYEAR     12

#define	LDAP_HOST	"ldap.itd.umich.edu"
#define	BIND_DN		NULL
#define BIND_METHOD	NULL
#define SEARCHBASE	"ou=People,dc=umich,dc=edu"
#define	ATTR_ONVAC	"onVacation"
#define	ATTR_VACMSG	"vacationMessage"
#define	ATTR_CN		"cn"
#define ATTRS		{ ATTR_ONVAC, ATTR_VACMSG, ATTR_CN, NULL }
#define	DOMAIN		"umich.edu"
#define	SUBJECTLINE	"Subject: Out of email contact"


typedef struct alias {
	struct alias *next;
	char *name;
} ALIAS;
ALIAS		*names;



static char	*VIT = "__VACATION__INTERVAL__TIMER__";
static char	from[MAXLINE];
static char	subject[MAXLINE];
static char	rdn[MAXLINE];
static char	*dn;
static char	**xdn;
static char	*fallback_vmsg[] = {
			"I am currently out of email contact.",
			"Your mail will be read when I return.",
			NULL };

extern int optind, opterr;
extern char *optarg;


main( argc, argv )
    int argc;
    char **argv;
{
    struct passwd *pw;
    ALIAS *cur;
    time_t interval;
    int ch, rc, rval, i;
    char *rcpt;
    LDAP *ld;
    char *ldap_host = LDAP_HOST;
    char *searchbase = SEARCHBASE;
    int ldap_port = LDAP_PORT;
    static struct timeval timeout;
    static char *attrs[] = ATTRS;
    char filter[64];
    LDAPMessage *result, *e;
    char **vac, **vacmsgs, **cnames;

    char *vdbpath, vdbdir[MAXPATHLEN], vdbpag[MAXPATHLEN];
    char *vdbroot = VDBDIR;
    DB	 *dbp = NULL;    /* Berkeley DB instance */

    char *progname;

    int matches;
    char *errmsgptr;

    if ( (progname = strrchr( argv[0], '/' )) == NULL )
	progname = strdup( argv[0] );
    else
	progname = strdup( progname + 1 );

    openlog( progname, LOG_PID, LOG_VACATION );
    opterr = 0;
    interval = -1;
    subject[0] = '\0';

    while (( ch = getopt( argc, argv, "f:r:s:h:p:v:" )) != EOF ) {
	switch( (char) ch ) {
	case 'f':
	    strncpy(from, optarg, MAXLINE - 1);
	    from[MAXLINE] = '\0';
	    break;
	case 'r':
	    if ( isdigit( *optarg )) {
		interval = atol( optarg ) * SECSPERDAY;
		if ( interval < 0 )
		    usage( progname );
	    }
	    else
		interval = LONG_MAX;
	    break;
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

	    case 'v':	/* dir for vacation db files */
		vdbroot = optarg;
		break;
	    case '?':
	    default:
		usage( progname );
	}
    }
    argc -= optind;
    argv += optind;

    if ( !*argv ) {
	usage( progname );
	myexit( NULL, 1 );
    }
    /*
     * Timeout values for LDAP searches
     */
    timeout.tv_sec = 30L;
    timeout.tv_usec = 0L;

    /*
     * Open ldap connection and bind
     */
    if (( ld = ldap_open( ldap_host, ldap_port )) == NULL ) {
	syslog( LOG_INFO, "ldap_open failed" );
	myexit( NULL, EX_TEMPFAIL ); /* Try again later */
    }

    if (( rc = ldap_simple_bind_s( ld, BIND_DN, BIND_METHOD ))
		 != LDAP_SUCCESS ) {
#if 0
	syslog( LOG_ALERT, "ldap_simple_bind failed: %s",
		ldap_err2string(ld->ld_errno ));
#endif
	ldap_get_option ( ld, LDAP_OPT_ERROR_STRING, &errmsgptr) ;
	syslog( LOG_ALERT, "ldap_simple_bind failed: %s", errmsgptr);
	free (errmsgptr);
	myexit( NULL, EX_TEMPFAIL ); /* Try again later */
    }

    /*
     * See if the user is "on vacation", and if so, retrieve the
     * vacationMessage attribute from their LDAP entry.
     */
    rcpt = *argv;
    sprintf( filter, "uid=%s", rcpt );	/* make LDAP search filter */
    rc = ldap_search_st( ld, searchbase, LDAP_SCOPE_SUBTREE,
		     filter, attrs, 0, &timeout, &result );
    switch ( rc ) {
    case LDAP_SUCCESS:
	break;
    case LDAP_SERVER_DOWN:
    case LDAP_TIMEOUT:
    case LDAP_BUSY:
    case LDAP_UNAVAILABLE:
    case LDAP_OTHER:
    case LDAP_LOCAL_ERROR:
	rval = EX_TEMPFAIL;	/* temporary errors */
	break;
    default:
	rval = 0;	/* permanent errors */
    }
    if ( rc != LDAP_SUCCESS ) {
	syslog( LOG_ALERT, "error in ldap_search: %s", ldap_err2string( rc ));
	myexit( NULL, rval );
    }		

    matches = ldap_count_entries( ld, result );
    if ( matches > 1 ) {
	syslog( LOG_ALERT, "ambiguous: %s", rcpt );
	myexit( NULL, 0 );
    } else if ( matches == 0 ) {
	syslog( LOG_ALERT, "no match for %s", rcpt );
	myexit( NULL, 0 );
    } else {
	e = ldap_first_entry( ld, result );
	dn = ldap_get_dn( ld, e );
	xdn = ldap_explode_dn( dn, 1 );
	vac = ldap_get_values( ld, e, ATTR_ONVAC );
	if ( vac && !strcasecmp( *vac, "TRUE" )) {
	    vacmsgs = ldap_get_values( ld, e, ATTR_VACMSG );
	    cnames = ldap_get_values( ld, e, ATTR_CN );
	} else {
	    /*
	     * XXX why were we invoked if user is not
	     * on vacation??? syslog it
	     */
	    syslog( LOG_ALERT, "user %s not on vacation", rcpt );
	    myexit(NULL, 0);
	}
    }

    /*
     * Set path to db files
     */
    vdbpath = makevdbpath( vdbroot, rcpt );
    sprintf( vdbdir, "%s.ddb", vdbpath );

    /*
    ** Create the database handle and Open the db
    */
    if ((rc = db_create( &dbp, NULL, 0)) != 0) {
        syslog( LOG_ALERT,  "db_create: %s\n", db_strerror(rc));
	myexit( NULL, 0);
    }   
      
    dbp->set_errpfx( dbp, "DB creation");
    dbp->set_errcall( dbp, bdb_err_log);
    if ((rc = dbp->set_pagesize( dbp, 1024)) != 0) {
	dbp->err(dbp, rc, "set_pagesize");
	(void)dbp->close( dbp, 0);
	myexit( NULL, 0);
    } 
    if ((rc = dbp->set_cachesize( dbp, 0, 32 * 1024, 0)) != 0) {
	dbp->err( dbp, rc, "set_cachesize");
	(void)dbp->close( dbp, 0);
	myexit( NULL, 0);
    }
	
    if ((rc = dbp->open(dbp,            /* DB handle */
			NULL,           /* transaction handle */
			vdbdir,         /* db file name */
			NULL,           /* database name */
			DB_BTREE,       /* DB type */
			DB_CREATE,      /* Create db if it doesn't exist */
			0664)) != 0) {
	dbp->err(dbp, rc, "%s: open", vdbpath);
	syslog( LOG_ALERT, "%s: %s\n", vdbpath, strerror( errno ));
	myexit( dbp, 0 );
    }
    dbp->set_errpfx( dbp, "");

    if (interval != -1)
	setinterval(dbp, interval);

    /*
     * Create a linked list of all names this user
     * might get mail for - LDAP "commonName" attribute.
     */
    if ( !( cur = (ALIAS *) malloc( sizeof( ALIAS )))) {
	syslog( LOG_ALERT, "malloc for alias failed");
	myexit( dbp, 0 );
    }
    cur->name = rcpt;
    cur->next = NULL;
    names = cur;
    for ( i = 0; cnames && cnames[i] != NULL; i++ ) {
	if ( !( cur->next = (ALIAS *) malloc( sizeof( ALIAS )))) {
	    syslog( LOG_ALERT, "malloc for alias failed");
	    myexit( dbp, 0 );
	}
	cur = cur->next;
	cur->name = cnames[i];
	cur->next = NULL;
    }

    readheaders( dbp );

    if ( !recent( dbp )) {
	char rcptstr[MAXLINE];
	setreply( dbp );
	sprintf(rcptstr, "%s@%s", rcpt, DOMAIN);
	sendmessage( rcptstr, vacmsgs );
	syslog( LOG_DEBUG, "sent message for %s to %s from %s",
			rcpt, from, rcptstr );
    } else {
	syslog( LOG_DEBUG, "suppressed message for %s to %s",
		rcpt, from );
    }
    dbp->close(dbp, 0);	
    myexit( NULL, 0 );
    /* NOTREACHED */
}

/*
 * readheaders --
 *	read mail headers
 */
readheaders( DB * dbp )
{
    register ALIAS *cur;
    register char *p;
    int tome, cont;
    char buf[MAXLINE];

    tome = cont = 0;
    while ( fgets( buf, sizeof( buf ), stdin ) && *buf != '\n' ) {
	switch( *buf ) {
	case 'F':		/* "From " */
	    cont = 0;
	    if ( !strncmp(buf, "From ", 5 )) {
		for ( p = buf + 5; *p && *p != ' '; ++p );
		*p = '\0';
		(void) strcpy( from, buf + 5 );
		if ( p = index( from, '\n' ))
		    *p = '\0';
		if ( junkmail()) {
		    syslog( LOG_DEBUG, "ignoring junkmail from %s", from );
		    myexit( dbp, 0 );
		}
	    }
	    break;

	case 'P':		/* "Precedence:" */
	    cont = 0;
	    if ( strncasecmp( buf, "Precedence", 10 ) ||
			buf[10] != ':' && buf[10] != ' ' && buf[10] != '\t' ) {
		break;
	    }
	    if ( !( p = index( buf, ':' ))) {
		break;
	    }
	    while ( *++p && isspace( *p ));
	    if ( !*p ) {
		break;
	    }
	    if ( !strncasecmp( p, "junk", 4 ) ||
		 !strncasecmp( p, "bulk", 4 )) {
		syslog( LOG_DEBUG, "ignoring bulkmail from %s", from );
		myexit( dbp, 0 );
	    }
	    break;

	case 'C':		/* "Cc:" */
	    if ( strncmp( buf, "Cc:", 3 )) {
		break;
	    }
	    cont = 1;
	    goto findme;

	case 'T':		/* "To:" */
	    if ( strncmp( buf, "To:", 3 )) {
		break;
	    }
	    cont = 1;
	    goto findme;

	case 'S':		/* "Subject:" */
	    if ( !strncmp( buf, "Subject:", 8 )) {
		p = index( buf, ':' );
		while ( p && *++p && isspace( *p ));
		if ( *p ) {
		    strcpy( subject, p );
		}
		/* get rid of newline */
		p = index( subject, '\n' );
		if ( p ) {
		    *p = '\0';
		}
	    }
	    break;

	default:
	    if ( !isspace( *buf ) || !cont || tome ) {
		cont = 0;
		break;
	    }
findme:	    for ( cur = names; !tome && cur; cur = cur->next ) {
		tome += nsearch( cur->name, buf );
	    }
	}
    }	

    if ( !tome ) {
	syslog( LOG_DEBUG, "mail from \"%s\" not to user \"%s\"\n",
			from ? from : "(unknown)", dn );
	myexit( dbp, 0 );
    }
    if ( !*from ) {
	syslog( LOG_NOTICE, "no initial \"From\" line.\n" );
	myexit( dbp, 0 );
    }
}

/*
 * nsearch --
 *	do a nice, slow, search of a string for a substring.
 *	(umich) - change any of {'.', '_'} to ' '.
 */
nsearch( name, str )
	register char *name, *str;
{
    register int len;
    register char *c;

    /*
     * convert any periods or underscores to spaces
     */
    for ( c = str; *c; c++ ) {
	if (( *c == '.' ) || ( *c == '_' )) {
	    *c = ' ';
	}
    }

    for ( len = strlen( name ); *str; ++str ) {
	if ( !strncasecmp( name, str, len )) {
	    return( 1 );
	}
    }
    return( 0 );
}

/*
 * junkmail --
 *	read the header and return if automagic/junk/bulk mail
 */
junkmail()
{
    static struct ignore {
		char	*name;
		int	len;
    } ignore[] = {
		"-request", 8,		"postmaster", 10,	"uucp", 4,
		"mailer-daemon", 13,	"mailer", 6,		"-relay", 6,
		"<>", 2,
#if 0
		NULL, NULL,
#endif
		NULL, 0,
    };
    register struct ignore *cur;
    register int len;
    register char *p;

    /*
     * This is mildly amusing, and I'm not positive it's right; trying
     * to find the "real" name of the sender, assuming that addresses
     * will be some variant of:
     *
     * From site!site!SENDER%site.domain%site.domain@site.domain
     */
    if ( !( p = index( from, '%' )))
	if ( !( p = index( from, '@' ))) {
	    if ( p = rindex( from, '!' ))
		++p;
	    else
		p = from;
	    for ( ; *p; ++p );
	}
    len = p - from;
    for ( cur = ignore; cur->name; ++cur )
	if ( len >= cur->len && 
		!strncasecmp( cur->name, p - cur->len, cur->len ))
	    return( 1 );
    return( 0 );
}


/*
 * recent --
 *	find out if user has gotten a vacation message recently.
 */
recent(DB * dbp)
{
    DBT		key;
    DBT		data;
    time_t	then;
    time_t	next;
    int		rc;

    /* get interval time */
    memset (&key, 0, sizeof( key ));
    key.data = VIT;
    key.size = strlen(VIT) - 1;

    memset (&data, 0, sizeof( data ));

    data.data = &next;
    data.size = sizeof( next );

    next = 0;   /* for debugging */
    dbp->set_errpfx(dbp, "Getting VIT");
    if ((rc = dbp->get(dbp, NULL, &key, &data, 0)) == 0) {
	memcpy (&next, data.data, sizeof( next ));
    } else {
	next = SECSPERDAY * DAYSPERWEEK;
    }

    /* get record for this email address */
    memset (&key, 0, sizeof( key ));
    key.data = from;
    key.size = strlen( from );

    memset (&data, 0, sizeof( data ));
    then = 0;   /* for debugging */
    dbp->set_errpfx(dbp, "Getting recent time");
    if ((rc = dbp->get(dbp, NULL, &key, &data, 0)) == 0) {
	memcpy (&then, data.data, sizeof( then ));

	if ( next == LONG_MAX || then + next > time(( time_t *) NULL ))
	    return( 1 );
    }
    return( 0 );
}

/*
 * setinterval --
 *	store the reply interval
 */
   int
setinterval( DB *dbp, time_t interval )
{
    DBT  key;
    DBT  data;
    int  rc;

    memset (&key, 0, sizeof ( key ));
    key.data = VIT;
    key.size = strlen( VIT ) - 1;
    memset (&data, 0, sizeof ( data ));
    data.data = (char *) &interval;
    data.size = sizeof( interval );
    rc = dbp->put(dbp, NULL, &key, &data, (u_int32_t) 0); /* allow overwrites */
    if (rc != 0) {
	syslog( LOG_ALERT, "DB Error while putting interval: %d, %s", 
		rc, db_strerror(rc) );
    }
    return (rc);
}

/*
 * setreply --
 *	store that this user knows about the vacation.
 */
   int
setreply(DB * dbp)
{
    DBT  key;
    DBT  data;
    int  rc;

    time_t now;

    memset (&key, 0, sizeof ( key ));
    key.data = from;
    key.size = strlen( from );
    (void) time( &now );
    memset (&data, 0, sizeof ( data ));
    data.data = (char *) &now;
    data.size = sizeof( now );
    rc = dbp->put(dbp, NULL, &key, &data, 0);  /* allow overwrites */
    if (rc != 0) {
	syslog( LOG_ALERT, "DB Error while putting reply time: %d, %s", 
		rc, db_strerror(rc) );
    }

    return (rc);
}

/*
 * sendmessage --
 *	exec sendmail to send the vacation file to sender
 */
sendmessage( char *myname, char **vmsg)
{
    char	*nargv[5];
    int		i;
    char	*p;

#ifdef HAVE_SENDMAIL
    nargv[0] = "sendmail";
    nargv[1] = "-f<>";
    nargv[2] = from;
    nargv[3] = NULL;
#else
    nargv[0] = "simsendmail";   /* really simsendmail */
    nargv[1] = "-f";
    nargv[2] = "";
    nargv[3] = from;
    nargv[4] = NULL;
#endif    

    if (( pexecv( _PATH_SENDMAIL, nargv )) == -1 ) {
	syslog( LOG_ERR, "pexecv of %s failed", _PATH_SENDMAIL );
	return( EX_TEMPFAIL );
    }
    /*
     * Our stdout should now be hooked up to sendmail's stdin.
     * Generate headers and print the vacation message.
     */
    printf( "From: %s <%s>\n", xdn[0], myname );
    printf( "To: %s\n", from );
    printf( SUBJECTLINE );
    if ( subject[0] ) {
	if ( strncasecmp( subject, "Re:", 3 )) {
	    printf( " (Re: %s)", subject );
	} else {
	    printf( " (%s)", subject );
	}
    }
    printf( "\n\n" );
    if ( vmsg == NULL ) {
	vmsg = fallback_vmsg;
    }
    for ( i = 0; vmsg[i] != NULL; i++ ) {
	for ( p = vmsg[i]; *p; p++ ) {

#if 0
	    if ( *p == ' ' && *(p + 1) == '$' ) {
		putchar( '\n' );
		p++;
#endif
	    if ( *p == '$') {
		putchar( '\n' );
	    } else {
		putchar( *p );
	    }
	}
	putchar( '\n' );
    }
#if 0
    free (frombuf);
#endif
}

usage( char * progname)
{
    syslog(LOG_NOTICE, "uid %u: usage: %s login\n", getuid(), progname);
    myexit( NULL, 0 );
}


/*
 * makevdbpath - compute the path to the user's db file.  One level
 * of indirection, e.g. "bob" has vacation files in VDBDIR/b/bob.{dir,pag}
 * Returns path *up to* the file, but not the files themselves.
 */
char *
makevdbpath( char *dir, char *user)
{
    char	buf[MAXPATHLEN];

    if (( user == NULL ) || ( dir == NULL )) {
	return( NULL );
    }

    if ( (strlen(dir) + strlen (user) + 4) > sizeof (buf) ) {
	return( NULL );
    }

    sprintf( buf, "%s/%c/%s", dir, user[0], user );
    return( strdup( buf ));
}

/*
 * bdb_err_log --
 *	Berkeley DB error log callback.
 */
void 
bdb_err_log ( const char *errpfx, char *msg)
{
    syslog( LOG_ALERT, "%s: %s", errpfx, msg);
    return;
}

/*
 * myexit --
 *	we're outta here...
 */
myexit( DB * dbp, int eval )
{
    if ( dbp )
	(void)dbp->close( dbp, 0);

    exit( eval );
}


/*
 * Interface to pipe and exec, for starting children in pipelines.
 *
 * Manipulates file descriptors 0, 1, and 2, such that the new child
 * is reading from the parent's output.
 */
pexecv( path, argv )
    char	*path, *argv[];
{
    int		fd[ 2 ], c;

    if ( pipe( fd ) < 0 ) {
	return( -1 );
    }

    switch ( c = vfork()) {
    case -1 :
	return( -1 );
	/* NOTREACHED */

    case 0 :
	if ( close( fd[ 1 ] ) < 0 ) {
	    return( -1 );
	}
	if ( dup2( fd[ 0 ], 0 ) < 0 ) {
	    return( -1 );
	}
	if ( close( fd[ 0 ] ) < 0 ) {
	    return( -1 );
	}
	execv( path, argv );
	return( -1 );
	/* NOTREACHED */

    default :
	if ( close( fd[ 0 ] ) < 0 ) {
	    return( -1 );
	}
	if ( dup2( fd[ 1 ], 1 ) < 0 ) {
	    return( -1 );
	}
	if ( close( fd[ 1 ] ) < 0 ) {
	    return( -1 );
	}
	return( c );
    }
}
