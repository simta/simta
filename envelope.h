/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#define	R_DELIVERED	0
#define	R_FAILED	1
#define	R_TEMPFAIL	2

#define	ENVELOPE_VERSION	0

struct recipient {
    struct recipient	*r_next;
    char		*r_rcpt;
    int			r_delivered;
    struct line_file	*r_text;
};

struct envelope {
    struct sockaddr_in	*e_sin;
    char		*e_hostname;
    char		e_expanded[ MAXHOSTNAMELEN ];
    char		*e_helo;
    char		*e_dir;;
    char		*e_mail;
    struct recipient	*e_rcpt;
    char		e_id[ 30 ];
    int			e_flags;
    int			e_old_dfile;
    int			e_success;
    int			e_failed;
    int			e_tempfail;
    struct timespec	e_etime;
};

#define E_TLS		(1<<0)

void		env_reset ___P(( struct envelope * ));
void		env_stdout ___P(( struct envelope * ));
void		env_cleanup ___P(( struct envelope *e ));

/* return pointer on success, NULL on syserror, syslog */
struct envelope	*env_create ___P(( char * ));
void		env_free ___P(( struct envelope * ));
void		rcpt_free ___P(( struct recipient * ));

/* return 0 on success, -1 on syserror, syslog */
int		env_recipient ___P(( struct envelope *, char * ));
int		env_outfile ___P(( struct envelope *, char * ));

/* return 0 on success, -1 on syserror, 1 on syntax error, syslog */
int		env_unexpanded ___P(( char *, int * ));
int		env_infile ___P(( struct envelope *, char * ));
int		env_gettimeofday_id ___P(( struct envelope * ));
int		env_fstat ___P(( struct envelope *, int ));
int		env_touch ___P(( struct envelope * ));
int		env_unlink ___P(( struct envelope * ));
