/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

struct recipient {
    struct recipient	*r_next;
    char		*r_rcpt;
};

struct envelope {
    struct sockaddr_in	*e_sin;
    char		e_hostname[ MAXHOSTNAMELEN ];
    char		e_expanded[ MAXHOSTNAMELEN ];
    char		*e_helo;
    char		*e_mail;
    struct recipient	*e_rcpt;
    char		e_id[ 30 ];
    int			e_flags;
};

#define E_TLS		(1<<0)

void		env_reset ___P(( struct envelope * ));
void		env_stdout ___P(( struct envelope * ));

/* return pointer on success, NULL on syserror, no syslog */
struct envelope	*env_create ___P(( char * ));

/* return 0 on success, -1 on syserror, no syslog */
int		env_recipient ___P(( struct envelope *, char * ));
int		env_outfile ___P(( struct envelope *, char * ));

/* return 0 on success, -1 on syserror, 1 on syntax error, no syslog */
int		env_unexpanded ___P(( char *, int * ));
int		env_infile ___P(( struct envelope *, char * ));
