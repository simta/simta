/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#define	R_TEMPFAIL	0
#define	R_DELIVERED	1
#define	R_FAILED	2

struct recipient {
    struct recipient	*r_next;
    char		*r_rcpt;
    int			r_delivered;
    struct line_file	*r_err_text;
};

struct envelope {
    struct sockaddr_in	*e_sin;
    struct envelope	*e_next;
    struct message	*e_message;
    char		*e_punt;
    char		e_expanded[ MAXHOSTNAMELEN + 1 ];
    char		*e_helo;
    char		*e_dir;
    char		*e_mail;
    struct recipient	*e_rcpt;
    struct line_file	*e_err_text;
    char		e_id[ 30 ];
    int			e_flags;
    int			e_relay;
    int			e_old_dfile;
    int			e_success;
    int			e_failed;
    int			e_tempfail;
    struct timespec	e_etime;
};

#define E_TLS			(1<<0)
#define E_READY			(1<<1)
#define ENV_BOUNCE		(1<<2)
#define ENV_ATTEMPT		(1<<3)
#define ENV_OLD			(1<<4)

/* NOT USED */
void		env_stdout ___P(( struct envelope * ));
void		env_free ___P(( struct envelope * ));

/* LOCAL */
void		env_rcpt_free ___P(( struct envelope * ));

/* GLOBAL */
struct envelope	*env_create ___P(( char * ));
struct envelope	*env_dup ___P(( struct envelope * ));
void		env_reset ___P(( struct envelope * ));
void		rcpt_free ___P(( struct recipient * ));
int		env_gettimeofday_id ___P(( struct envelope * ));
int		env_recipient ___P(( struct envelope *, char * ));
int		env_outfile ___P(( struct envelope *, char * ));
int		env_touch ___P(( struct envelope * ));
int		env_info ___P(( struct message *, char *, size_t ));
int		env_slow ___P(( struct envelope * ));
int		env_unlink ___P(( struct envelope * ));
int		env_read ___P(( struct message *, struct envelope *,
			SNET ** ));
