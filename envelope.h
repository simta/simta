/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

#define ENV_ID_LENGTH		30

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
    struct envelope	*e_next;
    struct envelope	*e_hq_next;
    struct host_q	*e_hq;
    char		e_hostname[ MAXHOSTNAMELEN + 1 ];
    char		*e_dir;
    char		*e_mail;
    struct recipient	*e_rcpt;
    struct line_file	*e_err_text;
    char		e_id[ ENV_ID_LENGTH + 1 ];
    int			e_flags;
    int			e_success;
    int			e_failed;
    int			e_tempfail;
    ino_t		e_dinode;
    struct timespec	e_last_attempt;
};

#define ENV_ON_DISK		(1<<1)
#define ENV_OLD			(1<<2)
#define ENV_EFILE		(1<<3)
#define ENV_DFILE		(1<<4)
#define E_TLS			(1<<5)
#define ENV_BOUNCE		(1<<6)

/* NOT USED */
void		env_stdout ___P(( struct envelope * ));
void		env_syslog ___P(( struct envelope * ));
void		env_free ___P(( struct envelope * ));

/* LOCAL */
void		env_rcpt_free ___P(( struct envelope * ));

/* GLOBAL */
struct envelope	*env_create ___P(( char * ));
struct envelope	*env_dup ___P(( struct envelope * ));
void		env_reset ___P(( struct envelope * ));
void		rcpt_free ___P(( struct recipient * ));
int		env_age( struct envelope *, struct timeval * );
int		env_gettimeofday_id ___P(( struct envelope * ));
int		env_set_id ___P(( struct envelope *, char * ));
int		env_recipient ___P(( struct envelope *, char * ));
int		env_sender ___P(( struct envelope *, char * ));
int		env_outfile ___P(( struct envelope * ));
int		env_touch ___P(( struct envelope * ));
int		env_slow ___P(( struct envelope * ));
int		env_from ___P(( struct envelope * ));
int		env_unlink ___P(( struct envelope * ));
int		env_read_queue_info ___P(( struct envelope * ));
int		env_read_delivery_info ___P(( struct envelope *, SNET ** ));
