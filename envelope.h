/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#define	R_TEMPFAIL	0
#define	R_ACCEPTED	1
#define	R_FAILED	2

struct recipient {
    struct recipient	*r_next;
    char		*r_rcpt;
    int			r_status;
    struct line_file	*r_err_text;
};

struct envelope {
    struct envelope	*e_next;
    struct envelope	*e_hq_next;
    struct recipient	*e_rcpt;
    struct host_q	*e_hq;
    struct line_file	*e_err_text;
    char		*e_dir;
    char		*e_mail;
    ino_t		e_dinode;
    int			e_age;
    int			e_flags;
    struct timespec	e_last_attempt;
    char		*e_hostname;
    char		*e_id;
};

#define ENV_AGE_UNKNOWN		0
#define ENV_AGE_OLD		1
#define ENV_AGE_NOT_OLD		2

#define ENV_FLAG_ON_DISK	(1<<1)
#define ENV_FLAG_EFILE		(1<<2)
#define ENV_FLAG_DFILE		(1<<3)
#define ENV_FLAG_BOUNCE		(1<<4)
#define ENV_FLAG_TEMPFAIL	(1<<5)
#define ENV_FLAG_PUNT		(1<<6)

struct envelope	*env_create( char * );
struct envelope	*env_dup( struct envelope * );
void		env_rcpt_free( struct envelope * );
void		env_free( struct envelope * );
void		env_reset( struct envelope * );
void		rcpt_free( struct recipient * );
void		env_clear_errors( struct envelope * );
int		env_is_old( struct envelope *, int );
int		env_id( struct envelope * );
int		env_set_id( struct envelope *, char * );
int		env_recipient( struct envelope *, char * );
int		env_sender( struct envelope *, char * );
int		env_hostname( struct envelope *, char * );
int		env_outfile( struct envelope * );
int		env_touch( struct envelope * );
int		env_slow( struct envelope * );
int		env_from( struct envelope * );
int		env_unlink( struct envelope * );
int		env_read_queue_info( struct envelope * );
int		env_read_delivery_info( struct envelope *, SNET ** );
int		env_truncate_and_unlink( struct envelope *, SNET * );
int		env_string_recipients( struct envelope *, char * );

/* debugging  functions */
void		env_stdout( struct envelope * );
void		env_syslog( struct envelope * );
