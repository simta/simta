/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     queue.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */


/* states for q_action */
#define	Q_REMOVE	1
#define	Q_REORDER	2
#define	Q_IGNORE	3

/* states for host_q->hq_status */
#define HOST_NULL	0
#define HOST_LOCAL	1
#define HOST_REMOTE	2
#define HOST_MAIL_LOOP	3

/* types of q_runners */
#define	Q_RUNNER_LOCAL	1

struct q_file {
    char			*q_id;
    char			*q_expanded;
    struct q_file		*q_inode_next;
    struct q_file		*q_etime_next;
    struct envelope		*q_env;
    struct message_data		*q_data;
    int				q_action;
    int				q_unexpanded;
    int				q_efile;
    int				q_dfile;
    ino_t			q_dfile_ino;
    nlink_t			q_dfile_nlink;
    struct timespec		q_dtime;
    struct timespec		*q_etime;
};

struct host_q {
    char			*hq_name;
    int				hq_status;
    int				hq_entries;
    struct stab_entry		*hq_qfiles;
};

int		q_runner ___P(( int ));

/* return NULL on syserror, doesn't syslog() */
struct q_file	*q_file_char ___P(( char * ));
struct q_file	*q_file_env ___P(( struct envelope * ));
void		q_file_free ___P(( struct q_file * ));
void		q_file_stdout ___P(( struct q_file * ));

struct host_q	*host_q_create ___P(( char * ));
struct host_q	*host_q_lookup ___P(( struct stab_entry **, char * )); 
void		host_q_stdout ___P(( struct host_q * ));
void		host_q_cleanup ___P(( struct host_q * ));

int		efile_time_compare ___P(( void *, void * ));

/* new from q_runner */
int		bounce ___P(( struct envelope *, SNET * ));
int		deliver ___P(( struct host_q * ));
