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

/* states for host_q->hq_status */
#define HOST_NULL	0
#define HOST_LOCAL	1
#define HOST_REMOTE	2
#define HOST_MAIL_LOOP	3
#define HOST_MX		4

struct host {
    int         		h_type;		/* Type of host */
    struct stab_entry		*h_expansion;	/* Ordered list of expansion */
};

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
    struct host_q		*hq_next;
};


/* types of q_runners */
#define	Q_RUNNER_LOCAL	1

int		q_runner ___P(( int ));

/* shared with q_cleanup.c */
void		q_file_stdout ___P(( struct q_file * ));
struct q_file	*q_file_char ___P(( char * ));
