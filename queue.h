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

/* states for struct message->m_action */
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
    struct host_q		*hq_next;
    struct host_q		*hq_deliver;
    char			*hq_hostname;
    int				hq_status;
    int				hq_entries;
    struct message		*hq_message_first;
    struct message		*hq_message_last;
};

struct message {
    struct message		*m_next;
    char			*m_id;
    char			*m_dir;
    int				m_old_dfile;
    int				m_mail_loop;
    struct timespec		m_etime;
};


void	message_stdout ___P(( struct message * ));
void	q_stdout ___P(( struct host_q * ));
void	q_list_stdout ___P(( struct host_q * ));
struct message	*message_create ___P(( char * ));
void	message_free ___P(( struct message * ));
int	message_queue ___P(( struct host_q *, struct message * ));
struct host_q	*host_q_lookup ___P(( struct host_q **, char * )); 
int	bounce ___P(( struct envelope *, SNET * ));
int	q_deliver ___P(( struct host_q * ));
int	q_runner ___P(( struct host_q ** ));
int	q_read_dir ___P(( char *, struct host_q ** ));
int	q_runner_dir ___P(( char * ));
