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


/* states for host_q->hq_status */
#define HOST_NULL	0
#define HOST_LOCAL	1
#define HOST_MX		2
#define HOST_BOUNCE	3
#define HOST_DOWN	4

struct host_list {
    char			*h_name;
    struct stab_entry		*h_addresses;
};

struct host {
    int         		h_type;		/* Type of host */
    char			*h_name;
    struct stab_entry		*h_expansion;	/* Ordered list of expansion */
};

struct host_q {
    struct host_q		*hq_next;
    struct host_q		*hq_deliver;
    char			*hq_hostname;
    int				hq_status;
    int				hq_entries;
    struct message		*hq_message_first;
    struct message		*hq_message_last;
    struct line_file		*hq_err_text;
};

struct message {
    struct message		*m_next;
    char			*m_id;
    char			*m_dir;
    struct timespec		m_etime;
    int				m_efile;
    int				m_expanded;
    ino_t			m_dfile;
};

int	q_runner ___P(( struct host_q ** ));
int	q_runner_dir ___P(( char * ));

struct	host_q	*host_q_lookup ___P(( struct host_q **, char * )); 
void	q_stdout ___P(( struct host_q * ));
void	q_stab_stdout ___P(( struct host_q * ));
struct	message	*message_create ___P(( char * ));
void	message_free ___P(( struct message * ));
void	message_stdout ___P(( struct message * ));
int	message_queue ___P(( struct host_q *, struct message * ));
