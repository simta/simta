/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     queue.h     *****/

/* states for host_q->hq_status */
#define HOST_NULL	0
#define HOST_LOCAL	1
#define HOST_MX		2
#define HOST_BOUNCE	3
#define HOST_DOWN	4

struct deliver {
    struct envelope		*d_env;
    struct recipient		*d_rcpt;
    int				d_dfile_fd;
    SNET			*d_dfile_snet;
    int				d_n_rcpt_accepted;
    int				d_n_rcpt_failed;
    int				d_n_rcpt_tempfail;
    int				d_attempt;
    int				d_delivered;
    int				d_unlinked;
};

struct host_list {
    char			*h_name;
    struct stab_entry		*h_addresses;
};

struct host {
    int         		h_type;		/* Type of host */
    char			h_name[ DNSR_MAX_HOSTNAME + 1 ];
    struct expansion		*h_expansion;	/* Ordered list of expansion */
};

struct expansion {
    int				e_type;
    struct expansion		*e_next;
};

struct host_q {
    struct host_q		*hq_next;
    struct host_q		*hq_deliver;
    char			*hq_hostname;
    char			*hq_smtp_hostname;
    struct sockaddr_in		hq_sin;
    int				hq_status;
    int				hq_entries;
    int				hq_from;
    struct envelope		*hq_env_head;
    struct line_file		*hq_err_text;
    struct dnsr_result		*hq_dnsr_result;
};

int	q_runner( struct host_q ** );
int	q_runner_dir( char * );

int	q_cleanup( void );
struct	host_q	*host_q_create_or_lookup( struct host_q **, char * ); 
void	queue_remove_envelope( struct envelope * );
int	queue_envelope( struct host_q **, struct envelope *);

/* debugging functions */
void	q_stab_syslog( struct host_q * );
void	q_stab_stdout( struct host_q * );
void	q_syslog( struct host_q * );
void	q_stdout( struct host_q * );
