/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     queue.h     *****/

/* states for host_q->hq_status */
#define HOST_NULL	0
#define HOST_UNKNOWN	1
#define HOST_LOCAL	2
#define HOST_MX		3
#define HOST_BOUNCE	4
#define HOST_DOWN	5
#define HOST_PUNT	6
#define HOST_PUNT_DOWN	7

struct deliver {
    struct envelope		*d_env;
    struct recipient		*d_rcpt;
    int				d_dfile_fd;
    int				d_n_rcpt_accepted;
    int				d_n_rcpt_failed;
    int				d_n_rcpt_tempfail;
    int				d_attempt;
    int				d_delivered;
    int				d_unlinked;

    /* SMTP connection variables */
    struct dnsr_result		*d_dnsr_result;
    struct dnsr_result		*d_dnsr_result_ip;
    struct sockaddr_in		d_sin;
    SNET			*d_snet_smtp;
    SNET			*d_snet_dfile;
    uint16_t			d_mx_preference_cutoff;
    int				d_cur_dnsr_result;
    int				d_cur_dnsr_result_ip;
};

struct host_q {
    struct host_q		*hq_next;
    struct host_q		*hq_deliver;
    char			*hq_hostname;
    char			*hq_smtp_hostname;
    int				hq_status;
    int				hq_entries;
    int				hq_from;
    int				hq_no_punt;
    struct envelope		*hq_env_head;
    struct line_file		*hq_err_text;
    struct dnsr_result		*hq_dnsr_result;
};

int	q_runner( struct host_q ** );
int	q_runner_dir( char * );

struct	host_q	*host_q_create_or_lookup( struct host_q **, char * ); 
void	queue_remove_envelope( struct envelope * );
int	queue_envelope( struct host_q **, struct envelope *);

/* debugging functions */
void	q_stab_syslog( struct host_q * );
void	q_stab_stdout( struct host_q * );
void	q_syslog( struct host_q * );
void	q_stdout( struct host_q * );
