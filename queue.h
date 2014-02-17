/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     queue.h     *****/

/* states for host_q->hq_status */
#define HOST_UNKNOWN	0
#define HOST_NULL	1
#define HOST_LOCAL	2
#define HOST_MX		3
#define HOST_BOUNCE	4
#define HOST_DOWN	5
#define HOST_PUNT	6
#define HOST_PUNT_DOWN	7
#define HOST_SUPRESSED	8
#define HOST_BITBUCKET	9

/* bits for host_q->hq_no_punt */
#define	NOPUNT_MX	1
#define NOPUNT_CONFIG	2

struct connection_data {
    struct connection_data	*c_prev;
    struct connection_data	*c_next;
    struct sockaddr_in		c_sin;
};

struct deliver {
    int				d_deliver_argc;
    char			**d_deliver_argv;
    struct envelope		*d_env;
    struct recipient		*d_rcpt;
    off_t			d_size;
    off_t			d_sent;
    int				d_dfile_fd;
    int				d_n_message_accepted_total;
    int				d_n_message_failed_total;
    int				d_n_message_tempfailed_total;
    int				d_n_rcpt_accepted;
    int				d_n_rcpt_accepted_total;
    int				d_n_rcpt_failed;
    int				d_n_rcpt_failed_total;
    int				d_n_rcpt_tempfailed;
    int				d_n_rcpt_tempfailed_total;
    int				d_delivered;
    int				d_unlinked;

    /* SMTP connection variables */
    int                         d_connection_msg_total;
    int				d_queue_movement;
    struct connection_data	*d_retry_list;
    struct connection_data	*d_retry_list_end;
    struct connection_data	*d_retry_cur;
    struct dnsr_result		*d_dnsr_result;
    struct dnsr_result		*d_dnsr_result_ip;
    struct sockaddr_in		d_sin;
    SNET			*d_snet_smtp;
    SNET			*d_snet_dfile;
    uint16_t			d_mx_preference_cutoff;
    int				d_mx_preference_set;
    int				d_cur_dnsr_result;
    int				d_cur_dnsr_result_ip;
#ifdef HAVE_LIBSSL
    int				d_tls_supported;
    int				d_tls_banner_check;
#endif /* HAVE_LIBSSL */
};

struct host_q {
    int				hq_entries;
    int				hq_entries_new;
    int				hq_entries_removed;
    int				hq_jail_envs;
    struct simta_red		*hq_red;
    struct host_q		*hq_deliver;
    struct host_q		*hq_next;
    struct host_q		*hq_deliver_prev;
    struct host_q		*hq_deliver_next;
    char			*hq_hostname;
    char			*hq_smtp_hostname;
    int				hq_primary;
    int				hq_status;
    int				hq_no_punt;
    int				hq_wait_min;
    int				hq_wait_max;
    int				hq_launches;
    int				hq_delay;
    int				hq_leaky;
    struct envelope		*hq_env_head;
    struct line_file		*hq_err_text;
    struct timeval		hq_last_launch;
    struct timeval		hq_next_launch;
    struct timeval		hq_wait_last;
    struct timeval		hq_wait_longest;
    struct timeval		hq_wait_shortest;
};

int	q_runner_dir( char * );

struct host_q *host_q_lookup( char * ); 
struct host_q *host_q_create_or_lookup( char * ); 
int	q_runner( void );
void	queue_remove_envelope( struct envelope * );
int	queue_envelope( struct envelope *);
int	q_single( struct host_q * );
void	hq_deliver_pop( struct host_q * );
void	queue_log_metrics( struct host_q * );

int	q_read_dir( struct simta_dirp * );
int	hq_deliver_push( struct host_q *, struct timeval *, struct timeval * );
