#ifndef SIMTA_QUEUE_H
#define SIMTA_QUEUE_H

#include <netinet/in.h>
#include <snet.h>

#include "simta.h"

/* states for host_q->hq_status */
typedef enum {
    SIMTA_HOST_UNKNOWN,
    SIMTA_HOST_NULL,
    SIMTA_HOST_LOCAL,
    SIMTA_HOST_MX,
    SIMTA_HOST_BOUNCE,
    SIMTA_HOST_DOWN,
    SIMTA_HOST_BITBUCKET,
} simta_host_status;

typedef enum {
    SIMTA_DNS_OK,
    SIMTA_DNS_EOF,
    SIMTA_DNS_AGAIN,
} simta_dns_result;


struct connection_data {
    struct connection_data *c_prev;
    struct connection_data *c_next;
    struct sockaddr_storage c_sa;
    char                    c_ip[ INET6_ADDRSTRLEN ];
};

struct deliver {
    struct envelope * d_env;
    struct recipient *d_rcpt;
    const char *      d_deliver_agent;
    off_t             d_size;
    off_t             d_sent;
    int               d_dfile_fd;
    int               d_n_message_accepted_total;
    int               d_n_message_failed_total;
    int               d_n_message_tempfailed_total;
    int               d_n_rcpt_accepted;
    int               d_n_rcpt_accepted_total;
    int               d_n_rcpt_failed;
    int               d_n_rcpt_failed_total;
    int               d_n_rcpt_tempfailed;
    int               d_n_rcpt_tempfailed_total;
    int               d_delivered;
    int               d_unlinked;

    /* SMTP connection variables */
    int                     d_connection_msg_total;
    bool                    d_queue_movement;
    SNET *                  d_snet_smtp;
    SNET *                  d_snet_dfile;
    ucl_object_t *          d_mx_list;
    ucl_object_t *          d_mx_current;
    ucl_object_t *          d_retry_list;
    ucl_object_t *          d_retry_current;
    struct dnsr_result *    d_dnsr_result;
    const char *            d_cur_mx_lookup_type;
    struct sockaddr_storage d_sa;
    char                    d_ip[ INET6_ADDRSTRLEN ];
    bool                    d_mx_check_ipv4;
    bool                    d_mx_check_ipv6;
    bool                    d_mx_cname_ok;
    int                     d_cur_mx_lookup;
    int                     d_cur_dnsr_result;
    int                     d_esmtp_8bitmime;
    int                     d_esmtp_size;
    int                     d_esmtp_starttls;
};

struct host_q {
    int               hq_entries;
    int               hq_entries_new;
    int               hq_entries_removed;
    ucl_object_t *    hq_red;
    struct host_q *   hq_deliver;
    struct host_q *   hq_deliver_prev;
    struct host_q *   hq_deliver_next;
    yastr             hq_hostname;
    char *            hq_smtp_hostname;
    int               hq_primary;
    simta_host_status hq_status;
    int               hq_wait_min;
    int               hq_wait_max;
    int               hq_launches;
    int               hq_delay;
    bool              hq_leaky;
    struct envelope * hq_env_head;
    struct line_file *hq_err_text;
    struct timeval    hq_last_launch;
    struct timeval    hq_next_launch;
    struct timeval    hq_wait_last;
    struct timeval    hq_wait_longest;
    struct timeval    hq_wait_shortest;
};

int q_runner_dir(char *);

struct host_q *host_q_lookup(char *);
struct host_q *host_q_create_or_lookup(char *);
int            q_runner(void);
void           queue_remove_envelope(struct envelope *);
simta_result   queue_envelope(struct envelope *);
int            q_single(struct host_q *);
void           hq_deliver_pop(struct host_q *);
void           queue_log_metrics(struct host_q *);
simta_result   next_dnsr_host_lookup(struct deliver *, struct host_q *);

int q_read_dir(struct simta_dirp *);
int hq_deliver_push(struct host_q *, struct timeval *, struct timeval *);

#endif /* SIMTA_QUEUE_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
