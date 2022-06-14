/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "dns.h"
#include "envelope.h"
#include "line_file.h"
#include "ml.h"
#include "red.h"
#include "simta_ldap.h"
#include "simta_malloc.h"
#include "smtp.h"

static void         deliver_q_queue(struct host_q *, struct host_q *);
static simta_result deliver_checksockaddr(struct deliver *, struct host_q *);
static void         free_dns_results(struct deliver *);
static void         real_q_deliver(struct deliver *, struct host_q *);
void                q_deliver(struct host_q *);
void                deliver_local(struct deliver *d);
void                deliver_remote(struct deliver *d, struct host_q *);
void                hq_clear_errors(struct host_q *);
simta_dns_result    next_dnsr_host(struct deliver *, struct host_q *);
void                hq_free(struct host_q *);
simta_result        get_outbound_dns(struct deliver *, struct host_q *);
void                queue_time_order(struct host_q *);
void                prune_messages(struct host_q *hq);

bool simta_leaky_queue = false;


void
deliver_q_queue(struct host_q *deliver_q, struct host_q *q) {
    struct host_q *last_q;

    while (deliver_q != NULL) {
        if (deliver_q == q) {
            return;
        }
        last_q = deliver_q;
        deliver_q = deliver_q->hq_deliver;
    }
    /* If we made it here, q isn't already queued. */
    last_q->hq_deliver = q;
    q->hq_deliver = NULL;
}

struct host_q *
host_q_lookup(const char *hostname) {
    const ucl_object_t *obj;
    yastr               buf = NULL;

    if (simta_host_q == NULL) {
        simta_host_q = ucl_object_typed_new(UCL_OBJECT);
        return NULL;
    }

    buf = yaslauto(hostname);
    yasltolower(buf);
    obj = ucl_object_lookup(simta_host_q, buf);
    yaslfree(buf);

    if (obj != NULL) {
        return obj->value.ud;
    }

    return NULL;
}


struct host_q *
host_q_create_or_lookup(char *hostname) {
    struct host_q *hq;
    struct timeval tv;

    /* create NULL host queue for unexpanded messages.  we always need to
     * have a NULL queue for error reporting.
     */
    if (simta_unexpanded_q == NULL) {
        simta_unexpanded_q = simta_calloc(1, sizeof(struct host_q));

        /* add this host to the host_q */
        simta_unexpanded_q->hq_hostname = S_UNEXPANDED;
    }

    if ((hostname == NULL) || (*hostname == '\0')) {
        return (simta_unexpanded_q);
    }

    if ((hq = host_q_lookup(hostname)) == NULL) {
        hq = simta_calloc(1, sizeof(struct host_q));
        hq->hq_hostname = yaslauto(hostname);
        yasltolower(hq->hq_hostname);

        hq->hq_red = ucl_object_ref(red_host_lookup(hq->hq_hostname, true));

        simta_ucl_object_totimeval(
                ucl_object_lookup_path(hq->hq_red, "deliver.queue.wait.min"),
                &tv);
        hq->hq_wait_min = tv.tv_sec;
        simta_ucl_object_totimeval(
                ucl_object_lookup_path(hq->hq_red, "deliver.queue.wait.max"),
                &tv);
        hq->hq_wait_max = tv.tv_sec;

        ucl_object_insert_key(simta_host_q,
                ucl_object_new_userdata(NULL, NULL, hq), hq->hq_hostname,
                yasllen(hq->hq_hostname), true);
    }

    return hq;
}


void
hq_clear_errors(struct host_q *hq) {
    if (hq->hq_err_text != NULL) {
        line_file_free(hq->hq_err_text);
        hq->hq_err_text = NULL;
    }
}


simta_result
queue_envelope(struct envelope *env) {
    struct envelope **ep;
    struct host_q *   hq;

    /* don't queue it if it's going in the dead queue */
    if (env->e_dir == simta_dir_dead) {
        return SIMTA_OK;
    }

    /* check to see if it's already already queued */
    if (env->e_hq) {
        return SIMTA_OK;
    }

    if ((hq = host_q_create_or_lookup(env->e_hostname)) == NULL) {
        return SIMTA_ERR;
    }

    /* sort queued envelopes by access time */
    for (ep = &(hq->hq_env_head); *ep != NULL; ep = &((*ep)->e_hq_next)) {
        if (env->e_etime.tv_sec < (*ep)->e_etime.tv_sec) {
            break;
        }
    }

    env->e_hq_next = *ep;
    *ep = env;
    env->e_hq = hq;
    hq->hq_entries++;

    return SIMTA_OK;
}


void
queue_remove_envelope(struct envelope *env) {
    struct envelope **ep;

    if (env != NULL) {
        for (ep = &(env->e_hq->hq_env_head); *ep != env;
                ep = &((*ep)->e_hq_next))
            ;

        *ep = env->e_hq_next;

        env->e_hq->hq_entries--;
        env->e_hq = NULL;
        env->e_hq_next = NULL;
    }

    return;
}


void
queue_time_order(struct host_q *hq) {
    char             fname[ MAXPATHLEN ];
    struct envelope *envs;
    struct envelope *sort;
    struct stat      sb;

    if (hq != NULL) {
        /* sort the envs based on etime */
        envs = hq->hq_env_head;
        hq->hq_entries = 0;
        hq->hq_env_head = NULL;
        while (envs != NULL) {
            sort = envs;
            envs = envs->e_hq_next;
            /* zero out hq so it gets sorted */
            sort->e_hq = NULL;
            sort->e_hq_next = NULL;
            sprintf(fname, "%s/E%s", sort->e_dir, sort->e_id);
            if (stat(fname, &sb) != 0) {
                if (errno != ENOENT) {
                    syslog(LOG_ERR,
                            "Syserror: simta_child_q_runner stat %s: %m",
                            fname);
                }
                env_free(sort);
                continue;
            }
            queue_envelope(sort);
        }
    }
}


int
q_runner(void) {
    SNET *              snet_dfile;
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;
    struct host_q *     hq;
    struct host_q *     deliver_q;
    struct host_q **    dq;
    struct envelope *   env_bounce;
    struct envelope *   unexpanded;
    int                 dfile_fd;
    int                 expanded;
    char                dfile_fname[ MAXPATHLEN ];
    struct timeval      tv_start;
    struct timeval      tv_end;
    int                 day;
    int                 hour;
    int                 min;
    int                 sec;

    if ((simta_host_q == NULL) && (simta_unexpanded_q == NULL)) {
        syslog(LOG_ERR, "Queue.manage: no host_q");
        return 0;
    }

    queue_time_order(simta_unexpanded_q);

    iter = ucl_object_iterate_new(simta_host_q);
    while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
        queue_time_order(obj->value.ud);
    }

    if (simta_gettimeofday(&tv_start) != 0) {
        return fast_q_total();
    }

    for (;;) {
        /* build the deliver_q by number of messages */
        deliver_q = NULL;

        ucl_object_iterate_reset(iter, simta_host_q);
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            hq = obj->value.ud;
            hq->hq_deliver = NULL;

            if (hq->hq_env_head == NULL) {
                continue;
            }

            /*
             * we're going to try to deliver the messages in this host
             * queue, so put it in the delivery queue.
             *
             * sort mail queues by number of messages in the queue.
             */

            simta_debuglog(1, "Queue %s: %d entries, adding to deliver queue",
                    hq->hq_hostname, hq->hq_entries);

            for (dq = &deliver_q; *dq != NULL; dq = &((*dq)->hq_deliver)) {
                if (hq->hq_entries >= ((*dq)->hq_entries)) {
                    simta_debuglog(2, "Queue %s: insert before %s (%d)",
                            hq->hq_hostname, ((*dq)->hq_hostname),
                            ((*dq)->hq_entries));
                    break;
                }

                simta_debuglog(3, "Queue %s: insert after %s (%d)",
                        hq->hq_hostname, ((*dq)->hq_hostname),
                        ((*dq)->hq_entries));
            }

            hq->hq_deliver = *dq;
            *dq = hq;
        }

        /* deliver all mail in every expanded queue */
        for (; deliver_q != NULL; deliver_q = deliver_q->hq_deliver) {
            syslog(LOG_INFO, "Queue %s: Delivering mail",
                    deliver_q->hq_hostname);
            q_deliver(deliver_q);
        }

        /* EXPAND MESSAGES */
        for (expanded = 0;;) {
            if ((unexpanded = simta_unexpanded_q->hq_env_head) == NULL) {
                /* no more unexpanded mail. we're done */
                if (expanded == 0) {
                    /* no mail was expanded in this loop, we're all done */
                    goto q_runner_done;
                } else {
                    break;
                }
            }

            /* pop message off unexpanded message queue */
            queue_remove_envelope(unexpanded);

            if (unexpanded->e_rcpt == NULL) {
                if (env_move(unexpanded, simta_dir_fast)) {
                    goto unexpanded_clean_up;
                }

                if (env_read(false, unexpanded, NULL) != SIMTA_OK) {
                    goto unexpanded_clean_up;
                }
            } else {
                assert(unexpanded->e_dir == simta_dir_fast);
            }
            /* expand message */
            if (expand(unexpanded) == 0) {
                env_free(unexpanded);
                expanded++;
                if (!simta_config_bool("expand.aggressive")) {
                    /* Try delivering mail */
                    break;
                }
                /* Keep expanding mail */
                continue;
            }

            /* message not expandable */
            if (simta_process_type == PROCESS_Q_SLOW) {
                /* check message's age */
                sprintf(dfile_fname, "%s/D%s", unexpanded->e_dir,
                        unexpanded->e_id);
                if ((dfile_fd = open(dfile_fname, O_RDONLY, 0)) < 0) {
                    syslog(LOG_ERR, "Queue.manage: bad Dfile: %s", dfile_fname);
                    goto unexpanded_clean_up;
                }

                if (env_is_old(unexpanded, dfile_fd) == 0) {
                    /* not old */
                    close(dfile_fd);

                } else {
                    /* old unexpanded message, create bounce */
                    unexpanded->e_flags |= ENV_FLAG_BOUNCE;
                    if ((snet_dfile = snet_attach(dfile_fd, 1024 * 1024)) ==
                            NULL) {
                        close(dfile_fd);
                        goto unexpanded_clean_up;
                    }

                    if ((env_bounce = bounce_snet(
                                 unexpanded, snet_dfile, NULL, NULL)) == NULL) {
                        snet_close(snet_dfile);
                        goto unexpanded_clean_up;
                    }

                    if (env_unlink(unexpanded) == 0) {
                        queue_envelope(env_bounce);
                        syslog(LOG_INFO,
                                "Deliver env <%s>: Message Deleted: Bounced",
                                unexpanded->e_id);

                    } else {
                        if (env_unlink(env_bounce) != 0) {
                            syslog(LOG_INFO,
                                    "Deliver env <%s>: System Error: "
                                    "Can't unwind bounce",
                                    env_bounce->e_id);
                        } else {
                            syslog(LOG_INFO,
                                    "Deliver env <%s>: Message Deleted: "
                                    "System error, unwound bounce",
                                    env_bounce->e_id);
                        }
                    }

                    snet_close(snet_dfile);
                }
            }

        unexpanded_clean_up:
            env_move(unexpanded, simta_dir_slow);
            env_free(unexpanded);
        }
    }

q_runner_done:
    ucl_object_iterate_free(iter);

    /* get end time for metrics */
    if (simta_gettimeofday(&tv_end) == 0) {
        tv_end.tv_sec -= tv_start.tv_sec;
        day = (tv_end.tv_sec / 86400);
        hour = ((tv_end.tv_sec % 86400) / 3600);
        min = ((tv_end.tv_sec % 3600) / 60);
        sec = (tv_end.tv_sec % 60);

        if (simta_message_count > 0) {
            if (day > 0) {
                if (day > 99) {
                    day = 99;
                }

                syslog(LOG_NOTICE,
                        "Queue Metrics: %d messages, "
                        "%d outbound_attempts, %d outbound_delivered, "
                        "%d+%02d:%02d:%02d",
                        simta_message_count, simta_smtp_outbound_attempts,
                        simta_smtp_outbound_delivered, day, hour, min, sec);

            } else {
                syslog(LOG_NOTICE,
                        "Queue Metrics: %d messages, "
                        "%d outbound_attempts, %d outbound_delivered, "
                        "%02d:%02d:%02d",
                        simta_message_count, simta_smtp_outbound_attempts,
                        simta_smtp_outbound_delivered, hour, min, sec);
            }
        }
    }

#ifdef HAVE_LDAP
    simta_ldap_reset();
#endif /* HAVE_LDAP */

    if (fast_q_total() != 0) {
        syslog(LOG_ERR, "Queue.manage: exiting with %d fast_files",
                fast_q_total());
        return SIMTA_EXIT_ERROR;
    } else if (simta_leaky_queue) {
        return SIMTA_EXIT_OK_LEAKY;
    }

    return SIMTA_EXIT_OK;
}


int
fast_q_count(struct host_q *hq) {
    int              retval = 0;
    struct envelope *e;

    if (hq) {
        e = hq->hq_env_head;
        while (e) {
            if (e->e_dir == simta_dir_fast) {
                retval++;
            }
            e = e->e_hq_next;
        }
    }

    return retval;
}


int
fast_q_total(void) {
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;
    int                 retval;

    retval = fast_q_count(simta_unexpanded_q);

    if (simta_host_q) {
        iter = ucl_object_iterate_new(simta_host_q);
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            retval += fast_q_count(obj->value.ud);
        }
        ucl_object_iterate_free(iter);
    }

    return retval;
}


void
q_clear(struct host_q *hq) {
    struct envelope *e;

    if (hq == NULL) {
        return;
    }

    while (hq->hq_env_head != NULL) {
        e = hq->hq_env_head;
        hq->hq_env_head = e->e_hq_next;
        simta_debuglog(3, "q_clear: freeing env <%s>", e->e_id);
        env_free(e);
    }
    hq->hq_entries = 0;
}


void
q_clear_all(void) {
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;

    q_clear(simta_unexpanded_q);

    if (simta_host_q) {
        iter = ucl_object_iterate_new(simta_host_q);
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            q_clear(obj->value.ud);
        }
        ucl_object_iterate_free(iter);
    }
}


int
q_runner_dir(char *dir) {
    struct simta_dirp s_dirp;

    memset(&s_dirp, 0, sizeof(struct simta_dirp));
    s_dirp.sd_dir = dir;

    do {
        if (q_read_dir(&s_dirp) != 0) {
            syslog(LOG_ERR, "Syserror: q_runner_dir opendir %s: %m", dir);
            return (EXIT_OK);
        }
    } while (s_dirp.sd_dirp != NULL);

    exit(q_runner() != 0);
}


int
hq_deliver_push(
        struct host_q *hq, struct timeval *tv_now, struct timeval *tv_delay) {
    int            order;
    struct timeval next_launch;
    struct host_q *insert;
    struct timeval tv;
    struct timeval wait_last;

    if (tv_now == NULL) {
        if (simta_gettimeofday(&tv) != 0) {
            return (1);
        }

        tv_now = &tv;
    }

    /* if there is a provided delay, use it but respect hq->hq_wait_max */
    if (tv_delay != NULL) {
        if (tv_delay->tv_sec > hq->hq_wait_max) {
            wait_last.tv_sec = hq->hq_wait_max;
            next_launch.tv_sec = hq->hq_wait_max + tv_now->tv_sec;

        } else {
            next_launch.tv_sec = tv_delay->tv_sec + tv_now->tv_sec;
            if (tv_delay->tv_sec < hq->hq_wait_min) {
                wait_last.tv_sec = hq->hq_wait_min;
            } else {
                wait_last.tv_sec = tv_delay->tv_sec;
            }
        }

    } else if (hq->hq_wait_last.tv_sec == 0) {
        /* new queue */
        wait_last.tv_sec = hq->hq_wait_min;
        if (strcasecmp(simta_config_str("receive.queue.strategy"), "fast") ==
                0) {
            next_launch.tv_sec = random() % hq->hq_wait_min + tv_now->tv_sec;
        } else {
            next_launch.tv_sec = tv_now->tv_sec;
        }

    } else if (hq->hq_leaky) {
        hq->hq_leaky = false;
        wait_last.tv_sec = hq->hq_wait_min;
        next_launch.tv_sec = random() % hq->hq_wait_min + tv_now->tv_sec;

    } else {
        /* wait twice what you did last time, but respect hq->hq_wait_max */
        if ((hq->hq_wait_last.tv_sec * 2) <= hq->hq_wait_max) {
            wait_last.tv_sec = hq->hq_wait_last.tv_sec * 2;
            if (wait_last.tv_sec < hq->hq_wait_min) {
                wait_last.tv_sec = hq->hq_wait_min;
            }
        } else {
            wait_last.tv_sec = hq->hq_wait_max;
        }
        next_launch.tv_sec = wait_last.tv_sec + tv_now->tv_sec;
    }

    /* use next_launch if the queue has already launched, or it's sooner */
    if ((hq->hq_next_launch.tv_sec <= hq->hq_last_launch.tv_sec) ||
            (hq->hq_next_launch.tv_sec > next_launch.tv_sec)) {
        hq->hq_wait_last.tv_sec = wait_last.tv_sec;
        hq->hq_next_launch.tv_sec = next_launch.tv_sec;
    }

    /* add to launch queue sorted on priority and launch time */
    if ((simta_deliver_q == NULL) || (simta_deliver_q->hq_next_launch.tv_sec >=
                                             hq->hq_next_launch.tv_sec)) {
        if ((hq->hq_deliver_next = simta_deliver_q) != NULL) {
            simta_deliver_q->hq_deliver_prev = hq;
        }
        simta_deliver_q = hq;
        order = 1;

    } else {
        for (insert = simta_deliver_q, order = 2;
                ((insert->hq_deliver_next != NULL) &&
                        (insert->hq_deliver_next->hq_next_launch.tv_sec <=
                                hq->hq_next_launch.tv_sec));
                insert = insert->hq_deliver_next, order++)
            ;

        if ((hq->hq_deliver_next = insert->hq_deliver_next) != NULL) {
            hq->hq_deliver_next->hq_deliver_prev = hq;
        }
        insert->hq_deliver_next = hq;
        hq->hq_deliver_prev = insert;
    }

    simta_debuglog(1, "Queue %s: order %d, next %ld", hq->hq_hostname, order,
            hq->hq_next_launch.tv_sec - tv_now->tv_sec);

    return (0);
}


void
hq_deliver_pop(struct host_q *hq_pop) {
    if (hq_pop) {
        if (hq_pop->hq_deliver_prev == NULL) {
            if (simta_deliver_q == hq_pop) {
                simta_deliver_q = hq_pop->hq_deliver_next;
            }

        } else {
            hq_pop->hq_deliver_prev->hq_deliver_next = hq_pop->hq_deliver_next;
        }

        if (hq_pop->hq_deliver_next != NULL) {
            hq_pop->hq_deliver_next->hq_deliver_prev = hq_pop->hq_deliver_prev;
        }

        hq_pop->hq_deliver_next = NULL;
        hq_pop->hq_deliver_prev = NULL;
    }

    return;
}


void
hq_free(struct host_q *hq_free) {
    if (hq_free) {
        hq_deliver_pop(hq_free);
        ucl_object_unref(hq_free->hq_red);
        yaslfree(hq_free->hq_hostname);
        free(hq_free);
    }

    return;
}


void
prune_messages(struct host_q *hq) {
    struct envelope * env;
    struct envelope **e;

    e = &(hq->hq_env_head);
    hq->hq_entries = 0;
    hq->hq_entries_new = 0;
    hq->hq_entries_removed = 0;

    /* make sure that all envs in all host queues are up to date */
    while (*e != NULL) {
        if ((*e)->e_cycle != simta_disk_cycle) {
            env = *e;
            env->e_list_next->e_list_prev = env->e_list_prev;
            env->e_list_prev->e_list_next = env->e_list_next;
            if (simta_env_queue == env) {
                if (env->e_list_next == env) {
                    simta_env_queue = NULL;
                } else {
                    simta_env_queue = env->e_list_next;
                }
            }
            env->e_list_next = NULL;
            env->e_list_prev = NULL;

            *e = (*e)->e_hq_next;
            simta_debuglog(1, "Queue %s: removed env <%s>", hq->hq_hostname,
                    env->e_id);
            env_free(env);
            hq->hq_entries_removed++;

        } else {
            hq->hq_entries++;
            e = &((*e)->e_hq_next);
        }
    }

    return;
}


int
q_read_dir(struct simta_dirp *sd) {
    struct dirent *entry;

    struct envelope *   last_read = NULL;
    struct envelope *   env;
    struct host_q *     hq;
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;

    /* metrics */
    struct timeval tv_stop;
    int            remain_hq = 0;
    int            total = 0;
    int new = 0;
    int removed = 0;

    if (sd->sd_dirp == NULL) {
        if (simta_gettimeofday(&(sd->sd_tv_start)) != 0) {
            return (1);
        }

        if ((sd->sd_dirp = opendir(sd->sd_dir)) == NULL) {
            syslog(LOG_ERR, "Syserror: q_read_dir opendir %s: %m", sd->sd_dir);
            return (1);
        }

        sd->sd_entries = 0;
        sd->sd_cycle++;
        return (0);
    }

    errno = 0;

    if ((entry = readdir(sd->sd_dirp)) == NULL) {
        if (errno != 0) {
            syslog(LOG_ERR, "Syserror: q_read_dir readdir %s: %m", sd->sd_dir);
            return (1);
        }

        if (closedir(sd->sd_dirp) != 0) {
            syslog(LOG_ERR, "Syserror: q_read_dir closedir %s: %m", sd->sd_dir);
            return (1);
        }

        sd->sd_dirp = NULL;

        if (simta_gettimeofday(&tv_stop) != 0) {
            return (1);
        }

        /* post disk-read queue management */
        if (simta_unexpanded_q != NULL) {
            prune_messages(simta_unexpanded_q);
            simta_debuglog(2, "Queue Metrics [Unexpanded]: entries %d",
                    simta_unexpanded_q->hq_entries);
        }

        iter = ucl_object_iterate_new(simta_host_q);
        while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
            if (ucl_object_type(obj) == UCL_NULL) {
                /* iterating over a NULL object will return the object, instead
                 * of not iterating at all.
                 */
                continue;
            }
            hq = obj->value.ud;

            prune_messages(hq);

            total += hq->hq_entries;
            new += hq->hq_entries_new;
            removed += hq->hq_entries_removed;
            hq->hq_entries_new = 0;
            hq->hq_entries_removed = 0;

            /* remove any empty host queues */
            if (hq->hq_env_head == NULL) {
                simta_debuglog(2, "Queue.manage %s: 0 entries, removing",
                        hq->hq_hostname);
                hq_free(hq);
                ucl_object_delete_key(simta_host_q, ucl_object_key(obj));
                continue;
            } else {
                simta_debuglog(2, "Queue Metrics %s: entries %d",
                        hq->hq_hostname, hq->hq_entries);
            }

            /* add new host queues to the deliver queue */
            remain_hq++;

            if (hq->hq_next_launch.tv_sec == 0) {
                syslog(LOG_INFO, "Queue.manage %s: %d entries, adding",
                        hq->hq_hostname, hq->hq_entries);
                if (hq_deliver_push(hq, &tv_stop, NULL) != 0) {
                    return (1);
                }
            }
        }

        ucl_object_iterate_free(iter);

        syslog(LOG_INFO,
                "Queue Metrics: cycle %d messages %d "
                "milliseconds %ld new %d removed %d hosts %d",
                sd->sd_cycle, sd->sd_entries,
                SIMTA_ELAPSED_MSEC(sd->sd_tv_start, tv_stop), new, removed,
                remain_hq);

        return (0);
    }

    switch (*entry->d_name) {
    /* "E*" */
    case 'E':
        sd->sd_entries++;
        break;

    /* "D*" */
    case 'D':
        return (0);

    /* "." && ".." */
    case '.':
        if (*(entry->d_name + 1) == '\0') {
            /* "." */
            return (0);
        } else if ((*(entry->d_name + 1) == '.') &&
                   (*(entry->d_name + 2) == '\0')) {
            /* ".." */
            return (0);
        }
        /* fall through to default */

    /* "*" */
    default:
        syslog(LOG_WARNING, "Queue.manage: unknown file: %s/%s", sd->sd_dir,
                entry->d_name);
        return (0);
    }

    env = NULL;

    if (simta_env_queue != NULL) {
        for (;; env = env->e_list_next) {
            if (env == NULL) {
                if (last_read != NULL) {
                    env = last_read->e_list_next;
                } else {
                    env = simta_env_queue;
                }
            } else if ((env == simta_env_queue) && (last_read == NULL)) {
                env = NULL;
                break;
            }

            if (strcmp(entry->d_name + 1, env->e_id) == 0) {
                break;
            }

            if (env == last_read) {
                env = NULL;
                break;
            }
        }
    }

    if (env != NULL) {
        env->e_cycle = simta_disk_cycle;
        return (0);
    }

    /* here env is NULL, we need to create an envelope */
    if ((env = env_create(sd->sd_dir, entry->d_name + 1, NULL, NULL)) == NULL) {
        return (1);
    }

    if (env_read(true, env, NULL) != SIMTA_OK) {
        env_free(env);
        return (0);
    }

    if (queue_envelope(env) != SIMTA_OK) {
        return 1;
    }

    env->e_cycle = simta_disk_cycle;

    if (simta_env_queue == NULL) {
        /* insert as the head */
        env->e_list_next = env;
        env->e_list_prev = env;
        simta_env_queue = env;
    } else if (last_read == NULL) {
        /* insert before the head */
        env->e_list_next = simta_env_queue;
        env->e_list_prev = simta_env_queue->e_list_prev;
        simta_env_queue->e_list_prev->e_list_next = env;
        simta_env_queue->e_list_prev = env;
        simta_env_queue = env;
    } else if (last_read != NULL) {
        /* insert after the last read */
        env->e_list_next = last_read->e_list_next;
        env->e_list_prev = last_read;
        last_read->e_list_next->e_list_prev = env;
        last_read->e_list_next = env;
    }

    return (0);
}


void
q_deliver(struct host_q *deliver_q) {
    struct deliver d;
    struct timeval tv_start;
    struct timeval tv_stop;
    int            message_total;
    int            rcpt_total;

    if (simta_gettimeofday(&tv_start) != 0) {
        return;
    }

    memset(&d, 0, sizeof(struct deliver));

    real_q_deliver(&d, deliver_q);

    if (simta_gettimeofday(&tv_stop) != 0) {
        return;
    }

    message_total = d.d_n_message_accepted_total + d.d_n_message_failed_total +
                    d.d_n_message_tempfailed_total;

    rcpt_total = d.d_n_rcpt_accepted_total + d.d_n_rcpt_failed_total +
                 d.d_n_rcpt_tempfailed_total;

    syslog(LOG_INFO,
            "Queue %s: Delivery complete: %ld milliseconds, "
            "%d messages: %d A %d F %d T, %d rcpts %d A %d F %d T",
            deliver_q->hq_hostname, SIMTA_ELAPSED_MSEC(tv_start, tv_stop),
            message_total, d.d_n_message_accepted_total,
            d.d_n_message_failed_total, d.d_n_message_tempfailed_total,
            rcpt_total, d.d_n_rcpt_accepted_total, d.d_n_rcpt_failed_total,
            d.d_n_rcpt_tempfailed_total);

    return;
}


void
real_q_deliver(struct deliver *d, struct host_q *deliver_q) {
    int                touch = 0;
    int                n_processed = 0;
    int                n_rcpt_remove;
    int                dfile_fd;
    int                shuffle;
    SNET *             snet_dfile = NULL;
    SNET *             snet_lock;
    char               dfile_fname[ MAXPATHLEN ];
    struct recipient **r_sort;
    struct recipient * remove;
    struct envelope *  env_deliver;
    struct envelope *  env_bounce = NULL;
    struct stat        sbuf;
    struct timespec    ts;

    memset(d, 0, sizeof(struct deliver));

    syslog(LOG_INFO, "Queue %s: delivering %d messages", deliver_q->hq_hostname,
            deliver_q->hq_entries);

    /* process each envelope in the queue */
    while (deliver_q->hq_env_head != NULL) {
        env_deliver = deliver_q->hq_env_head;

        if (strcasecmp(ucl_object_tostring(ucl_object_lookup_path(
                               deliver_q->hq_red, "deliver.queue.strategy")),
                    "shuffle") == 0) {
            for (shuffle = (random() % deliver_q->hq_entries); shuffle > 0;
                    shuffle--) {
                env_deliver = env_deliver->e_hq_next;
            }
        }

        queue_remove_envelope(env_deliver);

        syslog(LOG_INFO, "Deliver env <%s>: Attempting delivery",
                env_deliver->e_id);

        /* lock & read envelope to deliver */
        if (env_read(false, env_deliver, &snet_lock) != SIMTA_OK) {
            /* envelope not valid.  disregard */
            env_free(env_deliver);
            env_deliver = NULL;
            continue;
        }

        /* don't memset entire structure because we reuse connection data */
        d->d_env = env_deliver;
        d->d_dfile_fd = 0;
        d->d_n_rcpt_accepted = 0;
        d->d_n_rcpt_failed = 0;
        d->d_n_rcpt_tempfailed = 0;
        d->d_delivered = 0;
        d->d_unlinked = 0;
        d->d_size = 0;
        d->d_sent = 0;

        /* open Dfile to deliver */
        sprintf(dfile_fname, "%s/D%s", env_deliver->e_dir, env_deliver->e_id);
        if ((dfile_fd = open(dfile_fname, O_RDONLY, 0)) < 0) {
            syslog(LOG_ERR, "Queue %s: bad Dfile: %s", deliver_q->hq_hostname,
                    dfile_fname);
            goto message_cleanup;
        }

        d->d_dfile_fd = dfile_fd;

        if (fstat(dfile_fd, &sbuf) != 0) {
            syslog(LOG_ERR, "Syserror: q_deliver fstat %s: %m", dfile_fname);
            goto message_cleanup;
        }

        d->d_size = sbuf.st_size;

        if (env_deliver->e_jailed) {
            syslog(LOG_INFO, "Deliver.remote env <%s>: jail",
                    env_deliver->e_id);
        } else if (ucl_object_toboolean(ucl_object_lookup_path(
                           deliver_q->hq_red, "deliver.bitbucket.enabled"))) {
            simta_ucl_object_totimespec(
                    ucl_object_lookup_path(
                            deliver_q->hq_red, "deliver.bitbucket.delay"),
                    &ts);
            syslog(LOG_WARNING,
                    "Deliver.remote env <%s>: bitbucket in %ld.%06ld seconds",
                    env_deliver->e_id, ts.tv_sec, ts.tv_nsec / 1000);
            nanosleep(&ts, NULL);
            d->d_delivered = 1;
            d->d_n_rcpt_accepted = env_deliver->e_n_rcpt;
        } else if (ucl_object_toboolean(ucl_object_lookup_path(
                           deliver_q->hq_red, "deliver.local.enabled"))) {
            d->d_deliver_agent = ucl_object_tostring(ucl_object_lookup_path(
                    deliver_q->hq_red, "deliver.local.agent"));
            deliver_local(d);
        } else if (env_deliver->e_puntable &&
                   ucl_object_toboolean(ucl_object_lookup_path(
                           deliver_q->hq_red, "deliver.punt.enabled")) &&
                   ucl_object_toboolean(ucl_object_lookup_path(
                           deliver_q->hq_red, "deliver.punt.always"))) {
            syslog(LOG_INFO, "Deliver.remote env <%s>: punt",
                    env_deliver->e_id);
        } else {
            switch (deliver_q->hq_status) {
            case SIMTA_HOST_OK:
                if ((snet_dfile = snet_attach(dfile_fd, 1024 * 1024)) == NULL) {
                    syslog(LOG_ERR, "Liberror: q_deliver snet_attach: %m");
                    goto message_cleanup;
                }
                d->d_snet_dfile = snet_dfile;
                deliver_remote(d, deliver_q);
                break;

            case SIMTA_HOST_DOWN:
                syslog(LOG_NOTICE, "Deliver.remote env <%s>: host %s down",
                        d->d_env->e_id, deliver_q->hq_hostname);
                break;

            case SIMTA_HOST_BOUNCE:
                syslog(LOG_NOTICE,
                        "Deliver.remote env <%s>: host %s bouncing mail",
                        d->d_env->e_id, deliver_q->hq_hostname);
                env_deliver->e_flags |= ENV_FLAG_BOUNCE;
                break;

            default:
                panic("q_deliver host_status out of range");
            }
        }

        /* check to see if this is the primary queue, and if it has leaked */
        if (deliver_q->hq_primary && d->d_queue_movement) {
            simta_leaky_queue = true;
        }

        if (!env_deliver->e_bounceable) {
            env_clear_errors(env_deliver);
        }

        if (d->d_delivered != 0) {
            d->d_n_message_accepted_total++;
            n_rcpt_remove = d->d_n_rcpt_failed + d->d_n_rcpt_accepted;
            d->d_n_rcpt_accepted_total += d->d_n_rcpt_accepted;
            d->d_n_rcpt_failed_total += d->d_n_rcpt_failed;
            d->d_n_rcpt_tempfailed_total += d->d_n_rcpt_tempfailed;
        } else if ((env_deliver->e_flags & ENV_FLAG_BOUNCE) != 0) {
            d->d_n_message_failed_total++;
            n_rcpt_remove = env_deliver->e_n_rcpt;
            d->d_n_rcpt_failed_total += env_deliver->e_n_rcpt;
        } else {
            d->d_n_message_tempfailed_total++;
            n_rcpt_remove = d->d_n_rcpt_failed;
            d->d_n_rcpt_failed_total += d->d_n_rcpt_failed;
            d->d_n_rcpt_tempfailed_total +=
                    d->d_n_rcpt_tempfailed + d->d_n_rcpt_accepted;
        }

        /* check the age of the original message unless we've created
         * a bounce for the entire message, or if we've successfully
         * delivered the message and no recipients tempfailed.
         * note that this is the exact opposite of the test to delete
         * a message: it is not nessecary to check a message's age
         * for bounce purposes when it is already slated for deletion.
         */
        if (n_rcpt_remove != env_deliver->e_n_rcpt) {
            if (env_is_old(env_deliver, dfile_fd) != 0) {
                syslog(LOG_NOTICE, "Deliver env <%s>: old message, bouncing",
                        env_deliver->e_id);
                env_deliver->e_flags |= ENV_FLAG_BOUNCE;
            } else {
                simta_debuglog(
                        1, "Deliver env <%s>: not old", env_deliver->e_id);
            }
        } else {
            simta_debuglog(1, "Deliver env <%s>: not checking age of message",
                    env_deliver->e_id);
        }

        /* bounce the message if the message is bad, or if some recipients are bad.
         */
        if (env_deliver->e_bounceable &&
                ((env_deliver->e_flags & ENV_FLAG_BOUNCE) ||
                        d->d_n_rcpt_failed)) {
            simta_debuglog(
                    1, "Deliver env <%s>: creating bounce", env_deliver->e_id);
            if (lseek(dfile_fd, (off_t)0, SEEK_SET) != 0) {
                syslog(LOG_ERR, "Syserror: q_deliver lseek: %m");
                panic("q_deliver lseek fail");
            }

            if (snet_dfile == NULL) {
                if ((snet_dfile = snet_attach(dfile_fd, 1024 * 1024)) == NULL) {
                    syslog(LOG_ERR, "Liberror: q_deliver snet_attach: %m");
                    /* fall through, just won't get to append dfile */
                }
            } else {
                if (lseek(snet_fd(snet_dfile), (off_t)0, SEEK_SET) != 0) {
                    syslog(LOG_ERR, "Syserror: q_deliver lseek: %m");
                    panic("q_deliver lseek fail");
                }
            }

            if ((env_bounce = bounce_snet(
                         env_deliver, snet_dfile, deliver_q, NULL)) == NULL) {
                syslog(LOG_ERR, "Deliver env <%s>: bounce failed",
                        env_deliver->e_id);
                goto message_cleanup;
            }

        } else {
            simta_debuglog(2, "Deliver env <%s>: no bounces created",
                    env_deliver->e_id);
        }

        /* delete the original message if we've created
         * a bounce for the entire message, or if we've successfully
         * delivered the message and no recipients tempfailed.
         */
        if ((env_deliver->e_bounceable &&
                    (env_deliver->e_flags & ENV_FLAG_BOUNCE)) ||
                (n_rcpt_remove == env_deliver->e_n_rcpt)) {
            if (env_truncate_and_unlink(env_deliver, snet_lock) != 0) {
                goto message_cleanup;
            }

            d->d_unlinked = 1;

            if (env_deliver->e_flags & ENV_FLAG_BOUNCE) {
                syslog(LOG_INFO, "Deliver env <%s>: Message Deleted: Bounced",
                        env_deliver->e_id);
            } else {
                syslog(LOG_INFO, "Deliver env <%s>: Message Deleted: Delivered",
                        env_deliver->e_id);
            }

            /* else we remove rcpts that were delivered or hard failed */
        } else if (n_rcpt_remove != 0) {
            simta_debuglog(1, "Deliver env <%s>: Rewriting envelope",
                    env_deliver->e_id);

            r_sort = &(env_deliver->e_rcpt);
            while (*r_sort != NULL) {
                /* remove rcpts that were delivered or hard failed */
                if ((d->d_delivered && ((*r_sort)->r_status == R_ACCEPTED)) ||
                        ((*r_sort)->r_status == R_FAILED)) {
                    remove = *r_sort;
                    *r_sort = (*r_sort)->r_next;
                    env_deliver->e_n_rcpt--;

                    if (remove->r_status == R_FAILED) {
                        syslog(LOG_WARNING,
                                "Deliver env <%s>: "
                                "Removing To <%s> From <%s>: Failed",
                                env_deliver->e_id, remove->r_rcpt,
                                env_deliver->e_mail);

                    } else {
                        syslog(LOG_INFO,
                                "Deliver env <%s>: "
                                "Removing To <%s> From <%s>: Delivered",
                                env_deliver->e_id, remove->r_rcpt,
                                env_deliver->e_mail);
                    }

                    rcpt_free(remove);

                } else {
                    simta_debuglog(2,
                            "Deliver env <%s>: Keeping To <%s> From <%s>",
                            env_deliver->e_id, (*r_sort)->r_rcpt,
                            env_deliver->e_mail);
                    r_sort = &((*r_sort)->r_next);
                }
            }

            assert(env_deliver->e_n_rcpt > 0);

            if (env_outfile(env_deliver) == SIMTA_OK) {
                syslog(LOG_INFO, "Deliver env <%s>: Rewrote %d recipients",
                        env_deliver->e_id, env_deliver->e_n_rcpt);
            } else {
                syslog(LOG_WARNING,
                        "Deliver env <%s>: Rewrite failed, "
                        "double delivery will occur",
                        env_deliver->e_id);
                goto message_cleanup;
            }
        } else if (d->d_n_rcpt_accepted) {
            touch++;
        }

        if (env_bounce != NULL) {
            queue_envelope(env_bounce);
            env_bounce = NULL;
        }

    message_cleanup:
        if (((touch != 0) || (n_processed == 0)) &&
                (env_deliver->e_dir == simta_dir_slow) &&
                (d->d_unlinked == 0)) {
            touch = 0;
            env_touch(env_deliver);
            simta_debuglog(
                    2, "Deliver env <%s>: Envelope touched", env_deliver->e_id);
        }

        n_processed++;

        if (env_bounce != NULL) {
            if (env_unlink(env_bounce) != 0) {
                syslog(LOG_WARNING,
                        "Deliver env <%s>: System error, can't unwind bounce",
                        env_bounce->e_id);
            } else {
                syslog(LOG_WARNING,
                        "Deliver env <%s>: Message deleted: "
                        "System error, unwound bounce",
                        env_bounce->e_id);
            }

            env_free(env_bounce);
            env_bounce = NULL;
        }

        if (d->d_unlinked == 0) {
            if (deliver_q->hq_primary && env_deliver->e_jailed) {
                /* active jailed message */
                simta_leaky_queue = true;
            }
            if (ucl_object_toboolean(ucl_object_lookup_path(
                        deliver_q->hq_red, "deliver.connection.aggressive")) &&
                    (d->d_n_rcpt_tempfailed > 0) &&
                    (d->d_n_rcpt_accepted > 0) && (d->d_delivered)) {
                /* The message was accepted for some recipients, so we should
                 * requeue it and retry delivery for the tempfailed rcpts.
                 */
                queue_envelope(env_deliver);
                env_deliver = NULL;
                d->d_env = NULL;
            } else if (env_deliver->e_puntable &&
                       ucl_object_toboolean(ucl_object_lookup_path(
                               deliver_q->hq_red, "deliver.punt.enabled"))) {
                syslog(LOG_INFO, "Deliver env <%s>: queueing for punt",
                        env_deliver->e_id);
                env_clear_errors(env_deliver);
                /* Messages that we are punting cannot be punted or bounced */
                env_deliver->e_puntable = false;
                env_deliver->e_bounceable = false;
                env_hostname(env_deliver,
                        (ucl_object_tostring(ucl_object_lookup_path(
                                deliver_q->hq_red, "deliver.punt.host"))));
                queue_envelope(env_deliver);
                deliver_q_queue(deliver_q, env_deliver->e_hq);
                env_outfile(env_deliver);
            } else {
                if (!env_deliver->e_puntable) {
                    syslog(LOG_INFO, "Deliver env <%s>: not puntable",
                            env_deliver->e_id);
                }
                env_move(env_deliver, simta_dir_slow);
                env_free(env_deliver);
                env_deliver = NULL;
                d->d_env = NULL;
            }
        } else {
            env_free(env_deliver);
            env_deliver = NULL;
            d->d_env = NULL;
        }

        if (snet_dfile == NULL) {
            if (dfile_fd > 0) {
                if (close(dfile_fd) != 0) {
                    syslog(LOG_ERR, "Syserror: q_deliver close: %m");
                }
            }

        } else {
            if (snet_close(snet_dfile) != 0) {
                syslog(LOG_ERR, "Liberror: q_deliver snet_close: %m");
            }
            snet_dfile = NULL;
        }

        if (snet_lock != NULL) {
            if (snet_close(snet_lock) != 0) {
                syslog(LOG_ERR, "Liberror: q_deliver snet_close: %m");
            }
        }
    }

    if (d->d_snet_smtp != NULL) {
        simta_debuglog(
                2, "Queue %s: calling smtp_quit", deliver_q->hq_hostname);
        smtp_quit(deliver_q, d);
        if (snet_close(d->d_snet_smtp) != 0) {
            syslog(LOG_ERR, "Liberror: q_deliver snet_close: %m");
        }
    }
    free_dns_results(d);

    return;
}


void
deliver_local(struct deliver *d) {
    int ml_error;

    syslog(LOG_NOTICE, "Deliver.local env <%s>: local delivery attempt",
            d->d_env->e_id);

    for (d->d_rcpt = d->d_env->e_rcpt; d->d_rcpt != NULL;
            d->d_rcpt = d->d_rcpt->r_next) {

        /* Special handling for /dev/null */
        if (strncasecmp(d->d_rcpt->r_rcpt, "/dev/null@", 10) == 0) {
            d->d_rcpt->r_status = R_ACCEPTED;
            d->d_n_rcpt_accepted++;
            syslog(LOG_INFO,
                    "Deliver.local env <%s>: To <%s> From <%s>: bitbucketed",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail);
            continue;
        }

        ml_error = EX_TEMPFAIL;

        if (lseek(d->d_dfile_fd, (off_t)0, SEEK_SET) != 0) {
            syslog(LOG_ERR, "Syserror: deliver_local lseek: %m");
            goto lseek_fail;
        }

        ml_error = deliver_binary(d);

    lseek_fail:
        switch (ml_error) {
        case EXIT_SUCCESS:
            /* success */
            d->d_rcpt->r_status = R_ACCEPTED;
            d->d_n_rcpt_accepted++;
            syslog(LOG_INFO,
                    "Deliver.local env <%s>: To <%s> From <%s>: accepted",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail);
            break;

        default:
        case EX_TEMPFAIL:
            d->d_rcpt->r_status = R_TEMPFAIL;
            d->d_n_rcpt_tempfailed++;
            syslog(LOG_INFO,
                    "Deliver.local env <%s>: To <%s> From <%s>: tempfailed: %d",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
                    ml_error);
            break;

        case EX_DATAERR:
        case EX_NOUSER:
            /* hard failure caused by bad user data, or no local user */
            d->d_rcpt->r_status = R_FAILED;
            d->d_n_rcpt_failed++;
            syslog(LOG_INFO,
                    "Deliver.local env <%s>: To <%s> From <%s>: failed: %d",
                    d->d_env->e_id, d->d_rcpt->r_rcpt, d->d_env->e_mail,
                    ml_error);
            break;
        }

        syslog(LOG_INFO,
                "Deliver.local env <%s>: Accepted %d Tempfailed %d Failed %d",
                d->d_env->e_id, d->d_n_rcpt_accepted, d->d_n_rcpt_tempfailed,
                d->d_n_rcpt_failed);
    }

    d->d_delivered = 1;

    return;
}


void
deliver_remote(struct deliver *d, struct host_q *hq) {
    int            r_smtp;
    int            s;
    bool           env_movement = false;
    struct timeval tv_start;
    struct timeval tv_stop;

    if (simta_gettimeofday(&tv_start) != 0) {
        return;
    }

    syslog(LOG_NOTICE, "Deliver.remote env <%s>: host %s", d->d_env->e_id,
            hq->hq_hostname);
    hq->hq_status = SIMTA_HOST_DOWN;

    for (;;) {
        if (d->d_snet_smtp == NULL) {
            d->d_connection_msg_total = 0;
            /* need to build SMTP connection */
            if (next_dnsr_host_lookup(d, hq) != SIMTA_OK) {
                return;
            }

        retry:
            /* build snet */
            if ((s = socket(d->d_sa.ss_family, SOCK_STREAM, 0)) < 0) {
                syslog(LOG_ERR, "Syserror: deliver_remote socket: %m");
                continue;
            }

            if (connect(s, (struct sockaddr *)&(d->d_sa),
                        ((d->d_sa.ss_family == AF_INET6)
                                        ? sizeof(struct sockaddr_in6)
                                        : sizeof(struct sockaddr_in))) < 0) {
                syslog(LOG_ERR, "Connect.out [%s] %s: Failed: connect: %m",
                        d->d_ip, hq->hq_hostname);
                close(s);
                continue;
            }

            syslog(LOG_INFO, "Connect.out [%s] %s: Success", d->d_ip,
                    hq->hq_hostname);

            if ((d->d_snet_smtp = snet_attach(s, 1024 * 1024)) == NULL) {
                syslog(LOG_ERR, "Liberror: deliver_remote snet_attach: %m");
                close(s);
                continue;
            }

            simta_smtp_outbound_attempts++;
            hq_clear_errors(hq);

            if ((r_smtp = smtp_connect(hq, d)) == SMTP_BAD_TLS) {
                snet_close(d->d_snet_smtp);
                d->d_snet_smtp = NULL;
                syslog(LOG_INFO,
                        "Deliver.remote %s: disabling TLS and retrying",
                        hq->hq_hostname);
                simta_ucl_toggle(hq->hq_red, "deliver.tls", "enabled", false);
                goto retry;
            } else if (r_smtp != SMTP_OK) {
                goto smtp_cleanup;
            }

        } else {
            /* already have SMTP connection, say RSET and send message */
            if ((r_smtp = smtp_rset(hq, d)) != SMTP_OK) {
                goto smtp_cleanup;
            }
        }

        env_clear_errors(d->d_env);
        d->d_n_rcpt_accepted = 0;
        d->d_n_rcpt_failed = 0;
        d->d_n_rcpt_tempfailed = 0;
        d->d_sent = 0;
        d->d_connection_msg_total++;

        /* Reset to the beginning of the file... */
        if (lseek(snet_fd(d->d_snet_dfile), (off_t)0, SEEK_SET) != 0) {
            syslog(LOG_ERR, "Syserror: deliver_remote lseek: %m");
            return;
        }

        /* ...and clear the buffer of stale data */
        snet_flush(d->d_snet_dfile);

        r_smtp = smtp_send(hq, d);

        /* If we got any responses to RCPT the host is up. */
        if (d->d_n_rcpt_accepted || d->d_n_rcpt_tempfailed ||
                d->d_n_rcpt_failed) {
            d->d_queue_movement = true;
            env_movement = true;
        }

        if ((d->d_n_rcpt_failed) || (d->d_delivered && d->d_n_rcpt_accepted)) {
            simta_smtp_outbound_delivered++;
            simta_gettimeofday(&tv_stop);
            simta_debuglog(1,
                    "Queue %s: env <%s> Delivery activity: "
                    "%d failed %d accepted %ld milliseconds",
                    hq->hq_hostname, d->d_env->e_id, d->d_n_rcpt_failed,
                    d->d_delivered ? d->d_n_rcpt_accepted : 0,
                    SIMTA_ELAPSED_MSEC(tv_start, tv_stop));
        }

        if (r_smtp == SMTP_OK) {
            /* Close the connection if we've hit the per-connection
             * message limit. */
            if (d->d_connection_msg_total >=
                    ucl_object_toint(ucl_object_lookup_path(
                            hq->hq_red, "deliver.connection.max_messages"))) {
                smtp_quit(hq, d);
                snet_close(d->d_snet_smtp);
                d->d_snet_smtp = NULL;
            }

            hq->hq_status = SIMTA_HOST_OK;
        }

    smtp_cleanup:
        if (r_smtp == SMTP_ERROR) {
            smtp_quit(hq, d);
        }

        snet_close(d->d_snet_smtp);
        d->d_snet_smtp = NULL;

        if (hq->hq_status == SIMTA_HOST_BOUNCE) {
            free_dns_results(d);
            return;

        } else if (hq->hq_status == SIMTA_HOST_DOWN) {
            if (env_movement) {
                hq->hq_status = SIMTA_HOST_OK;
                return;
            }
        }
    }
}


simta_result
next_dnsr_host_lookup(struct deliver *d, struct host_q *hq) {
    simta_dns_result rc;
    while ((rc = next_dnsr_host(d, hq)) == SIMTA_DNS_AGAIN)
        ;
    if (rc == SIMTA_DNS_OK) {
        d->d_queue_movement = false;
        return SIMTA_OK;
    }

    syslog(LOG_INFO, "DNS %s: DNS exhausted", hq->hq_hostname);

    return SIMTA_ERR;
}


simta_result
get_outbound_dns(struct deliver *d, struct host_q *hq) {
    int                 i;
    const ucl_object_t *red;

    /*
     * RFC 5321 5.1 Locating the Target Host
     *
     * The lookup first attempts to locate an MX record associated with the
     * name.  If a CNAME record is found, the resulting name is processed as
     * if it were the initial name.  If a non-existent domain error is
     * returned, this situation MUST be reported as an error.  If a
     * temporary error is returned, the message MUST be queued and retried
     * later (see Section 4.5.4.1).  If an empty list of MXs is returned,
     * the address is treated as if it was associated with an implicit MX
     * RR, with a preference of 0, pointing to that host.  If MX records are
     * present, but none of them are usable, or the implicit MX is unusable,
     * this situation MUST be reported as an error.
     *
     * If one or more MX RRs are found for a given name, SMTP systems MUST
     * NOT utilize any address RRs associated with that name unless they are
     * located using the MX RRs; the "implicit MX" rule above applies only
     * if there are no MX records present.  If MX records are present, but
     * none of them are usable, this situation MUST be reported as an error.
     *
     * When a domain name associated with an MX RR is looked up and the
     * associated data field obtained, the data field of that response MUST
     * contain a domain name.  That domain name, when queried, MUST return
     * at least one address record (e.g., A or AAAA RR) that gives the IP
     * address of the SMTP server to which the message should be directed.
     * Any other response, specifically including a value that will return a
     * CNAME record when queried, lies outside the scope of this Standard.
     * The prohibition on labels in the data that resolve to CNAMEs is
     * discussed in more detail in RFC 2181, Section 10.3 [38].
     */

    /* The lookup first attempts to locate an MX record associated with the
     * name.
     */
    d->d_mx_cname_ok = false;
    if ((d->d_dnsr_result = get_mx(hq->hq_hostname)) == NULL) {
        simta_ucl_toggle(hq->hq_red, "deliver.punt", "enabled", false);
        syslog(LOG_ERR, "DNS %s: MX lookup failure, Punting disabled",
                hq->hq_hostname);
        return SIMTA_ERR;
    }

    /* Check to make sure the MX entry doesn't have 0 entries, and
     * that it doesn't contain a single CNAME entry only */
    if ((d->d_dnsr_result->r_ancount != 0) &&
            ((d->d_dnsr_result->r_ancount != 1) ||
                    (d->d_dnsr_result->r_answer[ 0 ].rr_type !=
                            DNSR_TYPE_CNAME))) {
        /* check remote host's mx entry for our local hostname and
         * low_pref_mx_domain if configured.
         * If we find one, we never punt mail destined for this host,
         * and we only try remote delivery to mx entries that have a
         * lower mx_preference than for what was matched.
         */
        syslog(LOG_INFO, "DNS %s: %d MX record entries", hq->hq_hostname,
                d->d_dnsr_result->r_ancount);

        for (i = 0; i < d->d_dnsr_result->r_ancount; i++) {
            /* If one or more MX RRs are found for a given name, SMTP
             * systems MUST NOT utilize any address RRs associated with
             * that name unless they are located using the MX RRs;
             */
            if (d->d_dnsr_result->r_answer[ i ].rr_type != DNSR_TYPE_MX) {
                continue;
            }

            /* Cut off processing and disable punting if we are listed as an MX */
            if (strcasecmp(d->d_dnsr_result->r_answer[ i ].rr_mx.mx_exchange,
                        simta_hostname) == 0) {
                simta_ucl_toggle(hq->hq_red, "deliver.punt", "enabled", false);
                syslog(LOG_ERR,
                        "DNS %s: Entry %d: MX record lists "
                        "localhost at precedence %d, Punting disabled",
                        hq->hq_hostname, i,
                        d->d_dnsr_result->r_answer[ i ].rr_mx.mx_preference);
                return SIMTA_OK;
            }

            /* Cut off processing if we are listed under a secondary name */
            red = red_host_lookup(
                    d->d_dnsr_result->r_answer[ i ].rr_mx.mx_exchange, false);
            if (red && ucl_object_toboolean(ucl_object_lookup_path(
                               red, "deliver.secondary_mx"))) {
                simta_ucl_toggle(hq->hq_red, "deliver.punt", "enabled", false);
                syslog(LOG_ERR,
                        "DNS %s: Entry %d: MX Record lists "
                        "secondary MX %s at precedence %d, "
                        "Punting disabled",
                        hq->hq_hostname, i,
                        d->d_dnsr_result->r_answer[ i ].rr_mx.mx_exchange,
                        d->d_dnsr_result->r_answer[ i ].rr_mx.mx_preference);
                return SIMTA_OK;
            }
            ucl_array_append(d->d_mx_list,
                    simta_ucl_object_fromstring(
                            d->d_dnsr_result->r_answer[ i ].rr_mx.mx_exchange));
        }
    }
    return SIMTA_OK;
}

simta_dns_result
next_dnsr_host(struct deliver *d, struct host_q *hq) {
    struct dnsr_rr *         rr;
    struct sockaddr_in *     sin;
    struct sockaddr_in6 *    sin6;
    struct sockaddr_storage *addr;
    int                      cur_dnsr_result;
    ucl_object_iter_t        iter;
    const ucl_object_t *     obj;
    ucl_object_t *           ref;

    if (d->d_mx_list == NULL) {
        d->d_mx_list = ucl_object_typed_new(UCL_ARRAY);

        if (get_outbound_dns(d, hq) != SIMTA_OK) {
            return SIMTA_DNS_EOF;
        }

        if (d->d_dnsr_result) {
            dnsr_free_result(d->d_dnsr_result);
            d->d_dnsr_result = NULL;
        }

        /* Fall back to the implicit MX */
        if (ucl_array_size(d->d_mx_list) == 0) {
            ucl_array_append(
                    d->d_mx_list, simta_ucl_object_fromyastr(hq->hq_hostname));
            d->d_mx_cname_ok = true;
        }
        d->d_mx_current = ucl_array_pop_first(d->d_mx_list);
        d->d_mx_check_ipv6 = ucl_object_toboolean(
                ucl_object_lookup_path(hq->hq_red, "deliver.connection.ipv6"));
        d->d_mx_check_ipv4 = ucl_object_toboolean(
                ucl_object_lookup_path(hq->hq_red, "deliver.connection.ipv4"));
    }

    /* This is an independent block so that it applies to both initial
     * attempts and retried IPs.
     */
    if (d->d_retry_current) {
        if (!d->d_queue_movement) {
            /* No transaction progress was made, mark the IP as down */
            simta_ucl_toggle(d->d_retry_current, NULL, "up", false);
        }
        ucl_object_unref(d->d_retry_current);
        d->d_retry_current = NULL;
    }

    if (d->d_mx_current == NULL) {
        if (d->d_retry_list == NULL) {
            if (hq->hq_status == SIMTA_HOST_DOWN) {
                /* If MX records are present, but none of them are usable,
                 * or the implicit MX is unusable, this situation MUST be
                 * reported as an error.
                 */
                syslog(LOG_INFO,
                        "DNS %s: address record missing, bouncing mail",
                        hq->hq_hostname);
                if (hq->hq_err_text == NULL) {
                    if ((hq->hq_err_text = line_file_create()) == NULL) {
                        syslog(LOG_ERR,
                                "Syserror: get_outbound_dns line_file_create: "
                                "%m");
                        return SIMTA_DNS_EOF;
                    }
                }
                if (line_append(hq->hq_err_text, "Host does not exist", COPY) ==
                        NULL) {
                    syslog(LOG_ERR,
                            "Syserror: get_outbound_dns line_append: %m");
                    return SIMTA_DNS_EOF;
                }
                hq->hq_status = SIMTA_HOST_BOUNCE;
                d->d_env->e_flags |= ENV_FLAG_BOUNCE;
            }
            return SIMTA_DNS_EOF;
        }

        iter = ucl_object_iterate_new(d->d_retry_list);
        while ((obj = ucl_object_iterate_safe(iter, true)) != NULL) {
            if (ucl_object_toboolean(ucl_object_lookup(obj, "up")) &&
                    (strcmp(d->d_env->e_id,
                             ucl_object_tostring(ucl_object_lookup(
                                     obj, "last_envelope"))) != 0)) {
                ref = ucl_object_ref(obj);
                ucl_object_replace_key(ref,
                        simta_ucl_object_fromyastr(d->d_env->e_id),
                        "last_envelope", 0, false);
                d->d_retry_current = ref;
                /* FIXME: can we do less juggling here? */
                strncpy(d->d_ip,
                        ucl_object_tostring(ucl_object_lookup(obj, "ip")),
                        sizeof(d->d_ip));
                memcpy(&(d->d_sa), ucl_object_lookup(obj, "address")->value.ud,
                        sizeof(struct sockaddr_storage));
                simta_debuglog(1, "DNS %s: Retrying address: %s",
                        hq->hq_hostname, d->d_ip);
                return SIMTA_DNS_OK;
            }
        }
        ucl_object_iterate_free(iter);

        return SIMTA_DNS_EOF;
    }

    if (d->d_dnsr_result == NULL) {
        d->d_cur_dnsr_result = 0;
        if (d->d_mx_check_ipv4 || d->d_mx_check_ipv6) {
            if (d->d_mx_check_ipv6) {
                d->d_cur_mx_lookup_type = "AAAA";
                d->d_dnsr_result =
                        get_aaaa(ucl_object_tostring(d->d_mx_current));
                d->d_mx_check_ipv6 = false;
            } else {
                d->d_cur_mx_lookup_type = "A";
                d->d_dnsr_result = get_a(ucl_object_tostring(d->d_mx_current));
                d->d_mx_check_ipv4 = false;
            }

            if (d->d_dnsr_result) {
                if (d->d_dnsr_result->r_ancount == 0) {
                    dnsr_free_result(d->d_dnsr_result);
                    d->d_dnsr_result = NULL;
                } else if (!d->d_mx_cname_ok &&
                           dnsr_result_is_cname(d->d_dnsr_result)) {
                    syslog(LOG_INFO,
                            "DNS %s: Entry %d: suppressing CNAME record %s",
                            hq->hq_hostname, d->d_cur_mx_lookup,
                            ucl_object_tostring(d->d_mx_current));
                    dnsr_free_result(d->d_dnsr_result);
                    d->d_dnsr_result = NULL;
                    d->d_mx_check_ipv6 = false;
                    d->d_mx_check_ipv4 = false;
                }
            }

            if (d->d_dnsr_result == NULL) {
                simta_debuglog(1, "DNS %s: Entry %d: no %s record: %s",
                        hq->hq_hostname, d->d_cur_mx_lookup,
                        d->d_cur_mx_lookup_type,
                        ucl_object_tostring(d->d_mx_current));
                return SIMTA_DNS_AGAIN;
            }
        } else {
            d->d_cur_mx_lookup++;
            ucl_object_unref(d->d_mx_current);
            d->d_mx_current = ucl_array_pop_first(d->d_mx_list);
            d->d_mx_check_ipv6 = ucl_object_toboolean(ucl_object_lookup_path(
                    hq->hq_red, "deliver.connection.ipv6"));
            d->d_mx_check_ipv4 = ucl_object_toboolean(ucl_object_lookup_path(
                    hq->hq_red, "deliver.connection.ipv4"));
            return SIMTA_DNS_AGAIN;
        }
    }

    if (d->d_dnsr_result == NULL) {
        return SIMTA_DNS_AGAIN;
    }

    if (d->d_cur_dnsr_result >= d->d_dnsr_result->r_ancount) {
        dnsr_free_result(d->d_dnsr_result);
        d->d_dnsr_result = NULL;
        return SIMTA_DNS_AGAIN;
    }

    cur_dnsr_result = d->d_cur_dnsr_result;
    d->d_cur_dnsr_result++;
    rr = d->d_dnsr_result->r_answer + cur_dnsr_result;

    if (rr->rr_type == DNSR_TYPE_AAAA) {
        sin6 = (struct sockaddr_in6 *)&(d->d_sa);
        sin6->sin6_family = AF_INET6;
        memcpy(&(sin6->sin6_addr), &(rr->rr_aaaa.aaaa_address),
                sizeof(struct in6_addr));
    } else if (rr->rr_type == DNSR_TYPE_A) {
        sin = (struct sockaddr_in *)&(d->d_sa);
        sin->sin_family = AF_INET;
        memcpy(&(sin->sin_addr), &(rr->rr_a.a_address), sizeof(struct in_addr));
    } else {
        simta_debuglog(1,
                "DNS %s: Entry %d.%s.%d: "
                "uninteresting dnsr rr type %s: %d",
                hq->hq_hostname, d->d_cur_mx_lookup, d->d_cur_mx_lookup_type,
                cur_dnsr_result, rr->rr_name, rr->rr_type);
        return SIMTA_DNS_AGAIN;
    }

    if (deliver_checksockaddr(d, hq) == SIMTA_OK) {
        if (d->d_retry_list == NULL) {
            d->d_retry_list = ucl_object_typed_new(UCL_ARRAY);
        }
        iter = ucl_object_iterate_new(d->d_retry_list);
        while ((obj = ucl_object_iterate_safe(iter, true)) != NULL) {
            if (strcmp(d->d_ip, ucl_object_tostring(
                                        ucl_object_lookup(obj, "ip"))) == 0) {
                simta_debuglog(1,
                        "DNS %s: Entry %d.%s.%d: suppressing previously seen "
                        "IP: %s",
                        hq->hq_hostname, d->d_cur_mx_lookup,
                        d->d_cur_mx_lookup_type, cur_dnsr_result, d->d_ip);
                ucl_object_iterate_free(iter);
                return SIMTA_DNS_AGAIN;
            }
        }
        ucl_object_iterate_free(iter);

        ref = ucl_object_typed_new(UCL_OBJECT);
        ucl_object_insert_key(
                ref, simta_ucl_object_fromstring(d->d_ip), "ip", 0, false);
        addr = simta_malloc(sizeof(struct sockaddr_storage));
        memcpy(addr, &(d->d_sa), sizeof(struct sockaddr_storage));
        ucl_object_insert_key(ref, ucl_object_new_userdata(NULL, NULL, addr),
                "address", 0, false);
        ucl_object_insert_key(ref, simta_ucl_object_fromyastr(d->d_env->e_id),
                "last_envelope", 0, false);
        ucl_object_insert_key(ref, ucl_object_frombool(true), "up", 0, false);
        ucl_array_append(d->d_retry_list, ref);
        d->d_retry_current = ucl_object_ref(ref);

        syslog(LOG_INFO, "DNS %s: Entry %d.%s.%d: Trying address record: %s",
                hq->hq_hostname, d->d_cur_mx_lookup, d->d_cur_mx_lookup_type,
                cur_dnsr_result, d->d_ip);
        return SIMTA_DNS_OK;
    }

    return SIMTA_DNS_AGAIN;
}


static void
free_dns_results(struct deliver *d) {
    if (d->d_dnsr_result) {
        dnsr_free_result(d->d_dnsr_result);
        d->d_dnsr_result = NULL;
    }
    if (d->d_mx_list) {
        ucl_object_unref(d->d_mx_list);
        d->d_mx_list = NULL;
    }
    if (d->d_mx_current) {
        ucl_object_unref(d->d_mx_current);
        d->d_mx_current = NULL;
    }
    if (d->d_retry_list) {
        ucl_object_unref(d->d_retry_list);
        d->d_retry_list = NULL;
    }
    if (d->d_retry_current) {
        ucl_object_unref(d->d_retry_current);
        d->d_retry_current = NULL;
    }
}


static simta_result
deliver_checksockaddr(struct deliver *d, struct host_q *hq) {
    int rc;
    int port;

    if ((rc = getnameinfo((struct sockaddr *)&(d->d_sa),
                 ((d->d_sa.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                  : sizeof(struct sockaddr_in)),
                 d->d_ip, sizeof(d->d_ip), NULL, 0, NI_NUMERICHOST)) != 0) {
        syslog(LOG_ERR, "Syserror: deliver_checksockaddr getnameinfo: %s",
                gai_strerror(rc));
        return SIMTA_ERR;
    }

    /* Reject non-routable meta addresses and link-local addresses */
    if (((d->d_sa.ss_family == AF_INET) &&
                ((strcmp(d->d_ip, "0.0.0.0") == 0) ||
                        (strncmp(d->d_ip, "169.254.", 8) == 0))) ||
            ((d->d_sa.ss_family == AF_INET6) &&
                    ((strncmp(d->d_ip, "fe80:", 5) == 0)))) {
        syslog(LOG_INFO, "DNS %s: suppressing bad address: %s", hq->hq_hostname,
                d->d_ip);
        return SIMTA_ERR;
    }

    /* Set the port */
    port = ucl_object_toint(
            ucl_object_lookup_path(hq->hq_red, "deliver.connection.port"));
    if (d->d_sa.ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)&(d->d_sa))->sin6_port = htons(port);
    } else {
        ((struct sockaddr_in *)&(d->d_sa))->sin_port = htons(port);
    }

    return SIMTA_OK;
}

void
queue_log_metrics(struct host_q *hq_schedule) {
    yastr          linkname = NULL;
    yastr          filename = NULL;
    int            fd;
    FILE *         f;
    struct host_q *hq;
    struct timeval tv_now;
    struct stat    st_file;

    if (simta_gettimeofday(&tv_now) != 0) {
        return;
    }

    linkname = yaslcat(
            yaslauto(simta_config_str("core.base_dir")), "/etc/queue_schedule");
    filename = yaslcatprintf(
            yasldup(linkname), "%lX", (unsigned long)tv_now.tv_sec);

    if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0664)) < 0) {
        syslog(LOG_ERR, "Syserror: queue_log_metrics open: %m");
        goto error;
    }

    if ((f = fdopen(fd, "w")) == NULL) {
        syslog(LOG_ERR, "Syserror: queue_log_metrics fdopen: %m");
        close(fd);
        goto error;
    }

    fprintf(f, "Disk Read:\t%d\n\n", simta_disk_cycle);

    if (simta_unexpanded_q != NULL) {
        fprintf(f, "Unexpanded Messages:\t%d\n\n",
                simta_unexpanded_q->hq_entries);
    }

    fprintf(f, "Next\tMessages\tQueue\n");

    for (hq = hq_schedule; hq != NULL; hq = hq->hq_deliver_next) {
        fprintf(f, "%d\t%d\t%s\n",
                (int)(hq->hq_next_launch.tv_sec - tv_now.tv_sec),
                hq->hq_entries, hq->hq_hostname);
    }

    fclose(f);

    if ((stat(linkname, &st_file) == 0) && (unlink(linkname) != 0)) {
        syslog(LOG_ERR, "Syserror: queue_log_metrics unlink: %m");
    } else if (link(filename, linkname) != 0) {
        syslog(LOG_ERR, "Syserror: queue_log_metrics link: %m");
    }

error:
    yaslfree(linkname);
    yaslfree(filename);

    return;
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
