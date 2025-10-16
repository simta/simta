/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <utime.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "envelope.h"
#include "line_file.h"
#include "queue.h"
#include "red.h"
#include "simta_malloc.h"

#ifdef HAVE_LDAP
#include "dn.h"
#include "simta_ldap.h"
#endif /* HAVE_LDAP */

void cleanup_envelope_list(struct envelope **);

int simta_expand_debug = 0;


struct envelope *
eo_lookup(struct expand_output *eo_list, char *hostname, char *from) {
    struct expand_output *e;

    for (e = eo_list; e != NULL; e = e->eo_next) {
        if (strcasecmp(e->eo_hostname, hostname) != 0) {
            continue;
        }

        if (strcasecmp(e->eo_from, from) == 0) {
            return (e->eo_env);
        }
    }

    return (NULL);
}


int
eo_insert(struct expand_output **eo_list, struct envelope *env) {
    struct expand_output *e_new;

    e_new = simta_malloc(sizeof(struct expand_output));

    if ((e_new->eo_hostname = env->e_hostname) == NULL) {
        e_new->eo_hostname = "";
    }

    e_new->eo_from = env->e_mail;
    e_new->eo_env = env;
    e_new->eo_next = *eo_list;
    *eo_list = e_new;

    return (0);
}

void
cleanup_envelope_list(struct envelope **env_p) {
    struct envelope *env;
    while (*env_p != NULL) {
        env = *env_p;
        env_p = &(env->e_next);

        /* unlink if written to disk */
        if ((env->e_flags & ENV_FLAG_EFILE) != 0) {
            queue_remove_envelope(env);
            if (env_unlink(env) == 0) {
                syslog(LOG_INFO,
                        "Expand env <%s>: Message Deleted: "
                        "System error, unwinding expansion",
                        env->e_id);
            } else {
                syslog(LOG_ERR,
                        "Expand env <%s>: "
                        "System error, can't unwind expansion",
                        env->e_id);
            }
        }

        env_free(env);
    }
}


/* return 0 on success
     * return 1 on syserror
     * return -1 on fata errors (leaving fast files behind in error)
     * syslog errors
     */

int
expand(struct envelope *unexpanded_env) {
    struct expand         exp;
    struct envelope      *base_error_env;
    struct envelope      *env_dead = NULL;
    struct envelope      *env = NULL;
    struct envelope     **env_p;
    struct recipient     *rcpt;
    struct expand_output *host_stab = NULL;
    struct expand_output *eo;
    struct expand_output *eo_free;
    struct exp_addr      *e_addr;
    struct exp_addr      *next_e_addr;
    const ucl_object_t   *hq_red;
    char                 *domain = NULL;
    SNET                 *snet = NULL;
    int                   n_rcpts;
    int                   return_value = 1;
    int                   env_out = 0;
    int                   fast_file_start;
    int                   sendermatch;
    char                  e_original[ MAXPATHLEN ];
    char                  d_original[ MAXPATHLEN ];
    char                  d_out[ MAXPATHLEN ];
    /* RFC 5321 4.5.3.1.3.  Path
     * The maximum total length of a reverse-path or forward-path is 256
     * octets (including the punctuation and element separators).
     */
    char header[ 270 ];
#ifdef HAVE_LDAP
    yastr            buf = NULL;
    char            *p;
    int              loop_color = 1;
    struct exp_link *parent;
#endif /* HAVE_LDAP */

    if (unexpanded_env->e_hostname != NULL) {
        syslog(LOG_INFO, "Expand env <%s>: already expanded for host %s",
                unexpanded_env->e_id, unexpanded_env->e_hostname);
        return_value = 0;
        goto done;
    }

    memset(&exp, 0, sizeof(struct expand));
    exp.exp_env = unexpanded_env;
    fast_file_start = fast_q_total();

    /* call address_expand on each address in the expansion list.
     *
     * if an address is expandable, the address(es) that it expands to will
     * be added to the expansion list. These non-terminal addresses must
     * have their st_data set to NULL to specify that they are not to be
     * included in the terminal expansion list.
     *
     * Any address in the expansion list whose st_data is not NULL is
     * considered a terminal address and will be written out as one
     * of the addresses in expanded envelope(s).
     */

    if ((base_error_env = address_bounce_create(&exp)) == NULL) {
        syslog(LOG_ERR, "Expand env <%s>: address_bounce_create: %m",
                unexpanded_env->e_id);
        goto done;
    }

    if (env_recipient(base_error_env, unexpanded_env->e_mail) != 0) {
        syslog(LOG_ERR, "Expand env <%s>: env_recipient: %m",
                unexpanded_env->e_id);
        goto done;
    }

    /* add all of the original recipients to the expansion list */
    for (rcpt = unexpanded_env->e_rcpt; rcpt != NULL; rcpt = rcpt->r_next) {
        if (add_address(&exp, rcpt->r_rcpt, base_error_env, ADDRESS_TYPE_EMAIL,
                    exp.exp_env->e_mail, false) != SIMTA_OK) {
            /* add_address syslogs errors */
            goto cleanup1;
        }
    }

    /* process the expansion list */
    for (exp.exp_addr_cursor = exp.exp_addr_head; exp.exp_addr_cursor != NULL;
            exp.exp_addr_cursor = exp.exp_addr_cursor->e_addr_next) {
        switch (address_expand(&exp)) {
        case ADDRESS_EXCLUDE:
            exp.exp_addr_cursor->e_addr_terminal = false;
            /* the address is not a terminal local address */
            break;

        case ADDRESS_OK:
            exp.exp_addr_cursor->e_addr_terminal = true;
            break;

        case ADDRESS_SYSERROR:
            goto cleanup1;

        default:
            panic("Expand: address_expand out of range");
        }
    }

#ifdef HAVE_LDAP
    for (e_addr = exp.exp_addr_head; e_addr != NULL;
            e_addr = e_addr->e_addr_next) {
        if (!e_addr->e_addr_requires_permission) {
            continue;
        }

        if (!e_addr->e_addr_has_permission) {
            /* Check permissions that require full expansion information. */
            if ((p = exp_addr_parent_permitted(e_addr)) != NULL) {
                e_addr->e_addr_has_permission = true;
                simta_debuglog(1,
                        "Expand env <%s>: group %s OK: parent %s permitted",
                        unexpanded_env->e_id, e_addr->e_addr, p);
            } else if (e_addr->e_addr_permit_members &&
                       sender_is_child(e_addr->e_addr_children, loop_color++)) {
                e_addr->e_addr_has_permission = true;
                simta_debuglog(1,
                        "Expand env <%s>: members-only group %s OK: "
                        "sender is child",
                        unexpanded_env->e_id, e_addr->e_addr);
            }
        }

        if (e_addr->e_addr_has_permission) {
            if (e_addr->e_addr_env_moderators != NULL) {
                env_free(e_addr->e_addr_env_moderators);
                e_addr->e_addr_env_moderators = NULL;
            }

        } else {
            syslog(LOG_INFO, "Expand env <%s>: unpermitted group %s suppressed",
                    unexpanded_env->e_id, e_addr->e_addr);
            e_addr->e_addr_ldap_flags |= STATUS_LDAP_SUPPRESSOR;
            suppress_addrs(e_addr->e_addr_children, loop_color++);
        }
    }
#endif /* HAVE_LDAP */

    sprintf(d_original, "%s/D%s", unexpanded_env->e_dir, unexpanded_env->e_id);

    /* Create one expanded envelope for every host we expanded address for */
    for (e_addr = exp.exp_addr_head; e_addr != NULL;
            e_addr = e_addr->e_addr_next) {

#ifdef HAVE_LDAP
        if (((e_addr->e_addr_ldap_flags & STATUS_LDAP_SUPPRESSED) != 0) &&
                (!unblocked_path_to_root(e_addr, loop_color++))) {
            if (simta_expand_debug != 0) {
                printf("Suppressed: %s\n", e_addr->e_addr);
            }
            continue;
        }

        if (e_addr->e_addr_requires_permission &&
                !e_addr->e_addr_has_permission &&
                e_addr->e_addr_env_moderators != NULL) {
            if (simta_expand_debug != 0) {
                printf("Moderated: %s\n", e_addr->e_addr);
                env_stdout(e_addr->e_addr_env_moderators);
                continue;
            }

            sprintf(d_out, "%s/D%s", e_addr->e_addr_env_moderators->e_dir,
                    e_addr->e_addr_env_moderators->e_id);

            /* Format the prefatory material */
            for (p = e_addr->e_addr_preface; *p != '\0'; p++) {
                if (*p == '$') {
                    switch (*(p + 1)) {
                    case 'n':
                        buf = simta_url_escape(e_addr->e_addr_group_name);
                        break;
                    case 'N':
                        buf = yasldup(e_addr->e_addr_group_name);
                        break;
                    case 'O':
                        buf = yasldup(e_addr->e_addr_owner);
                        break;
                    case 'S':
                        buf = yasldup(
                                e_addr->e_addr_env_moderators->e_mail_orig);
                        break;
                    case '$':
                        buf = yaslauto("$");
                        break;
                    default:
                        continue;
                    }
                    buf = yaslcat(buf, p + 2);
                    yaslrange(e_addr->e_addr_preface, 0,
                            p - e_addr->e_addr_preface - 1);
                    e_addr->e_addr_preface =
                            yaslcatyasl(e_addr->e_addr_preface, buf);
                    /* Reset the pointer */
                    p = e_addr->e_addr_preface +
                        yasllen(e_addr->e_addr_preface) - yasllen(buf);
                    yaslfree(buf);
                    buf = NULL;
                }
            }

            if (env_dfile_wrap(e_addr->e_addr_env_moderators, d_original,
                        e_addr->e_addr_preface) == 0) {
                syslog(LOG_ERR, "Expand env <%s>: %s: env_dfile_wrap failed",
                        unexpanded_env->e_id,
                        e_addr->e_addr_env_moderators->e_id);
                goto cleanup3;
            }

            simta_debuglog(2, "Expand env <%s>: %s: moderation env dinode %d",
                    unexpanded_env->e_id, e_addr->e_addr_env_moderators->e_id,
                    (int)e_addr->e_addr_env_moderators->e_dinode);

            n_rcpts = 0;
            for (rcpt = e_addr->e_addr_env_moderators->e_rcpt; rcpt != NULL;
                    rcpt = rcpt->r_next) {
                n_rcpts++;
                syslog(LOG_INFO, "Expand env <%s>: %s: To <%s> From <%s> (%s)",
                        unexpanded_env->e_id,
                        e_addr->e_addr_env_moderators->e_id, rcpt->r_rcpt,
                        e_addr->e_addr_env_moderators->e_mail,
                        unexpanded_env->e_mail);
            }
            syslog(LOG_INFO, "Expand env <%s>: %s: Expanded %d moderators",
                    unexpanded_env->e_id, e_addr->e_addr_env_moderators->e_id,
                    n_rcpts);

            if (env_outfile(e_addr->e_addr_env_moderators) != SIMTA_OK) {
                /* env_outfile syslogs errors */
                if (unlink(d_out) != 0) {
                    syslog(LOG_ERR, "expand unlink %s: %m", d_out);
                }
                goto cleanup3;
            }
            env_out++;
            queue_envelope(e_addr->e_addr_env_moderators);
            continue;

        } else if (e_addr->e_addr_ldap_flags & STATUS_LDAP_SUPPRESSOR) {
            for (parent = e_addr->e_addr_parents; parent != NULL;
                    parent = parent->el_next) {
                if (parent->el_exp_addr == NULL) {
                    if (bounce_text(base_error_env, TEXT_ERROR,
                                "Group permission conditions not met: ",
                                e_addr->e_addr, NULL) != 0) {
                        goto cleanup3;
                    }

                    if (bounce_text(base_error_env, TEXT_ERROR,
                                "If you have any questions, please contact the "
                                "group owner: ",
                                e_addr->e_addr_owner, NULL) != 0) {
                        goto cleanup3;
                    }

                } else if (!e_addr->e_addr_private) {
                    if (bounce_text(parent->el_exp_addr->e_addr_errors,
                                TEXT_ERROR,
                                "Group permission conditions not met: ",
                                e_addr->e_addr, NULL) != 0) {
                        goto cleanup3;
                    }

                    if (bounce_text(parent->el_exp_addr->e_addr_errors,
                                TEXT_ERROR,
                                "If you have any questions, please contact the "
                                "group owner: ",
                                e_addr->e_addr_owner, NULL) != 0) {
                        goto cleanup3;
                    }
                }
            }

            continue;
        }
#endif /* HAVE_LDAP */

        if (!e_addr->e_addr_terminal) {
            if (simta_expand_debug != 0) {
                printf("Non-terminal: %s\n", e_addr->e_addr);
            }
            /* not a terminal expansion, do not add */
            continue;
        }

        if (simta_expand_debug != 0) {
            printf("Terminal: %s\n", e_addr->e_addr);
        }

        switch (e_addr->e_addr_type) {
        case ADDRESS_TYPE_EMAIL:
            if ((domain = strchr(e_addr->e_addr, '@')) == NULL) {
                syslog(LOG_ERR, "Expand env <%s>: strchr blivet",
                        unexpanded_env->e_id);
                goto cleanup3;
            }
            domain++;
            env = eo_lookup(host_stab, domain, e_addr->e_addr_from);
            break;

        case ADDRESS_TYPE_DEAD:
            domain = NULL;
            env = env_dead;
            break;

        default:
            panic("expand: address type out of range");
        }

        if (env == NULL) {
            /* Create envelope and add it to list */
            if ((env = env_create(domain ? simta_dir_fast : simta_dir_dead,
                         NULL, e_addr->e_addr_from, unexpanded_env)) == NULL) {
                syslog(LOG_ERR, "Expand env <%s>: env_create: %m",
                        unexpanded_env->e_id);
                goto cleanup3;
            }

            simta_debuglog(2, "Expand env <%s>: %s: expansion env dinode %d",
                    unexpanded_env->e_id, env->e_id, (int)env->e_dinode);

            /* fill in env */
            if (domain != NULL) {
                env_hostname(env, domain);
            } else {
                env_dead = env;
            }

            /* Add env to host_stab */
            if (eo_insert(&host_stab, env) != 0) {
                syslog(LOG_ERR, "Expand env <%s>: eo_insert %s failed: %m",
                        unexpanded_env->e_id, env->e_id);
                env_free(env);
                goto cleanup3;
            }
        }

        if (env_recipient(env, e_addr->e_addr) != 0) {
            goto cleanup3;
        }

        syslog(LOG_NOTICE,
                "Expand env <%s>: %s: recipient <%s> added to env for host %s",
                unexpanded_env->e_id, env->e_id, e_addr->e_addr,
                env->e_hostname ? env->e_hostname : "NULL");
    }

    /* Write out all expanded envelopes and place them in to the host_q */
    for (eo = host_stab; eo != NULL; eo = eo->eo_next) {
        env = eo->eo_env;

        if (simta_expand_debug == 0) {
            sprintf(d_out, "%s/D%s", env->e_dir, env->e_id);

            /* RFC 5321 4.4 Trace Information
             * When the delivery SMTP server makes the "final delivery" of a
             * message, it inserts a return-path line at the beginning of the
             * mail data.  This use of return-path is required; mail systems
             * MUST support it.  The return-path line preserves the
             * information in the <reverse-path> from the MAIL command.
             * Here, final delivery means the message has left the SMTP
             * environment.
             */
            if (((hq_red = red_host_lookup(eo->eo_hostname, false)) != NULL) &&
                    (ucl_object_toboolean(ucl_object_lookup_path(
                            hq_red, "deliver.local.enabled")))) {
                if (snprintf(header, 270, "Return-Path: <%s>", env->e_mail) >=
                        270) {
                    syslog(LOG_ERR,
                            "Expand env <%s>: %s: return path is too large",
                            unexpanded_env->e_id, env->e_id);
                }
                if (env_dfile_copy(env, d_original, header) == 0) {
                    syslog(LOG_ERR,
                            "Expand env <%s>: %s: env_dfile_copy failed",
                            unexpanded_env->e_id, env->e_id);
                    goto cleanup4;
                }
            } else {
                /* Dfile: link Dold_id env->e_dir/Dnew_id */
                if (link(d_original, d_out) != 0) {
                    syslog(LOG_ERR, "Syserror: expand link %s %s: %m",
                            d_original, d_out);
                    goto cleanup4;
                }
            }

            sendermatch = !strcasecmp(unexpanded_env->e_mail, env->e_mail);

            n_rcpts = 0;
            for (rcpt = env->e_rcpt; rcpt != NULL; rcpt = rcpt->r_next) {
                n_rcpts++;
                if (sendermatch) {
                    syslog(LOG_INFO, "Expand env <%s>: %s: To <%s> From <%s>",
                            unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
                            env->e_mail);
                } else {
                    syslog(LOG_INFO,
                            "Expand env <%s>: %s: To <%s> From <%s> (%s)",
                            unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
                            env->e_mail, unexpanded_env->e_mail);
                }
            }

            syslog(LOG_INFO, "Expand env <%s>: %s: Expanded %d recipients",
                    unexpanded_env->e_id, env->e_id, n_rcpts);

            /* Efile: write env->e_dir/Enew_id for all recipients at host */
            syslog(LOG_NOTICE, "Expand env <%s>: %s: writing Efile for %s",
                    unexpanded_env->e_id, env->e_id,
                    env->e_hostname ? env->e_hostname : "NULL");
            if (env_outfile(env) != SIMTA_OK) {
                /* env_outfile syslogs errors */
                if (unlink(d_out) != 0) {
                    syslog(LOG_ERR, "Syserror: expand unlink %s: %m", d_out);
                }
                goto cleanup4;
            }

            env_out++;
            queue_envelope(env);

        } else {
            printf("\n");
            env_stdout(env);
        }
    }

    if (env_out == 0) {
        syslog(LOG_NOTICE,
                "Expand env <%s>: no terminal recipients, "
                "deleting message",
                unexpanded_env->e_id);
    }

    /* write errors out to disk */
    env_p = &(exp.exp_errors);
    while ((env = *env_p) != NULL) {
        if (simta_expand_debug == 0) {
            if (env->e_error != 0) {
                env_p = &(env->e_next);

                if (snet == NULL) {
                    if ((snet = snet_open(d_original, O_RDONLY, 0)) == NULL) {
                        syslog(LOG_ERR, "Liberror: expand snet_open %s: %m",
                                d_original);
                        goto cleanup5;
                    }
                } else {
                    if (lseek(snet_fd(snet), (off_t)0, SEEK_SET) != 0) {
                        syslog(LOG_ERR, "Syserror: q_deliver lseek: %m");
                        panic("q_deliver lseek fail");
                    }
                }

                /* write out error text, get Dfile inode */
                if (bounce_dfile_out(env, snet) == 0) {
                    if (snet != NULL) {
                        if (snet_close(snet) != 0) {
                            syslog(LOG_ERR,
                                    "Liberror: expand snet_close %s: %m",
                                    d_original);
                        }
                    }

                    goto cleanup5;
                }

                simta_debuglog(2, "Expand env <%s>: %s: errors env dinode %d",
                        unexpanded_env->e_id, env->e_id, (int)env->e_dinode);

                line_file_free(env->e_err_text);
                env->e_err_text = NULL;
                env->e_error = 0;

                if (env_outfile(env) != SIMTA_OK) {
                    /* env_outfile syslogs errors */
                    sprintf(d_out, "%s/D%s", env->e_dir, env->e_id);
                    if (unlink(d_out) != 0) {
                        syslog(LOG_ERR, "Syserror: expand unlink %s: %m",
                                d_out);
                    }
                    goto cleanup5;
                }

                sendermatch = !strcasecmp(unexpanded_env->e_mail, env->e_mail);

                n_rcpts = 0;
                for (rcpt = env->e_rcpt; rcpt != NULL; rcpt = rcpt->r_next) {
                    n_rcpts++;
                    if (sendermatch) {
                        syslog(LOG_INFO,
                                "Expand env <%s>: %s: To <%s> From <%s>",
                                unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
                                env->e_mail);
                    } else {
                        syslog(LOG_INFO,
                                "Expand env <%s>: %s: To <%s> From <%s> (%s)",
                                unexpanded_env->e_id, env->e_id, rcpt->r_rcpt,
                                env->e_mail, unexpanded_env->e_mail);
                    }
                }

                syslog(LOG_NOTICE, "Expand env <%s>: %s: Expanded %d bounces",
                        unexpanded_env->e_id, env->e_id, n_rcpts);

                queue_envelope(env);

            } else {
                *env_p = env->e_next;
                env_free(env);
            }

        } else {
            *env_p = env->e_next;
            bounce_stdout(env);
            env_free(env);
        }
    }

    if (snet != NULL) {
        if (snet_close(snet) != 0) {
            syslog(LOG_ERR, "Liberror: expand snet_close %s: %m", d_original);
            if (env) {
                sprintf(d_out, "%s/D%s", env->e_dir, env->e_id);
                if (unlink(d_out) != 0) {
                    syslog(LOG_ERR, "Syserror: expand unlink %s: %m", d_out);
                }
            }
            goto cleanup5;
        }
        snet = NULL;
    }

    syslog(LOG_INFO, "Expand env <%s>: Metric %d entries %d levels",
            unexpanded_env->e_id, exp.exp_entries, exp.exp_max_level);

    if (simta_expand_debug != 0) {
        return_value = 0;
        goto cleanup2;
    }

    if (utime(d_original, NULL) != 0) {
        syslog(LOG_ERR, "Syserror: expand utime %s: %m", d_original);
        goto cleanup5;
    }

    if (unexpanded_env->e_dir != simta_dir_fast) {
        /* truncate orignal Efile */
        sprintf(e_original, "%s/E%s", unexpanded_env->e_dir,
                unexpanded_env->e_id);

        if (truncate(e_original, (off_t)0) != 0) {
            syslog(LOG_ERR, "Syserror: expand truncate %s: %m", e_original);
            goto cleanup5;
        }
    }

    /* delete original message */
    if (env_unlink(unexpanded_env) != 0) {
        syslog(LOG_ERR,
                "Expand env <%s>: Expansion complete, can't delete message",
                unexpanded_env->e_id);
    } else {
        syslog(LOG_INFO, "Expand env <%s>: Expansion complete, message deleted",
                unexpanded_env->e_id);
    }

    return_value = 0;
    goto cleanup2;

cleanup5:
    cleanup_envelope_list(&exp.exp_errors);

cleanup4:
    for (eo = host_stab; eo != NULL; eo = eo->eo_next) {
        env = eo->eo_env;
        eo->eo_env = NULL;

        if ((env->e_flags & ENV_FLAG_EFILE) != 0) {
            queue_remove_envelope(env);
            if (env_unlink(env) == 0) {
                syslog(LOG_WARNING,
                        "Expand env <%s>: Message Deleted: "
                        "System error, unwinding expansion",
                        env->e_id);
            } else {
                syslog(LOG_ERR,
                        "Expand env <%s>: "
                        "System error, can't unwind expansion",
                        env->e_id);
            }
        }

        env_free(env);
    }

cleanup3:
#ifdef HAVE_LDAP
    /* FIXME: this feels weirdly duplicative, but is probably necessary for the
     * fast file check.
     */
    for (e_addr = exp.exp_addr_head; e_addr != NULL;
            e_addr = e_addr->e_addr_next) {
        if ((e_addr->e_addr_env_moderators != NULL) &&
                ((e_addr->e_addr_env_moderators->e_flags & ENV_FLAG_EFILE) !=
                        0)) {
            env_unlink(e_addr->e_addr_env_moderators);
            env_free(e_addr->e_addr_env_moderators);
            e_addr->e_addr_env_moderators = NULL;
        }
    }
#endif /* HAVE_LDAP */

    if (fast_q_total() != fast_file_start) {
        syslog(LOG_ERR, "Expand env <%s>: could not unwind expansion",
                unexpanded_env->e_id);
        return_value = 1;
    }

cleanup2:
    /* free host_stab */
    eo = host_stab;
    while (eo != NULL) {
        eo_free = eo;
        eo = eo->eo_next;
        simta_free(eo_free);
    }

cleanup1:
    /* free the expansion list */
    for (e_addr = exp.exp_addr_head; e_addr != NULL; e_addr = next_e_addr) {
        next_e_addr = e_addr->e_addr_next;

#ifdef HAVE_LDAP
        exp_addr_link_free(e_addr->e_addr_parents);
        exp_addr_link_free(e_addr->e_addr_children);
        exp_addr_permitted_destroy(e_addr);
        if ((e_addr->e_addr_env_moderators != NULL) &&
                ((e_addr->e_addr_env_moderators->e_flags & ENV_FLAG_EFILE) ==
                        0)) {
            env_free(e_addr->e_addr_env_moderators);
        }

        yaslfree(e_addr->e_addr_owner);
        yaslfree(e_addr->e_addr_group_name);
        yaslfree(e_addr->e_addr_preface);

        if (e_addr->e_addr_dn) {
            simta_free(e_addr->e_addr_dn);
        }
#endif

        yaslfree(e_addr->e_addr_localpart);
        yaslfree(e_addr->e_addr_domain);
        simta_free(e_addr->e_addr);
        simta_free(e_addr->e_addr_from);
        simta_free(e_addr);
    }

done:
    if (return_value != 0) {
        syslog(LOG_ERR, "Expand env <%s>: Expansion failed",
                unexpanded_env->e_id);
    }

    return (return_value);
}


#ifdef HAVE_LDAP
void
suppress_addrs(struct exp_link *list, int color) {
    struct exp_link *el;

    for (el = list; el != NULL; el = el->el_next) {
        if (el->el_exp_addr->e_addr_anti_loop == color) {
            continue;
        }
        el->el_exp_addr->e_addr_anti_loop = color;

        if ((el->el_exp_addr->e_addr_ldap_flags & STATUS_LDAP_SUPPRESSED) !=
                0) {
            continue;
        }

        el->el_exp_addr->e_addr_ldap_flags |= STATUS_LDAP_SUPPRESSED;
        suppress_addrs(el->el_exp_addr->e_addr_children, color);
    }

    return;
}


bool
sender_is_child(struct exp_link *el, int color) {
    struct exp_addr *e;

    for (; el != NULL; el = el->el_next) {
        e = el->el_exp_addr;

        if (e->e_addr_anti_loop == color) {
            continue;
        }
        e->e_addr_anti_loop = color;

        if ((e->e_addr_ldap_flags & STATUS_EMAIL_SENDER) != 0) {
            return true;
        }

        if ((e->e_addr_ldap_flags & STATUS_NO_EMAIL_SENDER) != 0) {
            continue;
        }

        if (sender_is_child(e->e_addr_children, color)) {
            e->e_addr_ldap_flags |= STATUS_EMAIL_SENDER;
            return true;
        }

        e->e_addr_ldap_flags |= STATUS_NO_EMAIL_SENDER;
    }

    return false;
}


bool
unblocked_path_to_root(struct exp_addr *e, int color) {
    struct exp_link *el;

    if (e->e_addr_anti_loop == color) {
        return false;
    }
    e->e_addr_anti_loop = color;

    if (e->e_addr_requires_permission && !e->e_addr_has_permission) {
        return false;
    }

    if ((e->e_addr_ldap_flags & STATUS_NO_ROOT_PATH) != 0) {
        return false;
    }

    if ((e->e_addr_ldap_flags & STATUS_ROOT_PATH) != 0) {
        return true;
    }

    for (el = e->e_addr_parents; el != NULL; el = el->el_next) {
        if ((el->el_exp_addr == NULL) ||
                (unblocked_path_to_root(el->el_exp_addr, color))) {
            e->e_addr_ldap_flags |= STATUS_ROOT_PATH;
            return true;
        }
    }

    e->e_addr_ldap_flags |= STATUS_NO_ROOT_PATH;
    return false;
}


int
exp_addr_permitted_add(struct exp_addr *e_addr, yastr permitted) {
    if (ll_insert(&e_addr->e_addr_ok, permitted, permitted, NULL) != 0) {
        return (1);
    }

    return (0);
}


void
exp_addr_permitted_destroy(struct exp_addr *e_addr) {
    struct stab_entry *pstab;
    struct stab_entry *nstab;

    pstab = e_addr->e_addr_ok;
    while (pstab != NULL) {
        nstab = pstab;
        pstab = pstab->st_next;
        yaslfree(nstab->st_key);
        simta_free(nstab);
    }
    return;
}


char *
exp_addr_parent_permitted(struct exp_addr *memonly) {
    struct exp_link   *parent;
    struct stab_entry *ok;

    for (ok = memonly->e_addr_ok; ok != NULL; ok = ok->st_next) {
        for (parent = memonly->e_addr_parents; parent != NULL;
                parent = parent->el_next) {
            if (parent->el_exp_addr == NULL) {
                continue;
            }

            if ((strcmp(ok->st_key, parent->el_exp_addr->e_addr_dn) == 0)) {
                return (parent->el_exp_addr->e_addr_dn);
            }
        }
    }

    return (NULL);
}
#endif /* HAVE_LDAP */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
