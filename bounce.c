/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "envelope.h"
#include "header.h"
#include "queue.h"


int
bounce_text(struct envelope *bounce_env, int mode, const char *t1,
        const char *t2, const char *t3) {
    int   ret = 0;
    yastr buf;

    if (mode != 0) {
        bounce_env->e_error = mode;
    }

    if (bounce_env->e_err_text == NULL) {
        bounce_env->e_err_text = line_file_create();
    }

    buf = yaslauto(t1);
    if (t2) {
        buf = yaslcat(buf, t2);
    }
    if (t3) {
        buf = yaslcat(buf, t3);
    }

    if (mode != 0) {
        if (line_append(bounce_env->e_err_text, buf, COPY) == NULL) {
            ret = -1;
        }
    } else {
        if (line_prepend(bounce_env->e_err_text, buf, COPY) == NULL) {
            ret = -1;
        }
    }

    yaslfree(buf);

    return (ret);
}


void
bounce_stdout(struct envelope *bounce_env) {
    struct line *     l;
    struct recipient *r;

    if ((bounce_env->e_err_text == NULL) ||
            ((l = bounce_env->e_err_text->l_first) == NULL) ||
            (bounce_env->e_error == 0)) {
        return;
    }

    printf("\n***   Bounce Message %s  ***\n", bounce_env->e_id);
    env_stdout(bounce_env);
    printf("Message Text:\n");

    /* dfile message headers */
    printf("From: <mailer-daemon@%s>\n", simta_hostname);
    for (r = bounce_env->e_rcpt; r != NULL; r = r->r_next) {
        if (*r->r_rcpt == '\0') {
            printf("To: <%s>\n", simta_postmaster);
        } else {
            printf("To: <%s>\n", r->r_rcpt);
        }
    }
    printf("\n");

    while (l != NULL) {
        printf("%s\n", l->line_data);
        l = l->line_next;
    }
}


ino_t
bounce_dfile_out(struct envelope *bounce_env, SNET *message) {
    int               ret = 0;
    char              dfile_fname[ MAXPATHLEN ];
    int               dfile_fd;
    int               write_body = 0;
    FILE *            dfile;
    struct line *     l;
    char *            line;
    char              daytime[ RFC822_TIMESTAMP_LEN ];
    struct stat       sbuf;
    struct recipient *r;

    sprintf(dfile_fname, "%s/D%s", bounce_env->e_dir, bounce_env->e_id);

#ifdef HAVE_LIBOPENDKIM
    if (simta_dkim_sign != DKIMSIGN_POLICY_OFF) {
        bounce_env->e_flags |= ENV_FLAG_DKIMSIGN;
    }
#endif /* HAVE_LIBOPENDKIM */

    if ((dfile_fd = env_dfile_open(bounce_env)) < 0) {
        goto error;
    }

    if ((dfile = fdopen(dfile_fd, "w")) == NULL) {
        syslog(LOG_ERR, "Syserror: bounce_dfile_out fdopen %s: %m",
                dfile_fname);
        if (close(dfile_fd) != 0) {
            syslog(LOG_ERR, "Syserror: bounce_dfile_out fclose %s: %m",
                    dfile_fname);
        }
        return (0);
    }

    if (message != NULL) {
        if (fstat(snet_fd(message), &sbuf) != 0) {
            syslog(LOG_ERR, "Syserror: bounce_dfile_out fstat: %m");
            goto cleanup;
        }

        if (sbuf.st_size < simta_max_bounce_size) {
            write_body = 1;
        }
    }

    if (rfc822_timestamp(daytime) != 0) {
        goto cleanup;
    }

    /* dfile message headers */
    fprintf(dfile, "From: <mailer-daemon@%s>\n", simta_hostname);
    for (r = bounce_env->e_rcpt; r != NULL; r = r->r_next) {
        if (r->r_rcpt == NULL || *r->r_rcpt == '\0') {
            fprintf(dfile, "To: <%s>\n", simta_postmaster);
        } else {
            fprintf(dfile, "To: <%s>\n", r->r_rcpt);
        }
    }
    fprintf(dfile, "Date: %s\n", daytime);
    fprintf(dfile, "Message-ID: <%s@%s>\n", bounce_env->e_id, simta_hostname);
    fprintf(dfile, "Subject: undeliverable mail\n");
    fprintf(dfile, "\n");

    for (l = bounce_env->e_err_text->l_first; l != NULL; l = l->line_next) {
        fprintf(dfile, "%s\n", l->line_data);
    }
    fprintf(dfile, "\n");

    if (message != NULL) {
        if (write_body == 1) {
            fprintf(dfile, "Bounced message:\n");
        } else {
            fprintf(dfile, "Bounced message headers:\n");
        }
        fprintf(dfile, "\n");

        while ((line = snet_getline(message, NULL)) != NULL) {
            if ((*line == '\0') && (write_body == 0)) {
                /* End of headers, stop writing */
                break;
            } else {
                fprintf(dfile, "%s\n", line);
            }
        }
    }

    ret = 1;

cleanup:
    if (fclose(dfile) != 0) {
        syslog(LOG_ERR, "Syserror: bounce_dfile_out fclose %s: %m",
                dfile_fname);
        ret = 0;
    }

error:
    if (ret != 0) {
        return (bounce_env->e_dinode);
    }

    env_dfile_unlink(bounce_env);

    return (0);
}


struct envelope *
bounce(struct envelope *env, int body, const char *err) {
    struct envelope *env_bounce;
    char             dfile_fname[ MAXPATHLEN ];
    int              dfile_fd;
    SNET *           sn = NULL;

    if (body == 1) {
        sprintf(dfile_fname, "%s/D%s", env->e_dir, env->e_id);
        if ((dfile_fd = open(dfile_fname, O_RDONLY, 0)) < 0) {
            syslog(LOG_ERR, "Syserror: bounce open %s: %m", dfile_fname);
            return (NULL);
        }

        if ((sn = snet_attach(dfile_fd, 1024 * 1024)) == NULL) {
            close(dfile_fd);
            return (NULL);
        }
    }

    env->e_flags |= ENV_FLAG_BOUNCE;

    if ((env_bounce = bounce_snet(env, sn, NULL, err)) == NULL) {
        return (NULL);
    }

    if (sn != NULL) {
        snet_close(sn);
    }

    return (env_bounce);
}

static char *
host_or_jailhost(struct host_q *hq) {
    return (simta_host_is_jailhost(hq->hq_hostname) ? "quarantine host"
                                                    : "host");
}

static char *
old_or_jailed(struct envelope *env) {
    if (env->e_jail == ENV_JAIL_PRISONER) {
        return ("quarantined");
    }
    return ("undeliverable");
}


struct envelope *
bounce_snet(
        struct envelope *env, SNET *sn, struct host_q *hq, const char *err) {
    struct envelope * bounce_env;
    int               n_bounces = 0;
    struct recipient *r;
    struct line *     l;
    char              buf[ 1024 ];
    char *            return_address;

    if ((bounce_env = env_create(simta_dir_fast, NULL, "", env)) == NULL) {
        return (NULL);
    }

    if ((simta_rqueue_policy == RQUEUE_POLICY_JAIL) &&
            (simta_bounce_jail == 0)) {
        /* bounces must be able to get out of jail */
        env_jail_set(bounce_env, ENV_JAIL_NO_CHANGE);
    }

    /* if the postmaster is a failed recipient,
     * we need to put the bounce in the dead queue.
     */
    for (r = env->e_rcpt; r != NULL; r = r->r_next) {
        if (((env->e_flags & ENV_FLAG_BOUNCE) || (r->r_status == R_FAILED))) {
            if (*(r->r_rcpt) == '\0') {
                bounce_env->e_dir = simta_dir_dead;
                break;
            }
        }
    }

    return_address = env->e_mail;
    if ((env->e_jail == ENV_JAIL_PRISONER) &&
            (simta_jail_bounce_address != NULL)) {
        return_address = simta_jail_bounce_address;
    }
    if (env_recipient(bounce_env, return_address) != 0) {
        goto cleanup1;
    }

    if (bounce_env->e_err_text == NULL) {
        bounce_env->e_err_text = line_file_create();
    }

    line_append(bounce_env->e_err_text,
            "Message delivery failed for "
            "one or more recipients, check specific errors below\n",
            COPY);

    if (env->e_age == ENV_AGE_OLD) {
        sprintf(buf, "This message is old and %s.\n", old_or_jailed(env));
        line_append(bounce_env->e_err_text, buf, COPY);
    }

    if (env->e_jail == ENV_JAIL_PRISONER) {
        /* Nothing */
    } else if (hq == NULL) {
        if (err == NULL) {
            line_append(bounce_env->e_err_text,
                    "An error occurred during the expansion of "
                    "the message recipients.\n",
                    COPY);
        } else {
            sprintf(buf, "%s\n", err);
            line_append(bounce_env->e_err_text, buf, COPY);
        }

    } else if (hq->hq_err_text != NULL) {
        sprintf(buf,
                "The following error occurred during delivery to "
                "%s %s:\n",
                host_or_jailhost(hq), hq->hq_hostname);
        line_append(bounce_env->e_err_text, buf, COPY);
        for (l = hq->hq_err_text->l_first; l != NULL; l = l->line_next) {
            line_append(bounce_env->e_err_text, l->line_data, COPY);
        }
        line_append(bounce_env->e_err_text, "", COPY);

    } else {
        sprintf(buf, "An error occurred during delivery to %s %s.\n",
                host_or_jailhost(hq), hq->hq_hostname);
        line_append(bounce_env->e_err_text, buf, COPY);
    }

    if (env->e_err_text != NULL) {
        sprintf(buf,
                "The following error occurred during delivery of "
                "message %s:\n",
                env->e_id);
        line_append(bounce_env->e_err_text, buf, COPY);

        if (err != NULL) {
            sprintf(buf, "%s\n", err);
            line_append(bounce_env->e_err_text, buf, COPY);
        }

        for (l = env->e_err_text->l_first; l != NULL; l = l->line_next) {
            line_append(bounce_env->e_err_text, l->line_data, COPY);
        }

        line_append(bounce_env->e_err_text, "", COPY);
    }

    syslog(LOG_INFO, "Bounce env <%s>: %s: To <%s> From <>", env->e_id,
            bounce_env->e_id, bounce_env->e_rcpt->r_rcpt);

    for (r = env->e_rcpt; r != NULL; r = r->r_next) {
        if ((env->e_flags & ENV_FLAG_BOUNCE) || (r->r_status == R_FAILED)) {
            n_bounces++;
            syslog(LOG_INFO, "Bounce env <%s>: %s: Bouncing <%s> From <%s>",
                    env->e_id, bounce_env->e_id, r->r_rcpt, env->e_mail);
            sprintf(buf, "address %s\n", r->r_rcpt);
            line_append(bounce_env->e_err_text, buf, COPY);
            if (r->r_err_text != NULL) {
                for (l = r->r_err_text->l_first; l != NULL; l = l->line_next) {
                    line_append(bounce_env->e_err_text, l->line_data, COPY);
                }
            }
        }
    }

    if (bounce_dfile_out(bounce_env, sn) == 0) {
        syslog(LOG_ERR, "Bounce env <%s>: %s: bounce_dfile_out failed",
                env->e_id, bounce_env->e_id);
        goto cleanup2;
    }

    if (env_outfile(bounce_env) != 0) {
        goto cleanup2;
    }

    syslog(LOG_INFO, "Bounce env <%s>: %s: Bounced %d addresses", env->e_id,
            bounce_env->e_id, n_bounces);

    return (bounce_env);

cleanup2:
    syslog(LOG_ERR, "Bounce env <%s>: Message Deleted: System Error",
            bounce_env->e_id);

cleanup1:
    env_free(bounce_env);
    return (NULL);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
