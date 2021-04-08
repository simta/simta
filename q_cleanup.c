/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "envelope.h"
#include "simta.h"
#include "simta_malloc.h"

#define INCOMPLETE_T 1
#define STRANDED_D 2

#define Q_DIR_EMPTY 1
#define Q_DIR_EXIST 2
#define Q_DIR_CLEAN 3

struct file_list {
    struct file_list *f_next;
    char *            f_name;
};

struct i_list {
    ino_t            i_dinode;
    struct i_list *  i_next;
    struct envelope *i_expanded_list;
    struct envelope *i_unexpanded;
};

int q_cleanup(void);
int q_dir_startup(char *, int, struct envelope **);
int q_expansion_cleanup(struct envelope **);
int q_move_to_slow(struct envelope **, struct envelope **);
int file_list_add(struct file_list **, int, char *, char *);


int
q_cleanup(void) {
    struct envelope *slow = NULL;
    struct envelope *fast = NULL;
    struct envelope *local = NULL;

    if (q_dir_startup(simta_dir_dead, Q_DIR_EXIST, NULL)) {
        return (1);
    }

    if (q_dir_startup(simta_dir_slow, Q_DIR_CLEAN, &slow)) {
        return (1);
    }

    if (simta_filesystem_cleanup) {
        if (q_dir_startup(simta_dir_fast, Q_DIR_CLEAN, &fast)) {
            return (1);
        }

        if (q_expansion_cleanup(&fast)) {
            return (1);
        }

        if (q_move_to_slow(&slow, &fast) != 0) {
            return (1);
        }

    } else {
        if (q_dir_startup(simta_dir_fast, Q_DIR_EMPTY, NULL)) {
            return (1);
        }
    }

    if (q_dir_startup(simta_dir_local, Q_DIR_CLEAN, &local)) {
        return (1);
    }

    if (q_move_to_slow(&slow, &local) != 0) {
        return (1);
    }

    return (0);
}


int
q_move_to_slow(struct envelope **slow_q, struct envelope **other_q) {
    struct envelope * move;
    struct envelope **slow;
    int               result;
    int               collisions = 0;

    for (slow = slow_q; *other_q != NULL;) {
        /* pop move odd other_q */
        move = *other_q;
        *other_q = move->e_next;

        for (;;) {
            if ((*slow != NULL) &&
                    ((result = strcmp(move->e_id, (*slow)->e_id)) > 0)) {
                /* advance the slow list by one */
                slow = &((*slow)->e_next);

            } else {
                if ((*slow == NULL) || (result < 0)) {
                    /* move message files to SLOW */
                    if (env_move(move, simta_dir_slow) != 0) {
                        return (1);
                    }

                    /* insert move to slow_q */
                    move->e_next = *slow;
                    *slow = move;

                } else {
                    /* file collision - message is already in the slow queue */
                    syslog(LOG_NOTICE,
                            "Queue %s/%s: collision with existing file in slow",
                            move->e_dir, move->e_id);
                    if (simta_filesystem_cleanup) {
                        if (env_unlink(move) != 0) {
                            return (1);
                        }
                    } else {
                        collisions++;
                    }

                    env_free(move);
                }

                slow = &((*slow)->e_next);
                break;
            }
        }
    }

    return (collisions);
}


int
q_dir_startup(char *dir, int action, struct envelope **messages) {
    DIR *             dirp;
    struct dirent *   entry;
    struct envelope * env;
    struct envelope **env_p;
    int               result;
    int               bad_filesystem = 0;
    struct file_list *f_list = NULL;
    struct file_list *f;

    if ((dirp = opendir(dir)) == NULL) {
        syslog(LOG_ERR, "Syserror: q_dir_startup opendir %s: %m", dir);
        return (1);
    }

    if (action == Q_DIR_EXIST) {
        if (closedir(dirp) != 0) {
            syslog(LOG_ERR, "Syserror: q_dir_startup closedir %s: %m", dir);
            return (1);
        }
        return (0);
    }

    /* clear errno before trying to read */
    errno = 0;

    if (messages != NULL) {
        /* start from scratch */
        *messages = NULL;
    }

    while ((entry = readdir(dirp)) != NULL) {
        /* ignore "." and ".." */
        if (entry->d_name[ 0 ] == '.') {
            if (entry->d_name[ 1 ] == '\0') {
                continue;
            } else if (entry->d_name[ 1 ] == '.') {
                if (entry->d_name[ 2 ] == '\0') {
                    continue;
                }
            }
        }

        if (action == Q_DIR_EMPTY) {
            syslog(LOG_NOTICE, "Queue %s/%s: Directory not empty", dir,
                    entry->d_name);
            bad_filesystem = 1;
            continue;
        }

        if ((*entry->d_name == 'E') || (*entry->d_name == 'D')) {
            for (env_p = messages; *env_p != NULL;
                    env_p = &((*env_p)->e_next)) {
                if ((result = strcmp(entry->d_name + 1, (*env_p)->e_id)) <= 0) {
                    break;
                }
            }

            if ((*env_p == NULL) || (result != 0)) {
                if ((env = env_create(dir, entry->d_name + 1, NULL, NULL)) ==
                        NULL) {
                    return (1);
                }

                env->e_next = *env_p;
                *env_p = env;

            } else {
                env = *env_p;
            }

            if (*entry->d_name == 'E') {
                env->e_flags = env->e_flags | ENV_FLAG_EFILE;
            } else {
                env->e_flags = env->e_flags | ENV_FLAG_DFILE;
            }

        } else if (*entry->d_name == 't') {
            syslog(LOG_NOTICE, "Queue %s/%s: stranded t_file", dir,
                    entry->d_name);
            if (dir == simta_dir_local) {
                /* Nothing. */
            } else if (simta_filesystem_cleanup) {
                if (!bad_filesystem) {
                    /* Keep track of stranded t files */
                    if (file_list_add(
                                &f_list, INCOMPLETE_T, dir, entry->d_name)) {
                        return (1);
                    }
                }
            } else {
                /* illegal stranded t */
                bad_filesystem = 1;
            }

        } else {
            /* unknown file */
            bad_filesystem = 1;
            syslog(LOG_WARNING, "Queue %s/%s: unknown file", dir,
                    entry->d_name);
        }
    }

    /* did readdir finish, or encounter an error? */
    if (errno != 0) {
        syslog(LOG_ERR, "Syserror: q_dir_startup readdir %s: %m", dir);
        bad_filesystem = 1;
    }

    if (closedir(dirp) != 0) {
        syslog(LOG_ERR, "Syserror: q_dir_startup closedir %s: %m", dir);
        return (1);
    }

    if ((bad_filesystem) || (action == Q_DIR_EMPTY)) {
        return (bad_filesystem);
    }

    for (env_p = messages; *env_p != NULL;) {
        env = *env_p;

        if ((env->e_flags & ENV_FLAG_DFILE) == 0) {
            syslog(LOG_ERR, "Queue %s/E%s: missing Dfile", dir, env->e_id);
            bad_filesystem = 1;
            *env_p = env->e_next;
            env_free(env);

        } else if ((env->e_flags & ENV_FLAG_EFILE) == 0) {
            syslog(LOG_ERR, "Queue %s/D%s: missing Efile", dir, env->e_id);
            if (dir == simta_dir_local) {
                /* Nada. */
            } else if ((simta_filesystem_cleanup) && (!bad_filesystem)) {
                if (file_list_add(&f_list, STRANDED_D, dir, env->e_id)) {
                    return (1);
                }
            } else {
                bad_filesystem = 1;
            }

            *env_p = env->e_next;
            env_free(env);

        } else {
            env_p = &((*env_p)->e_next);
        }
    }

    while (f_list != NULL) {
        f = f_list;
        f_list = f->f_next;

        if (!bad_filesystem) {
            if (unlink(f->f_name) != 0) {
                syslog(LOG_ERR, "Syserror: q_dir_startup unlink %s: %m",
                        f->f_name);
                return (1);
            }
            syslog(LOG_INFO, "Queue %s: unlinked", f->f_name);
        }

        free(f->f_name);
        free(f);
    }

    return (bad_filesystem);
}


int
q_expansion_cleanup(struct envelope **fast) {
    struct envelope **e;
    struct envelope * env;
    struct envelope *delete;
    struct i_list **i;
    struct i_list * inode_list = NULL;
    struct i_list * i_add;
    struct stat     sb;
    char            fname[ MAXPATHLEN + 1 ];

    /* check for interrupted expansion, build list of messages to delete */
    for (env = *fast; env != NULL; env = env->e_next) {
        sprintf(fname, "%s/D%s", env->e_dir, env->e_id);

        if (stat(fname, &sb) != 0) {
            syslog(LOG_ERR, "Syserror q_expansion_cleanup stat %s: %m", fname);
            return (1);
        }

        env->e_dinode = sb.st_ino;

        /* if the link count >1 it could be part of an expansion */
        if (sb.st_nlink > 1) {
            /* build a linked list of all shared Dfiles */
            if (env_read(READ_QUEUE_INFO, env, NULL) != 0) {
                return (1);
            }

            for (i = &inode_list; *i != NULL; i = &((*i)->i_next)) {
                if (env->e_dinode <= ((*i)->i_dinode)) {
                    break;
                }
            }

            if ((*i != NULL) && (env->e_dinode == (*i)->i_dinode)) {
                if ((*i)->i_unexpanded != NULL) {
                    /* unexpanded exists, mark env for deletion */
                    assert((env->e_n_exp_level - 1) ==
                            ((*i)->i_unexpanded->e_n_exp_level));
                    env->e_flags |= ENV_FLAG_DELETE;
                    syslog(LOG_INFO, "Queue %s/%s: %s/%s expansion interrupted",
                            simta_dir_fast, env->e_id, simta_dir_fast,
                            (*i)->i_unexpanded->e_id);
                    continue;

                } else if ((*i)->i_expanded_list->e_n_exp_level ==
                           env->e_n_exp_level) {
                    /* env same as expanded list, add to list */
                    env->e_expanded_next = (*i)->i_expanded_list;
                    (*i)->i_expanded_list = env;
                    continue;

                } else if ((*i)->i_expanded_list->e_n_exp_level ==
                           env->e_n_exp_level + 1) {
                    /* env is unexpanded */
                    (*i)->i_unexpanded = env;

                } else {
                    /* expanded should be single unexpanded message */
                    assert((*i)->i_expanded_list->e_expanded_next == NULL);
                    assert((*i)->i_expanded_list->e_n_exp_level ==
                            env->e_n_exp_level - 1);
                    (*i)->i_unexpanded = (*i)->i_expanded_list;
                    (*i)->i_expanded_list = env;
                }

                for (delete = (*i)->i_expanded_list; delete != NULL;
                        delete = delete->e_expanded_next) {
                    delete->e_flags |= ENV_FLAG_DELETE;
                    syslog(LOG_INFO, "Queue %s/%s: %s/%s expansion interrupted",
                            simta_dir_fast, delete->e_id, simta_dir_fast,
                            env->e_id);
                }

            } else {
                /* insert into i stab */
                i_add = simta_calloc(1, sizeof(struct i_list));

                i_add->i_expanded_list = env;
                i_add->i_dinode = env->e_dinode;
                i_add->i_next = *i;
                *i = i_add;
            }
        }
    }

    e = fast;
    while (*e != NULL) {
        if ((*e)->e_flags & ENV_FLAG_DELETE) {
            env = *e;
            *e = env->e_next;

            if (env_unlink(env) != 0) {
                return (1);
            }

            env_free(env);

        } else {
            e = &((*e)->e_next);
        }
    }

    /* FIXME: mem free */

    return (0);
}


int
file_list_add(struct file_list **f_list, int mode, char *dir, char *f_id) {
    struct file_list *f;
    size_t            len;

    switch (mode) {
    case STRANDED_D:
        len = strlen(dir) + strlen(f_id) + 3;
        break;

    case INCOMPLETE_T:
        len = strlen(dir) + strlen(f_id) + 2;
        break;

    default:
        syslog(LOG_ERR, "Queue: file_list_add: unknown mode");
        return (1);
    }

    f = simta_calloc(1, sizeof(struct file_list));
    f->f_name = simta_malloc(len);

    switch (mode) {
    case STRANDED_D:
        sprintf(f->f_name, "%s/D%s", dir, f_id);
        break;

    case INCOMPLETE_T:
        sprintf(f->f_name, "%s/%s", dir, f_id);
        break;

    default:
        syslog(LOG_ERR, "Queue: file_list_add: unknown mode");
        return (1);
    }

    f->f_next = *f_list;
    *f_list = f;

    return (0);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
