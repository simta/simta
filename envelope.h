#ifndef SIMTA_ENVELOPE_H
#define SIMTA_ENVELOPE_H

#include <sys/stat.h>

#include <snet.h>
#include <yasl.h>

#define R_TEMPFAIL 0
#define R_ACCEPTED 1
#define R_FAILED 2

#define READ_QUEUE_INFO 1
#define READ_DELIVER_INFO 2
#define READ_JAIL_INFO 3

struct sender_list {
    struct dll_entry *sl_dll;
    struct dll_entry *sl_entries;
    int               sl_n_entries;
};

struct sender_entry {
    struct sender_list *se_list;
    struct envelope *   se_env;
    struct dll_entry *  se_dll;
};

struct recipient {
    struct recipient *r_next;
    char *            r_rcpt;
    struct line_file *r_err_text;
    int               r_status;
};

struct envelope {
    struct envelope *    e_next;
    struct envelope *    e_list_next;
    struct envelope *    e_list_prev;
    struct envelope *    e_hq_next;
    struct envelope *    e_hq_prev;
    struct envelope *    e_expanded_next;
    struct recipient *   e_rcpt;
    struct sender_entry *e_sender_entry;
    struct dll_entry *   e_env_list_entry;
    struct host_q *      e_hq;
    const char *         e_dir;
    char *               e_id;
    char *               e_hostname;
    char *               e_mail;
    char *               e_mail_orig;
    char *               e_mid;
    char *               e_header_from;
    char *               e_subject;
    yastr                e_extra_headers;
    struct line_file *   e_err_text;
    int                  e_error;
    int                  e_n_rcpt;
    int                  e_n_exp_level;
    int                  e_cycle;
    int                  e_age;
    int                  e_flags;
    int                  e_attributes;
    int                  e_jail;
    ino_t                e_dinode;
    struct timeval       e_etime;
};

#define ENV_AGE_UNKNOWN 0
#define ENV_AGE_OLD 1
#define ENV_AGE_NOT_OLD 2

/* jail values */
#define ENV_JAIL_NO_CHANGE 0
#define ENV_JAIL_PAROLEE 1
#define ENV_JAIL_PRISONER 2

#define ENV_FLAG_TFILE (1 << 0)
#define ENV_FLAG_EFILE (1 << 1)
#define ENV_FLAG_DFILE (1 << 2)
#define ENV_FLAG_BOUNCE (1 << 3)
#define ENV_FLAG_TEMPFAIL (1 << 4)
#define ENV_FLAG_PUNT (1 << 5)
#define ENV_FLAG_DELETE (1 << 6)
#define ENV_FLAG_SUPPRESS_NO_EMAIL (1 << 7)
#define ENV_FLAG_DKIMSIGN (1 << 8)

#define ENV_ATTR_ARCHIVE_ONLY (1 << 0)
#define ENV_ATTR_8BITMIME (1 << 1)

/* Efile syntax, by minimum version number:
 *
 * 1 int        Vsimta_version
 * 2 char*      Equeue_id
 * 4 char*      Mmid - ignored for now
 * 1 ino_t      Idinode
 * 3 int        Xexpansion_level
 * 1 char*      Hhostname
 * 1 int        Dattributes
 * 1 char*      Ffrom_address
 * 1 char*      Rto_address
 */

struct envelope *env_create(
        const char *, const char *, const char *, const struct envelope *);
void  env_rcpt_free(struct envelope *);
void  env_free(struct envelope *);
void  rcpt_free(struct recipient *);
void  env_clear_errors(struct envelope *);
int   env_clear(struct envelope *);
int   env_jail_status(struct envelope *, int);
int   env_is_old(struct envelope *, int);
int   env_set_id(struct envelope *, char *);
int   env_recipient(struct envelope *, char *);
int   env_sender(struct envelope *, const char *);
int   env_hostname(struct envelope *, char *);
int   env_outfile(struct envelope *);
int   env_efile(struct envelope *);
int   env_tfile(struct envelope *);
int   env_tfile_unlink(struct envelope *);
int   env_dfile_unlink(struct envelope *);
int   env_touch(struct envelope *);
int   env_move(struct envelope *, char *);
int   env_unlink(struct envelope *);
int   env_read(int, struct envelope *, SNET **);
int   env_fsync(const char *);
ino_t env_dfile_copy(struct envelope *, char *, char *);
int   env_truncate_and_unlink(struct envelope *, SNET *);
int   env_string_recipients(struct envelope *, char *);
int   sender_list_add(struct envelope *);
yastr env_dkim_sign(struct envelope *);
int   env_jail_set(struct envelope *, int);
int   env_dfile_open(struct envelope *);

/* debugging  functions */
void env_stdout(struct envelope *);

#endif /* SIMTA_ENVELOPE_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
