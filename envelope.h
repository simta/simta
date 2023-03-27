#ifndef SIMTA_ENVELOPE_H
#define SIMTA_ENVELOPE_H

#include <stdbool.h>
#include <sys/stat.h>

#include "simta.h"

#define R_TEMPFAIL 0
#define R_ACCEPTED 1
#define R_FAILED 2

struct sender_list {
    struct dll_entry *sl_dll;
    struct dll_entry *sl_entries;
    int               sl_n_entries;
};

struct sender_entry {
    struct sender_list *se_list;
    struct envelope    *se_env;
    struct dll_entry   *se_dll;
};

struct recipient {
    struct recipient *r_next;
    char             *r_rcpt;
    struct line_file *r_err_text;
    int               r_status;
};

struct envelope {
    struct envelope     *e_next;
    struct envelope     *e_list_next;
    struct envelope     *e_list_prev;
    struct envelope     *e_hq_next;
    struct envelope     *e_hq_prev;
    struct envelope     *e_expanded_next;
    struct recipient    *e_rcpt;
    struct sender_entry *e_sender_entry;
    struct dll_entry    *e_env_list_entry;
    struct host_q       *e_hq;
    const char          *e_dir;
    yastr                e_extra_headers;
    yastr                e_header_from;
    yastr                e_hostname;
    yastr                e_id;
    yastr                e_mail;
    yastr                e_mail_orig;
    yastr                e_mid;
    yastr                e_subject;
    struct line_file    *e_err_text;
    int                  e_error;
    int                  e_n_rcpt;
    int                  e_n_exp_level;
    int                  e_cycle;
    int                  e_age;
    int                  e_flags;
    ino_t                e_dinode;
    struct timeval       e_etime;
    bool                 e_8bitmime;
    bool                 e_bounceable;
    bool                 e_jailed;
    bool                 e_puntable;
};

#define ENV_AGE_UNKNOWN 0
#define ENV_AGE_OLD 1
#define ENV_AGE_NOT_OLD 2

#define ENV_FLAG_TFILE (1 << 0)
#define ENV_FLAG_EFILE (1 << 1)
#define ENV_FLAG_DFILE (1 << 2)
#define ENV_FLAG_BOUNCE (1 << 3)
#define ENV_FLAG_TEMPFAIL (1 << 4)
#define ENV_FLAG_DELETE (1 << 5)
#define ENV_FLAG_SUPPRESS_NO_EMAIL (1 << 6)
#define ENV_FLAG_DKIMSIGN (1 << 7)

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
ucl_object_t *env_repr(struct envelope *);
void          env_rcpt_free(struct envelope *);
void          env_free(struct envelope *);
void          rcpt_free(struct recipient *);
void          env_clear_errors(struct envelope *);
int           env_clear(struct envelope *);
bool          env_is_old(struct envelope *, int);
int           env_set_id(struct envelope *, char *);
int           env_recipient(struct envelope *, const char *);
simta_result  env_sender(struct envelope *, const char *);
void          env_hostname(struct envelope *, const char *);
simta_result  env_outfile(struct envelope *);
int           env_efile(struct envelope *);
simta_result  env_tfile(struct envelope *);
int           env_tfile_unlink(struct envelope *);
int           env_dfile_unlink(struct envelope *);
int           env_touch(struct envelope *);
int           env_move(struct envelope *, char *);
int           env_unlink(struct envelope *);
simta_result  env_read(bool, struct envelope *, SNET **);
int           env_fsync(const char *);
ino_t         env_dfile_copy(struct envelope *, const char *, const char *);
ino_t         env_dfile_wrap(struct envelope *, const char *, const char *);
int           env_truncate_and_unlink(struct envelope *, SNET *);
simta_result  env_parole(struct envelope *);
simta_result  env_string_recipients(struct envelope *, char *);
int           sender_list_add(struct envelope *);
yastr         env_dkim_sign(struct envelope *);
int           env_dfile_open(struct envelope *);

/* debugging  functions */
void env_stdout(struct envelope *);

#endif /* SIMTA_ENVELOPE_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
