#ifndef SIMTA_SIMTA_LMDB_H
#define SIMTA_SIMTA_LMDB_H

#include <lmdb.h>
#include <yasl.h>

#define SIMTA_DB_OK 0
#define SIMTA_DB_SYSERROR 1
#define SIMTA_DB_NOTFOUND 2

struct simta_dbh {
    MDB_env *h_env;
};

struct simta_dbc {
    MDB_cursor *c_cursor;
    int         c_init;
    int         c_keyed;
};

char *simta_db_strerror(int);

int simta_db_new(struct simta_dbh **, const char *);
int simta_db_open_rw(struct simta_dbh **, const char *);
int simta_db_open_r(struct simta_dbh **, const char *);

int simta_db_put(struct simta_dbh *, yastr, yastr);
int simta_db_get(struct simta_dbh *, yastr, yastr *);

int  simta_db_cursor_open(struct simta_dbh *, struct simta_dbc **);
int  simta_db_cursor_get(struct simta_dbc *, yastr *, yastr *);
void simta_db_cursor_close(struct simta_dbc *);

void simta_db_close(struct simta_dbh *);

#endif /* SIMTA_SIMTA_LMDB_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
