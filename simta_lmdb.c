/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <inttypes.h>
#include <string.h>

#include "simta_lmdb.h"
#include "simta_malloc.h"

static int simta_db_open(struct simta_dbh **, const char *, uint32_t, int);

static int
simta_db_open(
        struct simta_dbh **dbh, const char *file, uint32_t flags, int mode) {
    int      ret;
    MDB_env *dbp;

    *dbh = simta_calloc(1, sizeof(struct simta_dbh));

    if ((ret = mdb_env_create(&dbp)) != 0) {
        return ret;
    }

    if ((ret = mdb_env_set_mapsize(dbp, 104857600)) != 0) {
        return ret;
    }

    if ((ret = mdb_env_open(dbp, file, flags, 0664)) != 0) {
        mdb_env_close(dbp);
        return ret;
    } else {
        (*dbh)->h_env = dbp;
    }

    return SIMTA_DB_OK;
}

char *
simta_db_strerror(int err) {
    switch (err) {
    case SIMTA_DB_SYSERROR:
        return ("System Error");
    case SIMTA_DB_NOTFOUND:
        err = MDB_NOTFOUND;
        break;
    }
    return (mdb_strerror(err));
}

int
simta_db_open_rw(struct simta_dbh **dbh, const char *file) {
    return (simta_db_open(dbh, file, MDB_NOSUBDIR | MDB_NOLOCK, 0664));
}

int
simta_db_open_r(struct simta_dbh **dbh, const char *file) {
    return (simta_db_open(
            dbh, file, MDB_NOSUBDIR | MDB_NOLOCK | MDB_RDONLY, 0664));
}

int
simta_db_new(struct simta_dbh **dbh, const char *file) {
    int      ret;
    MDB_txn *txn;
    MDB_dbi  dbi;

    if ((ret = simta_db_open_rw(dbh, file)) != 0) {
        return (ret);
    }

    if ((ret = mdb_txn_begin((*dbh)->h_env, NULL, 0, &txn)) != 0) {
        goto cleanup;
    }

    if ((ret = mdb_dbi_open(txn, NULL, MDB_CREATE | MDB_DUPSORT, &dbi)) != 0) {
        goto cleanup;
    }

    if ((ret = mdb_drop(txn, dbi, 0)) == 0) {
        ret = mdb_txn_commit(txn);
        return (ret);
    }

cleanup:
    mdb_txn_abort(txn);
    mdb_env_close((*dbh)->h_env);
    return (ret);
}

int
simta_db_put(struct simta_dbh *dbh, yastr key, yastr value) {
    int      ret;
    MDB_val  db_key, db_value;
    MDB_txn *txn;
    MDB_dbi  dbi;

    memset(&db_key, 0, sizeof(MDB_val));
    memset(&db_value, 0, sizeof(MDB_val));

    db_key.mv_data = key;
    db_key.mv_size = yasllen(key);
    db_value.mv_data = value;
    db_value.mv_size = yasllen(value);

    if ((ret = mdb_txn_begin(dbh->h_env, NULL, 0, &txn)) != 0) {
        return (ret);
    }

    if ((ret = mdb_dbi_open(txn, NULL, MDB_DUPSORT, &dbi)) != 0) {
        goto cleanup;
    }

    if ((ret = mdb_put(txn, dbi, &db_key, &db_value, 0)) == 0) {
        ret = mdb_txn_commit(txn);
        return (ret);
    }

cleanup:
    mdb_txn_abort(txn);
    return (ret);
}

int
simta_db_get(struct simta_dbh *dbh, yastr key, yastr *value) {
    MDB_val  db_key, db_value;
    MDB_txn *txn;
    MDB_dbi  dbi;
    int      ret;

    memset(&db_key, 0, sizeof(MDB_val));
    db_key.mv_data = key;
    db_key.mv_size = yasllen(key);

    if ((ret = mdb_txn_begin(dbh->h_env, NULL, MDB_RDONLY, &txn)) != 0) {
        return (ret);
    }

    if ((ret = mdb_dbi_open(txn, NULL, MDB_DUPSORT, &dbi)) != 0) {
        goto cleanup;
    }

    if ((ret = mdb_get(txn, dbi, &db_key, &db_value)) != 0) {
        goto cleanup;
    }

    *value = yaslnew(db_value.mv_data, db_value.mv_size);

    if (ret == MDB_NOTFOUND) {
        ret = SIMTA_DB_NOTFOUND;
    }

cleanup:
    mdb_txn_abort(txn);
    return (ret);
}

int
simta_db_cursor_open(struct simta_dbh *dbh, struct simta_dbc **dbc) {
    int         ret;
    MDB_txn    *txn;
    MDB_cursor *dbcp;
    MDB_dbi     dbi;

    *dbc = simta_calloc(1, sizeof(struct simta_dbc));

    if ((ret = mdb_txn_begin(dbh->h_env, NULL, MDB_RDONLY, &txn)) != 0) {
        return (ret);
    }

    if ((ret = mdb_dbi_open(txn, NULL, MDB_DUPSORT, &dbi)) != 0) {
        goto cleanup;
    }

    if ((ret = mdb_cursor_open(txn, dbi, &dbcp)) == 0) {
        (*dbc)->c_cursor = dbcp;
        return (ret);
    }

cleanup:
    mdb_txn_abort(txn);
    return (ret);
}

int
simta_db_cursor_get(struct simta_dbc *dbc, yastr *key, yastr *value) {
    MDB_val       db_key, db_value;
    MDB_cursor_op op;
    int           ret;

    if (dbc->c_init == 0) {
        if ((*key != NULL) && (yasllen(*key) > 0)) {
            memset(&db_key, 0, sizeof(MDB_val));
            db_key.mv_data = *key;
            db_key.mv_size = yasllen(*key);
            dbc->c_keyed = 1;
            op = MDB_SET;
        } else {
            op = MDB_FIRST;
        }
        dbc->c_init = 1;
    } else if (dbc->c_keyed == 1) {
        op = MDB_NEXT_DUP;
    } else {
        op = MDB_NEXT;
    }

    if ((ret = mdb_cursor_get(dbc->c_cursor, &db_key, &db_value, op)) != 0) {
        if (ret == MDB_NOTFOUND) {
            ret = SIMTA_DB_NOTFOUND;
        }
        return (ret);
    }

    if ((ret = mdb_cursor_get(
                 dbc->c_cursor, &db_key, &db_value, MDB_GET_CURRENT)) != 0) {
        return (ret);
    }

    if (*key == NULL) {
        *key = yaslempty();
    }
    *key = yaslcpylen(*key, db_key.mv_data, db_key.mv_size);

    if (*value == NULL) {
        *value = yaslempty();
    }
    *value = yaslcpylen(*value, db_value.mv_data, db_value.mv_size);

    return (ret);
}

void
simta_db_cursor_close(struct simta_dbc *dbc) {
    if (dbc == NULL) {
        return;
    }
    if (dbc->c_cursor != NULL) {
        mdb_txn_abort(mdb_cursor_txn(dbc->c_cursor));
    }
    simta_free(dbc);
}

void
simta_db_close(struct simta_dbh *dbh) {
    if (dbh == NULL) {
        return;
    }
    if (dbh->h_env != NULL) {
        mdb_env_close(dbh->h_env);
        dbh->h_env = NULL;
    }
    simta_free(dbh);
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
