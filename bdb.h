int db_new( DB **bdp, u_int32_t flags, char *file, char *database,
    DBTYPE type );
int db_open_rw( DB **bdp, char *file, char *database );
int db_open_r( DB **bdp, char *file, char *database );

int db_put( DB *dbp, char *keydata, char *valuedata );
int db_get( DB *dbp, char *keyvalue, DBT *value );

int db_cursor_set( DB *dbp, DBC **dbcp, DBT *key, DBT *value );
int db_cursor_next( DB *dbp, DBC **dbcp, DBT *key, DBT *value );
int db_cursor_close( DBC *dbcp );

int db_close( DB *dbp );

extern DB               *simta_dbp;
