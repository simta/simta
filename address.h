#define SIMTA_EXPAND_ERROR_NONE		0
#define SIMTA_EXPAND_ERROR_SYSTEM	1
#define SIMTA_EXPAND_ERROR_BAD_FORMAT	2
#define SIMTA_EXPAND_ERROR_OFF_HOST	3
#define SIMTA_EXPAND_ERROR_NOT_LOCAL	4
#define SIMTA_EXPAND_ERROR_SEEN		5
#define SIMTA_EXPAND_ERROR_LDAP		6

int address_local( char *address );
int address_expand( char *address, struct recipient *rcpt,
    struct stab_entry **expansion, struct stab_entry **expanded,
    int *ae_error );
int add_address( struct stab_entry **stab, char *address,
    struct recipient *rcpt );

void expansion_stab_stdout( void * );
