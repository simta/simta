int address_local( char *address );
int address_expand( char *address, struct recipient *rcpt, struct stab_entry **expansion, struct stab_entry **expanded );

void expansion_stab_stdout( void * );
