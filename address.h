/**********          address.h          **********/

/* return codes for address_expand */
#define	ADDRESS_FINAL			1
#define	ADDRESS_EXCLUDE			2

/* return codes for address_local */
#define	ADDRESS_LOCAL			3
#define	ADDRESS_NOT_LOCAL		4

/* return codes for address_local & address_expand */
#define	ADDRESS_SYSERROR		5

void expansion_stab_stdout( void * );
int add_address( struct stab_entry **, char *, struct recipient * );
int address_local( char * );
int address_expand( char *, struct recipient *, struct stab_entry **,
	struct stab_entry ** );

