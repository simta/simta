/**********          address.h          **********/

/* return codes for address_local and address_expand */
#define	ADDRESS_SYSERROR		1
#define	ADDRESS_BAD_FORMAT		2
#define	ADDRESS_EXTERNAL		3
#define	ADDRESS_LOCAL			4
#define	ADDRESS_NOT_FOUND		5

/* additional return codes for address_expand */
#define	ADDRESS_EXPANDED		6
#define	ADDRESS_SEEN			7

void expansion_stab_stdout( void * );
int add_address( struct stab_entry **, char *, struct recipient * );
int address_local( char * );
int address_expand( char *, struct recipient *, struct stab_entry **,
	struct stab_entry ** );

