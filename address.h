/**********          address.h          **********/

/* return codes for address_local and address_expand */
#define	ADDRESS_SYSERROR		0
#define	ADDRESS_BAD_FORMAT		1
#define	ADDRESS_EXTERNAL		2
#define	ADDRESS_LOCAL			3
#define	ADDRESS_NOT_FOUND		4

/* additional return codes for address_expand */
#define	ADDRESS_EXPANDED		5
#define	ADDRESS_SEEN			6

void expansion_stab_stdout( void * );
int add_address( struct stab_entry **, char *, struct recipient * );
int address_local( char * );
int address_expand( char *, struct recipient *, struct stab_entry **,
	struct stab_entry ** );

