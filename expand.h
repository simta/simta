/**********          expand.h          **********/

/* return codes for expand_and_deliver(...) */
#define	EXPAND_OK			0
#define	EXPAND_SYSERROR			1
#define	EXPAND_FATAL			2

/* return codes for address_expand */
#define	ADDRESS_FINAL			1
#define	ADDRESS_EXCLUDE			2

/* return codes for address_local */
#define	ADDRESS_LOCAL			3
#define	ADDRESS_NOT_LOCAL		4

/* return codes for address_local & address_expand */
#define	ADDRESS_SYSERROR		5

/* address types */
#define	ADDRESS_TYPE_EMAIL		1
#ifdef HAVE_LDAP
#define	ADDRESS_TYPE_LDAP		2
#endif /* HAVE_LDAP */

struct expand {
    struct envelope		*exp_env;	/* original envelope */
    struct stab_entry		*exp_addr_list;	/* expanded addresses */
    struct envelope		*exp_errors;	/* error envelope list */
    struct exp_addr		*exp_addr_root;	/* address tree root */
    struct exp_addr		*exp_addr_parent; /* used for tree building */
};

struct exp_addr {
    char			*e_addr;	/* address string */
    int				e_addr_type;	/* address type */
    struct envelope		*e_addr_errors;	/* address error handle */
    struct exp_addr		*e_addr_parent;
    struct exp_addr		*e_addr_peer;
    struct exp_addr		*e_addr_child;
#ifdef HAVE_LDAP
    /* these variables are needed to do exclusive groups */
    int				e_addr_exclusive;
#endif /* HAVE_LDAP */
};

/* expand.c */
int	expand_and_deliver ___P(( struct host_q **, struct envelope * ));
int	expand ___P(( struct host_q **, struct envelope * ));

/* address.c */
int address_error ___P(( struct envelope *, char *, char *, char * ));
void expansion_stab_stdout( void * );
int add_address( struct expand *, char *, struct envelope *, int );
struct envelope *address_bounce_create ___P(( struct expand* ));
int address_local( char * );
int address_expand( struct expand *, struct exp_addr * );
