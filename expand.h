/**********          expand.h          **********/

/* expansion types */
#define	EXPAND_TYPE_PASSWORD		1
#define	EXPAND_TYPE_ALIAS		2
#define	EXPAND_TYPE_LDAP		3

/* return codes for expand_and_deliver(...) */
#define	EXPAND_OK			0
#define	EXPAND_SYSERROR			1
#define	EXPAND_FATAL			2

/* return codes for address_expand */
#define	ADDRESS_FINAL			1
#define	ADDRESS_EXCLUDE			2
#define	ADDRESS_SYSERROR		3

/* return codes for alias_expand */
#define	ALIAS_NOT_FOUND			1
#define	ALIAS_EXCLUDE			2
#define	ALIAS_SYSERROR			3

/* return codes for password_expand */
#define	PASSWORD_NOT_FOUND			1
#define	PASSWORD_EXCLUDE			2
#define	PASSWORD_SYSERROR			3
#define	PASSWORD_FINAL				4

/* address types */
#define	ADDRESS_TYPE_EMAIL		1
#define	ADDRESS_TYPE_DEAD		2
#ifdef HAVE_LDAP
#define	ADDRESS_TYPE_LDAP		3
#endif /* HAVE_LDAP */

/* address status */
#define STATUS_TERMINAL			(1<<1)

#ifdef HAVE_LDAP
#define	STATUS_LDAP_EXCLUSIVE		(1<<2)
#define	STATUS_EMAIL_SENDER		(1<<3)
#endif /* HAVE_LDAP */

struct expand {
    struct envelope		*exp_env;	/* original envelope */
    struct stab_entry		*exp_addr_list;	/* expanded addresses */
    struct envelope		*exp_errors;	/* error envelope list */
#ifdef HAVE_LDAP
    struct exp_addr		*exp_root;
    struct exp_addr		*exp_parent;
#endif /* HAVE_LDAP */
};

struct exp_addr {
    char			*e_addr;	/* address string */
    char			*e_addr_at;	/* char the email addresses @ */
    int				e_addr_type;	/* address data type */
    struct envelope		*e_addr_errors;	/* address error handle */
    int				e_addr_status;
#ifdef HAVE_LDAP
    struct exp_addr		*e_addr_parent;
    struct exp_addr		*e_addr_peer;
    struct exp_addr		*e_addr_child;
    struct stab_entry		*e_addr_ok;
    struct stab_entry		*e_addr_x_children;
    char			*e_addr_dn;
#endif /* HAVE_LDAP */
};

/* expand.c */
int	expand_and_deliver( struct host_q **, struct envelope * );
int	expand( struct host_q **, struct envelope * );

/* address.c */
int address_error( struct envelope *, char *, char *, char * );
void expansion_stab_stdout( void * );
int add_address( struct expand *, char *, struct envelope *, int );
struct envelope *address_bounce_create( struct expand* );
int address_expand( struct expand *, struct exp_addr * );
int alias_expand( struct expand *, struct exp_addr * );
int password_expand( struct expand *, struct exp_addr * );
void expand_tree_stdout( struct exp_addr *, int );

#ifdef HAVE_LDAP
int ldap_check_ok( struct expand *, struct exp_addr * );
#endif /* HAVE_LDAP */
