/*****     ldap.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

/* this library is a linked list implamentation of a symbol table */

struct list {
    char		*l_string;
    struct list		*l_next;
};

/* return codes for ldap_expand */
#define LDAP_SYSERROR		1
#define LDAP_NOT_FOUND		2
#define LDAP_FINAL		3
#define LDAP_EXCLUDE		4
int	ldap_expand ___P(( struct expand *, struct exp_addr * ));

/* return codes for ldap_address_local */
#define LDAP_LOCAL		2
#define LDAP_NOT_LOCAL		3
int	ldap_address_local ___P(( char * ));

/* Public functions */
int	ldap_value ___P(( LDAPMessage *, char *, struct list * ));
int	ldap_config ___P(( char * ));
/* XXX neex ldap_close */
