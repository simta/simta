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

int	ldap_config ___P(( char * ));
int	ldap_value ___P(( LDAPMessage *, char *, struct list * ));
int	ldap_expand ___P(( char * ));
