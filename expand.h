/**********          expand.h          **********/

/* expansion types */
#define	EXPANSION_TYPE_PASSWORD		1
#define	EXPANSION_TYPE_ALIAS		2
#define	EXPANSION_TYPE_LDAP		3

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

#ifdef HAVE_LDAP
#define	STATUS_LDAP_MEMONLY		(1<<0)
#define	STATUS_LDAP_PRIVATE		(1<<1)
#define	STATUS_LDAP_SUPRESSOR		(1<<2)
#define	STATUS_LDAP_SUPRESSED		(1<<3)
#define	STATUS_EMAIL_SENDER		(1<<4)
#define	STATUS_NO_EMAIL_SENDER		(1<<5)
#define	STATUS_ROOT_PATH		(1<<6)
#define	STATUS_NO_ROOT_PATH		(1<<7)
#endif /* HAVE_LDAP */

struct expand_output {
    char			*eo_from;
    char			*eo_hostname;
    struct envelope		*eo_env;
    struct expand_output	*eo_next;
};

struct expand {
    struct envelope		*exp_env;	/* original envelope */
    struct stab_entry		*exp_addr_list;	/* expanded addresses */
    struct envelope		*exp_errors;	/* error envelope list */
#ifdef HAVE_LDAP
    struct exp_addr		*exp_parent;
    struct exp_link		*exp_memonly;
#endif /* HAVE_LDAP */
};

#ifdef HAVE_LDAP
struct exp_link {
    struct exp_link		*el_next;
    struct exp_addr		*el_exp_addr;
};
#endif /* HAVE_LDAP */

struct exp_addr {
    int				e_addr_type;	/* address data type */
    int				e_addr_terminal;
    char			*e_addr;	/* address string */
    char			*e_addr_at;	/* char the email addresses @ */
    char			*e_addr_from;
    struct envelope		*e_addr_errors;	/* address error handle */
#ifdef HAVE_LDAP
    int				e_addr_ldap_flags;
    int				e_addr_anti_loop;
    char			*e_addr_dn;
    char			*e_addr_mail;
    struct stab_entry		*e_addr_ok;
    struct envelope		*e_addr_env_moderated;
    struct exp_link		*e_addr_parents;
    struct exp_link		*e_addr_children;
#endif /* HAVE_LDAP */
};

/* expand.c */
int	expand_and_deliver( struct host_q **, struct envelope * );
int	expand( struct host_q **, struct envelope * );
struct envelope *eo_lookup( struct expand_output *, char *, char * );
int eo_insert( struct expand_output **, struct envelope * );

/* address.c */
int address_error( struct envelope *, char *, char *, char * );
void expansion_stab_stdout( void * );
int add_address( struct expand *, char *, struct envelope *, int, char * );
struct envelope *address_bounce_create( struct expand* );
int address_expand( struct expand *, struct exp_addr * );
int alias_expand( struct expand *, struct exp_addr * );
int password_expand( struct expand *, struct exp_addr * );
void expand_tree_stdout( struct exp_addr *, int );
int address_string_recipients( struct expand *, char *, struct exp_addr *,
	char * );

#ifdef HAVE_LDAP
int exp_addr_link( struct exp_link **, struct exp_addr * );
void exp_addr_link_free( struct exp_link * );
int unblocked_path_to_root( struct exp_addr *, int );
int sender_is_child( struct exp_addr *, int );
int sender_is_moderator( char *, struct exp_addr * );
void supress_addrs( struct exp_link *, int );
int permitted_create( struct exp_addr *, char ** );
void permitted_destroy( struct exp_addr * );
int is_permitted( struct exp_addr * );
int moderate_membersonly( struct expand *, struct exp_addr *, char ** );
#endif /* HAVE_LDAP */
