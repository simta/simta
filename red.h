/*****     red.h     *****/

struct action {
    int				a_action;
    int				a_flags;
    char			*a_fname;
    DB				*a_dbp;
    struct action		*a_next;
    struct action		*a_next_secondary_mx;
#ifdef HAVE_LDAP
    struct simta_ldap		*a_ldap;
#endif /* HAVE_LDAP */
};

struct simta_red {
    char			*red_host_name;
    struct simta_red		*red_next;
    struct action		*red_receive;
    struct action		*red_expand;
    int				red_deliver_type;
    int				red_deliver_argc;
    char			**red_deliver_argv;
    int				red_wait_set;
    int				red_wait_min;
    int				red_wait_max;
    int				red_policy_punting;
    int				red_policy_tls;
    int				red_policy_tls_cert;
    char			*red_tls_ciphers;
};

/* red_deliver_types */
#define RED_DELIVER_SMTP_DEFAULT	0
#define RED_DELIVER_SMTP		1
#define RED_DELIVER_BINARY		2

/* struct red_action->a_flags */
#define ACTION_REQUIRED			1
#define ACTION_SUFFICIENT		2

/* simta_red_add_expansion red_types */
#define RED_CODE_R			1<<0
#define RED_CODE_r			1<<1
#define RED_CODE_E			1<<2
#define RED_CODE_D			1<<4

/* struct simta_red->red_punting_policy */
#define RED_PUNTING_DEFAULT		0
#define RED_PUNTING_ENABLED		1
#define RED_PUNTING_DISABLED		2

struct simta_red *red_host_lookup( char * );
struct simta_red *red_host_add( char * );
struct action *red_action_add( struct simta_red *, int, int, char * );
int red_action_default( struct simta_red * );
void red_hosts_stdout( void );
void red_action_stdout( void );

int alias_expand( struct expand *, struct exp_addr *, struct action * );
struct passwd *simta_getpwnam( struct action *, char * );
int password_expand( struct expand *, struct exp_addr *, struct action * );
#ifdef HAVE_LDAP
void red_close_ldap_dbs( void );
#endif /* HAVE_LDAP */

/* global variables */
extern struct simta_red			*simta_red_hosts;
extern struct simta_red			*simta_red_host_default;
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
