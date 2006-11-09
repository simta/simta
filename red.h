/*****     red.h     *****/

struct simta_red {
    char			*red_host_name;
    int				red_host_type;
    struct simta_red		*red_next;
    struct action		*red_receive;
    struct action		*red_expand;
    int				red_deliver_argc;
    char			**red_deliver_argv;
};

struct action {
    int				a_action;
    int				a_flags;
    char			*a_fname;
    DB				*a_dbp;
    struct action		*a_next;
};

/* struct red_action->a_flags */
#define ACTION_REQUIRED			1
#define ACTION_SUFFICIENT		2

/* simta_red_add_expansion red_types */
#define RED_CODE_R			1<<0
#define RED_CODE_r			1<<1
#define RED_CODE_E			1<<2
#define RED_CODE_D			1<<4

/* struct simta_red->red_host_type */
#define RED_HOST_TYPE_LOCAL		1
#define RED_HOST_TYPE_SECONDARY_MX	2

struct simta_red *simta_red_lookup_host( char * );
struct simta_red *simta_red_add_host( char *, int );
struct action *simta_red_add_action( struct simta_red *, int, int, char * );
int simta_red_action_default( struct simta_red * );
void simta_red_stdout( void );

/* global variables */
extern struct simta_red			*simta_red_hosts;
extern struct simta_red			*simta_default_host;
extern struct simta_red			*simta_secondary_mx;
