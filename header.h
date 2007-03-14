/**********          header.h          **********/

#define STRING_MID		"Message-ID"
#define STRING_MID_LEN		10
#define STRING_RECEIVED		"Received"
#define STRING_RECEIVED_LEN	8

/* for struct receive_headers->r_state */
#define R_HEADER_READ		0
#define R_HEADER_END		1
#define R_HEADER_MID		2

struct header {
    char                *h_key;
    struct line         *h_line;
    char		*h_data;
};

struct string_address {
    char		*sa_string;
    char		*sa_start;
    int			sa_swap;
    char		sa_swap_char;
};

struct receive_headers {
    int				r_state;
    char			*r_mid;
    int				r_mid_set;
    int				r_received_count;
    struct envelope		*r_env;
};


/* public */
int	parse_emailaddr( int, char *, char **, char ** );
char	*skip_cws( char * );
char	*token_domain_literal( char * );
char	*token_domain( char * );
char	*token_quoted_string( char * );
char	*token_dot_atom( char * );
int	header_timestamp( struct envelope *, FILE * );
int	header_text( int, char *, struct receive_headers * );
int	header_punt( struct line_file * );
int	header_correct( int, struct line_file *, struct envelope * );
int	header_file_out( struct line_file *, FILE * );
int	is_emailaddr( char * );
int	correct_emailaddr( char ** );
char	*tz( struct tm * );
struct string_address *string_address_init( char * );
void	string_address_free( struct string_address * );
char	*string_address_parse( struct string_address * );
