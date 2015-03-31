/**********          header.h          **********/

#define RFC822_TIMESTAMP_LEN	32

#define STRING_MID		"Message-ID"
#define STRING_MID_LEN		10
#define STRING_MIME_VERSION	"Mime-Version"
#define STRING_MIME_VERSION_LEN	12
#define STRING_RECEIVED		"Received"
#define STRING_RECEIVED_LEN	8
#define STRING_SEEN_BEFORE	"X-Simta-Seen-Before"
#define STRING_SEEN_BEFORE_LEN	19

/* for struct receive_headers->r_state */
#define R_HEADER_READ		0
#define R_HEADER_END		1
#define R_HEADER_MID		2
#define R_HEADER_SEEN		3

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
    char			**r_all_seen_before;
    char			*r_seen_before;
};


/* public */
int	parse_emailaddr( int, char *, char **, char ** );
char	*skip_cws( char * );
char	*token_domain_literal( char * );
char	*token_domain( char * );
char	*token_quoted_string( char * );
char	*token_dot_atom( char * );
int	header_timestamp( struct envelope *, FILE * );
int	header_text( int, char *, struct receive_headers *, char ** );
int	header_correct( int, struct line_file *, struct envelope * );
int	header_file_out( struct line_file *, FILE * );
int	is_emailaddr( char * );
int	correct_emailaddr( char ** );
int	rfc822_timestamp( char * );
struct string_address *string_address_init( char * );
void	string_address_free( struct string_address * );
char	*string_address_parse( struct string_address * );
void	header_free( struct receive_headers * );
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
