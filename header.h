/**********          header.h          **********/
struct header {
    char                *h_key;
    struct line         *h_line;
    char		*h_data;
};


/* public */
char	*token_domain_literal( char * );
char	*token_domain( char * );
char	*token_quoted_string( char * );
char	*token_dot_atom( char * );
int	header_timestamp( struct envelope *, FILE * );
int	header_end( struct line_file *, char * );
int	header_punt( struct line_file * );
int	header_correct( int, struct line_file *, struct envelope * );
int	header_correct( int, struct line_file *, struct envelope * );
int	header_file_out( struct line_file *, FILE * );
int	is_emailaddr( char * );
int	correct_emailaddr( char ** );
char	*tz( struct tm * );
