/**********          header.h          **********/

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

struct header {
    char                *h_key;
    struct line         *h_line;
    char		*h_data;
};


/* public */
int	header_timestamp ___P(( struct envelope *, FILE * ));
int	header_end ___P(( struct line_file *, char * ));
int	header_punt ___P(( struct line_file * ));
int	header_correct ___P(( int, struct line_file *, struct envelope * ));
int	header_correct ___P(( int, struct line_file *, struct envelope * ));
int	header_file_out ___P(( struct line_file *, FILE * ));
int	is_emailaddr ___P(( char ** ));
char	*tz ___P(( struct tm * ));
