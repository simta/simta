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

int		count_words ___P(( char * ));
char		*header_unfold ___P(( struct line * ));
int		header_uncomment ___P(( char ** ));
int		header_first_mailbox ___P(( char **, char * ));

/* public */
void		header_stdout ___P(( struct header[] ));
int		header_timestamp ___P(( struct envelope *, FILE * ));
int		header_end ___P(( struct line_file *, char * ));
int		header_exceptions ___P(( struct line_file * ));
int		header_correct ___P(( struct line_file *, struct envelope * ));
int		header_file_out ___P(( struct line_file *, FILE * ));
