/**********          header.h          **********/

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

int		count_words ___P(( char * ));

int		header_end ___P(( struct line_file *, char * ));
int		header_exceptions ___P(( struct line_file * ));
int		header_correct ___P(( struct line_file * ));
int		header_file_out ___P(( struct line_file *, FILE * ));
