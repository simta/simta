/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     line_file.h     *****/


struct line {
    struct line		*line_next;
    struct line		*line_prev;
    char		*line_data;
    int			line_no;
};

struct line_file {
    struct line		*l_first;
    struct line		*l_last;
};

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

/* public */
struct line_file *line_file_create ___P(( void ));
void	line_file_free ___P(( struct line_file * ));
struct line *line_append ___P(( struct line_file *, char * ));
struct line *line_prepend ___P(( struct line_file *, char * ));
void	line_free ___P(( struct line * ));
