/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     message.h     *****/


struct message {
    struct envelope	*m_env;
    struct line		*m_first_line;
    struct line		*m_last_line;
};

struct line {
    struct line		*line_next;
    struct line		*line_prev;
    char		*line_data;
};

struct header {
    char		*h_key;
    struct line		*h_line;
    char		*h_data;
};

#ifdef __STDC__
#define ___P(x)         x
#else /* __STDC__ */
#define ___P(x)         ()
#endif /* __STDC__ */

struct message	*message_create ___P(( char * ));
struct message	*message_infile ___P(( char *, char * ));
struct line	*message_add_line ___P(( struct message *, char * ));
struct line	*message_prepend_line ___P(( struct message *, char * ));
int		message_recipient ___P(( struct message *, char * ));
int		message_outfile ___P(( struct message * ));
void		message_stdout ___P(( struct message * ));
