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
    char		*line_data;
};

struct nlist {
    char		*n_key;
    struct line		*n_data;
};

struct message *message_create( void );
struct line *message_line( struct message *, char * );
struct line *message_prepend_line( struct message *, char * );
void message_stdout( struct message * );
int message_store( struct message * );
