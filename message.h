/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     message.h     *****/

struct message {
    struct line		*m_first;
    struct line		*m_last;
};

struct line {
    struct line		*line_next;
    char		*line_data;
};

struct nlist {
    char		*n_key;
    char		*n_data;
};

struct message *message_create( void );
struct line *message_line( struct message *, char * );
struct line *message_prepend_line( struct message *, char * );
void message_stdout( struct message * );
