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

struct message *message_create( void );
struct line *message_line( struct message *, char * );
struct line *message_prepend_line( struct message *, char * );
void message_stdout( struct message * );
int message_store( struct message * );
int message_recipient( struct message *, char * );
