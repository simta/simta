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

struct message *message_create( void );
int		message_line( struct message *, char * );
