/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     queue.h     *****/


#define	SLOW_DIR	"slow"
#define	FAST_DIR	"fast"
#define	LOCAL_DIR	"local"


struct q_file {
    char			*q_id;
    struct q_file		*q_inode_next;
    int				q_efile;
    int				q_dfile;
    ino_t			q_dfile_ino;
    nlink_t			q_dfile_nlink;
    struct timespec		q_etime;
    struct timespec		q_dtime;
};


struct q_file	*q_file_create( char * );
void		q_file_stdout( struct q_file * );
