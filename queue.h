/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     queue.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */


#define	SLOW_DIR	"slow"
#define	FAST_DIR	"fast"
#define	LOCAL_DIR	"local"


struct q_file {
    char			*q_id;
    char			*q_hostname;
    struct q_file		*q_inode_next;
    struct q_file		*q_etime_next;
    struct envelope		*q_env;
    struct message_data		*q_data;
    int				q_unexpanded;
    int				q_efile;
    int				q_dfile;
    ino_t			q_dfile_ino;
    nlink_t			q_dfile_nlink;
    struct timespec		q_etime;
    struct timespec		q_dtime;
};

struct host_q {
    char			*hq_name;
    struct stab_entry		*hq_qfiles;
};


struct q_file	*q_file_create ___P(( char * ));
struct host_q	*host_q_create ___P(( char * ));
void		q_file_stdout ___P(( struct q_file * ));
void		host_q_stdout ___P(( struct host_q * ));
