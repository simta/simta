/*
* Copyright (c) 1999 Regents of The University of Michigan.
* All Rights Reserved.  See COPYRIGHT.
*/

struct rcptlist {
    char                *r_rcpt;
    struct rcptlist     *r_next;
};

#ifdef __STDC__
#define ___P(x)         x
#else __STDC__
#define ___P(x)         ()
#endif __STDC__


struct rcptlist		*r_alloc ___P(( char * ));
int                     r_prepend ___P(( struct rcptlist **, char * ) );
int                     r_append ___P(( char *, struct rcptlist **, 
						struct rcptlist ** ) );
void			r_output ___P(( struct rcptlist * ));
