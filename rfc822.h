/*
* Copyright (c) 1998 Regents of The University of Michigan.
* All Rights Reserved.  See COPYRIGHT.
*/


#define IH_FROM 	( 1 << 0 )
#define IH_TO		( 1 << 1 )
#define FIRST 		( 1 << 2 )
#define IH_SUBJ		( 1 << 3 )

struct datalines {
    char                *d_line;
    struct datalines    *d_next;
};

struct ih {
    char	*ih_name;
    int		ih_bit;
};

#ifdef __STDC__
#define ___P(x)         x
#else __STDC__
#define ___P(x)         ()
#endif __STDC__

int 			dl_append ___P(( struct datalines ***, 
					    struct datalines ***, char *, ...));
int 			dl_prepend ___P(( struct datalines ***, char *, ... ));
int			dl_output ___P(( struct datalines *, SNET * ));
void			dl_free ___P(( struct datalines *** ));
int			parse_header ___P(( char *, int *, int *, int * ));
struct datalines 	*dl_alloc ___P(( char * ));
