/*
* Copyright (c) 1998 Regents of The University of Michigan.
* All Rights Reserved.  See COPYRIGHT.
*/

#ifdef __STDC__
#define ___P(x)         x
#else __STDC__
#define ___P(x)         ()
#endif __STDC__

int		main ___P(( int, char ** ));
int		read_headers ___P(( struct datalines **, struct datalines **, 
				    struct datalines **, struct datalines **, 
				    struct rcptlist *, char *, char *, int ));

NET		*smtp_connect ___P(( unsigned short, char *, int ));
int		transmit_envelope ___P(( NET *, struct rcptlist *, char *, int ));
int		transmit_headers ___P(( NET *, struct datalines *, int ));
int		read_body ___P(( NET *, int ));
