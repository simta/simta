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
int		read_headers ___P(( struct datalines **, struct rcptlist **,
			char *, int ));

SNET		*smtp_connect ___P(( unsigned short, char *, int ));
int		transmit_envelope ___P(( SNET *, struct rcptlist *,
			char *, int ));
int		transmit_headers ___P(( SNET *, struct datalines *, int ));
int		read_body ___P(( SNET *, int ));
