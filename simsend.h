/*
* Copyright (c) 1998 Regents of The University of Michigan.
* All Rights Reserved.  See COPYRIGHT.
*/

int		main( int, char ** );
int		read_headers( struct datalines **, struct rcptlist **,
			char *, int );

SNET		*smtp_connect( unsigned short, char *, int );
int		transmit_envelope( SNET *, struct rcptlist *, char *, int );
int		transmit_headers( SNET *, struct datalines *, int );
int		read_body( SNET *, int );
