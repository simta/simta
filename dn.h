#ifndef DN_H
#define DN_H
/*
** dn.h -- Originally from openldap-1.2.8 servers/slapd/dn.c
**         These 2 routines "Normalize" a dn.
*/

char * dn_normalize( char *dn );
char * dn_normalize_case( char *dn );

#endif
