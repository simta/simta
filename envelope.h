/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else __STDC__
#define ___P(x)		()
#endif __STDC__

struct recipient {
    struct recipient	*r_next;
    char		*r_rcpt;
};

struct envelope {
    struct envelope	*e_next;
    struct sockaddr_in	*e_sin;
    char		e_hostname[ MAXHOSTNAMELEN ];
    char		*e_helo;
    char		*e_mail;
    struct recipient	*e_rcpt;
    char		e_id[ 30 ];
};

struct envelope	*env_create ___P(( void ));
void		env_reset ___P(( struct envelope * ));
