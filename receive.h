/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

int		receive ___P(( int, struct sockaddr_in * ));
int		argcargv ___P(( char *, char **[] ));
char		*tz ___P(( struct tm * ));
