/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

/* return 0 on success, syslog errors */
int mail_local ___P(( int, char *, char * ));
int procmail ___P(( int, char *, char * ));
int(*get_local_mailer( void ))( int, char *, char * );
