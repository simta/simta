/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/* return 0 on success, syslog errors */
int mail_local( int, char *, struct recipient * );
int procmail( int, char *, struct recipient * );
int(*get_local_mailer( void ))( int, char *, struct recipient * );
