/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     bounce.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */


int bounce_text ___P(( struct envelope *, char *, char *, char * ));
void bounce_stdout ___P(( struct envelope * ));
int bounce_dfile_out ___P(( struct envelope *, SNET * ));
struct envelope *bounce ___P(( struct envelope *, SNET * ));
