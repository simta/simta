/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     expand.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

struct expn {
    char		*e_expn;
    struct recipient	*e_rcpt_parent;
};

int	expand ___P(( struct host_q **, struct envelope * ));
