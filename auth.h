/*
 * Copyright (c) 2000 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

#ifdef __STDC__
#define ___P(x)		x
#else __STDC__
#define ___P(x)		()
#endif __STDC__

struct sasl {
    char	*s_name;
    int		(*s_func) ___P(( struct sasl *, SNET *, struct envelope *,
			int, char *[] ));
};

int		f_auth ___P(( SNET *, struct envelope *, int, char *[] ));
struct sasl	*sasl;
