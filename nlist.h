/**********           nlist.h          **********/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */


struct nlist {
    char		*n_key;
    char		*n_data;
    int			n_lineno;
};


int	nlist ___P(( struct nlist *, char * ));
