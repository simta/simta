/**********           nlist.h          **********/

struct nlist {
    char		*n_key;
    char		*n_data;
    int			n_lineno;
};


int	nlist( struct nlist *, char * );
