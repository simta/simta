/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     ll.h     *****/

#ifdef __STDC__
#define ___P(x)		x
#else /* __STDC__ */
#define ___P(x)		()
#endif /* __STDC__ */

/* this library is a linked list implamentation of a symbol table */

struct stab_entry {
    char		*st_key;
    struct stab_entry	*st_next;
    void		*st_data;
};

void	*ll_lookup ___P(( struct stab_entry*, char * ));
int	ll_default_compare ___P(( char *, char * ));
int	ll_insert ___P(( struct stab_entry **, char *, void *,
		int(*)( char *, char * )));
int 	ll_insert_tail ___P(( struct stab_entry **stab, char *key, void *data );
void	*ll_remove ___P(( struct stab_entry **, char * )));
void	ll_walk ___P(( struct stab_entry *, void (*)( void *)));

int	ll__insert ___P(( struct stab_entry **, void *,
		int(*)( void *, void * )));
void	*ll__lookup ___P(( struct stab_entry *, void *,
		int(*)( void *, void * )));
