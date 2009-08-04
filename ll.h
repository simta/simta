/*
 * Copyright (c) 1998 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     ll.h     *****/

/* this library is a linked list implamentation of a symbol table */

struct stab_entry {
    char		*st_key;
    struct stab_entry	*st_next;
    struct stab_entry	*st_prev;
    void		*st_data;
};

struct dll_entry {
    struct dll_entry		*dll_next;
    struct dll_entry		*dll_prev;
    char			*dll_key;
    int				dll_free_key;
    void			*dll_data;
};

struct dll_entry *dll_lookup_or_create( struct dll_entry**, char*, int );
void dll_remove_entry( struct dll_entry **, struct dll_entry * );

void	*ll_lookup( struct stab_entry*, char * );
int	ll_insert( struct stab_entry **, char *, void *,
		int(*)( char *, char * ));
void	*ll_remove( struct stab_entry **, char * );
void	ll_walk( struct stab_entry *, void (*)( void *));

int 	ll_insert_tail( struct stab_entry **stab, char *key, void *data );

int	ll_default_compare( char *, char * );
int	ll__insert( struct stab_entry **, void *, int(*)( void *, void * ));
void	*ll__lookup( struct stab_entry *, void *, int(*)( void *, void * ));
