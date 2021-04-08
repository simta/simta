/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "ll.h"
#include "simta_malloc.h"


/*****     ll_lookup     *****/
/* looks through a given symbol table, and returns the entry, if any,
     * that has a key that corresponds to the one given
     */

void *
ll_lookup(struct stab_entry *st, const char *key) {
    for (; st != NULL; st = st->st_next) {
        if (strcasecmp(st->st_key, key) == 0) {
            /* match found */
            return (st->st_data);
        }
    }
    /* no match found */
    return (NULL);
}


int
ll_default_compare(char *a, char *b) {
    return (strcmp(a, b));
}


/*****     ll_insert     *****/
/* This function inserts a given node in to a given stab table */

int
ll_insert(struct stab_entry **stab, char *key, void *data,
        int (*ll_compare)(char *, char *)) {
    struct stab_entry * st;
    struct stab_entry **i;

    if (ll_compare == NULL) {
        ll_compare = ll_default_compare;
    }

    st = simta_calloc(1, sizeof(struct stab_entry));

    st->st_key = key;
    st->st_data = data;

    for (i = stab; *i != NULL; i = &((*i)->st_next)) {
        if (ll_compare(st->st_key, (*i)->st_key) < 0) {
            break;
        }
    }

    st->st_next = *i;
    *i = st;

    return (0);
}


/*****     ll_insert_tail     *****/
/* This function inserts a given node to the tail of a given stab table */

int
ll_insert_tail(struct stab_entry **stab, char *key, void *data) {
    struct stab_entry * st;
    struct stab_entry **i;

    st = simta_calloc(1, sizeof(struct stab_entry));

    st->st_key = key;
    st->st_data = data;

    /* Move to tail of table */
    for (i = stab; *i != NULL; i = &((*i)->st_next)) {
    }

    st->st_next = *i;
    *i = st;

    return (0);
}


/*****     ll_remove     *****/
/* This function removes a given node from a stab table */

void *
ll_remove(struct stab_entry **stab, char *key) {
    struct stab_entry * st;
    struct stab_entry **i;
    void *              data;

    for (i = stab; *i != NULL; i = &((*i)->st_next)) {
        if (strcmp(key, (*i)->st_key) == 0) {
            break;
        }
    }

    if ((st = *i) == NULL) {
        return (NULL);
    }

    data = st->st_data;

    *i = (*i)->st_next;

    free(st);

    return (data);
}


void
ll_walk(struct stab_entry *st, void (*ll_func)(void *)) {
    for (; st != NULL; st = st->st_next) {
        ll_func(st->st_data);
    }
}


void *
ll_nokey_lookup(
        struct stab_entry *st, void *data, int (*ll_compare)(void *, void *)) {
    for (; st != NULL; st = st->st_next) {
        if (ll_compare(st->st_data, data) == 0) {
            /* match found */
            return (st->st_data);
        }
    }
    /* no match found */
    return (NULL);
}


int
ll_nokey_insert(struct stab_entry **stab, void *data,
        int (*ll_compare)(void *, void *)) {
    struct stab_entry * st;
    struct stab_entry **i;

    st = simta_calloc(1, sizeof(struct stab_entry));

    st->st_data = data;

    for (i = stab; *i != NULL; i = &((*i)->st_next)) {
        if ((ll_compare != NULL) && (ll_compare(data, (*i)->st_data) < 0)) {
            break;
        }
    }

    st->st_next = *i;
    *i = st;

    return (0);
}

void
ll_free(struct stab_entry *stab) {
    struct stab_entry *next;

    for (; stab != NULL; stab = next) {
        next = stab->st_next;
        free(stab);
    }
}

struct dll_entry *
dll_lookup(struct dll_entry *dll_head, const char *key) {
    struct dll_entry *dll;
    int               c;

    for (dll = dll_head; dll != NULL; dll = dll->dll_next) {
        if ((c = strcasecmp(key, dll->dll_key)) == 0) {
            return (dll);
        } else if (c < 0) {
            return (NULL);
        }
    }

    return (NULL);
}


struct dll_entry *
dll_lookup_or_create(struct dll_entry **dll_head, const char *key) {
    struct dll_entry *dll;
    struct dll_entry *dll_last = NULL;
    struct dll_entry *dll_new;
    int               c;

    for (dll = *dll_head; dll != NULL; dll = dll->dll_next) {
        if ((c = strcasecmp(key, dll->dll_key)) == 0) {
            return (dll);
        } else if (c < 0) {
            break;
        }
        dll_last = dll;
    }

    dll_new = simta_calloc(1, sizeof(struct dll_entry));

    dll_new->dll_key = simta_strdup(key);

    if (dll_last == NULL) {
        /* head insert */
        dll_new->dll_next = *dll_head;
        *dll_head = dll_new;
        if (dll_new->dll_next != NULL) {
            dll_new->dll_next->dll_prev = dll_new;
        }
    } else if (dll == NULL) {
        /* tail insert */
        dll_new->dll_prev = dll_last;
        dll_last->dll_next = dll_new;
    } else {
        dll_new->dll_next = dll;
        dll_new->dll_prev = dll->dll_prev;
        dll->dll_prev->dll_next = dll_new;
        dll->dll_prev = dll_new;
    }

    return (dll_new);
}


void
dll_remove_entry(struct dll_entry **head, struct dll_entry *dll) {
    if (dll->dll_next != NULL) {
        dll->dll_next->dll_prev = dll->dll_prev;
    }

    if (dll->dll_prev != NULL) {
        dll->dll_prev->dll_next = dll->dll_next;
    } else {
        *head = dll->dll_next;
    }

    free(dll->dll_key);

    free(dll);

    return;
}

void
dll_free(struct dll_entry *head) {
    struct dll_entry *next;
    for (; head != NULL; head = next) {
        next = head->dll_next;
        free(head->dll_key);
        free(head);
    }
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
