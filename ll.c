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


int
ll_default_compare(char *a, char *b) {
    return (strcmp(a, b));
}


int
ll_insert(struct stab_entry **stab, char *key, void *data,
        int (*ll_compare)(char *, char *)) {
    struct stab_entry  *st;
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


int
ll_nokey_insert(struct stab_entry **stab, void *data,
        int (*ll_compare)(void *, void *)) {
    struct stab_entry  *st;
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
        simta_free(stab);
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

    simta_free(dll->dll_key);

    simta_free(dll);

    return;
}

void
dll_free(struct dll_entry *head) {
    struct dll_entry *next;
    for (; head != NULL; head = next) {
        next = head->dll_next;
        simta_free(head->dll_key);
        simta_free(head);
    }
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
