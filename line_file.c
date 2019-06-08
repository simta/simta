/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "line_file.h"


/* return a line_file */

struct line_file *
line_file_create(void) {
    struct line_file *lf;

    lf = calloc(1, sizeof(struct line_file));

    return (lf);
}


void
line_file_free(struct line_file *lf) {
    struct line *l;

    if (lf != NULL) {
        while ((l = lf->l_first) != NULL) {
            lf->l_first = l->line_next;
            free(l->line_data);
            free(l);
        }

        free(lf);
    }
}


/* append a line to a line_file structure  */

struct line *
line_append(struct line_file *lf, char *data, int copy) {
    struct line *l;

    if (data == NULL) {
        syslog(LOG_ERR, "line_append: no data");
        return (NULL);
    }

    l = calloc(1, sizeof(struct line));

    if (copy != 0) {
        l->line_data = strdup(data);
    } else {
        l->line_data = data;
    }

    l->line_next = NULL;

    if (lf->l_first == NULL) {
        lf->l_first = l;
        lf->l_last = l;
        l->line_prev = NULL;

    } else {
        l->line_prev = lf->l_last;
        lf->l_last->line_next = l;
        lf->l_last = l;
    }

    return (l);
}


/* prepend a line to a line_file structure  */

struct line *
line_prepend(struct line_file *lf, char *data, int copy) {
    struct line *l;

    if (data == NULL) {
        syslog(LOG_ERR, "line_prepend: no data");
        return (NULL);
    }

    l = calloc(1, sizeof(struct line));

    if (copy != 0) {
        l->line_data = strdup(data);
    } else {
        l->line_data = data;
    }

    l->line_prev = NULL;

    if (lf->l_first == NULL) {
        lf->l_first = l;
        lf->l_last = l;
        l->line_next = NULL;

    } else {
        l->line_next = lf->l_first;
        lf->l_first->line_prev = l;
        lf->l_first = l;
    }

    return (l);
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
