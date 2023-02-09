#ifndef SIMTA_HEADER_H
#define SIMTA_HEADER_H

#include <stdbool.h>
#include <stdio.h>

#include <yasl.h>

#include "line_file.h"
#include "ll.h"
#include "simta.h"

#define STRING_SEEN_BEFORE "SIMTA-Seen-Before"

/* for struct receive_headers->r_state */
#define R_HEADER_READ 0
#define R_HEADER_END 1

enum address_list_syntax {
    HEADER_MAILBOX_LIST,
    HEADER_ADDRESS_LIST,
    HEADER_MAILBOX_GROUP,
};

struct rfc822_header {
    struct stab_entry *h_lines;
    int                h_count;
};

struct string_address {
    char *sa_string;
    char *sa_start;
    int   sa_swap;
    char  sa_swap_char;
};

struct receive_headers {
    int               r_state;
    int               r_received_count;
    struct envelope  *r_env;
    char             *r_seen_before;
    struct line_file *r_headers;
    struct dll_entry *r_headers_index;
};


/* public */
simta_result parse_emailaddr(int, char *, char **, char **);
yastr       *parse_addr_list(yastr, size_t *, enum address_list_syntax);
char        *skip_cws(char *);
char        *token_domain_literal(char *);
char        *token_domain(char *);
char        *token_quoted_string(char *);
char        *token_dot_atom_text(char *);
int          header_text(int, char *, struct receive_headers *, char **);
int          header_check(struct receive_headers *, bool, bool, bool);
int          header_file_out(struct line_file *, FILE *);
bool         is_emailaddr(char *);
simta_result correct_emailaddr(yastr *, const char *);
yastr        rfc5322_timestamp();
struct string_address *string_address_init(char *);
void                   string_address_free(struct string_address *);
char                  *string_address_parse(struct string_address *);
void                   receive_headers_free(struct receive_headers *);

#endif /* SIMTA_HEADER_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
