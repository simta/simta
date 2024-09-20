#ifndef SIMTA_ARGCARGV_H
#define SIMTA_ARGCARGV_H

#define argcargv(X, Y) (acav_parse(NULL, X, Y))

typedef struct {
    char   **acv_argv;
    unsigned acv_argc;
} ACAV;

ACAV *acav_alloc(void);
int   acav_parse(ACAV *acav, char *, char ***);
int   acav_free(ACAV *acav);

#endif /* SIMTA_ARGCARGV_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
