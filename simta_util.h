#ifndef SIMTA_SIMTA_SMTP_H
#define SIMTA_SIMTA_SMTP_H

#include "simta.h"
#include "yasl.h"


typedef enum {
    SIMTA_CHARSET_ASCII,
    SIMTA_CHARSET_UTF8,
    SIMTA_CHARSET_INVALID,
} simta_charset;


yastr         env_string(const char *, const char *);
yastr        *split_smtp_command(const yastr, size_t *);
simta_charset simta_check_charset(const char *);
simta_result  validate_smtp_chars(const yastr);

#endif /* SIMTA_SIMTA_SMTP_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
