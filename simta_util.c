/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include "simta_malloc.h"
#include "simta_util.h"


typedef enum {
    SMTP_CMD_WHITESPACE,
    SMTP_CMD_WORD,
    SMTP_CMD_BRACKET,
    SMTP_CMD_DQUOTE,
} smtp_cmd_state;


yastr
env_string(const char *left, const char *right) {
    yastr buf;

    buf = yaslauto(left);
    buf = yaslcatlen(buf, "=", 1);
    if (right && (*right != '\0')) {
        buf = yaslcat(buf, right);
    }

    return buf;
}


yastr *
split_smtp_command(const yastr str, size_t *len) {
    yastr         *tokens;
    smtp_cmd_state state = SMTP_CMD_WHITESPACE;

    if (!str) {
        return NULL;
    }

    size_t i;
    size_t slots = 5;
    size_t start = 0;
    *len = 0;
    tokens = simta_malloc(sizeof(yastr) * slots);

    /* I'm not sure this is the most robust way to process SMTP
     * commands, but it's worked so far. We split on whitespace, unless that
     * whitespace is inside angle brackets. Angle brackets can also contain
     * double-quoted strings which allow escaping any character with '\'.
     *
     * This is just a first-pass tokenization; individual commands will
     * then evaluate the arguments to validate that they actually match
     * their expected syntax.
     */
    for (i = 0; i < yasllen(str); i++) {
        if ((state == SMTP_CMD_WHITESPACE) && (slots < *len + 1)) {
            /* make room for another element */
            slots *= 2;
            tokens = simta_realloc(tokens, sizeof(yastr) * slots);
        }

        switch (str[ i ]) {
        case ' ':
        case '\t':
            if (state == SMTP_CMD_WORD) {
                tokens[ *len ] = yaslnew(str + start, i - start);
                (*len)++;
                state = SMTP_CMD_WHITESPACE;
            }
            if (state == SMTP_CMD_WHITESPACE) {
                start = i + 1;
            }
            break;

        case '\\':
            if (state == SMTP_CMD_DQUOTE) {
                i++;
            } else if (state == SMTP_CMD_WHITESPACE) {
                state = SMTP_CMD_WORD;
            }
            break;

        case '>':
            if (state == SMTP_CMD_BRACKET || state == SMTP_CMD_WHITESPACE) {
                state = SMTP_CMD_WORD;
            }
            break;

        default:
            if (state == SMTP_CMD_WHITESPACE) {
                state = SMTP_CMD_WORD;
            }

            if (str[ i ] == '<' && state == SMTP_CMD_WORD) {
                state = SMTP_CMD_BRACKET;
            } else if (str[ i ] == '"') {
                if (state == SMTP_CMD_BRACKET) {
                    state = SMTP_CMD_DQUOTE;
                } else if (state == SMTP_CMD_DQUOTE) {
                    state = SMTP_CMD_BRACKET;
                }
            }
            break;
        }
    }

    if (state != SMTP_CMD_WHITESPACE) {
        tokens[ *len ] = yaslnew(str + start, i - start);
        (*len)++;
    }

    return tokens;
}


simta_charset
simta_check_charset(const char *str) {
    const unsigned char *c;
    size_t               charlen;
    int                  i;
    uint32_t             u;
    uint8_t              mask;
    simta_charset        ret = SIMTA_CHARSET_ASCII;

    for (c = (unsigned char *)str; *c != '\0'; c++) {
        if (*c < 0x80) {
            continue;
        }
        ret = SIMTA_CHARSET_UTF8;
        if ((*c & 0xe0) == 0xc0) {
            charlen = 2;
            mask = 0x1f;
        } else if ((*c & 0xf0) == 0xe0) {
            charlen = 3;
            mask = 0x0f;
        } else if ((*c & 0xf8) == 0xf0) {
            charlen = 4;
            mask = 0x07;
        } else {
            /* RFC 3629 limits UTF-8 to 21 bits (4 bytes), so
             * anything else that has the high bit set is either an
             * out-of-order continuation octet or completely invalid.
             */
            return SIMTA_CHARSET_INVALID;
        }

        u = *c & mask;
        for (i = 1; i < charlen; i++) {
            c++;
            if ((*c & 0xc0) != 0x80) {
                return SIMTA_CHARSET_INVALID;
            }
            u <<= 6;
            u |= (*c & 0x3f);
        }

        /* Check that the codepoint used the shortest representation */
        if ((u < 0x80) || ((u < 0x800) && (charlen > 2)) ||
                ((u < 0x10000) && (charlen > 3))) {
            return SIMTA_CHARSET_INVALID;
        }

        /* Check for invalid codepoints */
        /* surrogates */
        if (u >= 0xd800 && u <= 0xdfff) {
            return SIMTA_CHARSET_INVALID;
        }

        /* non-characters */
        if ((u >= 0xfdd0 && u <= 0xfdef) || u == 0xfffe || u == 0xffff ||
                u == 0x1fffe || u == 0x1ffff || u == 0x2fffe || u == 0x2ffff ||
                u == 0x3fffe || u == 0x3ffff || u == 0x4fffe || u == 0x4ffff ||
                u == 0x5fffe || u == 0x5ffff || u == 0x6fffe || u == 0x6ffff ||
                u == 0x7fffe || u == 0x7ffff || u == 0x8fffe || u == 0x8ffff ||
                u == 0x9fffe || u == 0x9ffff || u == 0x0afffe ||
                u == 0x0affff || u == 0x0bfffe || u == 0x0bffff ||
                u == 0x0cfffe || u == 0x0cffff || u == 0x0dfffe ||
                u == 0x0dffff || u == 0x0efffe || u == 0x0effff ||
                u == 0x0ffffe || u == 0x0fffff || u == 0x10fffe ||
                u == 0x10ffff) {
            return SIMTA_CHARSET_INVALID;
        }
    }

    return ret;
}


simta_result
validate_smtp_chars(const yastr line) {
    if (yasllen(line) != strlen(line)) {
        /* out-of-place NULL */
        return SIMTA_ERR;
    }

    if (strchr(line, '\r') || strchr(line, '\n')) {
        /* out-of-place CR or LF */
        return SIMTA_ERR;
    }

    return SIMTA_OK;
}


yastr
simta_slurp(const char *path) {
    SNET   *snet;
    yastr   contents;
    ssize_t chunk;
    char    buf[ 16384 ];

    if ((snet = snet_open(path, O_RDONLY, 0)) == NULL) {
        syslog(LOG_ERR, "Liberror: simta_slurp snet_open %s: %m", path);
        return NULL;
    }

    contents = yaslempty();
    while ((chunk = snet_read(snet, buf, 16384, NULL)) > 0) {
        contents = yaslcatlen(contents, buf, chunk);
    }

    snet_close(snet);
    return contents;
}

/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
