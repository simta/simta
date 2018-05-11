/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

int
main(int ac, char *av[]) {
    struct ucl_parser *parser;

    if (ac != 3) {
        fprintf(stderr, "Usage:\t\t%s <file> <slug>\n", av[ 0 ]);
        exit(1);
    }

    parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    if (!ucl_parser_add_file(parser, av[ 1 ])) {
        exit(1);
    }

    printf("#define LONG_STRING_CONST(...) #__VA_ARGS__\n"
           "const char *SIMTA_%s = LONG_STRING_CONST(\n",
            av[ 2 ]);
    printf("%s", ucl_object_emit(
                         ucl_parser_get_object(parser), UCL_EMIT_JSON_COMPACT));
    printf("\n);\n");
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
