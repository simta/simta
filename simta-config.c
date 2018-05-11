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

#include "simta.h"

const char *simta_progname = "simta-config";

int
main(int ac, char *av[]) {
    if (ac != 2) {
        fprintf(stderr, "Usage:\t\t%s <file>\n", av[ 0 ]);
        exit(1);
    }

    if (simta_read_config(av[ 1 ]) < 0) {
        exit(1);
    }

    /* Validate the config */
    struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_DEFAULT);
    ucl_parser_add_file(parser, "simta.conf.schema");
    struct ucl_schema_error schema_err;
    if (!ucl_object_validate(
                ucl_parser_get_object(parser), simta_config, &schema_err)) {
        syslog(LOG_ERR, "Config: validation failure %s on: %s", schema_err.msg,
                ucl_object_emit(schema_err.obj, UCL_EMIT_JSON_COMPACT));
        return (-1);
    } else {
        syslog(LOG_INFO, "Config: successfully validated config schema");
    }


    printf("%s", ucl_object_emit(simta_config, UCL_EMIT_CONFIG));
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
