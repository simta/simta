#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "simta.h"

#include "header.h"

const char *simta_progname = "test_header";

static void
test_parse_emailaddr(void **state) {
    assert_int_equal(parse_emailaddr(EMAIL_ADDRESS_NORMAL,
                             "localpart@example.com", NULL, NULL),
            0);
    assert_int_equal(parse_emailaddr(EMAIL_ADDRESS_NORMAL,
                             "\"quoted localpart\"@example.com", NULL, NULL),
            0);
    assert_int_equal(
            parse_emailaddr(EMAIL_ADDRESS_NORMAL,
                    "localpart*+!#$%&-/=?^_`{|}~'@example.com", NULL, NULL),
            0);

    /* malformed address */
    assert_int_equal(parse_emailaddr(EMAIL_ADDRESS_NORMAL,
                             "localpart\"@example.com", NULL, NULL),
            1);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_parse_emailaddr),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
