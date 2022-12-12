#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <cmocka.h>

#include "simta.h"

#include "yasl.h"

const char *simta_progname = "test_yasl";

static void
test_yasl_rangesepleft(void **state) {
    yastr str = yaslauto("foo@example@host.com");
    yaslrangesepleft(str, '@');
    assert_string_equal(str, "foo");
}

static void
test_yasl_rangesepright(void **state) {
    yastr str = yaslauto("foo@example@host.com");
    yaslrangesepright(str, '@');
    assert_string_equal(str, "example@host.com");
}

static void
test_yasl_rangeseprleft(void **state) {
    yastr str = yaslauto("foo@example@host.com");
    yaslrangeseprleft(str, '@');
    assert_string_equal(str, "foo@example");
}

static void
test_yasl_rangeseprright(void **state) {
    yastr str = yaslauto("foo@example@host.com");
    yaslrangeseprright(str, '@');
    assert_string_equal(str, "host.com");
}

int
main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_yasl_rangesepleft),
            cmocka_unit_test(test_yasl_rangesepright),
            cmocka_unit_test(test_yasl_rangeseprleft),
            cmocka_unit_test(test_yasl_rangeseprright),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
