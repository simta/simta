#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "simta.h"

#include "header.h"
#include "yasl.h"

const char *simta_progname = "test_header";

static void
test_parse_emailaddr(void **state) {
    assert_int_equal(parse_emailaddr(EMAIL_ADDRESS_NORMAL,
                             "localpart@example.com", NULL, NULL),
            SIMTA_OK);
}

static void
test_is_emailaddr_01(void **state) {
    assert_true(is_emailaddr("local.part@example.com"));
}

static void
test_is_emailaddr_02(void **state) {
    assert_true(is_emailaddr("_l.o.c.a.l.p.a.r.t_@example.com"));
}

static void
test_is_emailaddr_03(void **state) {
    assert_true(is_emailaddr("\"quoted localpart\"@example.com"));
}

static void
test_is_emailaddr_04(void **state) {
    assert_true(is_emailaddr("\".quoted..local...part.\"@example.com"));
}

static void
test_is_emailaddr_05(void **state) {
    assert_true(is_emailaddr("localpart*+!#$%&-/=?^_`{|}~'@example.com"));
}

static void
test_is_emailaddr_06(void **state) {
    assert_true(is_emailaddr("local.part@foo.example.com"));
}

/* malformed addresses */

static void
test_is_emailaddr_invalid_01(void **state) {
    assert_false(is_emailaddr("\"localpart@example.com"));
}

static void
test_is_emailaddr_invalid_02(void **state) {
    assert_false(is_emailaddr("localpart\"@example.com"));
}

static void
test_is_emailaddr_invalid_03(void **state) {
    assert_false(is_emailaddr("local..part@example.com"));
}

static void
test_is_emailaddr_invalid_04(void **state) {
    assert_false(is_emailaddr("localpart.@example.com"));
}

static void
test_is_emailaddr_invalid_05(void **state) {
    assert_false(is_emailaddr(".localpart@example.com"));
}

static void
test_is_emailaddr_invalid_06(void **state) {
    assert_false(is_emailaddr(".local.part@example.com"));
}

static void
test_is_emailaddr_invalid_07(void **state) {
    assert_false(is_emailaddr("local.part.@example.com"));
}

static void
test_is_emailaddr_invalid_08(void **state) {
    assert_false(is_emailaddr(".local.part.@example.com"));
}

static void
test_is_emailaddr_invalid_09(void **state) {
    assert_false(is_emailaddr("local.par..t@example.com"));
}

static void
test_is_emailaddr_invalid_10(void **state) {
    assert_false(is_emailaddr("localpart@example..com"));
}

static void
test_is_emailaddr_invalid_11(void **state) {
    assert_false(is_emailaddr("localpart@.example.com"));
}

/* RFC 5321 4.1.2. Command Argument Syntax
 *
 * Domain         = sub-domain *("." sub-domain)
 */
static void
test_is_emailaddr_invalid_12(void **state) {
    assert_false(is_emailaddr("localpart@example.com."));
}

static void
test_is_emailaddr_invalid_13(void **state) {
    assert_false(is_emailaddr("localpart\x7F@example.com"));
}

static void
test_is_emailaddr_invalid_14(void **state) {
    assert_false(is_emailaddr("\"localpart\x7F\"@example.com"));
}

static void
test_is_emailaddr_invalid_15(void **state) {
    assert_false(is_emailaddr("\x08localpart@example.com"));
}

static void
test_is_emailaddr_invalid_16(void **state) {
    assert_false(is_emailaddr("\"\x08localpart\"@example.com"));
}

static void test_correct_emailaddr_01(void **state) {
    yastr addr = yaslauto("localpart@example.com");
    assert_int_equal(correct_emailaddr(&addr, "example.com"), SIMTA_OK);
    assert_string_equal(addr, "localpart@example.com");
    yaslfree(addr);
}

static void test_correct_emailaddr_02(void **state) {
    yastr addr = yaslauto("localpart");
    assert_int_equal(correct_emailaddr(&addr, "example.com"), SIMTA_OK);
    assert_string_equal(addr, "localpart@example.com");
    yaslfree(addr);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_parse_emailaddr),
            cmocka_unit_test(test_is_emailaddr_01),
            cmocka_unit_test(test_is_emailaddr_02),
            cmocka_unit_test(test_is_emailaddr_03),
            cmocka_unit_test(test_is_emailaddr_04),
            cmocka_unit_test(test_is_emailaddr_05),
            cmocka_unit_test(test_is_emailaddr_06),
            cmocka_unit_test(test_is_emailaddr_invalid_01),
            cmocka_unit_test(test_is_emailaddr_invalid_02),
            cmocka_unit_test(test_is_emailaddr_invalid_03),
            cmocka_unit_test(test_is_emailaddr_invalid_04),
            cmocka_unit_test(test_is_emailaddr_invalid_05),
            cmocka_unit_test(test_is_emailaddr_invalid_06),
            cmocka_unit_test(test_is_emailaddr_invalid_07),
            cmocka_unit_test(test_is_emailaddr_invalid_08),
            cmocka_unit_test(test_is_emailaddr_invalid_09),
            cmocka_unit_test(test_is_emailaddr_invalid_10),
            cmocka_unit_test(test_is_emailaddr_invalid_11),
            cmocka_unit_test(test_is_emailaddr_invalid_12),
            cmocka_unit_test(test_is_emailaddr_invalid_13),
            cmocka_unit_test(test_is_emailaddr_invalid_14),
            cmocka_unit_test(test_is_emailaddr_invalid_15),
            cmocka_unit_test(test_is_emailaddr_invalid_16),
            cmocka_unit_test(test_correct_emailaddr_01),
            cmocka_unit_test(test_correct_emailaddr_02),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
