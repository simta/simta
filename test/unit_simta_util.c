#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <cmocka.h>

#include "simta.h"
#include "simta_util.h"

const char *simta_progname = "test_simta_smtp";


static void
test_env_string(void **state) {
    yastr str = env_string("FOO", "bar");
    assert_string_equal(str, "FOO=bar");
    yaslfree(str);
}


static void
check_split_smtp_command(const char *in, size_t len, const char **out) {
    yastr  str = yaslauto(in);
    size_t ac;
    yastr *av = split_smtp_command(str, &ac);
    assert_int_equal(ac, len);
    for (int i = 0; i < ac; i++) {
        assert_string_equal(av[ i ], out[ i ]);
    }
    yaslfreesplitres(av, ac);
    yaslfree(str);
}


static void
test_split_smtp_command_00(void **state) {
    const char *out[] = {"QUIT"};
    check_split_smtp_command("QUIT", 1, out);
    check_split_smtp_command("QUIT \t", 1, out);
    check_split_smtp_command(" \tQUIT \t", 1, out);
    check_split_smtp_command(" \tQUIT", 1, out);
}


static void
test_split_smtp_command_01(void **state) {
    const char *out[] = {"MAIL", "FROM:<foo@example.com>"};
    check_split_smtp_command("MAIL FROM:<foo@example.com>", 2, out);
    check_split_smtp_command("MAIL  FROM:<foo@example.com>\t", 2, out);
}


static void
test_split_smtp_command_02(void **state) {
    const char *out[] = {"MAIL", "FROM:<\"foo bar\"@example.com>"};
    check_split_smtp_command("MAIL FROM:<\"foo bar\"@example.com>", 2, out);
    check_split_smtp_command(" MAIL\tFROM:<\"foo bar\"@example.com>\t", 2, out);
}


static void
test_split_smtp_command_03(void **state) {
    const char *out[] = {"MAIL", "FROM:<\"foo > <\"@example.com>"};
    check_split_smtp_command("MAIL FROM:<\"foo > <\"@example.com>", 2, out);
    check_split_smtp_command(" MAIL\tFROM:<\"foo > <\"@example.com>\t", 2, out);
}


static void
test_split_smtp_command_04(void **state) {
    const char *out[] = {"MAIL", "FROM:<\"foo\\\"  > \\\\<\"@example.com>"};
    check_split_smtp_command(
            "MAIL FROM:<\"foo\\\"  > \\\\<\"@example.com>", 2, out);
    check_split_smtp_command(
            " MAIL\tFROM:<\"foo\\\"  > \\\\<\"@example.com>\t", 2, out);
}


static void
test_split_smtp_command_05(void **state) {
    const char *out[] = {"MAIL", "FROM:<foo   bar@example.com>"};
    check_split_smtp_command("MAIL FROM:<foo   bar@example.com>", 2, out);
    check_split_smtp_command("MAIL  FROM:<foo   bar@example.com>\t", 2, out);
}


static void
test_split_smtp_command_06(void **state) {
    const char *out[] = {"this", "is", "a", "long", "command", "that", "should",
            "require", "a", "couple", "of", "reallocations"};
    check_split_smtp_command(
            "this is a long command that should require a couple of "
            "reallocations",
            12, out);
}


static void
test_split_smtp_command_07(void **state) {
    size_t ac = 2;
    assert_null(split_smtp_command(NULL, &ac));
    assert_int_equal(ac, 2);
}


static void
test_split_smtp_command_08(void **state) {
    const char *out[] = {"EHLO", "\\"};
    check_split_smtp_command("EHLO \\", 2, out);
    check_split_smtp_command("EHLO  \\    ", 2, out);
}


static void
test_split_smtp_command_09(void **state) {
    const char *out[] = {"EHLO", ">", "< "};
    check_split_smtp_command("EHLO > < ", 3, out);
    check_split_smtp_command("EHLO  >    < ", 3, out);
}


static void
test_split_smtp_command_10(void **state) {
    const char *out[] = {"EHLO", ">"};
    check_split_smtp_command("EHLO >", 2, out);
    check_split_smtp_command("EHLO  >    ", 2, out);
}


static void
test_validate_smtp_chars(void **state) {
    yastr str = yaslauto(
            " !\"#$%&\'()*+,-./"
            "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
            "abcdefghijklmnopqrstuvwxyz{|}~");
    assert_int_equal(validate_smtp_chars(str), SIMTA_OK);
    str[ 0 ] = '\0';
    assert_int_equal(validate_smtp_chars(str), SIMTA_ERR);
    str[ 0 ] = '\r';
    assert_int_equal(validate_smtp_chars(str), SIMTA_ERR);
    str[ 0 ] = '\n';
    assert_int_equal(validate_smtp_chars(str), SIMTA_ERR);
    yaslfree(str);
}


int
main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_env_string),
            cmocka_unit_test(test_split_smtp_command_00),
            cmocka_unit_test(test_split_smtp_command_01),
            cmocka_unit_test(test_split_smtp_command_02),
            cmocka_unit_test(test_split_smtp_command_03),
            cmocka_unit_test(test_split_smtp_command_04),
            cmocka_unit_test(test_split_smtp_command_05),
            cmocka_unit_test(test_split_smtp_command_06),
            cmocka_unit_test(test_split_smtp_command_07),
            cmocka_unit_test(test_split_smtp_command_08),
            cmocka_unit_test(test_split_smtp_command_09),
            cmocka_unit_test(test_split_smtp_command_10),
            cmocka_unit_test(test_validate_smtp_chars),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
