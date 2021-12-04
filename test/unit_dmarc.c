#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <cmocka.h>

#include "simta.h"

#include "dmarc.h"

const char *simta_progname = "test_dmarc";

static void
check_public_suffix(const char *input, const char *expected) {
    const char *actual;

    actual = dmarc_orgdomain(input);

    if ((actual == NULL) || (expected == NULL)) {
        assert_ptr_equal(expected, actual);
        return;
    }

    assert_string_equal(expected, actual);
}


/* The following tests are based on
 * https://github.com/publicsuffix/list/blob/master/tests/test_psl.txt
 *
 * Some out-of-scope tests were removed, any of potential future interest
 * are merely commented out.
 */


// Mixed case.
static void
test_dmarc_orgdomain_01(void **state) {
    check_public_suffix("COM", NULL);
}

static void
test_dmarc_orgdomain_02(void **state) {
    check_public_suffix("example.COM", "example.com");
}

static void
test_dmarc_orgdomain_03(void **state) {
    check_public_suffix("WwW.example.COM", "example.com");
}

// Unlisted TLD.
static void
test_dmarc_orgdomain_04(void **state) {
    check_public_suffix("example", NULL);
}

static void
test_dmarc_orgdomain_05(void **state) {
    check_public_suffix("example.example", "example.example");
}

static void
test_dmarc_orgdomain_06(void **state) {
    check_public_suffix("b.example.example", "example.example");
}

static void
test_dmarc_orgdomain_07(void **state) {
    check_public_suffix("a.b.example.example", "example.example");
}

// TLD with only 1 rule.
static void
test_dmarc_orgdomain_08(void **state) {
    check_public_suffix("biz", NULL);
}

static void
test_dmarc_orgdomain_09(void **state) {
    check_public_suffix("domain.biz", "domain.biz");
}

static void
test_dmarc_orgdomain_10(void **state) {
    check_public_suffix("b.domain.biz", "domain.biz");
}

static void
test_dmarc_orgdomain_11(void **state) {
    check_public_suffix("a.b.domain.biz", "domain.biz");
}

// TLD with some 2-level rules.
static void
test_dmarc_orgdomain_12(void **state) {
    check_public_suffix("com", NULL);
}

static void
test_dmarc_orgdomain_13(void **state) {
    check_public_suffix("example.com", "example.com");
}

static void
test_dmarc_orgdomain_14(void **state) {
    check_public_suffix("b.example.com", "example.com");
}

static void
test_dmarc_orgdomain_15(void **state) {
    check_public_suffix("a.b.example.com", "example.com");
}

static void
test_dmarc_orgdomain_16(void **state) {
    check_public_suffix("uk.com", NULL);
}

static void
test_dmarc_orgdomain_17(void **state) {
    check_public_suffix("example.uk.com", "example.uk.com");
}

static void
test_dmarc_orgdomain_18(void **state) {
    check_public_suffix("b.example.uk.com", "example.uk.com");
}

static void
test_dmarc_orgdomain_19(void **state) {
    check_public_suffix("a.b.example.uk.com", "example.uk.com");
}

static void
test_dmarc_orgdomain_20(void **state) {
    check_public_suffix("test.ac", "test.ac");
}

// TLD with only 1 (wildcard) rule.
static void
test_dmarc_orgdomain_21(void **state) {
    check_public_suffix("mm", NULL);
}

static void
test_dmarc_orgdomain_22(void **state) {
    check_public_suffix("c.mm", NULL);
}

static void
test_dmarc_orgdomain_23(void **state) {
    check_public_suffix("b.c.mm", "b.c.mm");
}

static void
test_dmarc_orgdomain_24(void **state) {
    check_public_suffix("a.b.c.mm", "b.c.mm");
}

// More complex TLD.
static void
test_dmarc_orgdomain_25(void **state) {
    check_public_suffix("jp", NULL);
}

static void
test_dmarc_orgdomain_26(void **state) {
    check_public_suffix("test.jp", "test.jp");
}

static void
test_dmarc_orgdomain_27(void **state) {
    check_public_suffix("www.test.jp", "test.jp");
}

static void
test_dmarc_orgdomain_28(void **state) {
    check_public_suffix("ac.jp", NULL);
}

static void
test_dmarc_orgdomain_29(void **state) {
    check_public_suffix("test.ac.jp", "test.ac.jp");
}

static void
test_dmarc_orgdomain_30(void **state) {
    check_public_suffix("www.test.ac.jp", "test.ac.jp");
}

static void
test_dmarc_orgdomain_31(void **state) {
    check_public_suffix("kyoto.jp", NULL);
}

static void
test_dmarc_orgdomain_32(void **state) {
    check_public_suffix("test.kyoto.jp", "test.kyoto.jp");
}

static void
test_dmarc_orgdomain_33(void **state) {
    check_public_suffix("ide.kyoto.jp", NULL);
}

static void
test_dmarc_orgdomain_34(void **state) {
    check_public_suffix("b.ide.kyoto.jp", "b.ide.kyoto.jp");
}

static void
test_dmarc_orgdomain_35(void **state) {
    check_public_suffix("a.b.ide.kyoto.jp", "b.ide.kyoto.jp");
}

static void
test_dmarc_orgdomain_36(void **state) {
    check_public_suffix("c.kobe.jp", NULL);
}

static void
test_dmarc_orgdomain_37(void **state) {
    check_public_suffix("b.c.kobe.jp", "b.c.kobe.jp");
}

static void
test_dmarc_orgdomain_38(void **state) {
    check_public_suffix("a.b.c.kobe.jp", "b.c.kobe.jp");
}

static void
test_dmarc_orgdomain_39(void **state) {
    check_public_suffix("city.kobe.jp", "city.kobe.jp");
}

static void
test_dmarc_orgdomain_40(void **state) {
    check_public_suffix("www.city.kobe.jp", "city.kobe.jp");
}

// TLD with a wildcard rule and exceptions.
static void
test_dmarc_orgdomain_41(void **state) {
    check_public_suffix("ck", NULL);
}

static void
test_dmarc_orgdomain_42(void **state) {
    check_public_suffix("test.ck", NULL);
}

static void
test_dmarc_orgdomain_43(void **state) {
    check_public_suffix("b.test.ck", "b.test.ck");
}

static void
test_dmarc_orgdomain_44(void **state) {
    check_public_suffix("a.b.test.ck", "b.test.ck");
}

static void
test_dmarc_orgdomain_45(void **state) {
    check_public_suffix("www.ck", "www.ck");
}

static void
test_dmarc_orgdomain_46(void **state) {
    check_public_suffix("www.www.ck", "www.ck");
}

// US K12.
static void
test_dmarc_orgdomain_47(void **state) {
    check_public_suffix("us", NULL);
}

static void
test_dmarc_orgdomain_48(void **state) {
    check_public_suffix("test.us", "test.us");
}

static void
test_dmarc_orgdomain_49(void **state) {
    check_public_suffix("www.test.us", "test.us");
}

static void
test_dmarc_orgdomain_50(void **state) {
    check_public_suffix("ak.us", NULL);
}

static void
test_dmarc_orgdomain_51(void **state) {
    check_public_suffix("test.ak.us", "test.ak.us");
}

static void
test_dmarc_orgdomain_52(void **state) {
    check_public_suffix("www.test.ak.us", "test.ak.us");
}

static void
test_dmarc_orgdomain_53(void **state) {
    check_public_suffix("k12.ak.us", NULL);
}

static void
test_dmarc_orgdomain_54(void **state) {
    check_public_suffix("test.k12.ak.us", "test.k12.ak.us");
}

static void
test_dmarc_orgdomain_55(void **state) {
    check_public_suffix("www.test.k12.ak.us", "test.k12.ak.us");
}

// IDN labels.
/*
static void
test_dmarc_orgdomain_56(void **state) {
    check_public_suffix("食狮.com.cn", "食狮.com.cn");
}

static void
test_dmarc_orgdomain_57(void **state) {
    check_public_suffix("食狮.公司.cn", "食狮.公司.cn");
}

static void
test_dmarc_orgdomain_58(void **state) {
    check_public_suffix("www.食狮.公司.cn", "食狮.公司.cn");
}

static void
test_dmarc_orgdomain_59(void **state) {
    check_public_suffix("shishi.公司.cn", "shishi.公司.cn");
}

static void
test_dmarc_orgdomain_60(void **state) {
    check_public_suffix("公司.cn", NULL);
}

static void
test_dmarc_orgdomain_61(void **state) {
    check_public_suffix("食狮.中国", "食狮.中国");
}

static void
test_dmarc_orgdomain_62(void **state) {
    check_public_suffix("www.食狮.中国", "食狮.中国");
}

static void
test_dmarc_orgdomain_63(void **state) {
    check_public_suffix("shishi.中国", "shishi.中国");
}

static void
test_dmarc_orgdomain_64(void **state) {
    check_public_suffix("中国", NULL);
}
*/

// Same as above, but punycoded.
static void
test_dmarc_orgdomain_65(void **state) {
    check_public_suffix("xn--85x722f.com.cn", "xn--85x722f.com.cn");
}

static void
test_dmarc_orgdomain_66(void **state) {
    check_public_suffix(
            "xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn");
}

static void
test_dmarc_orgdomain_67(void **state) {
    check_public_suffix(
            "www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn");
}

static void
test_dmarc_orgdomain_68(void **state) {
    check_public_suffix("shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn");
}

static void
test_dmarc_orgdomain_69(void **state) {
    check_public_suffix("xn--55qx5d.cn", NULL);
}

static void
test_dmarc_orgdomain_70(void **state) {
    check_public_suffix("xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s");
}

static void
test_dmarc_orgdomain_71(void **state) {
    check_public_suffix("www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s");
}

static void
test_dmarc_orgdomain_72(void **state) {
    check_public_suffix("shishi.xn--fiqs8s", "shishi.xn--fiqs8s");
}

static void
test_dmarc_orgdomain_73(void **state) {
    check_public_suffix("xn--fiqs8s", NULL);
}


int
main(void) {
    simta_read_config(NULL,
            "{ receive { dmarc { public_suffix_file: public_suffix_list.dat } "
            "} }");

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_dmarc_orgdomain_01),
            cmocka_unit_test(test_dmarc_orgdomain_02),
            cmocka_unit_test(test_dmarc_orgdomain_03),
            cmocka_unit_test(test_dmarc_orgdomain_04),
            cmocka_unit_test(test_dmarc_orgdomain_05),
            cmocka_unit_test(test_dmarc_orgdomain_06),
            cmocka_unit_test(test_dmarc_orgdomain_07),
            cmocka_unit_test(test_dmarc_orgdomain_08),
            cmocka_unit_test(test_dmarc_orgdomain_09),
            cmocka_unit_test(test_dmarc_orgdomain_10),
            cmocka_unit_test(test_dmarc_orgdomain_11),
            cmocka_unit_test(test_dmarc_orgdomain_12),
            cmocka_unit_test(test_dmarc_orgdomain_13),
            cmocka_unit_test(test_dmarc_orgdomain_14),
            cmocka_unit_test(test_dmarc_orgdomain_15),
            cmocka_unit_test(test_dmarc_orgdomain_16),
            cmocka_unit_test(test_dmarc_orgdomain_17),
            cmocka_unit_test(test_dmarc_orgdomain_18),
            cmocka_unit_test(test_dmarc_orgdomain_19),
            cmocka_unit_test(test_dmarc_orgdomain_20),
            cmocka_unit_test(test_dmarc_orgdomain_21),
            cmocka_unit_test(test_dmarc_orgdomain_22),
            cmocka_unit_test(test_dmarc_orgdomain_23),
            cmocka_unit_test(test_dmarc_orgdomain_24),
            cmocka_unit_test(test_dmarc_orgdomain_25),
            cmocka_unit_test(test_dmarc_orgdomain_26),
            cmocka_unit_test(test_dmarc_orgdomain_27),
            cmocka_unit_test(test_dmarc_orgdomain_28),
            cmocka_unit_test(test_dmarc_orgdomain_29),
            cmocka_unit_test(test_dmarc_orgdomain_30),
            cmocka_unit_test(test_dmarc_orgdomain_31),
            cmocka_unit_test(test_dmarc_orgdomain_32),
            cmocka_unit_test(test_dmarc_orgdomain_33),
            cmocka_unit_test(test_dmarc_orgdomain_34),
            cmocka_unit_test(test_dmarc_orgdomain_35),
            cmocka_unit_test(test_dmarc_orgdomain_36),
            cmocka_unit_test(test_dmarc_orgdomain_37),
            cmocka_unit_test(test_dmarc_orgdomain_38),
            cmocka_unit_test(test_dmarc_orgdomain_39),
            cmocka_unit_test(test_dmarc_orgdomain_40),
            cmocka_unit_test(test_dmarc_orgdomain_41),
            cmocka_unit_test(test_dmarc_orgdomain_42),
            cmocka_unit_test(test_dmarc_orgdomain_43),
            cmocka_unit_test(test_dmarc_orgdomain_44),
            cmocka_unit_test(test_dmarc_orgdomain_45),
            cmocka_unit_test(test_dmarc_orgdomain_46),
            cmocka_unit_test(test_dmarc_orgdomain_47),
            cmocka_unit_test(test_dmarc_orgdomain_48),
            cmocka_unit_test(test_dmarc_orgdomain_49),
            cmocka_unit_test(test_dmarc_orgdomain_50),
            cmocka_unit_test(test_dmarc_orgdomain_51),
            cmocka_unit_test(test_dmarc_orgdomain_52),
            cmocka_unit_test(test_dmarc_orgdomain_53),
            cmocka_unit_test(test_dmarc_orgdomain_54),
            cmocka_unit_test(test_dmarc_orgdomain_55),
            /*
            cmocka_unit_test(test_dmarc_orgdomain_56),
            cmocka_unit_test(test_dmarc_orgdomain_57),
            cmocka_unit_test(test_dmarc_orgdomain_58),
            cmocka_unit_test(test_dmarc_orgdomain_59),
            cmocka_unit_test(test_dmarc_orgdomain_60),
            cmocka_unit_test(test_dmarc_orgdomain_61),
            cmocka_unit_test(test_dmarc_orgdomain_62),
            cmocka_unit_test(test_dmarc_orgdomain_63),
            cmocka_unit_test(test_dmarc_orgdomain_64),
            */
            cmocka_unit_test(test_dmarc_orgdomain_65),
            cmocka_unit_test(test_dmarc_orgdomain_66),
            cmocka_unit_test(test_dmarc_orgdomain_67),
            cmocka_unit_test(test_dmarc_orgdomain_68),
            cmocka_unit_test(test_dmarc_orgdomain_69),
            cmocka_unit_test(test_dmarc_orgdomain_70),
            cmocka_unit_test(test_dmarc_orgdomain_71),
            cmocka_unit_test(test_dmarc_orgdomain_72),
            cmocka_unit_test(test_dmarc_orgdomain_73),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
