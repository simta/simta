#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdbool.h>

#include "simta.h"

#include "dmarc.h"

const char          *simta_progname = "test_dmarc";

    static void
check_public_suffix( const char *input, const char *expected )
{
    const char      *actual;

    actual = dmarc_orgdomain( input );

    if (( actual == NULL ) || ( expected == NULL )) {
        assert_ptr_equal( expected, actual );
        return;
    }

    assert_string_equal( expected, actual );
}

    static void
test_dmarc_orgdomain( void **state )
{
    simta_read_config( NULL, "{ receive { dmarc { public_suffix_file: public_suffix_list.dat } } }" );

    /* The following tests are based on
     * https://github.com/publicsuffix/list/blob/master/tests/test_psl.txt
     *
     * Some out-of-scope tests were removed, any of potential future interest
     * were merely commented out.
     */
    // Mixed case.
    check_public_suffix( "COM", NULL );
    check_public_suffix( "example.COM", "example.com" );
    check_public_suffix( "WwW.example.COM", "example.com" );
    // Unlisted TLD.
    check_public_suffix( "example", NULL );
    check_public_suffix( "example.example", "example.example" );
    check_public_suffix( "b.example.example", "example.example" );
    check_public_suffix( "a.b.example.example", "example.example" );
    // TLD with only 1 rule.
    check_public_suffix( "biz", NULL );
    check_public_suffix( "domain.biz", "domain.biz" );
    check_public_suffix( "b.domain.biz", "domain.biz" );
    check_public_suffix( "a.b.domain.biz", "domain.biz" );
    // TLD with some 2-level rules.
    check_public_suffix( "com", NULL );
    check_public_suffix( "example.com", "example.com" );
    check_public_suffix( "b.example.com", "example.com" );
    check_public_suffix( "a.b.example.com", "example.com" );
    check_public_suffix( "uk.com", NULL );
    check_public_suffix( "example.uk.com", "example.uk.com" );
    check_public_suffix( "b.example.uk.com", "example.uk.com" );
    check_public_suffix( "a.b.example.uk.com", "example.uk.com" );
    check_public_suffix( "test.ac", "test.ac" );
    // TLD with only 1 (wildcard) rule.
    check_public_suffix( "mm", NULL );
    check_public_suffix( "c.mm", NULL );
    check_public_suffix( "b.c.mm", "b.c.mm" );
    check_public_suffix( "a.b.c.mm", "b.c.mm" );
    // More complex TLD.
    check_public_suffix( "jp", NULL );
    check_public_suffix( "test.jp", "test.jp" );
    check_public_suffix( "www.test.jp", "test.jp" );
    check_public_suffix( "ac.jp", NULL );
    check_public_suffix( "test.ac.jp", "test.ac.jp" );
    check_public_suffix( "www.test.ac.jp", "test.ac.jp" );
    check_public_suffix( "kyoto.jp", NULL );
    check_public_suffix( "test.kyoto.jp", "test.kyoto.jp" );
    check_public_suffix( "ide.kyoto.jp", NULL );
    check_public_suffix( "b.ide.kyoto.jp", "b.ide.kyoto.jp" );
    check_public_suffix( "a.b.ide.kyoto.jp", "b.ide.kyoto.jp" );
    check_public_suffix( "c.kobe.jp", NULL );
    check_public_suffix( "b.c.kobe.jp", "b.c.kobe.jp" );
    check_public_suffix( "a.b.c.kobe.jp", "b.c.kobe.jp" );
    check_public_suffix( "city.kobe.jp", "city.kobe.jp" );
    check_public_suffix( "www.city.kobe.jp", "city.kobe.jp" );
    // TLD with a wildcard rule and exceptions.
    check_public_suffix( "ck", NULL );
    check_public_suffix( "test.ck", NULL );
    check_public_suffix( "b.test.ck", "b.test.ck" );
    check_public_suffix( "a.b.test.ck", "b.test.ck" );
    check_public_suffix( "www.ck", "www.ck" );
    check_public_suffix( "www.www.ck", "www.ck" );
    // US K12.
    check_public_suffix( "us", NULL );
    check_public_suffix( "test.us", "test.us" );
    check_public_suffix( "www.test.us", "test.us" );
    check_public_suffix( "ak.us", NULL );
    check_public_suffix( "test.ak.us", "test.ak.us" );
    check_public_suffix( "www.test.ak.us", "test.ak.us" );
    check_public_suffix( "k12.ak.us", NULL );
    check_public_suffix( "test.k12.ak.us", "test.k12.ak.us" );
    check_public_suffix( "www.test.k12.ak.us", "test.k12.ak.us" );
    // IDN labels.
    /*
    check_public_suffix( "食狮.com.cn", "食狮.com.cn" );
    check_public_suffix( "食狮.公司.cn", "食狮.公司.cn" );
    check_public_suffix( "www.食狮.公司.cn", "食狮.公司.cn" );
    check_public_suffix( "shishi.公司.cn", "shishi.公司.cn" );
    check_public_suffix( "公司.cn", NULL );
    check_public_suffix( "食狮.中国", "食狮.中国" );
    check_public_suffix( "www.食狮.中国", "食狮.中国" );
    check_public_suffix( "shishi.中国", "shishi.中国" );
    check_public_suffix( "中国", NULL );
    */
    // Same as above, but punycoded.
    check_public_suffix( "xn--85x722f.com.cn", "xn--85x722f.com.cn" );
    check_public_suffix( "xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn" );
    check_public_suffix( "www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn" );
    check_public_suffix( "shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn" );
    check_public_suffix( "xn--55qx5d.cn", NULL );
    check_public_suffix( "xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s" );
    check_public_suffix( "www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s" );
    check_public_suffix( "shishi.xn--fiqs8s", "shishi.xn--fiqs8s" );
    check_public_suffix( "xn--fiqs8s", NULL );
}

    int
main( void )
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test( test_dmarc_orgdomain ),
    };

    return cmocka_run_group_tests( tests, NULL, NULL );
}
