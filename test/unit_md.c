#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <cmocka.h>

#include "simta.h"

#include "md.h"

const char *simta_progname = "test_md";

static void
test_md_sha1(void **state) {
    struct message_digest md;

    md_init(&md);
    md_reset(&md, "sha1");
    md_update(&md, "hello", 5);
    md_update(&md, "world", 5);
    md_finalize(&md);
    assert_string_equal(md.md_b16, "6adfb183a4a2c94a2f92dab5ade762a47889a5a1");
    assert_int_equal(md.md_ctx_bytes, 10);
    md_cleanup(&md);
}

static void
test_md_sha256(void **state) {
    struct message_digest md;

    md_init(&md);
    md_reset(&md, "sha256");
    md_update(&md, "helloworld", 10);
    md_finalize(&md);
    assert_string_equal(md.md_b16,
            "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af");
    assert_int_equal(md.md_ctx_bytes, 10);
    md_cleanup(&md);
}

static void
test_md_reset(void **state) {
    struct message_digest md;

    md_init(&md);
    md_finalize(&md); /* Really just for coverage */
    md_reset(&md, "sha1");
    md_update(&md, "blackholesun", 12);
    md_reset(&md, "sha256");
    md_update(&md, "helloworld", 10);
    md_finalize(&md);
    assert_string_equal(md.md_b16,
            "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af");
    assert_int_equal(md.md_ctx_bytes, 10);
    md_cleanup(&md);
}

int
main(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    OpenSSL_add_all_digests();
#endif /* OpenSSL < 1.1.0 */

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_md_sha1),
            cmocka_unit_test(test_md_sha256),
            cmocka_unit_test(test_md_reset),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
