#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <cmocka.h>
#include <ldap.h>

#include "simta.h"

#include "simta_ldap.h"
#include "simta_malloc.h"

#define LONG_STRING_CONST(...) #__VA_ARGS__
const char *simta_progname = "test_ldap";
const char *TEST_LDAP_RULE = LONG_STRING_CONST(ldap {
    timeout = 5;
    retries = 3;
    search = [ {
        uri = "ldap:///ou=People,dc=example,dc=com?*?sub?uid=%25s";
    } ] attributes { request = *; } bind {
        method = simple;
    }
});

int
__wrap_ldap_is_ldap_url(const char *url) {
    return 1;
}

int
__wrap_ldap_url_parse(const char *url, LDAPURLDesc **ludpp) {
    *ludpp = calloc(1, sizeof(LDAPURLDesc));
    (*ludpp)->lud_filter = "foo";
    return LDAP_URL_SUCCESS;
}

int
__wrap_ldap_initialize(LDAP **ld, char *uri) {
    *ld = malloc(1);
    return 0;
}

int
__wrap_ldap_set_option(LDAP *ld, int option, const void *invalue) {
    assert_non_null(ld);
    return LDAP_OPT_SUCCESS;
}

int
__wrap_ldap_sasl_bind_s(LDAP *ld, const char *dn, const char *mechanism,
        struct berval *cred, LDAPControl *sctrls[], LDAPControl *cctrls[],
        struct berval **servercredp) {
    assert_non_null(ld);
    return (int)mock();
}

int
__wrap_ldap_unbind_ext(LDAP *ld, LDAPControl *s[], LDAPControl *c[]) {
    return 0;
}

int
__wrap_ldap_msgfree(LDAPMessage *msg) {
    return 0;
}

int
__wrap_ldap_count_entries(LDAP *ld, LDAPMessage *result) {
    assert_non_null(ld);
    return 0;
}

int
__wrap_ldap_search_ext_s(LDAP *ld, char *base, int scope, char *filter,
        char *attrs[], int attrsonly, LDAPControl **s, LDAPControl **c,
        struct timeval *timeout, int sizelimit, LDAPMessage **res) {
    assert_non_null(ld);
    return (int)mock();
}

static void
test_ldap_search_retry(void **state) {
    struct ucl_parser *parser;
    ucl_object_t      *rule;

    parser = simta_ucl_parser();
    ucl_parser_add_string(parser, TEST_LDAP_RULE, 0);
    rule = ucl_parser_get_object(parser);

    will_return(__wrap_ldap_sasl_bind_s, LDAP_SUCCESS);
    will_return(__wrap_ldap_sasl_bind_s, LDAP_OPERATIONS_ERROR);
    will_return(__wrap_ldap_sasl_bind_s, LDAP_SUCCESS);
    will_return(__wrap_ldap_search_ext_s, LDAP_SERVER_DOWN);
    will_return(__wrap_ldap_search_ext_s, LDAP_SUCCESS);

    simta_ldap_reset();
    assert_int_equal(
            simta_ldap_address_local(rule, "postmaster", "example.com"),
            ADDRESS_NOT_FOUND);
}

static void
test_ldap_search_noretry(void **state) {
    struct ucl_parser *parser;
    ucl_object_t      *rule;

    parser = simta_ucl_parser();
    ucl_parser_add_string(parser, TEST_LDAP_RULE, 0);
    rule = ucl_parser_get_object(parser);

    will_return(__wrap_ldap_sasl_bind_s, LDAP_SUCCESS);
    will_return(__wrap_ldap_search_ext_s, LDAP_SUCCESS);

    simta_ldap_reset();
    assert_int_equal(
            simta_ldap_address_local(rule, "postmaster", "example.com"),
            ADDRESS_NOT_FOUND);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_ldap_search_retry),
            cmocka_unit_test(test_ldap_search_noretry),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
