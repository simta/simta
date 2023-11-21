/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <config.h>

#include <syslog.h>

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#ifdef HAVE_LIBSASL
#include <sasl/sasl.h>
#endif /* HAVE_LIBSASL */

#include "simta.h"
#include "tls.h"


static simta_result tls_ca_setup(SSL_CTX *);


static simta_result
tls_ca_setup(SSL_CTX *ctx) {
    if ((simta_config_str("core.tls.ca_file") != NULL) ||
            (simta_config_str("core.tls.ca_directory") != NULL)) {
        if (SSL_CTX_load_verify_locations(ctx,
                    simta_config_str("core.tls.ca_file"),
                    simta_config_str("core.tls.ca_directory")) != 1) {
            syslog(LOG_ERR,
                    "Liberror: tls_ca_setup "
                    "SSL_CTX_load_verify_locations: %s / %s: %s",
                    simta_config_str("core.tls.ca_file"),
                    simta_config_str("core.tls.ca_directory"),
                    ERR_error_string(ERR_get_error(), NULL));
            return SIMTA_ERR;
        }
    } else {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            syslog(LOG_ERR,
                    "Liberror: tls_ca_setup "
                    "SSL_CTX_set_default_verify_paths: %s",
                    ERR_error_string(ERR_get_error(), NULL));
            return SIMTA_ERR;
        }
    }

    return SIMTA_OK;
}

SSL_CTX *
tls_server_setup(void) {
    SSL_CTX            *ssl_ctx;
    int                 ssl_mode = 0;
    ucl_object_iter_t   iter;
    const ucl_object_t *obj;

#ifdef OSSL_IS_RHEL
    /* RedHat-specific feature that forcibly disables SHA1 unless we jump
     * through this hoop.
     * FIXME: This is only to fix TLS < 1.2, we would rather get rid of that. */
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_get0_global_default();
    ossl_ctx_legacy_digest_signatures_allowed_set(libctx, 1, 0);
#endif /* OSSL_IS_RHEL */

    if ((ssl_ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
        syslog(LOG_ERR, "Liberror: tls_server_setup SSL_CTX_new: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if (SSL_CTX_set_dh_auto(ssl_ctx, 1) != 1) {
        syslog(LOG_ERR, "Liberror: tls_server_setup SSL_CTX_set_dh_auto: %s",
                ERR_error_string(ERR_get_error(), NULL));
    }

    /* Disable old protocols, prefer server cipher ordering */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* FIXME: we want to make the minimum 1.2 when that's a viable choice. */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);

    SSL_CTX_set_cipher_list(ssl_ctx, simta_config_str("receive.tls.ciphers"));

    iter = ucl_object_iterate_new(simta_config_obj("receive.tls.key"));
    while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
        if (SSL_CTX_use_PrivateKey_file(
                    ssl_ctx, ucl_object_tostring(obj), SSL_FILETYPE_PEM) != 1) {
            syslog(LOG_ERR,
                    "Liberror: tls_server_setup "
                    "SSL_CTX_use_PrivateKey_file: %s: %s",
                    ucl_object_tostring(obj),
                    ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }
    }

    ucl_object_iterate_reset(iter, simta_config_obj("receive.tls.certificate"));
    while ((obj = ucl_object_iterate_safe(iter, false)) != NULL) {
        if (SSL_CTX_use_certificate_chain_file(
                    ssl_ctx, ucl_object_tostring(obj)) != 1) {
            syslog(LOG_ERR,
                    "Liberror: tls_server_setup "
                    "SSL_CTX_use_certificate_chain_file: %s: %s",
                    ucl_object_tostring(obj),
                    ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }

        /* Verify that private key matches cert */
        if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
            syslog(LOG_ERR,
                    "Liberror: tls_server_setup "
                    "SSL_CTX_check_private_key: %s: %s",
                    ucl_object_tostring(obj),
                    ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }
    }

    ucl_object_iterate_free(iter);

    /* Load CA */
    if (tls_ca_setup(ssl_ctx) != SIMTA_OK) {
        goto error;
    }

    /* Set level of security expecations */
    if (simta_config_bool("receive.tls.client_cert")) {
        ssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    } else {
        ssl_mode = SSL_VERIFY_NONE;
    }
    SSL_CTX_set_verify(ssl_ctx, ssl_mode, NULL);

#ifndef OPENSSL_NO_ECDH
    /* Do not reuse the same ECDH key pair */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);

#endif /* OPENSSL_NO_ECDH */

    return ssl_ctx;

error:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}


SSL_CTX *
tls_client_setup(const char *ciphers) {
    SSL_CTX *ssl_ctx;
    int      ssl_mode = 0;

    if ((ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
        syslog(LOG_ERR, "Liberror: tls_client_setup SSL_CTX_new: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    /* Disable old protocols */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    SSL_CTX_set_cipher_list(ssl_ctx, ciphers);

    /* Load CA */
    if (tls_ca_setup(ssl_ctx) != SIMTA_OK) {
        goto error;
    }

    /* Set level of security expectations */
    /* FIXME: implement rule.tls.verify */
    ssl_mode = SSL_VERIFY_NONE;
    SSL_CTX_set_verify(ssl_ctx, ssl_mode, NULL);
    return ssl_ctx;

error:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}

int
tls_client_cert(const char *hostname, const SSL *ssl) {
    char  buf[ 1024 ];
    X509 *peer;
    int   rc;

    if (ssl == NULL) {
        syslog(LOG_ERR, "TLS %s: tls_client_cert: ssl is NULL", hostname);
        return 1;
    }

    if ((peer = SSL_get_peer_certificate(ssl)) == NULL) {
        syslog(LOG_ERR,
                "Liberror: tls_client_cert "
                "SSL_get_peer_certificate: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

    syslog(LOG_INFO, "TLS %s: cert subject: %s", hostname,
            X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof(buf)));

    X509_free(peer);

    if ((rc = SSL_get_verify_result(ssl)) != X509_V_OK) {
        syslog(LOG_ERR, "TLS %s: verify failed: %s", hostname,
                X509_verify_cert_error_string(rc));
        return 1;
    }

    return 0;
}
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
