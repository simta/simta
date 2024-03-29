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
    SSL_CTX *ssl_ctx;
    int      ssl_mode = 0;

    /* OpenSSL 1.1.0 added auto-init */
#if !OPENSSL_VERSION_PREREQ(1, 1)
    SSL_load_error_strings();
    SSL_library_init();
#endif /* OpenSSL < 1.1.0 */

#ifdef OSSL_IS_RHEL
    /* RedHat-specific feature that forcibly disables SHA1 unless we jump
     * through this hoop.
     * FIXME: This is only to fix TLS < 1.2, we would rather get rid of that. */
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_get0_global_default();
    ossl_ctx_legacy_digest_signatures_allowed_set(libctx, 1, 0);
#endif /* OSSL_IS_RHEL */

    /* FIXME: Once we drop support for OpenSSL < 1.1.0 this can be changed to
     * TLS_server_method()
     */
    if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        syslog(LOG_ERR, "Liberror: tls_server_setup SSL_CTX_new: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

/* OpenSSL 1.1.0 added auto mode for DH */
#if OPENSSL_VERSION_PREREQ(1, 1)
    if (SSL_CTX_set_dh_auto(ssl_ctx, 1) != 1) {
        syslog(LOG_ERR, "Liberror: tls_server_setup SSL_CTX_set_dh_auto: %s",
                ERR_error_string(ERR_get_error(), NULL));
    }
#else
    /* Manual setup */
    static unsigned char dh4096_p[] = {
            0x91,
            0x6B,
            0xA1,
            0x6D,
            0xC7,
            0xE7,
            0x1C,
            0x21,
            0x69,
            0xCE,
            0x7C,
            0x3D,
            0x72,
            0x28,
            0x01,
            0x56,
            0xAE,
            0x71,
            0xFE,
            0xEF,
            0x29,
            0x4B,
            0xDC,
            0xD1,
            0x23,
            0x37,
            0x9E,
            0xA5,
            0x80,
            0x45,
            0xEF,
            0x51,
            0x7A,
            0x65,
            0x77,
            0x41,
            0x90,
            0x5D,
            0xEA,
            0xAB,
            0x52,
            0x39,
            0xF0,
            0xE1,
            0xA9,
            0x77,
            0xA1,
            0xCD,
            0x14,
            0xB1,
            0x8B,
            0x07,
            0x4F,
            0xC5,
            0x44,
            0xD9,
            0x2F,
            0x7A,
            0x74,
            0xFD,
            0xBB,
            0xEA,
            0x6C,
            0x4A,
            0x22,
            0xD0,
            0x78,
            0xCA,
            0xCF,
            0x51,
            0x04,
            0x0E,
            0x88,
            0x44,
            0x65,
            0x41,
            0xD9,
            0x10,
            0x6A,
            0x11,
            0x66,
            0x21,
            0x0E,
            0xE7,
            0x9B,
            0x39,
            0x36,
            0xF6,
            0x59,
            0x15,
            0x83,
            0xFB,
            0x57,
            0x51,
            0x02,
            0xE2,
            0x95,
            0xBE,
            0x85,
            0xDA,
            0x78,
            0x40,
            0xC1,
            0x9A,
            0x0A,
            0xE6,
            0x43,
            0x95,
            0xD8,
            0x7A,
            0x30,
            0x50,
            0x15,
            0x9F,
            0x37,
            0x5E,
            0xAA,
            0x27,
            0x50,
            0xA4,
            0x15,
            0x1C,
            0x6E,
            0xFE,
            0x3B,
            0xA5,
            0xD9,
            0xF6,
            0x0F,
            0xE3,
            0xA5,
            0xFF,
            0xE7,
            0xDA,
            0xD9,
            0x68,
            0x64,
            0x40,
            0xF3,
            0x54,
            0x32,
            0x84,
            0xF3,
            0x12,
            0xC4,
            0xD3,
            0x77,
            0x25,
            0x00,
            0x60,
            0x0D,
            0x95,
            0xEA,
            0x16,
            0xE0,
            0x51,
            0x91,
            0x8F,
            0xF4,
            0x40,
            0x1B,
            0x8A,
            0x2D,
            0x84,
            0x0E,
            0xAC,
            0x53,
            0x58,
            0x08,
            0x4E,
            0x52,
            0xC8,
            0xE4,
            0x6E,
            0xA1,
            0xCB,
            0xA6,
            0xF8,
            0x3B,
            0xE0,
            0x1F,
            0x35,
            0xA6,
            0x37,
            0x6A,
            0x62,
            0x61,
            0xDE,
            0x6D,
            0x5A,
            0x70,
            0x70,
            0x71,
            0xC9,
            0x24,
            0x41,
            0x70,
            0x7C,
            0xCD,
            0x3F,
            0xD9,
            0x38,
            0xDB,
            0x7B,
            0x26,
            0xFA,
            0xB5,
            0x6B,
            0xAC,
            0xF0,
            0x2D,
            0x45,
            0xD8,
            0x55,
            0x68,
            0xCB,
            0x89,
            0x04,
            0x1F,
            0xA0,
            0xAD,
            0x6F,
            0xCB,
            0x05,
            0x04,
            0xB3,
            0x26,
            0xF4,
            0x53,
            0x02,
            0x9E,
            0xB8,
            0x76,
            0x8D,
            0xC6,
            0xE8,
            0x12,
            0x24,
            0x38,
            0x4E,
            0x46,
            0x27,
            0x30,
            0xAE,
            0x55,
            0x1A,
            0xD0,
            0xDB,
            0xCE,
            0x4C,
            0x35,
            0xFA,
            0x7D,
            0x9D,
            0x40,
            0x3E,
            0x66,
            0x7A,
            0xBA,
            0xEA,
            0x78,
            0x6C,
            0x6E,
            0x47,
            0x81,
            0xBD,
            0xB0,
            0x57,
            0x5D,
            0x1C,
            0x94,
            0xCC,
            0x4F,
            0x08,
            0xF3,
            0x5E,
            0xB1,
            0x6E,
            0x0B,
            0xD5,
            0x55,
            0x45,
            0x3F,
            0x8B,
            0xFD,
            0x01,
            0x4E,
            0x01,
            0x21,
            0x34,
            0x20,
            0xA8,
            0x49,
            0xB0,
            0x75,
            0x40,
            0xB4,
            0x55,
            0x17,
            0x3A,
            0x55,
            0x1E,
            0xBA,
            0xF2,
            0x31,
            0x1D,
            0x89,
            0x81,
            0x7A,
            0xB3,
            0x87,
            0xC9,
            0xFB,
            0xBB,
            0x8A,
            0x26,
            0x66,
            0x99,
            0x19,
            0x7E,
            0x3C,
            0xB1,
            0x6A,
            0x9A,
            0x4A,
            0xDC,
            0xE9,
            0x3C,
            0xF0,
            0x7C,
            0x29,
            0xC9,
            0xA1,
            0xE1,
            0x78,
            0x3A,
            0x73,
            0x8F,
            0xEF,
            0x2B,
            0x33,
            0xDF,
            0x0C,
            0x53,
            0xCE,
            0x98,
            0x91,
            0x7C,
            0xE3,
            0xC9,
            0xE2,
            0x26,
            0xD8,
            0x2F,
            0x1A,
            0x69,
            0xCA,
            0xB8,
            0x64,
            0x3B,
            0x43,
            0x38,
            0xBB,
            0xFA,
            0x89,
            0x59,
            0xE0,
            0x3C,
            0xDA,
            0xED,
            0x93,
            0x65,
            0x8B,
            0x12,
            0xED,
            0xDB,
            0x6F,
            0x8F,
            0xC5,
            0xFE,
            0x9C,
            0xEB,
            0x88,
            0xD2,
            0xAB,
            0x89,
            0xAF,
            0xAF,
            0x60,
            0xFF,
            0xFC,
            0x40,
            0x69,
            0x3C,
            0xD0,
            0x22,
            0x02,
            0xB8,
            0x2C,
            0x1D,
            0x9A,
            0x26,
            0x19,
            0x33,
            0xCB,
            0x5A,
            0x9D,
            0x91,
            0xDD,
            0x05,
            0x39,
            0x68,
            0xBA,
            0x15,
            0x2B,
            0x14,
            0xFD,
            0x5D,
            0xB8,
            0x87,
            0x90,
            0xAF,
            0xAA,
            0x5F,
            0x54,
            0xC7,
            0x43,
            0x04,
            0xF4,
            0xE1,
            0x49,
            0x91,
            0x42,
            0x27,
            0x23,
            0xCC,
            0x5A,
            0xFC,
            0xF1,
            0xA6,
            0x2A,
            0x39,
            0x19,
            0xC1,
            0x31,
            0xBF,
            0xE5,
            0x89,
            0x8C,
            0x48,
            0xA7,
            0xCE,
            0x0E,
            0x67,
            0x18,
            0xA1,
            0x07,
            0x8E,
            0xBD,
            0xFE,
            0x2A,
            0x9F,
            0xF0,
            0xA3,
            0x19,
            0xAA,
            0xBC,
            0xD7,
            0x6D,
            0x43,
            0x1C,
            0x3D,
            0x31,
            0xBA,
            0x9B,
            0xD4,
            0xF7,
            0xDF,
            0x2C,
            0x7F,
            0x37,
            0x7B,
            0xD9,
            0x7B,
            0xDE,
            0x62,
            0x5C,
            0xDE,
            0x21,
            0x38,
            0x4D,
            0xB7,
            0x4A,
            0x45,
            0x04,
            0x7D,
            0x76,
            0x4A,
            0x93,
            0xFE,
            0x8E,
            0x49,
            0x04,
            0xD0,
            0xAD,
            0x99,
            0xCD,
            0xF0,
            0x86,
            0x24,
            0x5E,
            0x73,
    };
    static unsigned char dh4096_g[] = {
            0x02,
    };
    DH *dh = NULL;

    if ((dh = DH_new()) == NULL) {
        syslog(LOG_ERR, "Liberror: tls_server_setup DH_new: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    dh->p = BN_bin2bn(dh4096_p, sizeof(dh4096_p), NULL);
    dh->g = BN_bin2bn(dh4096_g, sizeof(dh4096_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) {
        syslog(LOG_ERR, "Liberror: tls_server_setup BN_bin2bn: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    if (SSL_CTX_set_tmp_dh(ssl_ctx, dh) != 1) {
        syslog(LOG_ERR, "Liberror: tls_server_setup SSL_CTX_set_tmp_dh: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }
#endif /* OpenSSL 1.1.0 */

    /* Disable old protocols, prefer server cipher ordering */
#if OPENSSL_VERSION_PREREQ(1, 1)
    SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* FIXME: we want to make the minimum 1.2 when that's a viable choice. */
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
#else
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                         SSL_OP_CIPHER_SERVER_PREFERENCE);
#endif /* OpenSSL 1.1.0 */

    SSL_CTX_set_cipher_list(ssl_ctx, simta_config_str("receive.tls.ciphers"));

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx,
                simta_config_str("receive.tls.key"), SSL_FILETYPE_PEM) != 1) {
        syslog(LOG_ERR,
                "Liberror: tls_server_setup "
                "SSL_CTX_use_PrivateKey_file: %s: %s",
                simta_config_str("receive.tls.key"),
                ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }
    if (SSL_CTX_use_certificate_chain_file(
                ssl_ctx, simta_config_str("receive.tls.certificate")) != 1) {
        syslog(LOG_ERR,
                "Liberror: tls_server_setup "
                "SSL_CTX_use_certificate_chain_file: %s: %s",
                simta_config_str("receive.tls.certificate"),
                ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }
    /* Verify that private key matches cert */
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        syslog(LOG_ERR,
                "Liberror: tls_server_setup "
                "SSL_CTX_check_private_key: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

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

#if OPENSSL_VERSION_PREREQ(1, 1)
    /* OpenSSL >= 1.1.0 automatically enables automatic handling of parameter
     * selection and makes SSL_CTX_set_ecdh_auto a noop, so we don't want
     * to do anything.
     */
#else
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#endif /* OpenSSL < 1.1.0 */
#endif /* OPENSSL_NO_ECDH */

    return ssl_ctx;

error:
    SSL_CTX_free(ssl_ctx);
#if !OPENSSL_VERSION_PREREQ(1, 1)
    if (dh != NULL) {
        DH_free(dh);
    }
#endif /* OpenSSL < 1.1.0 */
    return NULL;
}


SSL_CTX *
tls_client_setup(const char *ciphers) {
    SSL_CTX *ssl_ctx;
    int      ssl_mode = 0;

    /* OpenSSL 1.1.0 added auto-init */
#if !OPENSSL_VERSION_PREREQ(1, 1)
    SSL_load_error_strings();
    SSL_library_init();
#endif /* OpenSSL < 1.1.0 */

    if ((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        syslog(LOG_ERR, "Liberror: tls_client_setup SSL_CTX_new: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    /* Disable old protocols */
#if OPENSSL_VERSION_PREREQ(1, 1)
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
#else
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                         SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif /* OpenSSL 1.1.0 */

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
