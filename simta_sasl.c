/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>

#include "simta.h"
#include "simta_sasl.h"

static int simta_sasl_log( void *, int, const char * );

static sasl_callback_t server_callbacks[] = {
    {
        SASL_CB_LOG, (sasl_callback_ft)&simta_sasl_log, NULL
    }, {
        SASL_CB_LIST_END, NULL, NULL
    }
};

    int
simta_sasl_log( void *context __attribute__((unused)), int priority,
        const char *message )
{
    const char *label;

    if ( message == NULL ) {
        return SASL_BADPARAM;
    }

    switch (priority) {
    case SASL_LOG_ERR:
        label = "Error";
        break;
    case SASL_LOG_NOTE:
        label = "Info";
        break;
    default:
        label = "Other";
        break;
    }

    syslog( LOG_ERR, "SASL %s: %s", label, message );

    return( SASL_OK );
}

    int
simta_sasl_init( void )
{
    int     rc;

    if (( rc = sasl_server_init( server_callbacks, "simta" )) != SASL_OK ) {
        syslog( LOG_ERR, "Liberror: sasl_server_init: %s",
                sasl_errstring( rc, NULL, NULL ));
        return( 1 );
    }
    return( 0 );
}

    struct simta_sasl *
simta_sasl_server_new( int tls )
{
    int                 rc;
    sasl_conn_t         *conn;
    struct simta_sasl   *ret = NULL;

    ret = calloc( 1, sizeof( struct simta_sasl ));

    if (( rc = sasl_server_new( "smtp", simta_sasl_domain, NULL, NULL, NULL,
            NULL, 0, &conn )) != SASL_OK ) {
        syslog( LOG_ERR, "Liberror: sasl_server_new: %s",
                sasl_errstring( rc, NULL, NULL ));
        goto error;
    }

    ret = calloc( 1, sizeof( struct simta_sasl ));
    ret->s_conn = conn;
    if ( simta_sasl_reset( ret, tls ) != 0 ) {
        sasl_dispose( &conn );
        free( ret );
        ret = NULL;
    }

    ret->s_response = yaslempty( );

error:
    return( ret );
}

    int
simta_sasl_server_auth( struct simta_sasl *s, const char *mech,
        const char *resp )
{
    int             rc;
    int             proprc;
    yastr           buf = NULL;
    unsigned int    buflen = 0;
    const char      *out;
    unsigned int    outlen;
    char            *p;

    yaslclear( s->s_response );

    if ( resp ) {
        buf = yaslMakeRoomFor( yaslempty( ), strlen( resp ) * 2 );
        if ( mech && ( strcmp( resp, "=" ) == 0 )) {
            buf[ 0 ] = '\0';
        } else if ( sasl_decode64( resp, strlen( resp ), buf,
                yaslAllocSize( buf ), &buflen ) != SASL_OK ) {
            syslog( LOG_ERR, "SASL: unable to decode %s", resp );
            s->s_response = yaslcpy( s->s_response, "BASE64 decoding failed" );
            return( 501 );
        }
        yaslIncrLen( buf, buflen );
    }

    if ( mech ) {
        rc = sasl_server_start( s->s_conn, mech, resp ? buf : NULL, buflen,
                &out, &outlen );
    } else {
        rc = sasl_server_step( s->s_conn, buf, buflen, &out, &outlen );
    }

    yaslfree( buf );

    proprc = sasl_getprop( s->s_conn, SASL_USERNAME,
            (const void **) &s->s_auth_id );

    switch( rc ) {
    case SASL_OK:
        /* RFC 4954 6 Status Codes
         * 235 2.7.0  Authentication Succeeded
         * This response to the AUTH command indicates that the authentication
         * was successful.
         */
        if ( proprc != SASL_OK ) {
            /* Auth succeeded, but we couldn't get the identity. This shouldn't
             * happen.
             */
            syslog( LOG_ERR, "SASL: %s", sasl_errdetail( s->s_conn ));
            return( 454 );
        }
        sasl_getprop( s->s_conn, SASL_MECHNAME, (const void**) &s->s_mech );

        /* If the user specified a realm it might be included in the returned
         * username.
         */
        if ((p = strrchr(s->s_auth_id, '@')) != NULL) {
            *p = '\0';
        }

        return( 235 );

    case SASL_CONTINUE:
        /* RFC 4954 4 The AUTH Command
         * A server challenge is sent as a 334 reply with the text part
         * containing the BASE64 encoded string supplied by the SASL  mechanism.
         */
        if ( outlen ) {
            /* We need 1.33 bytes per original byte, so 2 is plenty. */
            if ( yaslAllocSize( s->s_response ) < ( outlen * 2 )) {
                s->s_response = yaslMakeRoomFor( s->s_response,
                        ( outlen * 2 ) - yaslAllocSize( s->s_response ));
            }
            if ( sasl_encode64( out, outlen, s->s_response,
                    yaslAllocSize( s->s_response ), NULL ) != SASL_OK ) {
                syslog( LOG_ERR, "SASL [%s]: Unable to base64 encode response",
                        s->s_auth_id );
                return( 454 );
            }
            yaslupdatelen( s->s_response );
        }

        return( 334 );

    /* RFC 4954 4 The AUTH Command
     * If the requested authentication mechanism is invalid (e.g., is not
     * supported or requires an encryption layer), the server rejects the AUTH
     * command with a 504 reply.
     */
    case SASL_NOMECH:
        syslog( LOG_ERR, "SASL: Unrecognized authentication type" );
        return( 504 );

    case SASL_ENCRYPT:
        syslog( LOG_ERR, "SASL: Encryption required for mechanism" );
        return( 504 );

    case SASL_BADPROT:
        /* RFC 4954 4 The AUTH Command
         * If the client uses an initial-response argument to the AUTH command
         * with a SASL mechanism in which the client does not begin the
         * authentication exchange, the server MUST reject the AUTH command
         * with a 501 reply.
         */
        syslog( LOG_ERR,
                "SASL: Invalid initial-response argument for mechanism" );
        return( 501 );

    case SASL_TOOWEAK:
        /* RFC 4954 6 Status Codes
         * 534 5.7.9 Authentication mechanism is too weak
         * This response to the AUTH command indicates that the selected
         * authentication mechanism is weaker than server policy permits for
         * that user.
         */
        syslog( LOG_ERR, "SASL [%s]: Authentication mechanism is too weak",
                s->s_auth_id );
        return( 534 );

    case SASL_TRANS:
        /* RFC 4954 6 Status Codes
         * 432 4.7.12  A password transition is needed
         * This response to the AUTH command indicates that the user needs to
         * transition to the selected authentication mechanism.  This is
         * typically done by authenticating once using the [PLAIN]
         * authentication mechanism.  The selected mechanism SHOULD then work
         * for authentications in subsequent sessions.
         */
        syslog( LOG_ERR, "SASL [%s]: A password transition is needed",
                s->s_auth_id );
        return( 432 );

    case SASL_FAIL:
    case SASL_NOMEM:
    case SASL_BUFOVER:
    case SASL_TRYAGAIN:
    case SASL_BADMAC:
    case SASL_NOTINIT:
        /* RFC 4954 6 Status Codes
         * 454 4.7.0  Temporary authentication failure
         * This response to the AUTH command indicates that the authentication
         * failed due to a temporary server failure.  The client SHOULD NOT
         * prompt the user for another password in this case, and should
         * instead notify the user of server failure.
         */
        syslog( LOG_ERR, "SASL [%s]: %s", s->s_auth_id,
                sasl_errdetail( s->s_conn ));
        return( 454 );

    default:
        /* RFC 4954 4 The AUTH Command
         * If the server is unable to authenticate the client, it SHOULD reject
         * the AUTH command with a 535 reply unless a more specific error code
         * is appropriate.
         *
         * RFC 4954 6 Status Codes
         * 535 5.7.8  Authentication credentials invalid
         * This response to the AUTH command indicates that the authentication
         * failed due to invalid or insufficient authentication credentials.
         */
        syslog( LOG_ERR, "SASL [%s]: %s", s->s_auth_id,
                sasl_errdetail( s->s_conn ));
        return( 535 );
    }
}

    void
simta_sasl_free( struct simta_sasl *s )
{
    if ( s ) {
        if ( s->s_conn ) {
            sasl_dispose( &(s->s_conn));
        }
        yaslfree( s->s_response );
        free( s );
    }
}

    int
simta_sasl_reset( struct simta_sasl *s, int tls )
{
    int                                 rc;
    sasl_security_properties_t          secprops;
    sasl_ssf_t                          ssf = tls;

    if (( rc = sasl_setprop( s->s_conn, SASL_SSF_EXTERNAL,
            &ssf )) != SASL_OK ) {
        syslog( LOG_ERR,
                "Liberror: simta_sasl_reset sasl_setprop SSF_EXTERNAL: %s",
                sasl_errdetail( s->s_conn ));
        return( 1 );
    }

    memset( &secprops, 0, sizeof( sasl_security_properties_t ));
    secprops.security_flags |= SASL_SEC_NOANONYMOUS;
    if ( !tls ) {
        secprops.security_flags |= SASL_SEC_NOPLAINTEXT;
    }

    if (( rc = sasl_setprop( s->s_conn, SASL_SEC_PROPS,
            &secprops)) != SASL_OK ) {
        syslog( LOG_ERR,
                "Liberror: simta_sasl_reset sasl_setprop SEC_PROPS: %s",
                sasl_errdetail( s->s_conn ));
        return( 1 );
    }

    return( 0 );
}

    int
simta_sasl_mechlist( struct simta_sasl *s, const char **result )
{
    if ( sasl_listmech( s->s_conn, NULL, "", " ", "", result, NULL,
            NULL ) != SASL_OK ) {
        syslog( LOG_ERR, "Liberror: sasl_listmech: %s",
                sasl_errdetail( s->s_conn ));
        return( 1 );
    }
    return( 0 );
}


/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
