/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#include <srs2.h>

#include "envelope.h"
#include "expand.h"
#include "srs.h"
#include "simta.h"

static srs_t *simta_srs_new( void );

    int
simta_srs_forward( struct envelope *env ) {
    char	*newaddr;
    char	*at;
    srs_t	*srs;
    int		rc;

    if ( strlen( env->e_mail ) == 0 ) {
	/* Null return-path, don't need to do anything */
	return( -1 );
    }

    if (( at = strrchr( env->e_mail, '@' )) == NULL ) {
	/* I think this shouldn't happen, ever. */
	syslog( LOG_ERR, "srs_forward: no @ in %s", env->e_mail );
	return( 1 );
    }

    if (( simta_srs != SRS_POLICY_ALWAYS ) &&
	    ( strcasecmp( at + 1, simta_srs_domain ) == 0 )) {
	/* Already from the correct domain, don't need to do anything */
	return( -1 );
    }

    srs = simta_srs_new( );
    rc = srs_forward_alloc( srs, &newaddr, env->e_mail, simta_srs_domain );
    srs_free( srs );

    if ( rc == SRS_SUCCESS ) {
	free( env->e_mail );
	env->e_mail = newaddr;
	return( 0 );
    }

    return( 1 );
}

    int
simta_srs_reverse( const char *addr, char **newaddr ) {
    srs_t	*srs;
    int		rc;

    srs = simta_srs_new();
    rc = srs_reverse_alloc( srs, newaddr, addr );
    srs_free( srs );
    return( rc );
}

    static srs_t *
simta_srs_new( )
{
    srs_t	*srs = srs_new( );
    srs_add_secret( srs, simta_srs_secret );
    /* Defaults to 21, which is too much */
    srs_set_maxage( srs, 7 );
    return( srs );
}

    int
srs_expand( struct expand *exp, struct exp_addr *e_addr, struct action *a )
{
    char	*newaddr;
    int		rc;

    if (( rc = simta_srs_reverse( e_addr->e_addr, &newaddr )) == SRS_SUCCESS ) {
	if ( add_address( exp, newaddr, e_addr->e_addr_errors,
		ADDRESS_TYPE_EMAIL, e_addr->e_addr_from ) != 0 ) {
	    free( newaddr );
	    return( EXPAND_SRS_SYSERROR );
	}
	syslog( LOG_DEBUG, "Expand %s <%s> EXPANDED <%s>: SRS",
		exp->exp_env->e_id, e_addr->e_addr, newaddr );
	free( newaddr );
	return( EXPAND_SRS_OK );
    }

    switch( SRS_ERROR_TYPE( rc )) {
    case SRS_ERRTYPE_CONFIG:
        return( EXPAND_SRS_SYSERROR );
    case SRS_ERRTYPE_NONE:
    case SRS_ERRTYPE_INPUT:
    case SRS_ERRTYPE_SYNTAX:
    case SRS_ERRTYPE_SRS:
    default:
        return( EXPAND_SRS_NOT_FOUND );
    }
}

    int
srs_valid( const char *addr )
{
    char	*newaddr;
    int		rc;

    if ( strncasecmp( addr, "SRS", 3 ) != 0 ) {
	return( EXPAND_SRS_NOT_FOUND );
    }

    if (( rc = simta_srs_reverse( addr, &newaddr )) == SRS_SUCCESS ) {
	free( newaddr );
	return( EXPAND_SRS_OK );
    }

    switch( SRS_ERROR_TYPE( rc )) {
    case SRS_ERRTYPE_CONFIG:
	return( EXPAND_SRS_SYSERROR );
    case SRS_ERRTYPE_NONE:
    case SRS_ERRTYPE_INPUT:
    case SRS_ERRTYPE_SYNTAX:
    case SRS_ERRTYPE_SRS:
    default:
	return( EXPAND_SRS_NOT_FOUND );
    }
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
