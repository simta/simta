#include "config.h"

#include <sys/param.h>
#include <stdlib.h>
#include <string.h>

#ifdef TLS
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif /* TLS */

#include <snet.h>

#include "ll.h"
#include "envelope.h"
#include "expand.h"
#include "oklist.h"
#include "dn.h"

    int
ok_create ( struct exp_addr *e_addr, char **permitted, char *dn)
{
    int		idx;
    char	*namedup;

    if (permitted && *permitted)
    {
	/* 
	** Normalize the permitted group list 
	** normalization happens "in-place"
	*/   
	for (idx = 0;  permitted[idx] != NULL; idx++) {
	    dn_normalize_case (permitted[idx]);

	    if ((namedup = strdup (permitted[idx])) == NULL)
		return (1);

	    if (ll_insert ( &e_addr->e_addr_ok, namedup, " ", NULL ) != 0 )
		return (1);
	}		
    }
    return 0;
}

    void
ok_destroy ( struct exp_addr *e_addr)
{

    struct stab_entry  *pstab;
    struct stab_entry  *nstab;

    pstab = e_addr->e_addr_ok;
    while ( pstab != NULL ) {
        nstab = pstab;
        pstab = pstab->st_next;
        if ( nstab->st_key != NULL ) {
            free( nstab->st_key );
        }
        free( nstab );
    }
    return;
}

