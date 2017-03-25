#ifndef SIMTA_DMARC_H
#define SIMTA_DMARC_H

#define DMARC_RESULT_NORECORD		0
#define DMARC_RESULT_ORGDOMAIN		1
#define DMARC_RESULT_NONE		2
#define DMARC_RESULT_QUARANTINE		3
#define DMARC_RESULT_REJECT		4
#define DMARC_RESULT_SYSERROR		5
#define DMARC_RESULT_PASS		6
#define DMARC_RESULT_BESTGUESSPASS	7

#define DMARC_ALIGNMENT_RELAXED		0
#define DMARC_ALIGNMENT_STRICT		1

#include "ll.h"


struct dmarc {
    int			policy;
    int			subpolicy;
    int			pct;
    int			result;
    int			dkim_alignment;
    int			spf_alignment;
    char		*domain;
    char		*spf_domain;
    struct dll_entry	*dkim_domain_list;
};

int dmarc_init( struct dmarc ** );
void dmarc_free( struct dmarc * );
void dmarc_reset( struct dmarc * );
int dmarc_spf_result( struct dmarc *, char * );
int dmarc_dkim_result( struct dmarc *, char * );
int dmarc_lookup( struct dmarc *, const char * );
int dmarc_result( struct dmarc * );
const char *dmarc_result_str( const int );
const char *dmarc_authresult_str( const int );

#endif /* SIMTA_DMARC_H */
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
