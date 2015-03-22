#ifndef SIMTA_SRS_H
#define SIMTA_SRS_H

#include "envelope.h"
#include "red.h"

/* return codes for srs_expand */
#define EXPAND_SRS_OK		0
#define EXPAND_SRS_NOT_FOUND	1
#define EXPAND_SRS_SYSERROR	2

int simta_srs_forward( struct envelope * );
int simta_srs_reverse( const char *, char ** );
int srs_expand( struct expand *, struct exp_addr *, struct action * );
int srs_valid( const char * );

#endif /* SIMTA_SRS_H */
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
