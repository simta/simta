#ifndef SIMTA_DMARC_H
#define SIMTA_DMARC_H

#include <yasl.h>

#include "ll.h"
#include "simta.h"

enum simta_dmarc_result {
    DMARC_RESULT_NORECORD,
    DMARC_RESULT_ORGDOMAIN,
    DMARC_RESULT_NONE,
    DMARC_RESULT_QUARANTINE,
    DMARC_RESULT_REJECT,
    DMARC_RESULT_SYSERROR,
    DMARC_RESULT_PASS,
    DMARC_RESULT_BESTGUESSPASS,
};

enum simta_dmarc_align {
    DMARC_ALIGNMENT_RELAXED,
    DMARC_ALIGNMENT_STRICT,
};

struct dmarc {
    enum simta_dmarc_result policy;
    enum simta_dmarc_result subpolicy;
    int                     pct;
    enum simta_dmarc_result result;
    enum simta_dmarc_align  dkim_alignment;
    enum simta_dmarc_align  spf_alignment;
    char *                  domain;
    char *                  spf_domain;
    struct dll_entry *      dkim_domain_list;
};

yastr dmarc_orgdomain(const char *);

void                    dmarc_init(struct dmarc **);
void                    dmarc_free(struct dmarc *);
void                    dmarc_reset(struct dmarc *);
simta_result            dmarc_spf_result(struct dmarc *, char *);
void                    dmarc_dkim_result(struct dmarc *, char *);
simta_result            dmarc_lookup(struct dmarc *, const char *);
enum simta_dmarc_result dmarc_result(struct dmarc *);
const char *            dmarc_result_str(const enum simta_dmarc_result);
const char *            dmarc_authresult_str(const enum simta_dmarc_result);

#endif /* SIMTA_DMARC_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
