#ifndef SIMTA_SPF_H
#define SIMTA_SPF_H

#define SPF_RESULT_NONE			0
#define SPF_RESULT_NEUTRAL		1
#define SPF_RESULT_PASS			2
#define SPF_RESULT_SOFTFAIL		3
#define SPF_RESULT_FAIL			4
#define SPF_RESULT_TEMPERROR		5
#define SPF_RESULT_PERMERROR		6


int spf_lookup( const char *, const char *, const struct sockaddr * );
const char *spf_result_str( const int );

#endif /* SIMTA_SPF_H */
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
