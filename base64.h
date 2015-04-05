#ifndef SIMTA_BASE64_H
#define SIMTA_BASE64_H

#define SZ_BASE64_E( x )	(((x)+2)/3*4+1)
#define SZ_BASE64_D( x )	(((x)/4)*3)

void	base64_e( unsigned char *, int, char * );
void	base64_d( char *, int, unsigned char * );

#endif /* SIMTA_BASE64_H */
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
