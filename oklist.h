#ifndef OKLIST_H
#define OKLIST_H

int ok_create __P (( struct exp_addr *e_addr, char **permitted, char *dn));
void ok_destroy __P (( struct exp_addr *e_addr));

#endif
