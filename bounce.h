/*
 * Copyright (c) 2003 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

/*****     bounce.h     *****/

int bounce_text( struct envelope *, char *, char *, char * );
void bounce_stdout( struct envelope * );
ino_t bounce_dfile_out( struct envelope *, SNET * );
struct envelope *bounce( struct host_q *, struct envelope *, SNET * );
