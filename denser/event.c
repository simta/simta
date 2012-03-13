#include "event.h"

/* This event table starts after the first name server has been queried */

struct event eventlist[ 32 ] = {
    /* First round  0 - 3 sec. */
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 1 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 2 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 3 },
    { DNSR_STATE_WAIT, 1 },

    /* Second round 4 - 11 sec. */
    { DNSR_STATE_ASK, 0 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 1 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 2 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 3 },
    { DNSR_STATE_WAIT, 5 },

    /* Third round  12 - 27 sec.*/
    { DNSR_STATE_ASK, 0 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 1 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 2 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 3 },
    { DNSR_STATE_WAIT, 13 },

    /* To give the last NS its full wait time, the final wait must be a full
     * 16 seconds.  We will still accept a valid response from the other NS's
     * during this time.
     */

    /* Final round  28 - 47 sec. */
    { DNSR_STATE_ASK, 0 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 1 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 2 },
    { DNSR_STATE_WAIT, 1 },
    { DNSR_STATE_ASK, 3 },
    { DNSR_STATE_WAIT, 16 },
    { DNSR_STATE_DONE, -1 }
};
