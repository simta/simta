#define DNSR_STATE_START 0
#define DNSR_STATE_ASK 1
#define DNSR_STATE_WAIT 2
#define DNSR_STATE_DONE 3

struct event {
    int         e_type;
    int         e_value;
};
