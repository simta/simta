#ifndef SIMTA_SMTP_H
#define SIMTA_SMTP_H

#define SMTP_CONNECT 1
#define SMTP_HELO 2
#define SMTP_EHLO 3
#define SMTP_MAIL 4
#define SMTP_RCPT 5
#define SMTP_DATA 6
#define SMTP_DATA_EOF 7
#define SMTP_RSET 8
#define SMTP_QUIT 9
#define SMTP_STARTTLS 10

typedef enum {
    SMTP_OK,
    SMTP_ERROR,
    SMTP_BAD_CONNECTION,
    SMTP_BAD_TLS,
} smtp_result;

smtp_result smtp_connect(struct host_q *, struct deliver *);
smtp_result smtp_rset(struct host_q *, struct deliver *);
smtp_result smtp_send(struct host_q *, struct deliver *);
void        smtp_quit(struct host_q *, struct deliver *);

#endif /* SIMTA_SMTP_H */
/* vim: set softtabstop=4 shiftwidth=4 expandtab :*/
