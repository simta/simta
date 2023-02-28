simta can call a content filter to examine the DATA portion of an incoming SMTP
message.

# Environment variables provided to the content filter

```
SIMTA_DFILE                 path to message's Dfile
SIMTA_TFILE                 path to message's tfile
SIMTA_REMOTE_IP             IP address of remote host
SIMTA_REMOTE_HOSTNAME       hostname of remote host
SIMTA_REVERSE_LOOKUP        forward-confirmed reverse DNS status
    "0"                     REVERSE_MATCH
    "1"                     REVERSE_ERROR
    "2"                     REVERSE_UNKNOWN
    "3"                     REVERSE_MISMATCH
    "4"                     REVERSE_UNRESOLVED
SIMTA_ACL_RESULT            result from the receive.connection.acl chain, if any
    "accept"
    "trust"
SIMTA_SMTP_MAIL_FROM        message's RFC5321.MailFrom
SIMTA_SMTP_HELO             AAHELO/EHLO hostname given by remote host
SIMTA_HEADER_FROM           message's RFC5322.From
SIMTA_MID                   message's RFC5322.Message-ID
SIMTA_UID                   message UID assigned by simta
SIMTA_PID                   calling process's PID
SIMTA_CID                   calling process's Connection ID
SIMTA_WRITE_BEFORE_BANNER   whether the client wrote before the SMTP banner
    "0"                     no write
    "1"                     write
SIMTA_AUTH_ID               authenticated identity, if any
SIMTA_CHECKSUM              message checksum
SIMTA_CHECKSUM_SIZE         number of bytes that were checksummed
SIMTA_BODY_CHECKSUM         message body checksum
SIMTA_BODY_CHECKSUM_SIZE    number of body bytes that were checksummed
SIMTA_BAD_HEADERS           result of cursory header validity check
    "0"                     no bad headers
    "1"                     header check failed
SIMTA_SPF_RESULT            result of SPF check
    "pass"
    "fail"
    "softfail"
    "neutral"
    "none"
    "temperror"
    "permerror"
SIMTA_SPF_DOMAIN            RFC7208.MAILFROM (often RFC5321.MailFrom, but not always)
SIMTA_DMARC_RESULT          result of DMARC check
    "absent"
    "none"
    "reject"
    "quarantine"
    "pass"
    "bestguesspass"
    "syserror"
SIMTA_DMARC_DOMAIN          domain used for DMARC check
SIMTA_DKIM_DOMAINS          space-separated list of domains with valid DKIM signatures
```

# Data returned from the content filter

The first line of text returned from the content filter will be
logged and displayed to the SMTP client. Other lines are discarded.

# Content filter return code

The content filter return code is a bitfield; not all combinations of bits
make sense, but simta will always attempt to obey it as fully as possible.

## Result bits

```
0x0000 0000   MESSAGE_ACCEPT
0x0000 0001   MESSAGE_TEMPFAIL
0x0000 0010   MESSAGE_REJECT
```

## Option bits

```
0x0000 0100   MESSAGE_DELETE
0x0000 1000   MESSAGE_DISCONNECT
0x0001 0000   MESSAGE_TARPIT
0x0010 0000   MESSAGE_JAIL
0x0100 0000   MESSAGE_BOUNCE
```

## Default return

If the content filter process is terminated abnormally, it should
return MESSAGE_TEMPFAIL.
