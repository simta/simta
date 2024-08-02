/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <unistd.h>

#include "simta_malloc.h"
#include "simta_snet.h"

#define SNET_BUFLEN 4096

/*
 * BOL is beginning of line, FUZZY is after a CR but before a possible LF,
 * IN is past BOL, but before the end of a line.
 */
#define SNET_BOL 0
#define SNET_FUZZY 1
#define SNET_IN 2

static ssize_t snet_read0(SNET *, char *, size_t, struct timeval *);

/*
 * This routine is necessary, since snet_getline() doesn't differentiate
 * between NULL => EOF and NULL => connection dropped (or some other error).
 */
int
snet_eof(SNET *sn) {
    return sn->sn_flag & SNET_EOF;
}

SNET *
snet_attach(int fd, size_t max) {
    SNET *sn;

    sn = simta_malloc(sizeof(SNET));
    sn->sn_fd = fd;
    sn->sn_rbuf = simta_malloc(SNET_BUFLEN);
    sn->sn_rbuflen = SNET_BUFLEN;
    sn->sn_rstate = SNET_BOL;
    sn->sn_rcur = sn->sn_rend = sn->sn_rbuf;
    sn->sn_maxlen = max;
    sn->sn_wbuf = yaslempty();

    sn->sn_flag = 0;

    return sn;
}

SNET *
snet_open(const char *path, int flags, int mode, size_t max) {
    int fd;

    if ((fd = open(path, flags, mode)) < 0) {
        return NULL;
    }
    return snet_attach(fd, max);
}

int
snet_close(SNET *sn) {
    int fd;

    fd = snet_fd(sn);
    yaslfree(sn->sn_wbuf);
    free(sn->sn_rbuf);
    free(sn);
    if (close(fd) < 0) {
        return -1;
    }
    return 0;
}

void
snet_timeout(SNET *sn, int flag, struct timeval *tv) {
    if (flag & SNET_READ_TIMEOUT) {
        sn->sn_flag |= SNET_READ_TIMEOUT;
        memcpy(&(sn->sn_read_timeout), tv, sizeof(struct timeval));
    }
    if (flag & SNET_WRITE_TIMEOUT) {
        sn->sn_flag |= SNET_WRITE_TIMEOUT;
        memcpy(&(sn->sn_write_timeout), tv, sizeof(struct timeval));
    }
    if (flag & SNET_SSL_ACCEPT_TIMEOUT) {
        sn->sn_flag |= SNET_SSL_ACCEPT_TIMEOUT;
        memcpy(&(sn->sn_ssl_accept_timeout), tv, sizeof(struct timeval));
    }
    if (flag & SNET_SSL_CONNECT_TIMEOUT) {
        sn->sn_flag |= SNET_SSL_CONNECT_TIMEOUT;
        memcpy(&(sn->sn_ssl_connect_timeout), tv, sizeof(struct timeval));
    }
    return;
}

#ifdef HAVE_LIBSSL
/*
 * Returns 0 on success, and all further communication is through
 * the OpenSSL layer.  Returns -1 on failure, check the OpenSSL error
 * stack for specific errors.
 */
int
snet_starttls(SNET *sn, SSL_CTX *sslctx, int sslaccept) {
    struct timeval default_tv;

    if ((sslaccept != 0) && (sn->sn_flag & SNET_SSL_ACCEPT_TIMEOUT)) {
        default_tv = sn->sn_ssl_accept_timeout;
        return snet_starttls_tv(sn, sslctx, sslaccept, &default_tv);
    } else if ((sslaccept == 0) && (sn->sn_flag & SNET_SSL_CONNECT_TIMEOUT)) {
        default_tv = sn->sn_ssl_connect_timeout;
        return snet_starttls_tv(sn, sslctx, sslaccept, &default_tv);
    } else {
        return snet_starttls_tv(sn, sslctx, sslaccept, NULL);
    }
}


int
snet_starttls_tv(SNET *sn, SSL_CTX *sslctx, int sslaccept, struct timeval *tv) {
    int rc;
    int oflags = 0;

    if ((sn->sn_ssl = SSL_new(sslctx)) == NULL) {
        return -1;
    }

    if ((rc = SSL_set_fd(sn->sn_ssl, snet_fd(sn))) != 1) {
        return rc;
    }

    if (tv != NULL) {
        if ((oflags = fcntl(snet_fd(sn), F_GETFL)) < 0) {
            return -1;
        }
        if ((oflags & O_NONBLOCK) == 0) {
            if (fcntl(snet_fd(sn), F_SETFL, oflags | O_NONBLOCK) < 0) {
                return -1;
            }
        }
    }

    for (;;) {
        int    err;
        fd_set fd_read;
        fd_set fd_write;

        if (sslaccept) {
            rc = SSL_accept(sn->sn_ssl);
        } else {
            rc = SSL_connect(sn->sn_ssl);
        }

        if (rc == 1) {
            sn->sn_flag |= SNET_TLS;
            break;
        }

        if (rc == 0) {
            break;
        }

        if (tv == NULL) {
            break;
        }

        if (tv->tv_sec == 0 && tv->tv_usec == 0) {
            break;
        }

        err = SSL_get_error(sn->sn_ssl, rc);

        if (err == SSL_ERROR_WANT_READ) {
            FD_ZERO(&fd_read);
            FD_ZERO(&fd_write);
            FD_SET(snet_fd(sn), &fd_read);

        } else if (err == SSL_ERROR_WANT_WRITE) {
            FD_ZERO(&fd_read);
            FD_ZERO(&fd_write);
            FD_SET(snet_fd(sn), &fd_write);

        } else {
            break;
        }

        if (snet_select(snet_fd(sn) + 1, &fd_read, &fd_write, NULL, tv) < 0) {
            break;
        }
    }

    if ((tv != NULL) && ((oflags & O_NONBLOCK) == 0)) {
        if (fcntl(snet_fd(sn), F_SETFL, oflags) < 0) {
            return -1;
        }
    }

    return rc;
}
#endif /* HAVE_LIBSSL */

/*
 * Just like fprintf, only use the SNET header to get the fd, and use
 * snet_write() to move the data.
 */
ssize_t
snet_writef(SNET *sn, const char *format, ...) {
    va_list vl;

    va_start(vl, format);

    yaslclear(sn->sn_wbuf);
    sn->sn_wbuf = yaslcatvprintf(sn->sn_wbuf, format, vl);

    va_end(vl);

    return snet_write(sn, sn->sn_wbuf, yasllen(sn->sn_wbuf));
}

/*
 * select that updates the timeout structure.
 *
 * We could define snet_select to just be select on platforms that update
 * the timeout structure.
 */
int
snet_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
        struct timeval *tv) {
#ifndef linux
#if _POSIX_TIMERS > 0
    struct timespec tv_begin, tv_end;
#ifdef CLOCK_MONOTONIC_COARSE
    clockid_t clock = CLOCK_MONOTONIC_COARSE;
#elif defined(CLOCK_MONOTONIC_FAST)
    clockid_t clock = CLOCK_MONOTONIC_FAST;
#elif _POSIX_MONOTONIC_CLOCK > 0
    clockid_t clock = CLOCK_MONOTONIC;
#else
    clockid_t clock = CLOCK_REALTIME;
#endif /* CLOCK_MONOTONIC_COARSE */
#else  /* _POSIX_TIMERS */
    struct timeval tv_begin, tv_end;
#endif /* _POSIX_TIMERS */
#endif /* linux */
    int rc;

#ifndef linux
#if _POSIX_TIMERS > 0
    if (clock_gettime(clock, &tv_begin) < 0) {
#else
    if (gettimeofday(&tv_begin, NULL) < 0) {
#endif /* _POSIX_TIMERS */
        return -1;
    }
#endif /* linux */

    rc = select(nfds, rfds, wfds, efds, tv);

#ifndef linux
#if _POSIX_TIMERS > 0
    if (clock_gettime(clock, &tv_end) < 0) {
#else
    if (gettimeofday(&tv_end, NULL) < 0) {
#endif /* _POSIX_TIMERS */
        return -1;
    }

#if _POSIX_TIMERS > 0
    if (tv_begin.tv_nsec > tv_end.tv_nsec) {
        tv_end.tv_nsec += 1000000000;
        tv_end.tv_sec -= 1;
    }
    if ((tv->tv_usec -= ((tv_end.tv_nsec - tv_begin.tv_nsec) / 1000)) < 0) {
#else
    if (tv_begin.tv_usec > tv_end.tv_usec) {
        tv_end.tv_usec += 1000000;
        tv_end.tv_sec -= 1;
    }
    if ((tv->tv_usec -= (tv_end.tv_usec - tv_begin.tv_usec)) < 0) {
#endif
        tv->tv_usec += 1000000;
        tv->tv_sec -= 1;
    }

    /*
     * If we've gone negative, we don't generate an additional error.  Instead,
     * we just zero tv and return whatever select() returned.  The caller
     * must inspect the fd_sets to determine that nothing was set.
     */
    if ((tv->tv_sec -= (tv_end.tv_sec - tv_begin.tv_sec)) < 0) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
#endif /* linux */

    return rc;
}

ssize_t
snet_write(SNET *sn, char *buf, size_t len) {
    fd_set         fds;
    ssize_t        rc;
    int            oflags;
    ssize_t        rlen = 0;
    struct timeval tv;

    if (!(sn->sn_flag & SNET_WRITE_TIMEOUT)) {
        if (sn->sn_flag & SNET_TLS) {
#ifdef HAVE_LIBSSL
            /*
	     * If SSL_MODE_ENABLE_PARTIAL_WRITE has been set, this routine
	     * can (abnormally) return less than a full write.
	     */
            return SSL_write(sn->sn_ssl, buf, len);
#else
            return -1;
#endif /* HAVE_LIBSSL */
        } else {
            return write(snet_fd(sn), buf, len);
        }
    }

    tv = sn->sn_write_timeout;

    if ((oflags = fcntl(snet_fd(sn), F_GETFL)) < 0) {
        return -1;
    }
    if ((oflags & O_NONBLOCK) == 0) {
        if (fcntl(snet_fd(sn), F_SETFL, oflags | O_NONBLOCK) < 0) {
            return -1;
        }
    }

    while (len > 0) {
        FD_ZERO(&fds);
        FD_SET(snet_fd(sn), &fds);

        if (snet_select(snet_fd(sn) + 1, NULL, &fds, NULL, &tv) < 0) {
            goto restoreblocking;
        }
        if (FD_ISSET(snet_fd(sn), &fds) == 0) {
            errno = ETIMEDOUT;
            goto restoreblocking;
        }

        if (sn->sn_flag & SNET_TLS) {
#ifdef HAVE_LIBSSL
            /*
	     * Make sure we ARE allowing partial writes.  This can't
	     * be turned off!!!
	     */
            SSL_set_mode(sn->sn_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);

            if ((rc = SSL_write(sn->sn_ssl, buf, len)) <= 0) {
                switch (SSL_get_error(sn->sn_ssl, rc)) {
                case SSL_ERROR_WANT_READ:
                    FD_ZERO(&fds);
                    FD_SET(snet_fd(sn), &fds);

                    if (snet_select(snet_fd(sn) + 1, &fds, NULL, NULL, &tv) <
                            0) {
                        goto restoreblocking;
                    }
                    if (FD_ISSET(snet_fd(sn), &fds) == 0) {
                        errno = ETIMEDOUT;
                        goto restoreblocking;
                    }

                case SSL_ERROR_WANT_WRITE:
                    continue;

                default:
                    goto restoreblocking;
                }
            }
#else
            goto restoreblocking;
#endif /* HAVE_LIBSSL */
        } else {
            if ((rc = write(snet_fd(sn), buf, len)) < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                goto restoreblocking;
            }
        }

        buf += rc;
        rlen += rc;
        len -= rc;
    }

    if ((oflags & O_NONBLOCK) == 0) {
        if (fcntl(snet_fd(sn), F_SETFL, oflags) < 0) {
            return -1;
        }
    }
    return rlen;

restoreblocking:
    if ((oflags & O_NONBLOCK) == 0) {
        if (fcntl(snet_fd(sn), F_SETFL, oflags) < 0) {
            return -1;
        }
    }
    return -1;
}

static ssize_t
snet_read0(SNET *sn, char *buf, size_t len, struct timeval *tv) {
    fd_set         fds;
    ssize_t        rc;
    struct timeval default_tv;
    extern int     errno;
    int            oflags = 0, dontblock = 0;

    if ((tv == NULL) && (sn->sn_flag & SNET_READ_TIMEOUT)) {
        default_tv = sn->sn_read_timeout;
        tv = &default_tv;
    }

    if (tv) {
        dontblock = 1;
#ifdef HAVE_LIBSSL
        /* Check to see if there is already data in SSL buffer */
        if (sn->sn_flag & SNET_TLS) {
            dontblock = !SSL_pending(sn->sn_ssl);
        }
#endif /* HAVE_LIBSSL */
    }

    if (dontblock) {
        if ((oflags = fcntl(snet_fd(sn), F_GETFL)) < 0) {
            return -1;
        }
        if ((oflags & O_NONBLOCK) == 0) {
            if ((fcntl(snet_fd(sn), F_SETFL, oflags | O_NONBLOCK)) < 0) {
                return -1;
            }
        }

#ifdef HAVE_LIBSSL
    retry:
#endif /* HAVE_LIBSSL */
        FD_ZERO(&fds);
        FD_SET(snet_fd(sn), &fds);

        /* time out case? */
        if (select(snet_fd(sn) + 1, &fds, NULL, NULL, tv) < 0) {
            goto restoreblocking;
        }
        if (FD_ISSET(snet_fd(sn), &fds) == 0) {
            errno = ETIMEDOUT;
            goto restoreblocking;
        }
    }

    if (sn->sn_flag & SNET_TLS) {
#ifdef HAVE_LIBSSL
        if ((rc = SSL_read(sn->sn_ssl, buf, len)) < 0) {
            switch (SSL_get_error(sn->sn_ssl, rc)) {
            case SSL_ERROR_WANT_WRITE:
                FD_ZERO(&fds);
                FD_SET(snet_fd(sn), &fds);

                if (snet_select(snet_fd(sn) + 1, NULL, &fds, NULL, tv) < 0) {
                    goto restoreblocking;
                }
                if (FD_ISSET(snet_fd(sn), &fds) == 0) {
                    errno = ETIMEDOUT;
                    goto restoreblocking;
                }

            case SSL_ERROR_WANT_READ:
                goto retry;

            default:
                goto restoreblocking;
            }
        }
#else  /* HAVE_LIBSSL */
        rc = -1;
#endif /* HAVE_LIBSSL */
    } else {
        rc = read(snet_fd(sn), buf, len);
    }
    if (rc == 0) {
        sn->sn_flag |= SNET_EOF;
    }

    if (dontblock && ((oflags & O_NONBLOCK) == 0)) {
        if ((fcntl(snet_fd(sn), F_SETFL, oflags)) < 0) {
            return -1;
        }
    }

    return rc;

restoreblocking:
    if (dontblock && ((oflags & O_NONBLOCK) == 0)) {
        if ((fcntl(snet_fd(sn), F_SETFL, oflags)) < 0) {
            return -1;
        }
    }
    return -1;
}

int
snet_hasdata(SNET *sn) {
    if (sn->sn_rcur < sn->sn_rend) {
        if (sn->sn_rstate == SNET_FUZZY) {
            if (*sn->sn_rcur == '\n') {
                sn->sn_rcur++;
            }
            sn->sn_rstate = SNET_BOL;
        }
        if (sn->sn_rcur < sn->sn_rend) {
            return 1;
        }
    }
    return 0;
}

/*
 * External entry point for reading with the snet library.  Compatible
 * with snet_getline()'s buffering.
 */
ssize_t
snet_read(SNET *sn, char *buf, size_t len, struct timeval *tv) {
    ssize_t rc;

    /*
     * If there's data already buffered, make sure it's not left over
     * from snet_getline(), and then return whatever's left.
     * Note that snet_getline() calls snet_read0().
     */
    if (snet_hasdata(sn)) {
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif /* min */
        rc = min(sn->sn_rend - sn->sn_rcur, len);
        memcpy(buf, sn->sn_rcur, rc);
        sn->sn_rcur += rc;
        return rc;
    }

    rc = snet_read0(sn, buf, len, tv);
    if ((rc > 0) && (sn->sn_rstate == SNET_FUZZY)) {
        sn->sn_rstate = SNET_BOL;
        if (*buf == '\n') {
            if (--rc <= 0) {
                rc = snet_read0(sn, buf, len, tv);
            } else {
                memmove(buf, buf + 1, rc);
            }
        }
    }

    return rc;
}

/*
 * Flush snet's internal buffer
 */
ssize_t
snet_flush(SNET *sn) {
    ssize_t rc;

    rc = sn->sn_rend - sn->sn_rcur;
    sn->sn_rcur = sn->sn_rend = sn->sn_rbuf;
    sn->sn_rstate = SNET_BOL;
    return rc;
}

/*
 * Get a null-terminated line of input, handle CR/LF issues.
 * Note that snet_getline() returns information from a common area which
 * may be overwritten by subsequent calls.
 */
char *
snet_getline(SNET *sn, struct timeval *tv) {
    char      *eol, *line;
    ssize_t    rc;
    extern int errno;

    for (eol = sn->sn_rcur;; eol++) {
        if (eol >= sn->sn_rend) { /* fill */
            /* pullup */
            if (sn->sn_rcur > sn->sn_rbuf) {
                if (sn->sn_rcur < sn->sn_rend) {
                    memmove(sn->sn_rbuf, sn->sn_rcur,
                            (unsigned)(sn->sn_rend - sn->sn_rcur));
                }
                eol = sn->sn_rend = sn->sn_rbuf + (sn->sn_rend - sn->sn_rcur);
                sn->sn_rcur = sn->sn_rbuf;
            }

            /* expand */
            if (sn->sn_rend == sn->sn_rbuf + sn->sn_rbuflen) {
                if (sn->sn_maxlen != 0 && sn->sn_rbuflen >= sn->sn_maxlen) {
                    errno = ENOMEM;
                    return NULL;
                }
                if ((sn->sn_rbuf = simta_realloc(sn->sn_rbuf,
                             sn->sn_rbuflen + SNET_BUFLEN)) == NULL) {
                    exit(1);
                }
                sn->sn_rbuflen += SNET_BUFLEN;
                eol = sn->sn_rend = sn->sn_rbuf + (sn->sn_rend - sn->sn_rcur);
                sn->sn_rcur = sn->sn_rbuf;
            }

            if ((rc = snet_read0(sn, sn->sn_rend,
                         sn->sn_rbuflen - (sn->sn_rend - sn->sn_rbuf), tv)) <
                    0) {
                return NULL;
            }
            if (rc == 0) { /* EOF */
                /*
		 * When we did the read, we made sure we had space to
		 * read, so when we place the '\0' below, we have space
		 * for that.
		 */
                if (sn->sn_rcur < sn->sn_rend) {
                    break;
                }
                return NULL;
            }
            sn->sn_rend += rc;
        }

        if (*eol == '\r' || *eol == '\0') {
            sn->sn_rstate = SNET_FUZZY;
            break;
        }
        if (*eol == '\n') {
            if (sn->sn_rstate == SNET_FUZZY) {
                sn->sn_rstate = SNET_BOL;
                sn->sn_rcur = eol + 1;
                continue;
            }
            sn->sn_rstate = SNET_BOL;
            break;
        }
        sn->sn_rstate = SNET_IN;
    }

    *eol = '\0';
    line = sn->sn_rcur;
    sn->sn_rcur = eol + 1;
    return line;
}

char *
snet_getline_multi(SNET *sn, void (*logger)(char *), struct timeval *tv) {
    char *line;

    do {
        if ((line = snet_getline(sn, tv)) == NULL) {
            return NULL;
        }

        if (logger != NULL) {
            (*logger)(line);
        }

        if (strlen(line) < 3) {
            errno = EINVAL;
            return NULL;
        }

        if (!isdigit((int)line[ 0 ]) || !isdigit((int)line[ 1 ]) ||
                !isdigit((int)line[ 2 ])) {
            errno = EINVAL;
            return NULL;
        }

        if (line[ 3 ] != '\0' && line[ 3 ] != ' ' && line[ 3 ] != '-') {
            errno = EINVAL;
            return NULL;
        }

    } while (line[ 3 ] == '-');

    return line;
}
