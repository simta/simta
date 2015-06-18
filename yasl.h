/* yasl, Yet Another String Library for C
 *
 * Copyright (c) 2006-2014, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2014-2015, The yasl developers
 *
 * This file is under the 2-clause BSD license. See the COPYING.yasl file for
 * the full license text
 */

#ifndef YASL_H
#define YASL_H

#ifndef __GNUC__
	#undef __attribute__
	#define __attribute__(x) /* nothing */
#endif

#define YASL_MAX_PREALLOC (1024*1024)

#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

typedef char *yastr;

struct yastrhdr {
	size_t len;
	size_t free;
	char buf[];
};


/**
 * User API function prototypes
 */

// Initialization //
yastr
yaslnew(const void * init, size_t initlen);

static inline yastr
yaslauto(const char * str);

yastr
yasldup(const yastr str);

yastr
yaslempty(void);

yastr
yaslfromlonglong(long long value);


// Querying //
static inline size_t
yaslavail(const yastr str);

static inline size_t
yasllen(const yastr str);

int
yaslcmp(const yastr str1, const yastr str2);


// Modification //
void
yaslclear(yastr str);

yastr
yaslgrowzero(yastr str, size_t len);

yastr
yaslcpylen(yastr dest, const char * src, size_t len);

yastr
yaslcpy(yastr dest, const char * src);

yastr
yasljoin(char ** argv, int argc, char * sep, size_t seplen);

yastr
yasljoinyasl(yastr * argv, int argc, const char * sep, size_t seplen);

yastr
yaslmapchars(yastr str, const char * from, const char * to, size_t setlen);

void
yaslrange(yastr str, ptrdiff_t start, ptrdiff_t end);

void
yasltolower(yastr str);

void
yasltoupper(yastr str);

void
yasltrim(yastr str, const char * cset);

void
yaslupdatelen(yastr str);

yastr *
yaslsplitargs(const char * line, int * argc);

yastr *
yaslsplitlen(const char * str, size_t len, const char * sep, size_t seplen, size_t * count);


// Concatenation //
yastr
yaslcat(yastr dest, const char * src);

yastr
yaslcatyasl(yastr dest, const yastr src);

yastr
yaslcatlen(yastr dest, const void * src, size_t len);

yastr
yaslcatrepr(yastr dest, const char * src, size_t len);

yastr
yaslcatvprintf(yastr str, const char * fmt, va_list ap);

yastr
yaslcatprintf(yastr str, const char * fmt, ...)
        __attribute__((format(printf, 2, 3)));


// Freeing //
void
yaslfree(yastr str);

void
yaslfreesplitres(yastr * tokens, size_t count);


// Low-level functions //
static inline struct yastrhdr *
yaslheader(const yastr str);

size_t
yaslAllocSize(yastr str);

void
yaslIncrLen(yastr str, size_t incr);

yastr
yaslMakeRoomFor(yastr str, size_t addlen)
        __attribute__((warn_unused_result));

yastr
yaslRemoveFreeSpace(yastr str)
        __attribute__((warn_unused_result));


// Low-level helper functions //
int
hex_digit_to_int(char c);


/**
 * Inline functions
 */

static inline struct yastrhdr *yaslheader(const yastr str) {
	if (!str) { return NULL; }

	/* The yastrhdr pointer has a different alignment than the original char
	 * pointer, so cast it through a void pointer to silence the warning. */
	return (void *)(str - offsetof(struct yastrhdr, buf));
}

static inline yastr yaslauto(const char * str) {
	return yaslnew(str, str ? strlen(str) : 0);
}

static inline size_t yaslavail(const yastr str) {
	if (!str) { return 0; }

	return yaslheader(str)->free;
}

static inline size_t yasllen(const yastr str) {
	if (!str) { return 0; }

	return yaslheader(str)->len;
}


#endif
