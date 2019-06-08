/* clang-format off */
/* yasl, Yet Another String Library for C
 *
 * Copyright (c) 2006-2014, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2014-2015, The yasl developers
 *
 * This file is under the 2-clause BSD license. See COPYING.yasl for the
 * full license text
 */

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yasl.h"


// Initialization //

/* Create a new yasl string, using `initlen` bytes from the `init` pointer to
 * initialize it with. */
yastr
yaslnew(const void * init, size_t initlen) {
	struct yastrhdr * hdr;

	if (init) {
		hdr = malloc(sizeof(struct yastrhdr) + initlen + 1);
	} else {
		hdr = calloc(sizeof(struct yastrhdr) + initlen + 1, 1);
	}
	if (!hdr) { return NULL; }

	hdr->len = initlen;
	hdr->free = 0;
	if (initlen && init) {
		memcpy(hdr->buf, init, initlen);
	}
	hdr->buf[initlen] = '\0';
	return (char*)hdr->buf;
}

/* Duplicate a yasl string. */
yastr
yasldup(const yastr str) {
	if (!str) { return NULL; }

	return yaslnew(str, yasllen(str));
}

/* Create an empty (zero length) yasl string. */
yastr
yaslempty(void) {
	return yaslnew("", 0);
}

/* Create a yasl string from a long long value. */
yastr
yaslfromlonglong(long long value) {
	char buf[32], * p;
	unsigned long long v;

	v = (unsigned long long)((value < 0) ? -value : value);
	p = buf + 31; /* point to the last character */
	do {
		*p-- = '0' + (v%10);
		v /= 10;
	} while(v);
	if (value < 0) { *p-- = '-'; }
	p++;
	return yaslnew(p, (size_t)(32 - (p - buf)));
}


// Querying //

/* Compare two yasl strings str1 and str2 with memcmp(). */
int
yaslcmp(const yastr str1, const yastr str2) {
	size_t len1, len2, minlen;
	int cmp;

	len1 = yasllen(str1);
	len2 = yasllen(str2);
	minlen = (len1 < len2) ? len1 : len2;
	cmp = memcmp(str1, str2, minlen);
	if (cmp == 0) { return (len1 > len2) - (len1 < len2); }
	return cmp;
}


// Modification //

/* Modify a yasl string in-place to make it empty (zero length). */
void
yaslclear(yastr str) {
	if (!str) { return; }

	struct yastrhdr * hdr = yaslheader(str);
	hdr->free += hdr->len;
	hdr->len = 0;
	hdr->buf[0] = '\0';
}

/* Grow the yasl string to have the specified length. Bytes that were not part
 * of the original length of the yasl string will be set to zero. */
yastr
yaslgrowzero(yastr str, size_t len) {
	if (!str) { return NULL; }

	struct yastrhdr * hdr = yaslheader(str);
	size_t totlen, curlen = hdr->len;

	if (len <= curlen) { return str; }
	str = yaslMakeRoomFor(str, len - curlen);
	if (!str) { return NULL; }

	/* Make sure added region doesn't contain garbage */
	hdr = yaslheader(str);
	memset(str + curlen, 0, (len - curlen + 1)); /* also set trailing \0 byte */
	totlen = hdr->len + hdr->free;
	hdr->len = len;
	hdr->free = totlen - hdr->len;
	return str;
}

/* Destructively modify the yasl string 'dest' to hold the specified binary
 * safe string pointed by 'src' of length 'len' bytes. */
yastr
yaslcpylen(yastr dest, const char * src, size_t len) {
	if (!dest || !src) { return NULL; }

	struct yastrhdr * hdr = yaslheader(dest);
	size_t totlen = hdr->free + hdr->len;

	if (totlen < len) {
		dest = yaslMakeRoomFor(dest, len - hdr->len);
		if (!dest) { return NULL; }
		hdr = yaslheader(dest);
		totlen = hdr->free + hdr->len;
	}
	memcpy(dest, src, len);
	dest[len] = '\0';
	hdr->len = len;
	hdr->free = totlen - len;
	return dest;
}

/* Like yaslcpylen() but 'src' must be a null-termined string so that the
 * length of the string is obtained with strlen(). */
yastr
yaslcpy(yastr dest, const char * src) {
	if (!dest || !src) { return NULL; }

	return yaslcpylen(dest, src, strlen(src));
}

/* Join an array of C strings using the specified separator (also a C string).
 * Returns the result as a yasl string. */
yastr
yasljoin(char ** argv, int argc, char * sep, size_t seplen) {
	if (!argv || !sep) { return NULL; }

	yastr join = yaslempty();

	for (int j = 0; j < argc; j++) {
		join = yaslcat(join, argv[j]);
		if (j != argc - 1) { join = yaslcatlen(join, sep, seplen); }
	}
	return join;
}

/* Like yasljoin, but joins an array of yasl strings. */
yastr
yasljoinyasl(yastr * argv, int argc, const char * sep, size_t seplen) {
	if (!argv || !sep) { return NULL; }

	yastr join = yaslempty();

	for (int j = 0; j < argc; j++) {
		join = yaslcatyasl(join, argv[j]);
		if (j != argc - 1) { join = yaslcatlen(join, sep, seplen); }
	}
	return join;
}

/* Modify the string substituting all the occurrences of the set of
 * characters specified in the 'from' string to the corresponding character
 * in the 'to' array. */
yastr
yaslmapchars(yastr str, const char * from, const char * to, size_t setlen) {
	if (!str || !from || !to) { return NULL; }

	for (size_t j = 0; j < yasllen(str); j++) {
		for (size_t i = 0; i < setlen; i++) {
			if (str[j] == from[i]) {
				str[j] = to[i];
				break;
			}
		}
	}
	return str;
}

/* Turn the string into a smaller (or equal) string containing only the
 * substring specified by the 'start' and 'end' indexes. */
void
yaslrange(yastr str, ptrdiff_t start, ptrdiff_t end) {
	if (!str) { return; }

	struct yastrhdr * hdr = yaslheader(str);
	size_t newlen, len = yasllen(str);

	if (len == 0) { return; }
	if (start < 0) {
		start = (ptrdiff_t)len + start;
		if (start < 0) { start = 0; }
	}
	if (end < 0) {
		end = (ptrdiff_t)len + end;
		if (end < 0) { end = 0; }
	}
	newlen = (size_t)((start > end) ? 0 : (end - start) + 1);
	if (newlen != 0) {
		if ((size_t)start >= len) {
			newlen = 0;
		} else if ((size_t)end >= len) {
			end = (ptrdiff_t)len - 1;
			newlen = (size_t)((start > end) ? 0 : (end - start) + 1);
		}
	} else {
		start = 0;
	}
	if (start && newlen) { memmove(hdr->buf, hdr->buf + start, newlen); }
	hdr->buf[newlen] = 0;
	hdr->free = hdr->free + (hdr->len - newlen);
	hdr->len = newlen;
}

/* Remove all matching characters from the string */
void
yaslstrip(yastr str, const char * cset) {
	if (!str || !cset) { return; }

	struct yastrhdr * hdr = yaslheader(str);
	size_t i = 0, newlen = 0, len = yasllen(str);

	if (len == 0) { return; }

	while (i <= len) {
		while (strchr(cset, str[i]) && i <= len) {
			i++;
		}
		if (i <= len) {
			str[newlen] = str[i];
			i++;
			newlen++;
		}
	}

	hdr->buf[newlen] = '\0';
	hdr->free = hdr->free + (hdr->len - newlen);
	hdr->len = newlen;
}

/* Apply tolower() to every character of the yasl string 's'. */
void
yasltolower(yastr str) {
	if (!str) { return; }

	for (size_t j = 0; j < yasllen(str); j++) {
		str[j] = (char)tolower(str[j]);
	}
}

/* Apply toupper() to every character of the yasl string 's'. */
void
yasltoupper(yastr str) {
	if (!str) { return; }

	for (size_t j = 0; j < yasllen(str); j++) {
		str[j] = (char)toupper(str[j]);
	}
}

/* Remove the part of the string from left and from right composed just of
 * contiguous characters found in 'cset', that is a null terminted C string. */
void
yasltrim(yastr str, const char * cset) {
	if (!str || !cset) { return; }

	struct yastrhdr * hdr = yaslheader(str);
	char * start, * end, * sp, * ep;
	size_t len;

	sp = start = str;
	ep = end = str + yasllen(str) - 1;
	while(sp <= end && strchr(cset, *sp)) { sp++; }
	while(ep > start && strchr(cset, *ep)) { ep--; }
	len = (size_t)((sp > ep) ? 0 : ((ep - sp) + 1));
	if (hdr->buf != sp) { memmove(hdr->buf, sp, len); }
	hdr->buf[len] = '\0';
	hdr->free = hdr->free + (hdr->len - len);
	hdr->len = len;
}

/* Set the yasl string length to the length as obtained with strlen(). */
void
yaslupdatelen(yastr str) {
	if (!str) { return; }

	struct yastrhdr * hdr = yaslheader(str);
	size_t reallen = strlen(str);
	hdr->free += (hdr->len - reallen);
	hdr->len = reallen;
}

/* Split a line into arguments, where every argument can be in the
 * following programming-language REPL-alike form:
 *
 * foo bar "newline are supported\n" and "\xff\x00otherstuff"
 */
yastr *
yaslsplitargs(const char * line, int * argc) {
	if (!line || !argc) { return NULL; }

	const char * p = line;
	char * current = NULL;
	char ** vector = NULL;

	*argc = 0;
	while(1) {
		/* skip blanks */
		while(*p && isspace(*p)) { p++; }
		if (*p) {
			/* get a token */
			int inq=0;  /* set to 1 if we are in "quotes" */
			int insq=0; /* set to 1 if we are in 'single quotes' */
			int done=0;

			if (!current) { current = yaslempty(); }
			while(!done) {
				if (inq) {
					if (*p == '\\' && *(p + 1) == 'x' &&
					                         isxdigit(*(p + 2)) &&
					                         isxdigit(*(p + 3)))
					{
						unsigned char byte;

						byte = (unsigned char)((hex_digit_to_int(*(p + 2)) * 16) +
						                        hex_digit_to_int(*(p + 3)));
						current = yaslcatlen(current, (char*)&byte, 1);
						p += 3;
					} else if (*p == '\\' && *(p + 1)) {
						char c;

						p++;
						switch(*p) {
						case 'n': c = '\n'; break;
						case 'r': c = '\r'; break;
						case 't': c = '\t'; break;
						case 'b': c = '\b'; break;
						case 'a': c = '\a'; break;
						default: c = *p; break;
						}
						current = yaslcatlen(current, &c, 1);
					} else if (*p == '"') {
						/* closing quote must be followed by a space or
						 * nothing at all. */
						if (*(p + 1) && !isspace(*(p + 1))) { goto err; }
						done=1;
					} else if (!*p) {
						/* unterminated quotes */
						goto err;
					} else {
						current = yaslcatlen(current, p, 1);
					}
				} else if (insq) {
					if (*p == '\\' && *(p + 1) == '\'') {
						p++;
						current = yaslcatlen(current, "'", 1);
					} else if (*p == '\'') {
						/* closing quote must be followed by a space or
						 * nothing at all. */
						if (*(p + 1) && !isspace(*(p + 1))) { goto err; }
						done=1;
					} else if (!*p) {
						/* unterminated quotes */
						goto err;
					} else {
						current = yaslcatlen(current, p, 1);
					}
				} else {
					switch(*p) {
					case ' ':
					case '\n':
					case '\r':
					case '\t':
					case '\0':
						done=1;
						break;
					case '"':
						inq=1;
						break;
					case '\'':
						insq=1;
						break;
					default:
						current = yaslcatlen(current, p, 1);
						break;
					}
				}
				if (*p) { p++; }
			}
			/* add the token to the vector */

			char ** tmp = realloc(vector, (unsigned long)((*argc) + 1) * (sizeof (char *)));
			if (!tmp) {
				goto err;
			}
			vector = tmp;

			vector[*argc] = current;
			(*argc)++;
			current = NULL;
		} else {
			/* Even on empty input string return something not NULL. */
			if (!vector) { vector = malloc(sizeof(void*)); }
			return vector;
		}
	}

err:
	while((*argc)--) {
		yaslfree(vector[*argc]);
	}
	free(vector);
	if (current) { yaslfree(current); }
	*argc = 0;
	return NULL;
}

/* Split 's' with separator in 'sep'. */
yastr *
yaslsplitlen(const char * str, size_t len, const char * sep, size_t seplen, size_t * count) {
	if (!str || !sep || !count) { return NULL; }

	size_t elements = 0, slots = 5, start = 0;
	yastr * tokens;

	if (seplen < 1) { return NULL; }

	tokens = malloc(sizeof(yastr)*slots);
	if (!tokens) { return NULL; }

	if (len == 0) {
		*count = 0;
		return tokens;
	}
	for (size_t j = 0; j < (len - (seplen - 1)); j++) {
		/* make sure there is room for the next element and the final one */
		if (slots < elements + 2) {
			yastr * newtokens;

			slots *= 2;
			newtokens = realloc(tokens, sizeof(yastr) * slots);
			if (!newtokens) { goto cleanup; }
			tokens = newtokens;
		}
		/* search the separator */
		if ((seplen == 1 && *(str + j) == sep[0]) || (memcmp(str + j, sep, seplen) == 0)) {
			tokens[elements] = yaslnew(str + start, (size_t)(j - start));
			if (!tokens[elements]) { goto cleanup; }
			elements++;
			start = j + seplen;
			j = j + seplen - 1; /* skip the separator */
		}
	}
	/* Add the final element. We are sure there is room in the tokens array. */
	tokens[elements] = yaslnew(str + start, (size_t)(len - start));
	if (!tokens[elements]) { goto cleanup; }
	elements++;
	*count = elements;
	return tokens;

cleanup:
	{
		for (size_t i = 0; i < elements; i++) {
			yaslfree(tokens[i]);
		}
		free(tokens);
		*count = 0;
		return NULL;
	}
}

// Concatenation //

/* Append the specified null termianted C string to the yasl string 'dest'. */
yastr
yaslcat(yastr dest, const char * src) {
	if (!dest || !src) { return NULL; }

	return yaslcatlen(dest, src, strlen(src));
}

/* Append the specified yasl string 'src' to the existing yasl string 'dest'. */
yastr
yaslcatyasl(yastr dest, const yastr src) {
	if (!dest || !src) { return NULL; }

	return yaslcatlen(dest, src, yasllen(src));
}

/* Append the specified binary-safe string pointed by 'src' of 'len' bytes to the
 * end of the specified yasl string 'dest'. */
yastr
yaslcatlen(yastr dest, const void * src, size_t len) {
	if (!dest || !src) { return NULL; }

	struct yastrhdr * hdr;
	size_t curlen = yasllen(dest);

	dest = yaslMakeRoomFor(dest, len);
	if (!dest) { return NULL; }
	hdr = yaslheader(dest);
	memcpy(dest + curlen, src, len);
	hdr->len = curlen + len;
	hdr->free = hdr->free - len;
	dest[curlen + len] = '\0';
	return dest;
}

/* Append to the yasl string "dest" an escaped string representation where
 * all the non-printable characters (tested with isprint()) are turned into
 * escapes in the form "\n\r\a...." or "\x<hex-number>". */
yastr
yaslcatrepr(yastr dest, const char * src, size_t len) {
	if (!dest || !src) { return NULL; }

	dest = yaslcatlen(dest, "\"", 1);
	while(len--) {
		switch(*src) {
		case '\\':
		case '"':
			dest = yaslcatprintf(dest, "\\%c", *src);
			break;
		case '\n': dest = yaslcatlen(dest, "\\n", 2); break;
		case '\r': dest = yaslcatlen(dest, "\\r", 2); break;
		case '\t': dest = yaslcatlen(dest, "\\t", 2); break;
		case '\a': dest = yaslcatlen(dest, "\\a", 2); break;
		case '\b': dest = yaslcatlen(dest, "\\b", 2); break;
		default:
			if (isprint(*src)) {
				dest = yaslcatprintf(dest, "%c", *src);
			} else {
				dest = yaslcatprintf(dest, "\\x%02x", (unsigned char)*src);
				break;
			}
		}
		src++;
	}
	return yaslcatlen(dest, "\"", 1);
}

/* Like yaslcatpritf() but gets va_list instead of being variadic. */
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
yastr
yaslcatvprintf(yastr str, const char * fmt, va_list ap) {
	if (!str || !fmt) { return NULL; }

	va_list cpy;
	char * buf, * t;
	size_t buflen = 16;

	while(1) {
		buf = malloc(buflen);
		if (!buf) { return NULL; }
		buf[buflen - 2] = '\0';
		va_copy(cpy, ap);
		vsnprintf(buf, buflen, fmt, cpy);
		va_end(cpy);
		if (buf[buflen - 2] != '\0') {
			free(buf);
			buflen *= 2;
			continue;
		}
		break;
	}
	t = yaslcat(str, buf);
	free(buf);
	return t;
}
#pragma GCC diagnostic warning "-Wformat-nonliteral"

/* Append to the yasl string 'str' a string obtained using printf-alike format
 * specifier. */
yastr
yaslcatprintf(yastr str, const char * fmt, ...) {
	if (!str || !fmt) { return NULL; }

	va_list ap;
	char * t;
	va_start(ap, fmt);
	t = yaslcatvprintf(str, fmt, ap);
	va_end(ap);
	return t;
}


// Freeing //

/* Free a yasl string. No operation is performed if 's' is NULL. */
void
yaslfree(yastr str) {
	if (str) {
		free(yaslheader(str));
	}
}

/* Free the result returned by yaslsplitlen(), or do nothing if 'tokens' is NULL. */
void
yaslfreesplitres(yastr * tokens, size_t count) {
	if (!tokens) { return; }

	while(count--) {
		yaslfree(tokens[count]);
	}
	free(tokens);
}


// Low-level functions //

/* Return the total size of the allocation of the specifed yasl string,
 * including:
 * 1) The yasl header before the pointer.
 * 2) The string.
 * 3) The free buffer at the end if any.
 * 4) The implicit null term.
 */
size_t
yaslAllocSize(yastr str) {
	if (!str) { return 0; }

	struct yastrhdr * hdr = yaslheader(str);

	return sizeof(*hdr) + hdr->len + hdr->free + 1;
}

/* Increment the yasl string length and decrements the left free space at the
 * end of the string according to 'incr'. Also set the null term in the new end
 * of the string. */
void
yaslIncrLen(yastr str, size_t incr) {
	if (!str) { return; }

	struct yastrhdr * hdr = yaslheader(str);

	assert(hdr->free >= incr);
	hdr->len += incr;
	hdr->free -= incr;
	str[hdr->len] = '\0';
}

/* Enlarge the free space at the end of the yasl string so that the caller
 * is sure that after calling this function can overwrite up to addlen
 * bytes after the end of the string, plus one more byte for nul term. */
yastr
yaslMakeRoomFor(yastr str, size_t addlen) {
	if (!str) { return NULL; }

	struct yastrhdr * hdr, * newhdr;
	size_t free = yaslavail(str);
	size_t len, newlen;

	if (free >= addlen) { return str; }
	len = yasllen(str);
	hdr = yaslheader(str);
	newlen = (len + addlen);
	if (newlen < YASL_MAX_PREALLOC) {
		newlen *= 2;
	} else {
		newlen += YASL_MAX_PREALLOC;
	}
	newhdr = realloc(hdr, sizeof(struct yastrhdr) + newlen + 1);
	if (!newhdr) { return NULL; }

	newhdr->free = newlen - len;
	return newhdr->buf;
}

/* Reallocate the yasl string so that it has no free space at the end. The
 * contained string remains not altered, but next concatenation operations
 * will require a reallocation. */
yastr
yaslRemoveFreeSpace(yastr str) {
	if (!str) { return NULL; }

	struct yastrhdr * hdr = yaslheader(str);

	struct yastrhdr * tmp = realloc(hdr, sizeof(struct yastrhdr) + hdr->len + 1);
	if (tmp) {
		hdr = tmp;
		hdr->free = 0;
	}

	return hdr->buf;
}


// Low-level helper functions //

/* Helper function for yaslsplitargs() that converts a hex digit into an
 * integer from 0 to 15 */
int
hex_digit_to_int(char c) {
	// Eg. 'B' - 'A' is 1, so we need to add 10 to get the correct value.
	return c >= '0' && c <= '9' ? c - '0'      :
	       c >= 'A' && c <= 'F' ? c - 'A' + 10 :
	       c >= 'a' && c <= 'f' ? c - 'a' + 10 : 0 ;
}

