/*
** cstring.h - written by vesely in milano on 18 feb 2002
** simple string that grows

Copyright (C) 2002, 2015 Alessandro Vesely

This file is part of zdkimfilter

zdkimfilter is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

zdkimfilter is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License version 3
along with zdkimfilter.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPLv3 section 7:

If you modify zdkimfilter, or any covered part of it, by linking or combining
it with OpenSSL, OpenDKIM, Sendmail, or any software developed by The Trusted
Domain Project or Sendmail Inc., containing parts covered by the applicable
licence, the licensor of zdkimfilter grants you additional permission to convey
the resulting work.

*/
#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
// #if defined(TEST_MAIN)
#include <stdio.h> // for vsnprintf
// #endif

#include "cstring.h"
#include <assert.h>


#if !defined(NDEBUG)
static int cstr_assert(cstring const *const s)
{
#if defined(TEST_MAIN)
	printf("%p: %zu/%zu = \"%s\"\n", s, s->length, s->alloc, s->data);
#endif
	return s != NULL &&
		s->alloc >= s->length &&
		s->data[s->length] == 0;
}
#endif /* NDEBUG */

cstring* cstr_init(size_t const total)
/* alloc one byte more than needed */
{
	cstring *const rtc = (cstring*)malloc(total + sizeof(cstring));
	if (rtc)
	{
		rtc->alloc = total;
		rtc->length = 0;
		rtc->data[0] = 0;
	}

	assert(rtc == NULL || cstr_assert(rtc));
	return rtc;
}

cstring* cstr_from_string(char const *data)
{
	size_t length = strlen(data);
	cstring *rtc = cstr_init(length);
	if (rtc)
		rtc = cstr_addblob(rtc, data, length);

	assert(rtc == NULL || cstr_assert(rtc));

	return rtc;
}

cstring* cstr_reserve(cstring* const s, size_t const total)
{
	cstring *rtc;
	assert(cstr_assert(s));

	if (s->alloc >= total)
		return s;
	rtc = (cstring*)realloc(s, total + sizeof(cstring));
	if (rtc != NULL)
		rtc->alloc = total;
	else
		free(s);

	assert(rtc == NULL || cstr_assert(rtc));
	return rtc;

#if 0
	if ((rtc = (cstring*)malloc(total + sizeof(cstring))) != NULL)
	{
		size_t const l = rtc->length = s->length;
		memcpy(rtc->data, s->data, l + 1);
		rtc->alloc = total;
	}
	free(s);
	return rtc;
#endif
}

cstring* cstr_grow(cstring* const s, size_t const incr)
{
	cstring *rtc;
	size_t total;
	size_t const req = s->length + incr;
	
	assert(cstr_assert(s));
	
	if (s->alloc >= req)
		return s;
	
	total = 2 * s->alloc;
	if (total <= req)
		total = req;
	rtc = cstr_reserve(s, total);
	
	assert(rtc == NULL || cstr_assert(rtc));
	return rtc;	
}

cstring* cstr_addch(cstring* s, int const ch)
{
	assert(cstr_assert(s));

	if ((s = cstr_grow(s, 1)) != NULL)
	{
		s->data[s->length] = ch;
		s->data[++s->length] = 0;
	}

	assert(s == NULL || cstr_assert(s));
	return s;
}

cstring* cstr_addblob(cstring* s, char const* str, size_t const l)
{
	assert(cstr_assert(s));

	if (l > 0 && (s = cstr_grow(s, l)) != NULL)
	{
		memcpy(&s->data[s->length], str, l);
		s->data[s->length += l] = 0;
	}

	assert(s == NULL || cstr_assert(s));
	return s;
}

cstring* cstr_addstr(cstring* s, char const* str)
{
	return cstr_addblob(s, str, strlen(str));
}

void cstr_trunc(cstring* s, size_t l)
{
	assert(cstr_assert(s));

	if (l > s->alloc)
		l = s->alloc;
	s->data[s->length = l] = 0;
	
	assert(cstr_assert(s));
}

cstring* cstr_final(cstring* const s)
{
	size_t const l = s->length;
	cstring* rtc;
	assert(cstr_assert(s));

	rtc = realloc(s, l + sizeof(cstring));
	if (rtc == NULL) /* ??? */
		rtc = s;
	else
		rtc->alloc = l;

	assert(rtc == NULL || cstr_assert(rtc));
	return rtc;
}

cstring* cstr_dup(cstring const * const s)
{
	size_t const l = s->length;
	cstring* rtc;
	assert(cstr_assert(s));

	rtc = (cstring*)malloc(l + sizeof(cstring));
	if (rtc)
	{
		rtc->length = rtc->alloc = l;
		memcpy(rtc->data, s->data, l + 1);
	}

	assert(rtc == NULL || cstr_assert(rtc));
	return rtc;
}

cstring* cstr_setblob(cstring* s, char const* str, size_t const l)
{
	assert(cstr_assert(s));

	if (l > s->alloc && (s = cstr_grow(s, l - s->alloc)) == NULL)
		return NULL;

	memcpy(s->data, str, l);
	s->data[s->length = l] = 0;
	
	assert(s == NULL || cstr_assert(s));
	return s;
}

cstring* cstr_setstr(cstring* s, char const* str)
{
	return cstr_setblob(s, str, strlen(str));
}

cstring* cstr_set(cstring* s, cstring const* str)
{
	assert(cstr_assert(s));
	assert(cstr_assert(str));
	if (s == str) return s;
	return cstr_setblob(s, str->data, str->length);
}

cstring* cstr_add(cstring *s, cstring const *str)
{
	cstring *rtc;
	assert(cstr_assert(s));
	assert(cstr_assert(str));
	if (s == str)
	{
		cstring *s1 = cstr_dup(str);
		if (s1 == NULL)
			return NULL;
		rtc = cstr_add(s, s1);
		free(s1);
	}
	else
		rtc = cstr_addblob(s, str->data, str->length);
	return rtc;
}

cstring *cstr_printf(cstring *s, char const *fmt, ...)
{
	assert(cstr_assert(s));
	assert(fmt);

	size_t size = strlen(fmt) + 80;
	s = cstr_reserve(s, size);
	if (s == NULL)
		return NULL;

	va_list ap;
	size_t l = s->length, avail = s->alloc - l;
	for (;;)
	{
		va_start(ap, fmt);
		int grow = vsnprintf(s->data + l, avail, fmt, ap);
		va_end(ap);

		// Until glibc 2.0.6, vsnprintf would return -1 when the output was truncated
		if (grow > -1)
		{
			if ((size_t)grow < avail)
			{
				s->length += grow;
				break;
			}

			size += grow;
		}
		else
			size *= 2;

		s->data[l] = 0;
		s = cstr_grow(s, size);
		if (s == NULL)
			break;

		avail = s->alloc -l;
	}

	assert(s == NULL || cstr_assert(s));
	return s;
}


#if defined(TEST_MAIN)

void do_final(cstring *s)
{
	fputs("final:\n", stdout);
	s = cstr_final(s);
	free(s);
}

int main(int argc, char *argv[])
{
	int i, j, bychar = 0;
	cstring* s = NULL;
	for (i = 1; i < argc; ++i)
	{
		int size = atoi(argv[i]);
		if (size > 0 || strcmp(argv[i], "0") == 0)
		{
			if (s)
				do_final(s);
			s = cstr_init(size);
			continue;
		}

		if (s == NULL)
			s = cstr_init(0);

		if (s == NULL)
			break;

		static char const lorem_ipsum[] =
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n"
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n"
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n"
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n"
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n"
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n"
			"lorem ipsum lorem ipsum lorem ipsum lorem ipsum lorem ipsum\n";

		if (strcmp(argv[i], "printf") == 0)
			for (j = 0; j < 4 && s; ++j)
				s = cstr_printf(s, "\nj=%d, s->alloc=%zu, s->length=%zu\n%s",
					j, s->alloc, s->length, lorem_ipsum);
		else
		{
			j = 0;
			if (++bychar > 4)
				bychar = 0;
			else
				for (; j < 4 && argv[i][j] != 0; ++j)
					if ((s = cstr_addch(s, argv[i][j])) == NULL)
						break;
			if (s && argv[i][j])
				s = cstr_addstr(s, &argv[i][j]);
		}
	}

	if (s)
		do_final(s);
	else
		fputs("s == NULL!!!\n", stderr);
	return 0;
}

#endif
