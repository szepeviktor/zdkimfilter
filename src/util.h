/*
** util.h - written in milano by vesely on 6mar2013
** collected mail parsing utilities
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2013 Alessandro Vesely

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
#if !defined UTIL_H_INCLUDED
#include <ctype.h>
#include <stddef.h>

// define static functions "inline" to avoid "warning... defined but not used"
static inline int stricmp(const char *a, const char *b)
{
	int c, d;
	do c = *a++, d = *b++;
	while (c != 0 && d != 0 && (c == d || (c = tolower(c)) == (d = tolower(d))));

	return c < d ? -1 : c > d;
}

static inline int strincmp(const char *a, const char *b, size_t n)
{
	while (n)
	{
		int c = *a++, d = *b++;
		if (c == 0 || d == 0 || (c != d && (c = tolower(c)) != (d = tolower(d))))
			return c < d ? -1 : c > d;
		--n;
	}
	return 0;
}

char *hdrval(const char *a, const char *b);
char *skip_comment(char const *s);
char *skip_cfws(char const *s);

typedef struct name_val
{
	char const *name;
	char const *value;
} name_val;
int
a_r_parse(char const *a_r, int (*cb)(void*, int, name_val*, size_t), void *cbv);

#define UTIL_H_INCLUDED
#endif
