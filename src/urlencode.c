/*
** urlencode.c - written by vesely in milano on Fri 01 Feb 2019
** urlencode arguments or stdin if no arg given

Copyright (C) 2019 Alessandro Vesely

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



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cstring.h"

#include <assert.h>

// urlencode a string
cstring* urlencode(char const *s)
{
	assert(s);

	cstring *u = cstr_init(2*strlen(s));
	while (u)
	{
		int const ch = *(unsigned char*)s++;
		if (ch == 0)
			break;

		if (isalnum(ch) || strchr("-._~", ch)) // rfc3986's unreserved char
			u = cstr_addch(u, ch);
		else
		{
			char perc[4];
			sprintf(perc, "%%%02X", ch);
			u = cstr_addstr(u, perc);
		}
	}

	return u;
}

#if defined TEST_URLENCODE
int main(int argc, char *argv[])
{
	cstring *u = NULL;
	if (argc > 1)
		for (int i = 1; i < argc; ++i)
		{
			u = urlencode(argv[i]);
			if (u)
			{
				printf("%s\n", cstr_get(u));
				free(u);
			}
		}
	else
	{
		cstring *s = cstr_init(1024);
		int ch;
		while (s && (ch = getchar()) != EOF)
			s = cstr_addch(s, ch);

		if (s)
		{
			u = urlencode(cstr_get(s));
			free(s);
			if (u)
			{
				printf("%s\n", cstr_get(u));
				free(u);
			}
		}
	}

	return 0;
}
#endif
