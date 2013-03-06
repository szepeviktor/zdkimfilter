/*
** util.c - written in milano by vesely on 6mar2013
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

#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif

#include <string.h>
#include "util.h"
#include <assert.h>

char *hdrval(const char *a, const char *b)
// b must be without trailing ':'
// return pointer after column if headers match, NULL otherwise
{
	assert(a && b && strchr(b, ':') == NULL);
	
	int c, d;
	do c = *(unsigned char const*)a++, d = *(unsigned char const*)b++;
	while (c != 0 && d != 0 && (c == d || tolower(c) == tolower(d)));
	
	if (d != 0 || c == 0)
		return NULL;

	while (c != ':')
		if (!isspace(c) || (c = *(unsigned char const*)a++) == 0)
			return NULL;

	return (char*)a;
}

char *skip_comment(char const *s)
{
	assert(s && *s == '(');
	
	int comment = 1;
	for (;;)
	{
		switch (*(unsigned char*)++s)
		{
			case 0:
				return NULL;

			case '(':
				++comment;
				break;

			case ')':
				if (--comment <= 0)
					return (char*)s;
				break;

			case '\\': // quoted pair, backslash cannot be last char
				++s;    // since there must be a newline anyway
				break;

			default:
				break;
		}
	}
}

char *skip_cfws(char const *s)
{
	while (s)
	{
		int ch;
		while (isspace(ch = *(unsigned char const*)s))
			++s;
		if (ch == '(')
		{
			if ((s = skip_comment(s)) != NULL)
			{
				assert(*s == ')');
				++s;
			}
		}
		else if (ch)
			break;
		else
			s = NULL;
	}
	return (char*)s;
}
