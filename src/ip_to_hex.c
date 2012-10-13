/*
** ip_to_hex.c - written in milano by vesely on 3oct2012
** read/write via odbx
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2012 Alessandro Vesely

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

If you modify zdkimfilter, or any covered work, by linking or combining it
with software developed by The OpenDKIM Project and its contributors,
containing parts covered by the applicable licence, the licensor or
zdkimfilter grants you additional permission to convey the resulting work.
*/
#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

static char *buf2hex(size_t bytes, unsigned char *s)
{
	static char const hex_digit[] = "0123456789abcdef";
	char *const r = malloc(2*bytes + 1), *p = r;

	if (r)
	{
		while (bytes--> 0)
		{
			unsigned char ch = *s++;
			*p++ = hex_digit[(ch & 0xf0U) >> 4];
			*p++ = hex_digit[ch & 0xfU];
		}
		*p = 0;
	}
	return r;
}

char *ip_to_hex(char const *ip)
{
	if (ip == NULL)
		return NULL;

	if (strchr(ip, ':') == NULL)
	{
		unsigned char dst[sizeof(struct in_addr)];
		if (inet_pton(AF_INET, ip, dst) <= 0)
			return NULL;

		return buf2hex(sizeof dst, dst);
	}

	unsigned char dst[sizeof(struct in6_addr)];
	if (inet_pton(AF_INET6, ip, dst) <= 0)
		return NULL;

	int i;
	for (i = 0; i < 10; ++i)
		if (dst[i] != 0)
			break;

	if (i < 10 || dst[10] != 0xffU || dst[11] != 0xffU)
		return buf2hex(16, dst);

	return buf2hex(4, &dst[12]);
}