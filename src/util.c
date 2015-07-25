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
#include <stdlib.h>
#include <ctype.h>
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

typedef struct token
{
	char *p, *q;
	int end_delimiter;
} token;

static char* a_r_scan(token *tok, int joint)
/*
* Tokenize the string as a sequence of 0-terminated words and return the type.
* On first call, p points to the input string to be parsed and q == NULL.
* The input string is overwritten with the output as the scan proceeds.
* On subsequent calls, p and q point to the input and output respectively.
* The start of the output is the return value.
*/
{
	assert(tok && tok->p && tok->q <= tok->p);

	char *p = skip_cfws(tok->p);
	char *q = tok->q? tok->q: tok->p, *entry = q;

	int quot = 0, escape = 0, ch;

	while (p && (ch = *(unsigned char*)p++) != 0)
	{
		assert (q <= p);

		if (escape)
		{
			*q++ = ch;
			escape = 0;
			continue;
		}

		if (quot)
		{
			switch (ch)
			{
				case '\\':
					escape = 1;
					continue;

				case '"':
					quot = 0;
					continue;

				default:
					*q++ = ch;
					continue;
			}
		}

		switch (ch)
		{
			case '\\':
				escape = 1;
				continue;

			case '"':
				quot = 1;
				continue;

			case '(':
				p = skip_comment(p - 1);
				if (p)
				{
					assert(*p == ')');
					++p;
				}
				continue;

			default:
				break;
		}

		if (isspace(ch))
		{
			char *next = skip_cfws(p);
			int ch2 = next? *(unsigned char*)next: 0;

			/*
			* If a joint is admitted, CFWS can be placed around it
			*/
			if (joint && ch2 == joint && (next = skip_cfws(next + 1)) != 0)
			{
				*q++ = joint;
				p = next;
				continue;
			}

			/*
			* If the next value is a delimiter, use it.
			* Otherwise space or zero is the delimiter.
			*/
			if (ch2 && strchr(";=", ch2) != NULL)
			{
				ch = ch2;
				p = next + 1;
			}
			else if (ch2)
				ch = ' ';
			else
				ch = 0;
			break;
		}
		else if (strchr(";=", ch) != NULL)
			break;

		*q++ = ch;
	}

	if (p == NULL || escape || quot)
		return NULL;

	*q++ = 0;
	tok->q = q;
	tok->p = p;
	tok->end_delimiter = ch;

	assert(tok && tok->p && tok->q <= tok->p);
	return entry;
}

int
a_r_parse(char const *a_r, int (*cb)(void*, int, name_val*, size_t), void *cbv)
/*
* Parse a_r, which should start with the authserv-id, and call back cb with
* arguments:
*
* 1 (void*) the cbv given on entry,
* 2 (int) -1 for authserv-id, 0, 1, ... for "resinfo" stanzas, rtc for last call
* 3 (name_val*) an array of name=value pairs, and
* 4 (size_t) the number of elements in the array.
*
* The value is null for authserv-id.  The array itself is null on the last call.
*/
{
	assert(a_r);
	assert(cb);

	char *s = strdup(a_r);
	name_val resinfo[16];
	int rtc = 0;

	if (s == NULL) return -1;

	enum a_r_state {
		a_r_server,
		a_r_method,
		a_r_name,
		a_r_value
	} state = a_r_server;

	// it just happens that the elements that expect an '=' have a joint
	// to be considered.
	static const int joint[] = {
		'/', // a_r_server,
		'/', // a_r_method,
		'.', // a_r_name,
		'@'  //a_r_value
	};

	int count = 0;
	size_t n = 0;
	token tok;
	memset(&tok, 0, sizeof tok);
	tok.p = s;

	do
	{
		char *r = a_r_scan(&tok, joint[state]);
		if (r == NULL)
		{
			rtc = -1;
			break;
		}

		switch(state)
		{
			case a_r_server:
				if (tok.end_delimiter == ';')
				{
					resinfo[0].name = r;
					resinfo[0].value = NULL;
					rtc = (*cb)(cbv, -1, resinfo, 1);
					state = a_r_method;
				}
				break;

			case a_r_method:
				n = 0;
				if (count == 0 && stricmp(r, "none") == 0)
					break;

				/* else thru */

			case a_r_name:
				resinfo[n].name = r;
				state = a_r_value;
				if (tok.end_delimiter != '=')
					rtc = -2;
				break;

			case a_r_value:
				resinfo[n].value = r;
				++n;

				if (tok.end_delimiter == ' ')
					state = a_r_name;

				else if (tok.end_delimiter == ';' || tok.end_delimiter == 0)
				{
					state = a_r_method;
					rtc = (*cb)(cbv, count, resinfo, n);
					++count;
				}
				else
					rtc = -3;
				break;

			default:
				assert(0);
				break;
		}
	} while (rtc == 0 && tok.end_delimiter != 0 &&
		n < sizeof resinfo / sizeof resinfo[0]);

	if (rtc == 0 && tok.end_delimiter != 0) rtc = -4;
	rtc = (*cb)(cbv, rtc, NULL, 0); // last call

	free(s);
	return rtc;
}

#if defined TEST_MAIN
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static int verbose = 0;

static int my_cb(void *v, int step, name_val* nv, size_t nv_count)
{
	assert(v == NULL);

	if (verbose)
		printf("%3zu value%s at %d\n", nv_count, nv_count > 1? "s": "", step);

	if (nv == NULL)
		return step;

	if (step < 0)
		printf("%s;\n", nv[0].name);
	else
	{
		for (size_t i = 0; i < nv_count; ++i)
			printf(" %s=%s", nv[i].name, nv[i].value);
		putchar('\n');
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char *fname = NULL;
	int i, errs = 0, rtc = 1;

	for (i = 1; i < argc; ++i)
	{
		char *arg = argv[i];

		if (arg[0] == '-' && arg[1])
		{
			int ch;
			while ((ch = *++arg) != 0)
			{
				switch (ch)
				{
					case 'v':
						++verbose;
						break;

					default:
						fprintf(stderr, "Invalid arg[%d]: %s\n", i, argv[i]);
						++errs;
						break;
				}
			}
		}
		else if (fname == NULL)
			fname = arg;
		else
		{
			fprintf(stderr, "Unexpected arg[%d]: %s\n", i, argv[i]);
			++errs;
		}
	}

	if (errs == 0)
	{
		FILE *fp = fopen(fname, "r");
		if (fp == NULL)
			perror(fname);
		else
		{
			struct stat st;
			char *buf = NULL;
			if (fstat(fileno(fp), &st) == 0 &&
				st.st_size < 65535 &&
				(buf = malloc(st.st_size + 1)) != NULL &&
				fread(buf, st.st_size, 1, fp) == 1)
			{
				token tok;
				memset(&tok, 0, sizeof tok);
				tok.p = buf;
				buf[st.st_size] = 0;
				if (verbose)
					printf("scanning %s", buf);

				rtc = a_r_parse(buf, &my_cb, NULL);
				if (verbose)
					printf("a_r_parse returned %d\n", rtc);
			}

			free(buf);
			fclose(fp);
		}
	}

	return errs || rtc;
}
#endif // TEST_MAIN