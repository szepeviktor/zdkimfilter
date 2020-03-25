/*
** redact.c - written in milano by vesely on 20sep2012
** string redaction (encription)
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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#if defined HAVE_NETTLE
#include <nettle/arcfour.h>
#include <nettle/base64.h>
#endif // HAVE_NETTLE
#include "redact.h"

#if defined MAIN
#include "parm.h"
#endif

#if defined HAVE_NETTLE

static const char my_exp_base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static const char my_exp_input[] =
	"!\"#$%&'*,-.:;=?@[\\]^_`{|}~"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static size_t my_compress(unsigned char *out, size_t outlength, char const *in)
/*
* txt is case insensitive, ascii, no space, no ctrl, no "()<>", no trailing '@'.
* convert to lowercase base64, sort of, then to binary.
*
* return 0 for invalid input
*/
{
	struct base64_decode_ctx ctx;
	base64_decode_init(&ctx);

	unsigned char *p = out, *const ep = p + outlength;
	int ch, cnt = 0;
	while ((ch = *(unsigned char*)in++) != 0)
	{
		if (!isascii(ch))
			return 0;

		if (isupper(ch))
			ch = tolower(ch);
		else if (ispunct(ch))
		{
			char *it = strchr(my_exp_input, ch);
			if (it)
				ch = my_exp_base64[it - &my_exp_input[0]];
			else
				return 0;
		}
		else if (!isalnum(ch))
			return 0;

		int rc = base64_decode_single(&ctx, p, ch);
		if (rc < 0 || (p += rc) >= ep)
			return 0;

		++cnt;
	}

	if (ch == 'P') // trailing '@'
		return 0;

	for (; (cnt & 3) > 0; ++cnt)
	{
		int rc = base64_decode_single(&ctx, p, 'P');
		if (rc < 0 || (p += rc) >= ep)
			return 0;
	}

	if (base64_decode_final(&ctx) == 0)
		return 0;

	return p - out;
}

#if defined MAIN
#include <stdio.h>
#include <errno.h>
#include "vb_fgets.h"

size_t frombase64(unsigned char *dest, size_t destlen, char *src, size_t len)
{
	if (destlen < BASE64_DECODE_LENGTH(len))
		return 0;

	struct base64_decode_ctx ctx;
	base64_decode_init(&ctx);

#if HAVE_NETTLE_V3
	// Fri Apr 26 13:43:57 2013, commit 86fdb2ce31177028de997b98cc71b5027cf0bc1c
	// Use size_t rather than unsigned for base16, base64, nettle_bufer and sexp related functions.
	size_t l = len;
#else
	unsigned l = len;
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
	base64_decode_update(&ctx, &l, dest, len, src);
#pragma GCC diagnostic pop

	int rc = base64_decode_final(&ctx);
	return rc? l: 0;
}

static char *my_expand(unsigned char *in, size_t len)
{
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);

	unsigned char tr[512], *p = &tr[0], *s = in;
	if (BASE64_ENCODE_LENGTH(len) >= sizeof tr)
		return NULL;

	while (len)
	{
		int rc = base64_encode_single(&ctx, p, *s++);
		if (rc < 0)
			return NULL;
		while (rc)
		{
			int const ch = *p;
			if (isupper(ch))
				*p = my_exp_input[ch - 'A'];
			++p;
			--rc;
		}
		--len;
	}

	*p-- = 0;
	while (p > &tr[0] && *p == '@')
		*p-- = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
	return strdup(&tr[0]);
#pragma GCC diagnostic pop
}

static char *unredacted(char const *key, char const*txt)
// return a malloc'ed string or NULL
{
	size_t klen = strlen(key);
	size_t tlen = strlen(txt);
	if (tlen > 320 || tlen == 0)
	{
		return NULL;
	}

	if (klen > ARCFOUR_MAX_KEY_SIZE)
		klen = ARCFOUR_MAX_KEY_SIZE;
	else if (klen < ARCFOUR_MIN_KEY_SIZE)
		klen = ARCFOUR_MIN_KEY_SIZE;

	struct arcfour_ctx ctx;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
	arcfour_set_key(&ctx, klen, key);
#pragma GCC diagnostic pop

	char buf[512], buf2[512];
	strcpy(buf2, txt);
	char *const is_compressed = strchr(buf2, '@');
	if (is_compressed)
	{
		memmove(is_compressed, is_compressed + 1,
			tlen - (is_compressed - &buf2[0]));
		--tlen;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
	size_t sz = frombase64(buf, sizeof buf, buf2, tlen);
	if (sz == 0)
	{
		fprintf(stderr, "cannot decode \"%s\"\n", txt);
		return NULL;
	}

	unsigned char clear[512];
	arcfour_crypt(&ctx, sz, clear, buf);
	clear[sz] = 0;

	char *orig = is_compressed? my_expand(clear, sz): strdup(clear);
#pragma GCC diagnostic pop
	if (orig == NULL)
		fprintf(stderr, "cannot expand \"%s\"\n", txt);

	return orig;
}
#endif // MAIN

static size_t
tobase64(unsigned char *dest, size_t destlen, unsigned char *src, size_t len)
{
	if (destlen < BASE64_ENCODE_LENGTH(len) + BASE64_ENCODE_FINAL_LENGTH)
		return 0;

	size_t l1, l2;
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);
	l1 = base64_encode_update(&ctx, dest, len, src);
	l2 = base64_encode_final(&ctx, dest + l1);
	dest[l1 + l2] = 0;
	return l1 + l2;
}

char *redacted(char const *key, char const*txt)
// return a malloc'ed string or NULL
{
	size_t klen = strlen(key);
	size_t tlen = strlen(txt);
	if (tlen > 320 || tlen == 0)
	{
		return NULL;
	}

	if (klen > ARCFOUR_MAX_KEY_SIZE)
		klen = ARCFOUR_MAX_KEY_SIZE;
	else if (klen < ARCFOUR_MIN_KEY_SIZE)
		klen = ARCFOUR_MIN_KEY_SIZE;

	struct arcfour_ctx ctx;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
	arcfour_set_key(&ctx, klen, key);
#pragma GCC diagnostic pop

	unsigned char clear[512];
	size_t sz = my_compress(clear, sizeof clear, txt);
	int const is_compressed = sz != 0;
	if (!is_compressed)
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
		strcpy(clear, txt);
#pragma GCC diagnostic pop
		sz = tlen;
	}

	unsigned char buf[512];
	arcfour_crypt(&ctx, sz, buf, clear);

	unsigned char buf2[512];
	size_t length = tobase64(buf2, sizeof buf2 - is_compressed, buf, sz);
	if (length <= 0)
		return NULL;

	if (is_compressed)
	{
		size_t const l2 = length/2;
		memmove(&buf2[l2 + 1], &buf2[l2], length - l2 + 1);
		buf2[l2] = '@';
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
	return strdup(buf2);
#pragma GCC diagnostic pop
}
#else
char *redacted(char const *key, char const*txt)
// return NULL, since we don't have nettle
{
	return NULL;
}
#endif // HAVE_NETTLE


int redact_is_fully_featured()
{
	return
#if defined HAVE_NETTLE
			1
#else
			0
#endif
			;
}

#if defined MAIN
#if defined HAVE_NETTLE
static inline int do_get_password(char *config_file, char**password)
// return 0 if ok, 1 if ok and must free, -1 if error
{
	if (*password)
		return 0;

	char const *const pname[1] = {"redact_received_auth"};
	int rtc = read_single_values(config_file, 1, pname, password);
	if (rtc != 1 || *password == NULL)
	{
		char const *const dfname = config_file? config_file: "config file";
		if (rtc < 0)
			perror(dfname);
		else
			fprintf(stderr, "%s not found in %s\n", pname[0], dfname);
		return -1;
	}

	return 1;
}

static int opt_encode(char *txt, char *config_file, char *password)
{
	int do_free = do_get_password(config_file, &password);
	if (password)
	{
		char *r = redacted(password, txt);
		if (r)
		{
			puts(r);
			free(r);
		}
	}
	if (do_free > 0)
		free(password);

	return do_free < 0;
}

static int opt_decode(char *txt, char *config_file, char *password)
{
	int do_free = do_get_password(config_file, &password);
	if (password)
	{
		char *r = unredacted(password, txt);
		if (r)
		{
			puts(r);
			free(r);
		}
	}
	if (do_free > 0)
		free(password);

	return do_free < 0;
}
#endif

int main(int argc, char *argv[])
{
	int rtc = 0, i;
	char *config_file = NULL;
	char *password = NULL;

	for (i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		
		if (strcmp(arg, "-f") == 0)
		{
			config_file = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "--version") == 0)
		{
			puts(PACKAGE_NAME ", version " PACKAGE_VERSION "\n"
				"Compiled with"
#if !defined HAVE_NETTLE
				"out"
#endif
				" libnettle\n");
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			printf("redact command line args:\n"
				"  -f config-filename      override %s\n"
				"  --password password     instead of the one in config-file\n"
#if defined HAVE_NETTLE
				"  --encode clearstring    produce an encoded string\n"
				"  --decode obfuscated     retrieve cleartext\n"
#endif
				"  --help                  print this stuff and exit\n"
				"  --version               print version string and exit\n",
					default_config_file);
			return 0;
		}
		else if (strcmp(arg, "--password") == 0)
		{
			password = ++i < argc ? argv[i] : NULL;
		}
#if defined HAVE_NETTLE
		else if (strcmp(arg, "--encode") == 0)
		{
			char *txt = ++i < argc ? argv[i] : NULL;
			rtc = opt_encode(txt, config_file, password);
		}
		else if (strcmp(arg, "--decode") == 0)
		{
			char *txt = ++i < argc ? argv[i] : NULL;
			rtc = opt_decode(txt, config_file, password);
		}
#endif
	}

	return rtc;
}
#endif // MAIN
