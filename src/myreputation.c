/*
** myreputation.c - written in milano by vesely on 20dec2014
** query for dkim-reputation.org
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2014 Alessandro Vesely

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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <opendkim/dkim.h>

#if defined HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if defined HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if defined HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if defined HAVE_NETDB_H
#include <netdb.h>
#endif
#include <resolv.h>

#include "myreputation.h"
#include "util.h"
#if defined TEST_MAIN
#include <unistd.h> // isatty
#endif
#include <assert.h>

#include "md5.h"

#define MD5_STRING_LENGTH 32 /* 2*16, trailing 0 not set */
static char *md5_string(char *digest, char const *src)
// digest is a string of MD5_STRING_LENGTH
// return next available byte
{
	assert(digest);
	assert(src);

	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char*)src, strlen(src));

	static const char hex[] = "0123456789abcdef";
	unsigned char bin[16];
	MD5Final(bin, &ctx);

	for (size_t i = 0; i < sizeof bin; ++i)
	{
		int const ch = bin[i];
		*digest++ = hex[ch >> 4];
		*digest++ = hex[ch & 0xf];
	}
	return digest;
}

static char *skip_fws(char *s)
{
	if (s)
	{
		int ch;
		while (isspace(ch = *(unsigned char*)s))
			++s;
		if (ch == 0)
			s = NULL;
	}
	return s;
}

static int
do_reputation_query(char const *user, char const *domain,
	char const *signer, char const *rep_root, int *rep)
// run query and return:
//   0  and a response if found
//   1  found, but no reputation retrieved
//   3  for NXDOMAIN
//  -1  on caller's error
//  -2  on temporary error (includes SERVFAIL)
//  -3  on bad data or other error
{
	if (user == NULL || *user == 0 ||
		domain == NULL || *domain == 0 ||
		signer == NULL || *signer == 0 ||
		rep_root == NULL || *rep_root == 0)
			return -1;

	/* construct the query */
	size_t const len_d = strlen(rep_root) + 3 * MD5_STRING_LENGTH + 3;
	char query[1536];

	if (len_d >= sizeof query)
		return -1;

	char *p = md5_string(query, user);
	*p++ = '.';
	p = md5_string(p, domain);
	*p++ = '.';
	p = md5_string(p, signer);
	*p++ = '.';
	strcat(p, rep_root);

#if defined TEST_MAIN
	if (isatty(fileno(stdout)))
		printf("query: %s\n", query);
#endif

	union dns_buffer
	{
		unsigned char answer[1536];
		HEADER h;
	} buf;
	
	// res_query returns -1 for NXDOMAIN
	int rc = res_query(query, 1 /* Internet */, 16 /* TXT */,
		buf.answer, sizeof buf.answer);

	if (rc < 0)
		return h_errno == TRY_AGAIN? -2:
			h_errno == HOST_NOT_FOUND? 3: -3;

	size_t ancount;
	if (rc < HFIXEDSZ ||
		(unsigned)rc > sizeof buf ||
		ntohs(buf.h.qdcount) != 1 ||
		(ancount = ntohs(buf.h.ancount)) < 1 ||
		buf.h.tc ||
		buf.h.rcode != NOERROR)
			return -3;

	unsigned char *cp = &buf.answer[HFIXEDSZ];
	unsigned char *const eom = &buf.answer[rc];

	// question
	char expand[1536];
	int n = dn_expand(buf.answer, eom, cp, expand, sizeof expand); //name
	if (n < 0 || strncasecmp(expand, query, len_d) != 0)
		return -3;

	cp += n;
	if (cp + 2*INT16SZ > eom ||
		ns_get16(cp) != 16 || // qtype
			ns_get16(cp + INT16SZ) != 1) // qclass
				return -3;

	cp += 2*INT16SZ;

	// answers
	int found = 0;
	int found_rep = 0;
	while (ancount--> 0)
	{
		n = dn_expand(buf.answer, eom, cp, expand, sizeof expand);
		if (n < 0 || cp + n + 3*INT16SZ + INT32SZ + INADDRSZ > eom)
			return -3;

		uint16_t type = ns_get16(cp + n);
		uint16_t class = ns_get16(cp + n + INT16SZ);
		uint16_t rdlength = ns_get16(cp + n + 2*INT16SZ + INT32SZ); // (skip ttl)

		cp += n + 3*INT16SZ + INT32SZ;
		// not if it was cname... if (strncasecmp(expand, query, len_d) != 0 ||
		if (type != 16 || class != 1)
		{
			cp += rdlength;
			continue;
		}

		char *p = &query[0];  // reuse query to assemble character-strings.
		char *const end = p + sizeof query;

		// TXT-DATA consists of one or more <character-string>s.
		// <character-string> is a single length octet followed by that number
		// of characters.  RFC 1035

		while (rdlength > 0 && p < end)
		{
			size_t sl = *(unsigned char*)cp++;
			rdlength -= 1;
			if (p + sl >= end || sl > rdlength)
				break;

			memcpy(p, cp, sl);
			p += sl;
			cp += sl;
			rdlength -= sl;
		}

		if (rdlength == 0 && p < end)
		{
			*p = 0;
#if defined TEST_MAIN
			if (isatty(fileno(stdout)))
				printf("answer: %s\n", query);
#endif

			for (p = strtok(query, ";"); p; p = strtok(NULL, ";"))
			{
				p = skip_fws(p);
				if (strncasecmp(p, "rep", 3) == 0)
				{
					p = skip_fws(p + 3);
					if (*p == '=')
					{
						char *t = NULL;
						long l = strtol(p + 1, &t, 10);
						if (l > INT_MIN && l <= INT_MAX && t &&
							(*t == 0 || isspace(*(unsigned char*)t)))
						{
							if (found)
							{
								if (found_rep > (int)l)
									found_rep = (int)l;
							}
							else
							{
								found = 1;
								found_rep = (int)l;
							}
						}
					}
				}
			}
		}
	}

	if (found && rep)
		*rep = found_rep;

	return found != 1;
}

#if !defined TEST_MAIN
static int
do_get_reputation(DKIM* dkim, DKIM_SIGINFO* sig, char *root, int *rep)
{
#if defined DKIM_REPUTATION_ROOT
	// my query
	return do_reputation_query(dkim_getuser(dkim),
		dkim_getdomain(dkim),
		dkim_sig_getdomain(sig), root, rep);

#elif defined DKIM_REP_ROOT
	// older query (2010)
	if (dkim_get_reputation(dkim, sig, root, rep) == DKIM_STAT_OK)
		return 0;

#elif defined DKIM_REP_DEFROOT
	// newer query (2013)
	int rtc = -1;
	DKIM_REP dr = dkim_rep_init(NULL, NULL, NULL);
	if (dr)
	{
		void *qh = NULL;
		dkim_rep_setdomain(dr, root);


/*
**  DKIM_REP_QUERY_START -- initiate a query to the DKIM_REP for entries
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	user -- local-part of From:
**  	domain -- domain part of From:
**  	signdomain -- signing domain
**  	qh -- query handle (returned)
**
**  Return value:
**  	DKIM_REP_STAT_INVALID -- dkim_rep_setdomain() was not called,
**                               or "query" was NULL
** 	DKIM_REP_STAT_* -- as defined
*/
		DKIM_REP_STAT status = dkim_rep_query_start(dr,
			dkim_getuser(dkim),
			dkim_getdomain(dkim),
			dkim_sig_getdomain(sig),
			&qh);
		if (status == DKIM_REP_STAT_OK && qh != NULL)
		{
			struct timeval tv; // doesn't seem to be used by dkim_rep_res_waitreply
			tv.tv_sec = 1;     // should use parm.z.dns_timeout, in case
			tv.tv_usec = 0;
			if (dkim_rep_query_check(dr, qh, &tv, rep) == DKIM_REP_STAT_FOUND)
				rtc = 0;
		}
		dkim_rep_close(dr);
	}
	return rtc;
#endif
}


static int
(*reputation_query)(DKIM*, DKIM_SIGINFO*, char*, int*) = &do_get_reputation;


static int
fake_reputation_query(DKIM* dkim, DKIM_SIGINFO* sig, char *root, int *rep)
// debug function: reads data from "REPFILE" formatted like:
//  fromdomain   sigdomain   rep
{
	assert(dkim);
	char const *fromdomain = dkim_getdomain(dkim);
	char const *sigdomain = sig? (char const*)dkim_sig_getdomain(sig): fromdomain;

	if (fromdomain == NULL || sigdomain == NULL)
		return -1;

	char buf[512];
	size_t const siglen = strlen(sigdomain);
	size_t const fromlen = strlen(fromdomain);

	FILE *fp = fopen("REPFILE", "r");
	if (fp == NULL)
		return -1;

	char *s;
	int rtc = -1;
	while ((s = fgets(buf, sizeof buf, fp)) != NULL)
	{
		s = skip_fws(s);
		if (s && strincmp(s, fromdomain, fromlen) == 0)
		{
			s = skip_fws(s + fromlen);
			if (s && strincmp(s, sigdomain, siglen) == 0)
			{
				s = skip_fws(s + siglen);
				if (s)
				{
					*rep = atoi(s);
					rtc = 0;
					break;
				}
			}
		}
	}

	fclose(fp);
	return rtc;

	(void)root; // unused
}

int flip_reputation_query_was_faked(void)
{
	int const faked = reputation_query != &do_get_reputation;
	reputation_query = faked? &do_get_reputation: &fake_reputation_query;
	return faked;
}

int my_get_reputation(DKIM* dkim, DKIM_SIGINFO* sig, char *root, int *rep)
{
	return (*reputation_query)(dkim, sig, root, rep);
}
#endif // TEST_MAIN


#if defined TEST_MAIN

int main(int argc, char *argv[])
{
	if (argc >= 4)
	{
		char *root = argc > 4? argv[4]: DKIM_REPUTATION_ROOT;
		int rep = 0;
		int rtc = do_reputation_query(argv[1], argv[2], argv[3], root, &rep);
		printf("rtc = %d, rep = %d.\n", rtc, rep);
	}
	else
		printf("Usage:\n\t%s user domain signer [root]\n", argv[0]);
	return 0;
}
#endif

