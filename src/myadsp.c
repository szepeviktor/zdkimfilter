/*
** myadsp.c - written in milano by vesely on 4feb2015
** query for _adsp._domainkeys.example.com
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2015 Alessandro Vesely

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

#include "myadsp.h"
#include "util.h"
#if defined TEST_MAIN
#include <unistd.h> // isatty
#endif
#include <assert.h>

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

static int parse_adsp(char *record, int *policy)
{
	int found = 0;

	if (strncmp(record, "dkim", 4) == 0)
	{
		char *p = skip_fws(&record[4]);
		if (*p == '=')
		{
			found = 1;

			p = skip_fws(p + 1);
			char *q = p;
			int ch;
			while (isalnum(ch = *(unsigned char*)q) || ch == '-')
				++q;

			size_t len = q - p;
			if (policy)
			{
				if (len == 7 && strncmp(p, "unknown", 7) == 0)
					*policy = DKIM_POLICY_UNKNOWN;
				if (len == 3 && strncmp(p, "all", 3) == 0)
					*policy = DKIM_POLICY_ALL;
				else if (len == 11 && strncmp(p, "discardable", 11) == 0)
					*policy = DKIM_POLICY_DISCARDABLE;
				else
					*policy = DKIM_POLICY_NONE;
			}
		}
	}

	return found;
}


static int
do_adsp_query(char const *domain, int *policy)
// run query and return:
//   0  and a response if found
//   1  found, but no adsp retrieved
//   3  for NXDOMAIN
//  -1  on caller's error
//  -2  on temporary error (includes SERVFAIL)
//  -3  on bad DNS data or other error
{
	if (domain == NULL || *domain == 0)
		return -1;

	static char const subdomain[] = "_adsp._domainkey.";
	/* construct the query */
	size_t len_d = strlen(domain) + sizeof subdomain;
	char query[1536];

	if (len_d >= sizeof query)
		return -1;

	memcpy(query, subdomain, sizeof subdomain);
	strcat(&query[sizeof subdomain - 1], domain);

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
	unsigned int qtype;
	int rc = res_query(query, 1 /* Internet */, qtype = 16 /* TXT */,
		buf.answer, sizeof buf.answer);

	if (rc < 0)
	{
		if (h_errno != HOST_NOT_FOUND)
			return h_errno == TRY_AGAIN? -2: -3;

		// check the base domain exists
		strcpy(query, domain);
		len_d -= sizeof subdomain;
		rc = res_query(query, 1 /* Internet */, qtype = 2 /* NS */,
			buf.answer, sizeof buf.answer);
		if (rc < 0)
			return h_errno == TRY_AGAIN? -2:
				h_errno == HOST_NOT_FOUND? 3: -3;
	}

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
		ns_get16(cp) != qtype ||
			ns_get16(cp + INT16SZ) != 1) // qclass
				return -3;

	cp += 2*INT16SZ;

	// answers
	int found = 0;
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
			found = parse_adsp(query, policy);
		}
	}

	return found != 1;
}

static int
do_get_adsp(char const *domain, int* policy)
{
	return do_adsp_query(domain, policy);
}

static int
(*adsp_query)(char const*, int*) = &do_get_adsp;

static int
fake_adsp_query_keyfile(char const *domain, int *policy)
// debug function: reads data from "KEYFILE" formatted like
//   label record
{
	char buf[2048];
	FILE *fp = fopen("KEYFILE", "r");
	if (fp == NULL)
		return 3; // NXDOMAIN

	static char const subdomain[] = "_adsp._domainkey.";
	char *s;
	int rtc = -1;
	size_t const len_d = strlen(domain);
	while ((s = fgets(buf, sizeof buf, fp)) != NULL)
	{
		if (strncmp(buf, subdomain, sizeof subdomain -1) == 0 &&
			strncmp(&buf[sizeof subdomain - 1], domain, len_d) == 0)
		{
			rtc = parse_adsp(&buf[sizeof subdomain + len_d], policy) != 1;
			break;
		}
	}

	fclose(fp);
	return rtc;
}

static int
fake_adsp_query_policyfile(char const *domain, int *policy)
// debug function: reads data from "POLICYFILE" formatted like record
// return values similar to do_adsp_query
{
	char buf[512];
	FILE *fp = fopen("POLICYFILE", "r");
	if (fp == NULL)
		return 3; // NXDOMAIN

	char *s;
	int rtc = -1;
	while ((s = fgets(buf, sizeof buf, fp)) != NULL)
	{
		if (parse_adsp(buf, policy))
		{
			rtc = 0;
			break;
		}
	}

	fclose(fp);
	return rtc;

	(void)domain;
}

// mode is r(eal), k(eyfile), or p(olicyfile)
int set_adsp_query_faked(int mode)
{
	int const old_mode = adsp_query == &do_get_adsp? 'r':
		adsp_query == &fake_adsp_query_keyfile? 'k': 'p';
	adsp_query = mode == 'r'? &do_get_adsp:
		mode == 'k'? &fake_adsp_query_keyfile: &fake_adsp_query_policyfile;
	return old_mode;
}

int my_get_adsp(char const *domain, int *policy)
{
	return (*adsp_query)(domain, policy);
}


#if defined TEST_MAIN

static char const *rtc_explain(int rtc)
{
	if (rtc == 0) return "found, response given";
	if (rtc == 1) return "found, but no adsp retrieved";
	if (rtc == 3) return "NXDOMAIN";
	if (rtc == -1) return "caller's error";
	if (rtc == -2) return "temporary error (includes SERVFAIL)";
	if (rtc == -3) return "bad DNS data or other error";
	return "???????";
}

int main(int argc, char *argv[])
{
	if (argc >= 2)
	{
		for (int i = 1; i < argc; ++i)
		{
			int policy = 0;
			char *a = argv[i];
			if (a[0] == '-' && strchr("rkp", a[1]))
			{
				set_adsp_query_faked(a[1]);
				a += 2;
			}
			int rtc = my_get_adsp(a, &policy);
			printf("rtc = %d %s, policy = %d\n", rtc, rtc_explain(rtc), policy);
		}
	}
	else
		printf("Usage:\n\t%s domain...\n", argv[0]);
	return 0;
}
#endif

