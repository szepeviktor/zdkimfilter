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

#define NS_BUFFER_SIZE 1536

static int do_txt_query(char *query, size_t len_d, size_t len_sub,
	int (*parse_fn)(char*, void*), void* parse_arg)
/*
* query is a char buffer (1536 long) also used to parse answers,
* len_d is the length of the query string,
* len_sub is the length of the prefix or 0 if no base query is needed,
* parse_fn is a parsing function, and parse_arg its argument. 
*
* Run query and return:
*   >= 0 txt records successfully parsed
*  -1  on caller's error
*  -2  on temporary error (includes SERVFAIL)
*  -3  on bad DNS data or other transient error
*  -4  for NXDOMAIN if len_sub > 0, or just res_query() failed
*/
{
	assert(query);
	assert(len_d);
	assert(parse_fn);

#if defined TEST_MAIN
	if (isatty(fileno(stdout)))
		printf("query: %s\n", query);
#endif

	union dns_buffer
	{
		unsigned char answer[NS_BUFFER_SIZE];
		HEADER h;
	} buf;
	
	// res_query returns -1 for NXDOMAIN
	unsigned int qtype;
	char *query_cmp = query;
	int rc = res_query(query, 1 /* Internet */, qtype = 16 /* TXT */,
		buf.answer, sizeof buf.answer);

	if (rc < 0)
	{
		if (h_errno != HOST_NOT_FOUND)
			return h_errno == TRY_AGAIN? -2: -3;

		// check the base domain exists
		if (len_sub == 0)
			return -4;

		len_d -= len_sub;
		query_cmp = query + len_sub;
		rc = res_query(query_cmp, 1 /* Internet */, qtype = 2 /* NS */,
			buf.answer, sizeof buf.answer);
		if (rc < 0)
			return h_errno == TRY_AGAIN? -2:
				h_errno == HOST_NOT_FOUND? -4: -3;
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
	char expand[NS_BUFFER_SIZE];
	int n = dn_expand(buf.answer, eom, cp, expand, sizeof expand); //name
	if (n < 0 || strncasecmp(expand, query_cmp, len_d + 1) != 0)
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
		char *const end = p + NS_BUFFER_SIZE;

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
			int rtc = parse_fn(query, parse_arg);
			if (rtc < 0)
				return -3;

			found += rtc;
		}
	}

	return found;
}

static int (*txt_query)(char*, size_t, size_t, int (*)(char*, void*), void*) =
	&do_txt_query;

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

static int parse_adsp(char *record, void *v_policy)
{
	assert(record);

	int *policy = v_policy;
	int found = 0;

	if (strncmp(record, "dkim", 4) == 0)
	{
		char *p = skip_fws(&record[4]);
		if (p && *p == '=')
		{
			p = skip_fws(p + 1);
			if (p)
			{
				found = 1;

				char *q = p;
				int ch;
				while (isalnum(ch = *(unsigned char*)q) || ch == '-')
					++q;

				size_t len = q - p;
				if (policy)
				{
					if (len == 7 && strncmp(p, "unknown", 7) == 0)
						*policy = ADSP_POLICY_UNKNOWN;
					else if (len == 3 && strncmp(p, "all", 3) == 0)
						*policy = ADSP_POLICY_ALL;
					else if (len == 11 && strncmp(p, "discardable", 11) == 0)
						*policy = ADSP_POLICY_DISCARDABLE;
					else
						*policy = DKIM_POLICY_NONE;
				}
			}
		}
	}

	return found;
}

static int do_adsp_query(char const *domain, int *policy)
// run query and return:
//   0  and a response if found
//   1  found, but no adsp retrieved
//   3  for NXDOMAIN
//  -1  on caller's error
//  -2  on temporary error (includes SERVFAIL)
//  -3  on bad DNS data or other transient error
{
	if (domain == NULL || *domain == 0)
		return -1;

	static char const subdomain[] = "_adsp._domainkey.";
	size_t len_sub = sizeof subdomain - 1;
	size_t len_d = strlen(domain) + len_sub;
	char query[NS_BUFFER_SIZE];

	if (len_d >= sizeof query)
		return -1;

	memcpy(query, subdomain, sizeof subdomain);
	strcat(&query[sizeof subdomain - 1], domain);

	int rtc = (*txt_query)(query, len_d, len_sub, parse_adsp, policy);
	return rtc == -4? 3: rtc >= 0? rtc != 1: rtc;
}

static int do_get_adsp(char const *domain, int* policy)
{
	return do_adsp_query(domain, policy);
}

static int
(*adsp_query)(char const*, int*) = &do_get_adsp;

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

static int
fake_txt_query_keyfile(char *query, size_t len_d, size_t not_used,
	int (*parse_fn)(char*, void*), void* parse_arg)

// debug function: reads data from "KEYFILE" formatted like
//   label txt-record
{
	char buf[2048];
	FILE *fp = fopen("KEYFILE", "r");
	if (fp == NULL)
		return 3; // NXDOMAIN

	int found = 0;
	while (fgets(buf, sizeof buf, fp) != NULL)
	{
		if (strncmp(buf, query, len_d) == 0 && buf[len_d] == ' ')
			found += (*parse_fn)(&buf[len_d + 1], parse_arg);
	}

	fclose(fp);
	return found;

	(void)not_used;
}

int set_adsp_query_faked(int mode)
// mode is r(eal), k(eyfile), or p(olicyfile)
// this also affects dmarc.
{
	int const old_mode =
		adsp_query == &fake_adsp_query_policyfile? 'p':
		txt_query == &do_txt_query? 'r': 'k';
	switch (mode)
	{
		case 'p':
			adsp_query = &fake_adsp_query_policyfile;
			txt_query = &fake_txt_query_keyfile;
			break;

		case 'k':
			adsp_query = &do_adsp_query;
			txt_query = &fake_txt_query_keyfile;
			break;

		case 'r':
		default:
			adsp_query = &do_adsp_query;
			txt_query = &do_txt_query;
			break;
	}
	return old_mode;
}

int my_get_adsp(char const *domain, int *policy)
{
	return (*adsp_query)(domain, policy);
}

//// dmarc

typedef struct tag_value
{
	char *tag;
	char *value;
} tag_value;

static char *next_tag(char *buf, tag_value *tv)
{
	assert(buf);
	assert(tv);

	// must be at tag on entry
	char *p = tv->tag = buf;
	int ch;
	while (isalnum(ch = *(unsigned char*)p) ||
		(ch != 0 && strchr("_-", ch)))
			*p++ = tolower(ch);

	if (ch != '=' && !isspace(ch))
		return NULL;

	*p++ = 0;
	if (ch != '=')
	{
		p = skip_fws(p);
		if (p == NULL || *p != '=')
			return NULL;

		++p;
	}

	if ((p = tv->value = skip_fws(p)) == NULL)
		return NULL;

	// EXCLAMATION to TILDE except SEMICOLON
	while ((ch = *(unsigned char*)p) >= 0x21 &&
		ch <= 0x7e && ch != ';')
			++p;

	if (ch)
	// consume trailing white space and separator
	{
		*p++ = 0;
		while (isspace(ch = *(unsigned char*)p) || ch == ';')
			++p;
	}
	return p;
}

static int none_quarantine_reject(char const *p)
{
	static char const *nqr[3] = {"none", "quarantine", "reject"};
	for (int i = 0; i < 3; ++i)
		if (strcasecmp(p, nqr[i]) == 0)
			return nqr[i][0];

	return 0;
}

static inline int relax_strict(char const *p)
{
	int ch = tolower(*(unsigned char*)p);
	if (p[1] == 0 && (ch == 'r' || ch == 's'))
		return ch;

	return 0;
}

static int parse_dmarc(char *record, void *v_dmarc)
{
	dmarc_rec *dmarc = v_dmarc;
	int found = 0;

	tag_value tv = {NULL, NULL};
	char *p = next_tag(record, &tv);

	if (p && strcmp(tv.tag, "v") == 0 && strcmp(tv.value, "DMARC1") == 0)
	{
		found = 1;
		while ((p = next_tag(p, &tv)) != NULL)
		{
			if (strcmp(tv.tag, "p") == 0)
			{
				int p = none_quarantine_reject(tv.value);
				if (p)
					dmarc->p = p;
			}
			else if (strcmp(tv.tag, "pct") == 0)
			{
				char *t = NULL;
				unsigned long pct = strtoul(tv.value, &t, 10);
				if (t && *t == 0 && pct <= 100)
					dmarc->pct = (unsigned char) pct;
			}
			else if (strcmp(tv.tag, "rua") == 0)
			{
				if (strncasecmp(tv.value, "mailto:", 7) == 0)
				{
					tv.value += 7;
					if (dmarc->rua == NULL &&
						(dmarc->rua = strdup(tv.value)) == NULL)
							return -1;
				}
			}
			else if (strcmp(tv.tag, "ri") == 0)
			{
				char *t = NULL;
				unsigned long ri = strtoul(tv.value, &t, 10);
				if (t && *t == 0 && ri <= UINT32_MAX)
					dmarc->ri = (uint32_t) ri;
			}
			else if (strcmp(tv.tag, "sp") == 0)
			{
				int sp = none_quarantine_reject(tv.value);
				if (sp)
					dmarc->sp = sp;
			}
			else if (strcmp(tv.tag, "adkim") == 0)
			{
				int a = relax_strict(tv.value);
				if (a)
					dmarc->adkim = a;
			}
			else if (strcmp(tv.tag, "aspf") == 0)
			{
				int a = relax_strict(tv.value);
				if (a)
					dmarc->aspf = a;
			}
		}
	}

	return found;
}

/* static inline int nqr_to_int(int p)
{
	if (p == 'q) return DMARC_POLICY_
} */

int get_dmarc(char const *domain, char const *org_domain, dmarc_rec *dmarc)
// run query and return:
//   0  and a response if found
//   1  found, but no dmarc retrieved
//   3  for NXDOMAIN
//  -1  on caller's error
//  -2  on temporary error (includes SERVFAIL)
//  -3  on bad DNS data or other transient error
{
	assert(domain);
	assert(dmarc);
	assert(org_domain == NULL || strlen(org_domain) <= strlen(domain));

	if (domain == NULL || *domain == 0)
		return -1;

	// clear it on entry
	memset(dmarc, 0, sizeof *dmarc);

	static char const subdomain[] = "_dmarc.";
	size_t len_sub = sizeof subdomain - 1;
	size_t len_d = strlen(domain) + len_sub;
	char query[NS_BUFFER_SIZE];

	if (len_d >= sizeof query)
		return -1;

	memcpy(query, subdomain, sizeof subdomain);
	strcat(&query[len_sub], domain);
	char const *dd = domain;

	int rtc = (*txt_query)(query, len_d, len_sub, parse_dmarc, dmarc);
	/*
	http://tools.ietf.org/html/draft-kucherawy-dmarc-base-13#section-6.6.3
   3.  If the set is now empty, the Mail Receiver MUST query the DNS for
       a DMARC TXT record at the DNS domain matching the Organizational
       Domain in place of the RFC5322.From domain in the message (if
       different).  This record can contain policy to be asserted for
       subdomains of the Organizational Domain.  A possibly empty set of
       records is returned.	
	*/
	if (rtc == 0)
	{
		dmarc->effective_p = 0; // FIXME
	}
	else if (org_domain && *org_domain && strcmp(domain, org_domain))
	{
		len_d = strlen(org_domain) + len_sub;
		memcpy(query, subdomain, sizeof subdomain);
		strcat(&query[len_sub], domain);
		dd = org_domain;
		rtc = (*txt_query)(query, len_d, len_sub, parse_dmarc, dmarc);
	}

	if (rtc == 0)
	{
		// check subdomain policy that may apply
		// don't check domains of rua addresses: do once on sending
	}
	return rtc == -4? 3: rtc >= 0? rtc != 1: rtc;
}

#if defined TEST_MAIN

static char const *rtc_explain(int rtc)
{
	if (rtc == 0) return "found, response given";
	if (rtc == 1) return "domain exists, but no adsp retrieved";
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

