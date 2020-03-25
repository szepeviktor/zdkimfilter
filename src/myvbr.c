/*
** myvbr.c - written in milano by vesely on 1oct2010
** IPv4 address query for vbr certification
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2010 Alessandro Vesely

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

#include <myvbr.h>
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

static void vbr_info_cnt(vbr_info *v, size_t *str_size, size_t *mv_ndx)
{
	assert(v && v->md && *v->md);

	size_t s = strlen(v->md) + 2, ndx;
	if (v->mc && *v->mc)
		s += strlen(v->mc);

	char *mv;
	for (ndx = 0; (mv = v->mv[ndx]) != NULL; ++ndx)
	{
		s += sizeof(char*);
		s += strlen(mv) + 1;
	}

	if (str_size) *str_size = s;
	if (mv_ndx) *mv_ndx = ndx;
}

static inline void vbr_info_cpy(char **target, char const *src, char **cv)
{
	assert(target && src && cv && *cv);
	size_t const l = strlen(src) + 1;
	memcpy(*target = *cv, src, l);
	*cv += l;
}

static vbr_info *vbr_info_merge(vbr_info *a, vbr_info *b)
{
	assert(a && b);
	assert(a->md && b->md && strcasecmp(a->md, b->md) == 0);

	size_t s_a, ndx_a, s_b, ndx_b;
	vbr_info_cnt(a, &s_a, &ndx_a);
	vbr_info_cnt(b, &s_b, &ndx_b);
	size_t s = s_a + s_b + sizeof(char*) + sizeof(vbr_info);
	char *cv = calloc(1, s);
	if (cv == NULL)
		return NULL;

	vbr_info *v = (vbr_info*) cv;
	cv = (char*)&v->mv[ndx_a + ndx_b + 1];

	vbr_info_cpy(&v->md, a->md, &cv);
	if (a->mc || b->mc)
		vbr_info_cpy(&v->mc, a->mc? a->mc: b->mc, &cv);

	size_t ndx = 0, i;
	for (i = 0; i < ndx_a; ++i)
		vbr_info_cpy(&v->mv[ndx++], a->mv[i], &cv);
	for (i = 0; i < ndx_b; ++i)
	{
		char *const cur = b->mv[i];
		char *amv;
		for (size_t j = 0; (amv = a->mv[j]) != NULL; ++j)
			if (strcasecmp(cur, amv) == 0)
				break;
		if (amv == NULL)
			vbr_info_cpy(&v->mv[ndx++], cur, &cv);
	}
	
	assert(cv < (char*)v + s);
	return v;
}

int vbr_info_add(vbr_info **first, char const *orig)
/*
* orig should be 1*([FWS] element [FWS] ";")
* see http://tools.ietf.org/html/rfc5518#section-4.1
*
* save a vbr_info on a list ordered by ascending domain-name, and return 0
* or return 1 for invalid info
* or return -1 for memory error
*/
{
	assert(first);
	assert(orig);

	// count max no of vouchers
	size_t vouchers = 2, mv_ndx = 0;
	char *s = strchr(orig, ':');
	while (s)
	{
		++vouchers;
		s = strchr(s + 1, ':');
	}

	size_t all = strlen(orig) + 1 + vouchers * sizeof(char*) + sizeof(vbr_info);
	vbr_info *n = calloc(1, all);

	if (n == NULL)
		return -1;

	s = (char*)&n->mv[vouchers];
	strcpy(s, orig);
	while ((s = skip_fws(s)) != NULL)
	{
		int ch = tolower(*(unsigned char*)s);
		int element = ch == 'm'? tolower(*(unsigned char*)&s[1]) : 0;

		char **target;
		switch (element != 0 && s[2] == '='? element: 0)
		{
			case 'c':
				target = &n->mc;
				break;
			case 'd':
				target = &n->md;
				break;
			case 'v':
				assert(mv_ndx < vouchers - 1);
				target = &n->mv[mv_ndx++];
				break;
			default:
				s = strchr(s, ';');
				if (s) ++s;
				continue;
		}

		if ((s = skip_fws(s + 3)) == NULL || // missing value
			*target != NULL)                  // tag already used
				goto invalid_info;

		for (;;) // do multiple assignments in case target is a list
		{
			*target = s;

			while (isalnum(ch = *(unsigned char*)s) || ch == '-' || ch == '.')
				++s;
			*s++ = 0;

			if (isspace(ch))
			{
				s = skip_fws(s);
				ch = s? *s: 0;
			}

			if (ch != ':' || element != 'v')
				break;

			assert(mv_ndx < vouchers - 1);
			if (**target && strlen(*target) < 63)
			{
				size_t ndx;
				for (ndx = 0; ndx < mv_ndx; ++ndx)
					if (strcasecmp(*target, n->mv[ndx]) == 0)
						break;
				// set new target or rewrite the same one
				if (ndx == mv_ndx)
					target = &n->mv[mv_ndx++];
			}
		}
		
		if (ch == 0)
			break;

		if (ch != ';')
			goto invalid_info;

		// continue the loop, s points right after ';'
	}

	if ((s = n->md) == NULL) // no domain
		goto invalid_info;

	vbr_info **v = first;
	int c = 1;

	while (*v != NULL && (c = strcasecmp((*v)->md, s)) < 0)
		v = &(*v)->next;

	if (c == 0) // further VBR-Info for the same domain: merge
	{
		vbr_info *w = vbr_info_merge(*v, n);
		if (w == NULL)
			goto invalid_info;

		w->next = (*v)->next;
		free(*v);
		free(n);
		*v = w;
	}
	else
	{
		n->next = *v;
		*v = n;
	}
	return 0;

invalid_info:
/*
*  the record is not good, discard it
*/
	free(n);
	return 1;
}

vbr_info* vbr_info_get(vbr_info *first, char const *domain)
/*
* return the vbr_info record for the given domain, or NULL
*/
{
	if (domain)
		while (first)
		{
			int c = strcasecmp(first->md, domain);
			if (c == 0)
				return first;

			if (c > 0)
				break;

			first = first->next;
		}

	return NULL;
}

char *vbr_info_vouchers(vbr_info const *v)
{
	size_t ndx, s = 0;
	char *mv;
	for (ndx = 0; (mv = v->mv[ndx]) != NULL; ++ndx)
		if (*mv)
			s += strlen(mv) + 1;

	char *r = malloc(s);
	if (r)
	{
		char *p = r;
		for (ndx = 0; (mv = v->mv[ndx]) != NULL; ++ndx)
		{
			size_t l = strlen(mv);
			memcpy(p, mv, l);
			p += l;
			*p++ = ':';
		}
		*--p = 0;
	}

	return r;
}

void vbr_info_clear(vbr_info *first)
{
	while (first)
	{
		vbr_info *next = first->next;
		free(first);
		first = next;
	}
}

static char dwl_query[] = "._vouch.";
extern int h_errno; // result from res_query
static int do_vbr_query(char const *signer, char const *vouch, char **resp)
// run query and return:
//   0  and possibly allocate the resonse if ok
//   3  for NXDOMAIN
//  -1  on caller's error
//  -2  on temporary error (includes SERVFAIL)
//  -3  on bad data or other error
{
	if (signer == NULL || *signer == 0 || vouch == NULL || *vouch == 0)
		return -1;

	size_t const len_d = strlen(signer), len_v = strlen(vouch),
		len_ = sizeof dwl_query - 1;
	char query[1536];

	if (len_d + sizeof dwl_query + len_v > sizeof query)
		return -1;

	strcat(strcat(strcpy(query, signer), dwl_query), vouch);

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

	if (rc < HFIXEDSZ ||
		(unsigned)rc > sizeof buf ||
		ntohs(buf.h.qdcount) != 1 ||
		ntohs(buf.h.ancount) < 1 ||
		buf.h.tc ||
		buf.h.rcode != NOERROR)
			return -3;

	unsigned char *cp = &buf.answer[HFIXEDSZ];
	unsigned char *const eom = &buf.answer[rc];

	// question
	int n = dn_expand(buf.answer, eom, cp, query, sizeof query); //name
	if (n < 0 ||
		strncasecmp(signer, query, len_d) != 0 ||
		strncasecmp(dwl_query, query + len_d, len_) != 0 ||
		strcasecmp(vouch, query + len_d + len_) != 0)
			return -3;
	cp += n;
	if (cp + 2*INT16SZ > eom ||
		ns_get16(cp) != 16 || // qtype
			ns_get16(cp + INT16SZ) != 1) // qclass
				return -3;

	cp += 2*INT16SZ;

	// answer
	n = dn_expand(buf.answer, eom, cp, query, sizeof query);
	if (n < 0 ||
		strncasecmp(signer, query, len_d) != 0 ||
		strncasecmp(dwl_query, query + len_d, len_) != 0 ||
		strcasecmp(vouch, query + len_d + len_) != 0)
			return -3;
	cp += n;
	if (cp + 3*INT16SZ + INT32SZ + INADDRSZ > eom ||
		ns_get16(cp) != 16 || //type
		ns_get16(cp + INT16SZ) != 1) //class
			return -3;

	n = ns_get16(cp + 2*INT16SZ + INT32SZ); // rdlength (skip ttl)
	cp += 3*INT16SZ + INT32SZ;
	char *p = &query[0];
	char *const end = p + sizeof query;
	
	// TXT-DATA consists of one or more <character-string>s.  <character-string>
	// is a single length octet followed by that number of characters.  RFC 1035

   // If the RDATA in the TXT record contains multiple character-strings
   // (as defined in Section 3.3 of [RFC1035]), the code handling that
   // reply from DNS MUST assemble all of these marshaled text blocks into
   // a single one before any syntactical verification takes place.

   // Verifiers MUST then check that the TXT record consists of strings of
   // lowercase letters separated by spaces, and discard any records not in
   // that format.  This defends against misconfigured records and
   // irrelevant records synthesized from DNS wildcards.  RFC 5518

	while (n--> 0 && p < end)
	{
		int sl = *(unsigned char*)cp++;
		while (sl--> 0 && p < end)
		{
			int const ch = (unsigned char) (*p++ = *cp++);
			if (!islower(ch) && !isspace(ch))
				return -3;
			--n;
		}
	}

	if (n < -1 || p >= end)
		return -3;

	*p = 0;
	if (resp)
		*resp = strdup(query);

	return 0;
}

static int
(*my_vbr_query)(char const*, char const*, char**) = &do_vbr_query;

int
vbr_check(vbr_info *first, char const*domain, vbr_cb cb, vbr_check_result* res)
// run do_vbr_query and return:
//   0  and possibly allocate the resonse if ok
//  -1  otherwise
{
	if (first == NULL || cb == NULL || res == NULL ||
		(res->vbr = vbr_info_get(first, domain)) == NULL)
			return -1;

	char **mv = res->vbr->mv;
	if (mv)
		for (; *mv; ++mv)
			if ((*cb)(res->tv, *mv))
			{
				int rc = (*my_vbr_query)(domain, *mv, &res->resp);
				++res->queries;
				if (rc >= 0)
				{
					res->mv = *mv;
					if (rc == 0)
						return 0;
				}
				else if (rc == -2)
					++res->tempfail;
			}

	return -1;
}

static int fake_vbr_query(char const *signer, char const *vouch, char **resp)
// debug function: reads data from "VBRFILE" formatted like:
//   <label>[<space char><data>]<newline char>
// and return:
//   0  and possibly allocate the resonse if found label and data
//  -2  if found label but no data
//   3  if label not found
//  -1  if other error occurs
{
	if (signer == NULL || *signer == 0 || vouch == NULL || *vouch == 0)
		return -1;

	size_t const len_d = strlen(signer), len_v = strlen(vouch),
		len_ = sizeof dwl_query - 1 + len_d + len_v;
	char query[1536];

	if (len_d + sizeof dwl_query + len_v > sizeof query)
		return -1;

	strcat(strcat(strcpy(query, signer), dwl_query), vouch);

	FILE *fp = fopen("VBRFILE", "r");
	if (fp == NULL)
	{
		perror("fake_vbr_query: cannot read VBRFILE");
		return -1;
	}

	char buf[1024], *s;
	while ((s = fgets(buf, sizeof buf, fp)) != NULL)
	{
		size_t l = strlen(s);
		int ch;
		if (l >= len_ &&
			strncasecmp(query, s, len_) == 0 &&
			((ch = *(unsigned char*)&buf[len_]) == 0 || isspace(ch)))
		{
			int rtc = l == len_? -2: 0;
			if (rtc == 0 && resp)
			{
				for (--l; l > len_ && isspace(*(unsigned char*)&buf[l]); --l)
					buf[l] = 0;
				*resp = strdup(&buf[len_ + 1]);
			}
			fclose(fp);
			return rtc;
		}
	}

	fclose(fp);
	return 3;
}

int flip_vbr_query_was_faked(void)
{
	int const faked = my_vbr_query != &do_vbr_query;
	my_vbr_query = faked? &do_vbr_query: &fake_vbr_query;
	return faked;
}

#if defined TEST_MAIN

// fields we can/cannot parse
static char* vbr_test[][32] =
{
	// order
	{
		"md=something; mv=something-else; mc=unusual",
		"md=something; mc=unusual; mv=something-else",
		"mv=something-else; md=something; mc=unusual",
		"mv=something-else; mc=unusual; md=something",
		"mc=unusual; md=something; mv=something-else",
		"mc=unusual; mv=something-else; md=something",
		NULL
	},
	// spaces and semicolon
	{
		"md=something; mv=something-else; mc=unusual",
		" md=something; mv=something-else; mc=unusual",
		" md= something; mv=something-else; mc=unusual",
		"md=something;  mv=something-else; mc=unusual",
		"md=something ; mv= something-else; mc=unusual;",
		"md= something; mv=something-else\t; mc=unusual ;",
		"md= something; mv=something-else\t\t; mc=unusual ;",
		"md= something; mv=something-else\t\t\t; mc=unusual ;",
		"md=something ; mv=something-else; mc=unusual ;  ",
		"md=something ; mv=\r\nsomething-else; mc=unusual  ; ",
		"md=something ; mv=    something-else; mc=unusual  ;  ",
		"md=   something  ;  mv=something-else; mc=unusual   ;   ",
		"md=something ; mv=something-else; mc=unusual       ",
		NULL
	}
};

static int run_tests(int from, int to, int silent)
{
	vbr_info *start = NULL;

	if (from < 0) from = 0;
	if (to < 0) to = sizeof vbr_test/sizeof vbr_test[0];
	if (to <= from) to = from + 1;

	for (int i = from; i < to; ++i)
	{
		char **t = vbr_test[i];
		for (char *a = *t; a; a = *++t)
		{
#if 0
			if ((a[0] == 'Q' || a[0] == 'q') && a[1] == '=')
			{
				vbr_info *v = vbr_info_get(start, &a[2]);
				printf("get(%s) returns %sNULL\n", &a[2], v? "non-": "");
				if (v && v->mv && v->md && a[0] == 'Q')
				{
					//char *s = v->mv;
					for (;;)
					{
					break;
					}
				}
			}
			else
#endif
			{
				int rtc = vbr_info_add(&start, a);
				if (rtc)
				{
					while (isspace(*(unsigned char*)a))
						++a;
					char *e = a;
					int ch;
					while ((ch = *(unsigned char*)e) != 0 && ch != ';' && !isspace(ch))
						++e;
					printf("add(%.*s) returns %d\n", (int)(e - a), a, rtc);
				}
			}
		}
	}

	if (!silent)
	{
		int count = 0;
		for (vbr_info *v = start; v != NULL; v = v->next)
		{
			char *mv = vbr_info_vouchers(v);
			printf("md=%s; mc=%s; mv=%s\n",
				v->md? v->md: "(null)",
				v->mc? v->mc: "(null)",
				mv? mv: "(null)");
			free(mv);
			++count;
		}
	
		printf("%d record(s)\n", count);
	}

	vbr_info_clear(start);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc == 1)
		argv[argc++] = "md=dwltest.com; mv=dwl.spamhaus.org;";

	for (int i = 1; i < argc; ++i)
	{
		char *a = argv[i];
		if (strcmp(a, "--help") == 0)
		{
			printf("%s:\n"
				"--test                 - run all tests\n"
				"--query domain voucher - run the query\n",
					argv[0]);
			return 0;
		}
		else if (strcmp(a, "--test") == 0)
		{
			run_tests(-1, -1, 0);
		}
		else if (strcmp(a, "--query") == 0)
		{
			if (i + 2 >= argc)
			{
				fprintf(stderr, "%s: missing two arguments for query\n", argv[0]);
				return 1;
			}

			char *resp = NULL;
			int rtc = do_vbr_query(argv[i+1], argv[i+2], &resp);
			printf("rtc = %d (%s) \"%s\"\n", rtc,
				rtc == 0? "noerror":
				rtc == 3? "nxdomain":
				rtc == -1? "invalid parameter":
				rtc == -2? "query failed":
				rtc == -3? "query returned bad data":
				"unexpected result",
				resp? resp: "(null)");
			free(resp);			
		}
	}
	
	return 0;
}
#endif
