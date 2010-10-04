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
#include <string.h>
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

static char dwl_query[] = "._vouch.dwl.spamhaus.org";

int spamhaus_vbr_query(char const *signer, char **resp)
{
	if (signer == NULL || *signer == 0)
		return -1;

	size_t len = strlen(signer);	
	char query[1536];
	
	if (len + sizeof dwl_query > sizeof query)
		return -1;

	strcat(strcpy(query, signer), dwl_query);

	union dns_buffer
	{
		unsigned char answer[1536];
		HEADER h;
	} buf;
	int rc = res_query(query, 1 /* Internet */, 16 /* TXT */,
		buf.answer, sizeof buf.answer);
	
	if (rc < HFIXEDSZ ||
		(unsigned)rc > sizeof buf ||
		ntohs(buf.h.qdcount) != 1 ||
		ntohs(buf.h.ancount) < 1 ||
		buf.h.tc ||
		buf.h.rcode != NOERROR)
			return -1;

	unsigned char *cp = &buf.answer[HFIXEDSZ];
	unsigned char *const eom = &buf.answer[rc];
	
	// question
	int n = dn_expand(buf.answer, eom, cp, query, sizeof query);
	if (n < 0 ||
		strncasecmp(signer, query, len) != 0 ||
		strcasecmp(dwl_query, query + len) != 0)
			return -1;
	cp += n;
	if (cp + 2*INT16SZ > eom ||
		ns_get16(cp) != 16 ||
			ns_get16(cp + INT16SZ) != 1)
				return -1;

	cp += 2*INT16SZ;
	
	// answer
	n = dn_expand(buf.answer, eom, cp, query, sizeof query);
	if (n < 0 ||
		strncasecmp(signer, query, len) != 0 ||
		strcasecmp(dwl_query, query + len) != 0)
			return -1;
	cp += n;
	if (cp + 3*INT16SZ + INT32SZ + INADDRSZ > eom ||
		ns_get16(cp) != 16 ||
		ns_get16(cp + INT16SZ) != 1)
			return -1;

	n = ns_get16(cp + 2*INT16SZ + INT32SZ);
	cp += 3*INT16SZ + INT32SZ;
	char *p = &query[0];
	char *const end = p + sizeof query;
	while (n--> 0 && p < end)
	{
		int sl = *(unsigned char*)cp++;
		while (sl--> 0 && p < end)
		{
			*p++ = *cp++;
			--n;
		}
	}
	
	if (n < -1 || p >= end)
		return -1;

	*p = 0;
	if (resp)
		*resp = strdup(query);

	return 0;
}

#if defined TEST_MAIN
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	if (argc == 1)
		argv[argc++] = "dwltest.com";

	for (int i = 1; i < argc; ++i)
	{
		char *resp = NULL;
		int rc = spamhaus_vbr_query(argv[i], &resp);
		printf("%s: %s\n", argv[i], rc == 0? resp: "--failed");
		free(resp);
	}

	return 0;
}
#endif
