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

#if HAVE_DKIM_REP_DKIM_REP_H
#include <dkim-rep/dkim-rep.h>
#endif

#include "myreputation.h"
#include "util.h"
#include <assert.h>

static int
do_get_reputation(DKIM* dkim, DKIM_SIGINFO* sig, char *root, int *rep)
{
#if defined DKIM_REP_ROOT
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

