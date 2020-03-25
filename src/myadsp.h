/*
** myadsp.h - written in milano by vesely on 4feb2015
** query for _adsp._domainkeys.example.com
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2015-2019 Alessandro Vesely

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

#if !defined MYADSP_H_INCLUDED
#define MYADSP_H_INCLUDED

#define POLICY_NOT_DEFINED        0
#define DMARC_POLICY_NONE         4
#define DMARC_POLICY_QUARANTINE   5
#define DMARC_POLICY_REJECT       6
#define ADSP_POLICY_UNKNOWN       8
#define ADSP_POLICY_ALL           9
#define ADSP_POLICY_DISCARDABLE  10
#define POLICY_IS_DMARC(n)  (((n)&4) != 0)
#define POLICY_IS_ADSP(n)   (((n)&8) != 0)
#define POLICY_IS_STRICT(n) (((n)&3) != 0)


#define PRESULT_FOUND 0
#define PRESULT_NOT_FOUND 1
#define PRESULT_NXDOMAIN 3
#define PRESULT_INT_ERROR -1
#define PRESULT_DNS_ERROR -2
#define PRESULT_DNS_BAD -3
#define PRESULT_NOT_DONE -4


#include <stdint.h>

typedef struct dmarc_domains
{
	char *domain;      // aka dkim_domain, the domain of From:
	char *org_domain;  // can be in dwa
	char *super_org;   // psddmarc domain, if any
} dmarc_domains;

typedef struct dmarc_rec
{
	char *rua;       // malloc'd with sentinel
	int effective_p; // one of the DMARC macros above
	uint32_t ri;
	char fo[8];
	char adkim, aspf, p, sp, np, pct;
	char found_at_org; // 1 if found at org, 2 if super
	char nxdomain;     // 1 if domain not found, 2 if org not found
	char nu;
} dmarc_rec;

int query_init(void);
void query_done(void);

int set_adsp_query_faked(int mode);
int my_get_adsp(char const *domain, int *policy);
int get_dmarc(dmarc_domains const *dd, dmarc_rec *dmarc);
int verify_dmarc_addr(char const *poldo, char const *rcptdo,
	char **override, char **badout);
char* write_dmarc_rec(dmarc_rec const *dmarc);
int parse_dmarc_rec(dmarc_rec *dmarc, char const *rec);
int check_remove_sentinel(char *rua);
int adjust_ri(int ri, int min_ri);
char* adjust_rua(char**, char**);
char const *presult_explain(int);
static inline int adjust_period(int period)
{
	if (period <= 0 || period > 86400)
		period = 86400;
	else if (86400 % period)
	{
		int per_day = 86400 / period;
		period = 86400 / per_day;
	}
	return period;
}
#endif // MYADSP_H_INCLUDED
