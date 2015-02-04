/*
** myadsp.h - written in milano by vesely on 4feb2015
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

#if !defined MYADSP_H_INCLUDED
#define MYADSP_H_INCLUDED

#if ! defined DKIM_POLICY_NONE
#define DKIM_POLICY_NONE	(-1)	/* none/undefined */
#endif

#if ! defined DKIM_POLICY_UNKNOWN
#define DKIM_POLICY_UNKNOWN	0	/* unknown */
#endif

#if ! defined DKIM_POLICY_ALL
#define DKIM_POLICY_ALL		1	/* all */
#endif

#if ! defined DKIM_POLICY_DISCARDABLE
#define DKIM_POLICY_DISCARDABLE	2	/* discardable */
#endif

#if ! defined DKIM_PRESULT_NONE
#define DKIM_PRESULT_NONE		(-1)	/* none/undefined */
#endif

#if ! defined DKIM_PRESULT_NXDOMAIN
#define DKIM_PRESULT_NXDOMAIN		0	/* domain does not exist */
#endif

#if ! defined DKIM_PRESULT_FOUND
#define DKIM_PRESULT_FOUND		1	/* ADSP query succeeded */
#endif

int set_adsp_query_faked(int mode);
int my_get_adsp(char const *domain, int *policy);

#endif // MYADSP_H_INCLUDED
