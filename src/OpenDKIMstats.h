/*
** statslog.h - written in milano by vesely on 7sep2010
** enumeration of OpenDKIM statistics log fields
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

#if !defined STATSLOG_H_INCLUDED

typedef enum OpenDKIM_stats_M // message
{
	ODsM_jobid,
	ODsM_reporter,
	ODsM_fromdomain,
	ODsM_ipaddr,
	ODsM_anon,
	ODsM_msgtime,
	ODsM_size,
	ODsM_nsigs,
	ODsM_adsp_found,
	ODsM_adsp_unknown,
	ODsM_adsp_all,
	ODsM_adsp_discardable,
	ODsM_adsp_fail,
	ODsM_fromlist,
	ODsM_rhcnt,
	ODsM_ct,
	ODsM_cte,
	ODsM_MAX_FIELDS
} OpenDKIM_stats_M;

typedef enum OpenDKIM_stats_S // signature
{
	ODsS_domain,
	ODsS_algo,
	ODsS_hdr_canon,
	ODsS_body_canon,
	ODsS_ignored,
	ODsS_pass,
	ODsS_fail_body,
	ODsS_sig_l,
	ODsS_key_t,
	ODsS_key_g,
	ODsS_key_g_name,
	ODsS_key_dk_compat,
	ODsS_sigerror,
	ODsS_sig_t,
	ODsS_sig_x,
	ODsS_sig_z,
	ODsS_dnssec,
	ODsS_fields,
	ODsS_zchanged,
	ODsS_MAX_FIELDS
} OpenDKIM_stats_S;

#define STATSLOG_H_INCLUDED 1
#endif

