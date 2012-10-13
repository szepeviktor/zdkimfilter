/*
* database.h - written by ale in milano on 25sep2012
* read/write via odbx

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

If you modify zdkimfilter, or any covered work, by linking or combining it
with OpenDKIM, containing parts covered by the applicable licence, the licensor
or zdkimfilter grants you additional permission to convey the resulting work.
*/

#if !defined DATABASE_H_INCLUDED
#include "parm.h"

typedef struct db_work_area db_work_area;

db_work_area *db_init(void);
void db_clear(db_work_area* dwa);
db_parm_t* db_parm_addr(db_work_area *dwa);
int db_config_wrapup(db_work_area* dwa);
int db_connect(db_work_area *dwa);
int db_is_whitelisted(db_work_area* dwa, char const* domain);

typedef struct domain_data
{
	char *domain;
	int whitelisted:8;
	int auth_spf:2;
	int auth_dkim:2;
	int author_domain:2;
	int vbr:2;
} domain_data;

typedef struct domain_prescreen
{
	int sigval;       // multiple uses: sort key, index, verified sigs
	int nsigs;        // total number of signatures
	int start_ndx;    // first index in libopendkim's array of sigs
	int whitelisted;  // value retrieved from db
	union flags_as_an_int_or_bitfields
	{
		struct flags_as_bitfields
		{
			unsigned int sig_is_ok:1;      // dkim authenticated
			unsigned int has_vbr:1;
			unsigned int vbr_is_trusted:1;
			unsigned int vbr_is_ok:1;      // verified trusted vbr
			unsigned int is_whitelisted:1; // whitelisted > 1
			unsigned int is_from:1;        // author_domain
			unsigned int is_mfrom:1;       // spf authenticated
			unsigned int is_helo:1;        // spf_helo auth
			unsigned int looks_like_helo:1;
		} f;
		unsigned int all;
	} u;
	char const *vbr_mv;            // trusted voucher (in parm->z) or NULL
	struct domain_prescreen *next; // name alphabetic order
	char name[];
} domain_prescreen;

typedef struct stats_info
{
	char *content_type, *content_encoding;
	char *date;
	char *message_id;
	char *vbr_result_resp;         // actual response from vbr check

	char *ip;
	char *ino_mtime_pid;

	domain_prescreen* domain_head;

	unsigned received_count;
	unsigned signatures_count;

	unsigned adsp_found:2;
	unsigned adsp_unknown:2;
	unsigned adsp_all:2;
	unsigned adsp_discardable:2;
	unsigned adsp_fail:2;
	unsigned mailing_list:2;
} stats_info;

void db_set_stats_info(db_work_area* dwa, stats_info const*info);

#define DATABASE_H_INCLUDED
#endif
