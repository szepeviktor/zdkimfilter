/*
* database.h - written by ale in milano on 25sep2012
* read/write via odbx

Copyright (C) 2012-2015 Alessandro Vesely

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

If you modify zdkimfilter, or any covered part of it, by linking or combining
it with OpenSSL, OpenDKIM, Sendmail, or any software developed by The Trusted
Domain Project or Sendmail Inc., containing parts covered by the applicable
licence, the licensor of zdkimfilter grants you additional permission to convey
the resulting work.
*/

#if !defined DATABASE_H_INCLUDED
#include "parm.h"

typedef struct db_work_area db_work_area;

db_work_area *db_init(void);
void db_clear(db_work_area* dwa);
db_parm_t* db_parm_addr(db_work_area *dwa);
int db_config_wrapup(db_work_area* dwa, int *in, int *out);
int db_connect(db_work_area *dwa);
int db_is_whitelisted(db_work_area* dwa, char /*const*/ *domain);
int db_get_domain_flags(db_work_area* dwa, char *domain,
	int *is_whitelisted, int *is_dmarc_enabled, int *is_adsp_enabled);
char *db_check_user(db_work_area* dwa);

void db_set_authenticated_user(db_work_area *dwa,
	char const *local_part, char const *domain);
void db_set_client_ip(db_work_area *dwa, char const *ip);
void db_set_org_domain(db_work_area *dwa, char *org_domain);

typedef enum spf_result
{
	spf_none,
	spf_fail,
	spf_permerror,
	spf_temperror,
	spf_neutral,
	spf_softfail,
	spf_pass
} spf_result;

typedef enum dkim_result
{
	dkim_none,
	dkim_pass,
	dkim_fail,
	dkim_policy,
	dkim_neutral,
	dkim_temperror,
	dkim_permerror
} dkim_result;

typedef struct domain_prescreen
{
	int sigval;       // multiple uses: index, verified sigs
	int nsigs;        // total number of signatures
	int start_ndx;    // first index in libopendkim's array of sigs
	int first_good;   // relative ndx (0 <= fg < nsigs)) of first verified sig
	int whitelisted;  // value retrieved from db
	union flags_as_an_int_or_bitfields
	{
		struct flags_as_bitfields            // (quoted db_ flag name)
		{
			unsigned int sig_is_ok:1;         // dkim authenticated ("dkim")
			unsigned int spf_pass:1;          // spf authenticated
			unsigned int has_vbr:1;
			unsigned int vbr_is_trusted:1;
			unsigned int vbr_is_ok:1;         // verified trusted vbr ("vbr")
			unsigned int is_trusted:1;        // whitelisted > 2
			unsigned int is_whitelisted:1;    // whitelisted > 1
			unsigned int is_known:1;          // whitelisted > 0
			unsigned int is_from:1;           // dkim author_domain ("author")
			unsigned int is_org_domain:1;     // org domain of author's domain
			unsigned int is_aligned:1;        // dmarc alignment ("")
			unsigned int is_dmarc:1;          // dmarc policy publisher ("")
			unsigned int is_dnswl:1;          // domain of dnswl address ("dnswl")
			unsigned int is_mfrom:1;          // spf ("spf")
			unsigned int is_helo:1;           // spf_helo ("spf_helo")
			unsigned int is_spf_from:1;       // can it differ from is_from?
			unsigned int is_reputed:1;        // ("rep")
			unsigned int is_reputed_signer:1; // ("rep_s")
		} f;
		unsigned int all;
	} u;
	char *vbr_mv;                  // trusted voucher (in parm->z) or NULL
	struct domain_prescreen *next; // ordered by name
	int reputation;                // if is_reputed*
	spf_result spf[3];             // helo, mfrom, from
	dkim_result dkim;
	uint8_t dnswl_value;
	uint16_t domain_val;           // sort key
	char name[];
} domain_prescreen;

typedef enum dmarc_reason
{
	dmarc_reason_none, // policy not overridden
	dmarc_reason_forwarded,
	dmarc_reason_sampled_out,
	dmarc_reason_trusted_forwarder,
	dmarc_reason_mailing_list,
	dmarc_reason_local_policy,
	dmarc_reason_other
} dmarc_reason;

typedef struct stats_info
{
	// strings purposedly duplicated (collect_stats())
	// can be "picked"
	char *content_type, *content_encoding;
	char *date;
	char *message_id;
	char *from;
	char *subject;
	char *envelope_sender;

	// actual response from vbr check
	char *vbr_result_resp;

	// non-flag dmarc values
	char *dmarc_record;
	char *dmarc_rua;

	char *ino_mtime_pid;

	domain_prescreen* domain_head;

	// outgoing messages only
	unsigned rcpt_count;
	unsigned complaint_flag;

	// incoming messages only (except outgoing flag)
	unsigned received_count;
	unsigned signatures_count;

	uint32_t dmarc_ri; // report interval

	unsigned nxdomain: 1;
	unsigned adsp_any: 1;
	unsigned adsp_found: 1;
	unsigned adsp_unknown: 1;
	unsigned adsp_all: 1;
	unsigned adsp_discardable: 1;
	unsigned adsp_fail: 1;
	unsigned dmarc_found: 1;
	unsigned dmarc_dkim: 1; // 0=fail
	unsigned dmarc_spf: 1;
	unsigned dmarc_dispo: 2; // 0=none, 1=quarantine, 2=reject (as honored)
	unsigned dmarc_reason: 3; // dmarc_reason
	unsigned dmarc_subdomain: 1;
	unsigned dmarc_fail: 1;
	unsigned policy_overridden: 1;
	unsigned mailing_list: 1;
	unsigned reject: 1;
	unsigned drop: 1;
	unsigned outgoing: 1;

	enum save_unauthenticated_domains {
		save_unauthenticated_never,
		save_unauthenticated_from,
		save_unauthenticated_dmarc } scope;
} stats_info;

void db_set_stats_info(db_work_area* dwa, stats_info *info);

#define DATABASE_H_INCLUDED
#endif
