/*
* parm.h - written by ale in milano on 21sep2012
* parameter file parsing

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

#if !defined PARM_H_INCLUDED
#include "filedefs.h"
static char const default_config_file[] =
	COURIER_SYSCONF_INSTALL "/filters/zdkimfilter.conf";

/*
* each option has to be defined in three places: in one of the structures below,
* in the conf[] array in parm.c, and in etc/zdkimfilter.conf.dist.in
*/
typedef struct parm_t
{
	char *domain_keys;
	char *selector;
	char *default_domain;
	char *tmp;
	char *stats_file;
	char *redact_received_auth;
	const char **sign_hfields;
	const char **skip_hfields;
	const char **domain_whitelist;
	const char **key_choice_header;
	const char **trusted_vouchers;

	// end of pointers (some malloc'd but never free'd)
	int verbose;
	int dns_timeout;
	int reputation_fail, reputation_pass;
	int max_signatures;

	char add_a_r_anyway;
	char report_all_sigs;
	char no_spf;
	char no_signlen;
	char tempfail_on_error;
	char honor_author_domain;
	char reject_on_nxdomain;
	char no_reputation;
	char all_mode;
	char sign_rsa_sha1;
	char header_canon_relaxed;
	char body_canon_relaxed;
	char save_from_anyway;
} parm_t;

typedef struct db_parm_t
{
	char *db_backend;
	char *db_host;
	char *db_port;
	char *db_opt_tls;
	char *db_opt_mode;
	char *db_database;
	char *db_user;
	char *db_password;
	char *db_sql_whitelisted;
	char *db_sql_select_domain;
	char *db_sql_update_domain;
	char *db_sql_insert_domain;
	char *db_sql_insert_msg_ref;
	char *db_sql_insert_message;
	int db_opt_paged_results;
	int db_timeout; // seconds
	char db_opt_multi_statements;
	char db_opt_compress;
} db_parm_t;

typedef enum parm_target_t
{
	parm_t_id,
	db_parm_t_id,
	PARM_TARGET_SIZE
} parm_target_t;

// syslog style log function
typedef
#if defined __GNUC__
__attribute__ ((format(printf, 2, 3)))
#endif
void (*logfun_t)(int, const char*, ...);

logfun_t set_parm_logfun(logfun_t);
const char* set_program_name(const char * new_name);
void stderrlog(int severity, char const* fmt, ...);
int read_all_values(void *parm_target[PARM_TARGET_SIZE], char const *fname);
char* read_single_value(char const *pname, char const *fname);
void print_parm(void *parm_target[PARM_TARGET_SIZE]);
void clear_parm(void *parm_target[PARM_TARGET_SIZE]);

#define PARM_H_INCLUDED
#endif
