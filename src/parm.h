/*
* parm.h - written by ale in milano on 21sep2012
* parameter file parsing

Copyright (C) 2012-2013 Alessandro Vesely

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

#if !defined PARM_H_INCLUDED
#include "filedefs.h"
static char const default_config_file[] =
	COURIER_SYSCONF_INSTALL "/filters/zdkimfilter.conf";

/*
* each option has to be defined in three places: in one of the structures below,
* in the conf[] array in parm.c, and in one of the pod.in
*/
typedef struct parm_t
{
	char *domain_keys;
	char *selector;
	char *default_domain;
	char *tmp;
	char *blocked_user_list;
	char *redact_received_auth;
	char *reputation_root;
	const char **sign_hfields;
	const char **skip_hfields;
	const char **key_choice_header;
	const char **trusted_vouchers;
	const char **trusted_dnswl;

	// end of pointers (some malloc'd but never free'd)
	int verbose;
	int dns_timeout;
	int reputation_fail, reputation_pass;
	int max_signatures;

	char trust_a_r;
	char add_a_r_anyway;
	char add_auth_pass;
	char report_all_sigs;
	char verify_one_domain;
	char no_spf;
	char no_signlen;
	char tempfail_on_error;
	char honor_author_domain;
	char reject_on_nxdomain;
	char do_reputation;
	char all_mode;
	char sign_rsa_sha1;
	char header_canon_relaxed;
	char body_canon_relaxed;
	char save_from_anyway;
	char add_ztags;
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

#define DATABASE_STATEMENT(x) char *x;
	#include "database_statements.h"
#undef DATABASE_STATEMENT

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
int read_single_values(char const *fname, int, char const *const*, char **out);
void print_parm(void *parm_target[PARM_TARGET_SIZE]);
void clear_parm(void *parm_target[PARM_TARGET_SIZE]);

#define PARM_H_INCLUDED
#endif
