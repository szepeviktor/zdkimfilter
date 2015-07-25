/*
* zdkimfilter - written by ale in milano on Thu 11 Feb 2010 03:48:15 PM CET 
* Sign outgoing, verify incoming mail messages

Copyright (C) 2010-2015 Alessandro Vesely

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
#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h> // for LOG_DEBUG,... constants
#include <stdint.h>
#include <fcntl.h>

// name conflict with older opendkim versions
#define dkim_policy unsupported_dkim_policy
#include <opendkim/dkim.h>
#undef dkim_policy

#include <stddef.h>
#include <time.h>
#include <stdbool.h>
#include "filterlib.h"
#include "filedefs.h"
#include "myvbr.h"
#include "myreputation.h"
#include "myadsp.h"
#include "redact.h"
#include "vb_fgets.h"
#include "parm.h"
#include "database.h"
#include "filecopy.h"
#include "util.h"
#include "publicsuffix.h"
#include "spf_result_string.h"
#include <assert.h>

#if !PATH_MAX
#define PATH_MAX 1024
#endif

#if !HAVE_RANDOM
static inline long random(void) {return rand();}
static inline void srandom(unsigned int seed) {srand(seed);}
#endif

static inline char *my_basename(char const *name) // neither GNU nor POSIX...
{
	char *b = strrchr(name, '/');
	if (b)
		return b + 1;
	return (char*)name;
}

static char *strdup_normalize(char const *s, int stop_at)
{
	char *copy;

	// trim left
	int ch;
	while ((ch = *(unsigned char const*)s) != 0 && isspace(ch))
		++s;

	if (ch)
	{
		// find terminator
		char const *t = s;
		while ((ch = *(unsigned char const*)t) != 0 && ch != stop_at)
			++t;
		// trim right
		while (t > s && isspace(*(unsigned char const*)(t - 1)))
			--t;
		assert(t > s);

		// duplicate normalizing spaces
		char *d = copy = malloc(t - s + 1);
		if (d)
		{
			int spaces = 0;
			while (s < t)
			{
				ch = *(unsigned char const *)s++;
				if (isspace(ch))
				{
					if (spaces++ == 0)
						*d++ = ' ';
				}
				else
				{
					spaces = 0;
					*d++ = ch;
				}
			}
			*d = 0;
		}
	}
	else copy = strdup("");

	return copy;
}

static void clean_stats_info_content(stats_info *stats)
// only called by clean_stats
{
	if (stats)
	{
		free(stats->content_type);
		free(stats->content_encoding);
		free(stats->date);
		free(stats->message_id);
		free(stats->from);
		free(stats->subject);
		free(stats->envelope_sender);
		free(stats->vbr_result_resp);
		// don't free(stats->ino_mtime_pid); it is in dyn.info
		stats->ino_mtime_pid = NULL;
	}
}

typedef struct blocked_user_list
{
	char *data;
	size_t size;
	time_t mtime;
} blocked_user_list;
	
static int search_list(blocked_user_list *bul, char const *u)
{
	assert(bul);
	if (bul->data && bul->size && u)
	{
		size_t const ulen = strlen(u);
		char *p = bul->data;
		while (p)
		{
			while (isspace(*(unsigned char*)p))
				++p;
			if (*p != '#')
			{
				if (strincmp(p, u, ulen) == 0)
					return 1; // found
			}
			p = strchr(p, '\n');			
		}
	}

	return 0;
}

typedef struct per_message_parm
{
	dkim_sigkey_t key;
	char *selector;
	char *domain;
	char *authserv_id;
	char *action_header;
	stats_info *stats;
	var_buf vb;
	fl_msg_info info;
	int rtc;
	char db_connected;
	char special; // never block outgoing messages to postmaster@domain only.
} per_message_parm;

typedef enum split_filter
{
	split_do_both, split_verify_only, split_sign_only
} split_filter;

typedef struct dkimfl_parm
{
	DKIM_LIB *dklib;
	fl_parm *fl;
	db_work_area *dwa;
	publicsuffix_trie *pst;

	char const *config_fname; // static (either default or argv)
	char const *prog_name; //static, from argv[0]
	parm_t z;
	per_message_parm dyn;
	blocked_user_list blocklist;

	// other
	split_filter split;
	char pid_created;
	char use_dwa_after_sign, use_dwa_verifying;
	char user_blocked;
} dkimfl_parm;

static inline const u_char **
cast_const_u_char_parm_array(const char **a) {return (const u_char **)a;}

static inline u_char **
cast_u_char_parm_array(char **a) {return (u_char **)a;}

static char const parm_z_domain_keys[] = COURIER_SYSCONF_INSTALL "/filters/keys";
static char const *const parm_z_reputation_root = NULL; // no known service
static char const *const parm_z_trusted_dnswl[] = {"list.dnswl.org", NULL};

static void config_default(dkimfl_parm *parm) // only non-zero...
{
	parm->z.domain_keys = (char*)parm_z_domain_keys;
	parm->z.reputation_root = (char*)parm_z_reputation_root;
	parm->z.reputation_fail = 32767;
	parm->z.reputation_pass = -32768;
	parm->z.verbose = 3;
	parm->z.max_signatures = 128;
	parm->z.trusted_dnswl = (char const**)parm_z_trusted_dnswl;
	parm->z.dnswl_worthiness_pass = 1;
	parm->z.dnswl_invalid_ip = DNSWL_ORG_INVALID_IP_ENDIAN;
	parm->z.dnswl_octet_index = 3;
	parm->z.whitelisted_pass = 3;
	parm->z.honored_report_interval = DEFAULT_REPORT_INTERVAL;
}

static void config_cleanup_default(dkimfl_parm *parm)
{
	if (parm->z.domain_keys == parm_z_domain_keys)
		parm->z.domain_keys = NULL;
	if (parm->z.reputation_root == parm_z_reputation_root)
		parm->z.reputation_root = NULL;
	if (parm->z.trusted_dnswl == parm_z_trusted_dnswl)
		parm->z.trusted_dnswl = NULL;
}


static void no_trailing_char(char *s, int slash)
{
	if (s)
	{
		size_t l = strlen(s);
		while (l > 0 && s[l-1] == slash)
			s[--l] = 0;
	}
}

static void config_wrapup(dkimfl_parm *parm)
{
	if (parm->z.reputation_fail < parm->z.reputation_pass)
	{
		fl_report(LOG_WARNING,
			"reputation_fail = %d < reputation_pass = %d: swapped?",
				parm->z.reputation_fail, parm->z.reputation_pass);
		parm->z.reputation_fail = INT_MAX;
	}

	if (parm->z.dns_timeout < 0)
	{
		fl_report(LOG_WARNING,
			"dns_timeout cannot be negative (%d)", parm->z.dns_timeout);
		parm->z.dns_timeout = 0;
	}

	if (parm->z.dnswl_octet_index > 3)
		parm->z.dnswl_octet_index = 3;

	if (parm->z.verbose < 0)
		parm->z.verbose = 0;

	if (parm->z.dnswl_worthiness_pass > UINT8_MAX)
		parm->z.dnswl_worthiness_pass = UINT8_MAX;

	no_trailing_char(parm->z.action_header, ':');
	no_trailing_char(parm->z.domain_keys, '/');
	no_trailing_char(parm->z.tmp, '/');
	if (parm->z.tmp && strncmp(parm->z.tmp, "/tmp/", 5) == 0)
	{
		struct stat st;
		int rtc = stat(parm->z.tmp, &st);
		if (rtc && errno == ENOENT)
		{
			if (mkdir(parm->z.tmp, 0770))
				fl_report(LOG_CRIT,
					"mkdir %s failed: %s",
						parm->z.tmp, strerror(errno));
			rtc = stat(parm->z.tmp, &st);
		}
		if (rtc || !S_ISDIR(st.st_mode) ||
			euidaccess(parm->z.tmp, R_OK|W_OK|X_OK))
		{
			fl_report(LOG_WARNING,
				"disabling tmp = %s", parm->z.tmp);
			free(parm->z.tmp);
			parm->z.tmp = NULL;
		}
	}

	int period = adjust_period(parm->z.honored_report_interval);
	if (period != parm->z.honored_report_interval)
	{
		fl_report(LOG_WARNING,
			"bad honored_report_interval %d, adjusted to %d.  CHECK CRON!",
				parm->z.honored_report_interval, period);
		parm->z.honored_report_interval = period;
	}
}

static inline void some_dwa_cleanup(dkimfl_parm *parm)
{
	assert(parm);
	if (parm->dwa)
	{
		void *parm_target[PARM_TARGET_SIZE];
		parm_target[parm_t_id] = NULL;
		parm_target[db_parm_t_id] = db_parm_addr(parm->dwa);

		clear_parm(parm_target);
		db_clear(parm->dwa);
		parm->dwa = NULL;
	}
}

static void some_cleanup(dkimfl_parm *parm) // parent
{
	assert(parm);
	void *parm_target[PARM_TARGET_SIZE];
	parm_target[parm_t_id] = &parm->z;
	parm_target[db_parm_t_id] = parm->dwa? db_parm_addr(parm->dwa): NULL;

	config_cleanup_default(parm);
	clear_parm(parm_target);
	if (parm->dwa)
	{
		db_clear(parm->dwa);
		parm->dwa = NULL;
	}
	free(parm->blocklist.data);
	publicsuffix_done(parm->pst);
}

static int parm_config(dkimfl_parm *parm, char const *fname, int no_db)
// initialization, 0 on success
{
	set_parm_logfun(&fl_report);

	int errs = 0;

	config_default(parm);
	if (!no_db &&
		(parm->dwa = db_init()) == NULL)
			errs = 1;

	if (fname == NULL)
	{
		struct stat st;
		if (stat(default_config_file, &st))
		{
			if (errno == ENOENT)
				return 0; // can do without it

			fl_report(LOG_ALERT,
				"Cannot stat %s: %s", default_config_file, strerror(errno));
			return -1;
		}

		fname = default_config_file;
	}
	else if (*fname == 0)  // invoked with -f ""
		return 0;

	
	void *parm_target[PARM_TARGET_SIZE];
	parm_target[parm_t_id] = &parm->z;
	parm_target[db_parm_t_id] = parm->dwa? db_parm_addr(parm->dwa): NULL;

	errs += read_all_values(parm_target, fname);

	if (errs == 0)
	{
		config_wrapup(parm);
		if (parm->dwa)
		{
			int in = 0, out = 0;
			int rtc = db_config_wrapup(parm->dwa, &in, &out);
			if (rtc < 0)
				errs = 1;
			else if (in <= 0 && out <= 0) // no statements compiled: reset
			{
				some_dwa_cleanup(parm);
			}
			else
			{
				parm->use_dwa_after_sign = out > 0;
				parm->use_dwa_verifying = in > 0;
			}
		}
	}

	if (parm->z.verbose >= 4 &&
		parm->z.redact_received_auth && !redact_is_fully_featured())
			fl_report(LOG_WARNING,
				"Option redact_received_header is set in %s,"
				" but it is not fully featured.", fname);

	parm->config_fname = fname;
	return errs;
}

static void check_split(dkimfl_parm *parm)
{
	if (parm->z.split_verify)
	{
		if (strcmp(my_basename(parm->z.split_verify), parm->prog_name) == 0)
		{
			parm->split = split_verify_only;
			if (parm->dwa && parm->use_dwa_verifying == 0)
				some_dwa_cleanup(parm);
		}
		else
		{
			parm->split = split_sign_only;
			if (parm->dwa && parm->use_dwa_after_sign == 0)
				some_dwa_cleanup(parm);
		}
		
	}
	else
		parm->split = split_do_both; // 0

	if (parm->split)
	{
		if (parm->z.verbose >= 3)
			fl_report(LOG_INFO,
				"%s configured to %s only", parm->prog_name,
				parm->split == split_sign_only? "sign": "verify");
	}
}

// functions common for both incoming and outgoing msgs

static void clear_prescreen(domain_prescreen* dps)
{
	while (dps != NULL)
	{
		domain_prescreen* const next = dps->next;
		free(dps);
		dps = next;
	}
}

static domain_prescreen*
get_prescreen(domain_prescreen** dps_head, char const *domain)
{
	assert(dps_head);
	assert(domain);

	domain_prescreen**dps = dps_head;
	while (*dps != NULL)
	{
		int const cmp = stricmp(domain, (*dps)->name);
		if (cmp < 0)
		{
			dps = &(*dps)->next;
			continue;
		}
		if (cmp == 0)
			return *dps;

		break;
	}

	size_t const len = sizeof(domain_prescreen);
	size_t const len2 = strlen(domain) + 1;
	domain_prescreen *new_dps = malloc(len + len2);
	if (new_dps)
	{
		memset(new_dps, 0, len);
		new_dps->next = *dps;
		*dps = new_dps;
		memcpy(&new_dps->name[0], domain, len2);
	}
	else
		fl_report(LOG_ALERT, "MEMORY FAULT");

	return new_dps;
}

static void clean_stats(dkimfl_parm *parm)
{
	assert(parm);

	if (parm->dyn.stats)
	{
		clear_prescreen(parm->dyn.stats->domain_head);
		parm->dyn.stats->domain_head = NULL;
		clean_stats_info_content(parm->dyn.stats);
		free(parm->dyn.stats);
		parm->dyn.stats = NULL;
	}
}

static void collect_stats(dkimfl_parm *parm, char const *start)
{
	assert(parm);
	assert(parm->dyn.stats);

	char **target = NULL;
	char const *s;
	int stop_at = 0;
	if ((s = hdrval(start, "Content-Type")) != NULL)
	{
		target = &parm->dyn.stats->content_type;
		stop_at = ';';
	}
	else if ((s = hdrval(start, "Content-Transfer-Encoding")) != NULL)
		target = &parm->dyn.stats->content_encoding;
	else if ((s = hdrval(start, "Date")) != NULL)
		target = &parm->dyn.stats->date;
	else if ((s = hdrval(start, "Message-Id")) != NULL)
		target = &parm->dyn.stats->message_id;
	else if ((s = hdrval(start, "From")) != NULL)
		target = &parm->dyn.stats->from;
	else if ((s = hdrval(start, "Subject")) != NULL)
		target = &parm->dyn.stats->subject;

	if (target && *target == NULL &&
		(*target = strdup_normalize(s, stop_at)) == NULL)
		// memory faults are silently ignored for stats
			clean_stats(parm);

	else if ((s = hdrval(start, "Precedence")) != NULL)
	{
		while (isspace(*(unsigned char const*)s))
			++s;
		size_t len;
		int ch;
		if (strincmp(s, "list", 4) == 0 &&
			((len = strlen(s)) <= 4 ||
				(ch = ((unsigned char const*)s)[5]) == ';' || isspace(ch)))
					parm->dyn.stats->mailing_list = 1;
	}
	
	else if (strincmp(start, "List-", 5) == 0)
	{
		if (hdrval(start, "List-Id") ||
			hdrval(start, "List-Post") ||
			hdrval(start, "List-Unsubscribe"))
				parm->dyn.stats->mailing_list = 1;
	}
	
	else if (hdrval(start, "Mailing-List"))
		parm->dyn.stats->mailing_list = 1;
}

// outgoing
static int read_key(dkimfl_parm *parm, char *fname)
// read private key and selector from disk, return 0 or parm->dyn.rtc = -1;
// when returning 0, parm->dyn.key and parm->dyn.selector are set so as to
// reflect results, they are assumed to be NULL on entry.
{
	assert(parm);
	assert(parm->dyn.key == NULL);
	assert(parm->dyn.selector == NULL);

	char buf[PATH_MAX], buf2[PATH_MAX], *key = NULL, *selector = NULL;
	FILE *fp = NULL;
	struct stat st;
	size_t dkl, fl;
	
	if ((dkl = strlen(parm->z.domain_keys)) +
		(fl = strlen(fname)) + 2 >= PATH_MAX)
	{
		errno = ENAMETOOLONG;
		goto error_exit;
	}
	
	memcpy(buf, parm->z.domain_keys, dkl);
	buf[dkl] = '/';
	strcpy(&buf[dkl+1], fname);
	if (stat(buf, &st))
	{
		if (errno == ENOENT)
			return 0;  // OK, domain not configured

		goto error_exit;
	}
	
	if ((key = malloc(st.st_size + 1)) == NULL ||
		(fp = fopen(buf, "r")) == NULL ||
		fread(key, st.st_size, 1, fp) != 1)
			goto error_exit;
	
	fclose(fp);
	fp = NULL;
	key[st.st_size] = 0;

	/*
	* readlink fails with EINVAL if the domain is not a symbolic link.
	* It is not an error to omit selector specification.
	*/
	ssize_t lsz = readlink(buf, buf2, sizeof buf2);
	if (lsz < 0 || (size_t)lsz >= sizeof buf2)
	{
		if (errno != EINVAL && parm->z.verbose || parm->z.verbose >= 8)
			fl_report(errno == EINVAL? LOG_INFO: LOG_ALERT,
				"id=%s: cannot readlink for %s: readlink returns %zd: %s",
				parm->dyn.info.id,
				fname,
				lsz,
				strerror(errno));
		if (errno != EINVAL)
			goto error_exit_no_msg;
	}
	else
	/*
	* get selector from symbolic link base name, e.g.
	*
	*    example.com -> ../somewhere/my-selector
	* or
	*    example.com -> example.com.my-selector.private
	*/
	{
		buf2[lsz] = 0;
		char *name = my_basename(buf2);
		if (strincmp(name, fname, fl) == 0)
		{
			name += fl;
			if (*name == '.')
				++name;
		}
		
		char *ext = strrchr(name, '.');
		if (ext && (strcmp(ext, ".private") == 0 || strcmp(ext, ".pem") == 0))
			*ext = 0;

		if ((selector = strdup(name)) == NULL)
			goto error_exit_no_msg;
	}
	parm->dyn.key = (dkim_sigkey_t) key;
	parm->dyn.selector = selector;
	return 0;

	error_exit:
		if (parm->z.verbose)
			fl_report(LOG_ALERT,
				"id=%s: error reading key %s: %s",
				parm->dyn.info.id,
				fname,
				strerror(errno));

	error_exit_no_msg:
		if (fp)
			fclose(fp);
		free(key);
		free(selector);
		return parm->dyn.rtc = -1;
}

static int default_key_choice(dkimfl_parm *parm, int type)
{
	assert(parm);
	assert(parm->dyn.key == NULL);
	assert(parm->dyn.selector == NULL);
	assert(parm->dyn.domain == NULL);

	int rc = 0;
	char *domain;
	if (type == '*' &&
		(domain = strchr(parm->dyn.info.authsender, '@')) != NULL)
			++domain;
	else
		domain = parm->z.default_domain; // is that how local domains work?

	if (domain &&
		(rc = read_key(parm, domain)) == 0)
			parm->dyn.domain = domain;

	return rc;
}

static int read_key_choice(dkimfl_parm *parm)
{
	assert(parm);
	assert(parm->dyn.key == NULL);
	assert(parm->dyn.selector == NULL);
	assert(parm->dyn.domain == NULL);

	if (parm->z.key_choice_header == NULL)
		return default_key_choice(parm, '*');

	/*
	* have to read headers to determine signing domain
	*/
	
	int rtc = 0;
	size_t i, keep, count, choice_max = 0;
	struct choice_element
	{
		dkim_sigkey_t key;
		char *selector;
		char *domain;
		char const* header;  // alias, not malloced
	} *choice;
	
	while (parm->z.key_choice_header[choice_max] != NULL)
		++choice_max;
	
	if ((choice =
		(struct choice_element*)calloc(choice_max, sizeof *choice)) == NULL)
			return parm->dyn.rtc = -1;

	/*
	* key_choice_header may have duplicates which become active in case
	* the relevant field appears multiple times.  However, the default
	* domain ("-", or "*") cannot be duplicated.
	*
	* count "-", or "*" tokens
	*/
	keep = 0;
	count = choice_max;
	for (i = 0; i < choice_max; ++i)
	{
		char const* const h = parm->z.key_choice_header[i];
		if (h[1] == 0 && strchr("-*", h[0]))
			++keep;
		choice[i].header = h;
	}
	
	assert(count >= keep);

	/*
	* process each "-", or "*" tokens
	*/
	if (keep)
	{
		char seen[3] = {0, 0, 0};
		count -= keep;
		for (i = 0; i < choice_max; ++i)
		{
			char const *const  h = parm->z.key_choice_header[i];
			if (h[1] == 0 && strchr("-*", h[0]))
			{
				if (strchr(seen, h[0]) == NULL)
				{
					seen[strlen(seen)] = h[0];
					assert(strlen(seen) < sizeof seen);

					rtc = default_key_choice(parm, h[0]);
					if (rtc)
						break;
				
					choice[i].key = parm->dyn.key;
					choice[i].selector = parm->dyn.selector;
					if ((choice[i].domain = strdup(parm->dyn.domain)) == NULL)
						rtc = parm->dyn.rtc = -1;

					parm->dyn.key = NULL;
					parm->dyn.selector = NULL;
					parm->dyn.domain = NULL;
				}
				choice[i].header = NULL;				
				if (--keep <= 0)
					break;
			}
		}
	}

	assert(keep == 0 || rtc != 0);

	/*
	* Have to read header to find all values
	*/
	if (count > 0 && rtc == 0)
	{
		FILE* fp = fl_get_file(parm->fl);
		assert(fp);
		var_buf *vb = &parm->dyn.vb;

		while (rtc == 0)
		{
			char *p = vb_fgets(vb, keep, fp);
			char *eol = p? strchr(p, '\n'): NULL;

			if (eol == NULL)
			{
				if (parm->z.verbose)
					fl_report(LOG_ALERT,
						"id=%s: header too long (%.20s...)",
						parm->dyn.info.id, vb_what(vb, fp));
				rtc = parm->dyn.rtc = -1;
				break;
			}

			int const next = eol > p? fgetc(fp): '\n';
			int const cont = next != EOF && next != '\n';
			char *const start = vb->buf;
			if (cont && isspace(next)) // wrapped
			{
				*++eol = next;
				keep = eol + 1 - start;
				continue;
			}

			/*
			* full 0-terminated header field, including trailing \n, is in buffer;
			* if it is a choice header, check if it leads to a signing key.
			*/
			for (i = 0; i < choice_max; ++i)
			{
				char const *const h = choice[i].header;
				if (h)
				{
					char *const val = hdrval(start, h);
					if (val)
					{
						char *domain, *user;
						if ((dkim_mail_parse(val,
							cast_u_char_parm_array(&user),
							cast_u_char_parm_array(&domain))) == 0)
						{
							rtc = read_key(parm, domain);
							if (rtc)
								break;
							if ((choice[i].domain = strdup(domain)) == NULL)
							{
								rtc = parm->dyn.rtc = -1;
								break;
							}

							choice[i].key = parm->dyn.key;
							parm->dyn.key = NULL;
							choice[i].selector = parm->dyn.selector;
							parm->dyn.selector = NULL;
						}

						choice[i].header = NULL; // don't reuse it
						count -= 1;
						if (parm->z.verbose >= 8)
							fl_report(LOG_DEBUG,
								"id=%s: matched header \"%s\" at choice %zd: "
								"domain=%s, key=%s, selector=%s",
								parm->dyn.info.id, h, i,
								choice[i].domain? choice[i].domain: "NONE",
								choice[i].key? "yes": "no",
								choice[i].selector? choice[i].selector: "NONE");
						break;
					}
				}
			}

			if (!cont || count <= 0) // end of header or found all
				break;

			start[0] = next;
			keep = 1;
		}
		rewind(fp);
	}

	/*
	* all header fields processed;
	* keep 1st choice key or 1st choice domain, and free the rest.
	*/
	if (rtc == 0)
	{
		for (i = 0; i < choice_max; ++i)
			if (choice[i].key)
			{
				parm->dyn.key = choice[i].key;
				parm->dyn.selector = choice[i].selector;
				parm->dyn.domain = choice[i].domain;
				memset(&choice[i], 0, sizeof choice[0]);
				break;
			}

		if (parm->dyn.key == NULL)
			for (i = 0; i < choice_max; ++i)
				if (choice[i].domain)
				{
					parm->dyn.domain = choice[i].domain;
					memset(&choice[i], 0, sizeof choice[0]);
					break;
				}
	}

	for (i = 0; i < choice_max; ++i)
	{
		free(choice[i].key);
		free(choice[i].selector);
		free(choice[i].domain);
	}
	free(choice);	
	return parm->dyn.rtc;
}

static inline int
my_dkim_header(dkimfl_parm *parm, DKIM *dkim, char *field, size_t len)
{
	assert(len > 0);
	assert(dkim);

	DKIM_STAT status = dkim_header(dkim, field, len);
	if (status != DKIM_STAT_OK)
	{
		if (parm->z.verbose)
		{
			char const *err = dkim_getresultstr(status);
			fl_report(LOG_CRIT,
				"id=%s: signing dkim_header failed on %zu bytes: %s (%d)",
				parm->dyn.info.id, len,
				err? err: "unknown", (int)status);
		}
		return parm->dyn.rtc = -1;
	}

	return 0;
}

static int replace_received_auth(dkimfl_parm *parm, char **new_text,
	char *start, char *s, size_t s_len)
{
	char *p2, *eol2, *authuserbuf, *addr;

	if ((p2 = strchr(s, '\n')) != NULL &&
		(p2 = strchr(p2 + 1, '(')) != NULL &&
		(eol2 = strchr(p2, '\n')) != NULL &&
		(authuserbuf = strstr(p2, "AUTH: ")) != NULL &&
		//                         123456
		(authuserbuf += 6) < eol2 &&
		(addr = strchr(authuserbuf, ' ')) != NULL)
	{
		char *eaddr = ++addr;
		int ch;
		size_t const len = strlen(parm->dyn.info.authsender);
		while ((ch = *(unsigned char*)eaddr) != 0 &&
			strchr("),", ch) == NULL)
				++eaddr;
		if (eaddr < eol2 &&
			addr + len == eaddr &&
			strincmp(addr, parm->dyn.info.authsender, len) == 0)
		/*
		* found: compose the replacement with the redacted field
		*/
		{
			char *red =
				redacted(parm->z.redact_received_auth,
					parm->dyn.info.authsender);
			size_t redlen = red? strlen(red): 0;
			size_t r_len = s_len - len + redlen;
			char *p = *new_text = malloc(r_len + 1);
			if (p)
			{
				memcpy(p, start, addr - start);
				p += addr - start;
				if (red)
				{
					memcpy(p, red, redlen);
					p += redlen;
				}
				assert(strlen(eaddr) + redlen + (size_t)(addr - start) == r_len);
				strcpy(p, eaddr);
			}
			free(red);
			return p? 1: -1;
		}
	}
	return 0;
}

#include "rfc822.h"
static int replace_courier_wrap(char **new_text, char *start)
{
	int rtc = 0;

	char	**bufptrs = NULL;
	struct rfc822t *rfcp = rfc822t_alloc_new(start, NULL, NULL);
	struct rfc822a *rfca = rfc822a_alloc(rfcp);
	if (rfca)
	{
		if (rfca->naddrs)
		{
			bufptrs = malloc(sizeof(char*) * rfca->naddrs);
			if (bufptrs)
			{
				for (int i = 0; i<rfca->naddrs; ++i)
				{
					struct rfc822token *tokenp = rfca->addrs[i].tokens;
					if (tokenp == NULL)
					{
						bufptrs[i]=0;
						continue;
					}

					if ((bufptrs[i] = rfc822_gettok(tokenp)) == NULL)
						continue;

					tokenp->next=0;
					tokenp->token=0;
					tokenp->ptr=bufptrs[i];
					tokenp->len=strlen(tokenp->ptr);

				}
			}
		}

		char *new_header = rfc822_getaddrs_wrap(rfca, 70);
		if (new_header)
		{
			if (strcmp(new_header, start) != 0)
			{
				unsigned i, l;
				for (i=l=0; new_header[i]; i++)
					if (new_header[i] == '\n' && new_header[i+1])
						l += 3;

				char *p=malloc(strlen(new_header)+1+l);
				if (p)
				{
					for (i=l=0; new_header[i]; i++)
					{
						if (new_header[i] == '\n' && new_header[i+1])
						{
							p[l++]='\r';
							p[l++]='\n';
							p[l++]=' ';
							p[l++]=' ';
						}
						else
							p[l++]=new_header[i];
					}
					p[l]=0;
					free(new_header);
					*new_text = p;
					rtc = 1;
				}
				else
					rtc = -1;
			}
			else
				free(new_header);
		}
		if (bufptrs)
			for (int i=0; i<rfca->naddrs; ++i)
				if (bufptrs[i]) free(bufptrs[i]);
		rfc822a_free(rfca);
	}
	rfc822t_free(rfcp);
	free(bufptrs);

	return rtc;
}

static inline size_t chomp_cr(char *hdr)
{
	char *s = hdr, *d = hdr;
	if (d)
	{
		int ch;
		while ((ch = *(unsigned char*)s++) != 0)
			if (ch != '\r') *d++ = ch;
		*d = 0;
	}
	return d - hdr;
}

typedef struct replacement
{
	struct replacement *next;
	uint64_t offset; // offset (in file) where replacement starts
	char *new_text;  // possibly NULL, no trailing \n
	size_t length;   // length of old text w/o trailing \n
	size_t nu;
} replacement;

static int sign_headers(dkimfl_parm *parm, DKIM *dkim, replacement **repl)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(parm);

	size_t keep = 0;
	var_buf *vb = &parm->dyn.vb;
	FILE* fp = fl_get_file(parm->fl);
	assert(fp);

	uint64_t offset = 0;
	size_t newlines = 0;
	bool search_received = parm->z.redact_received_auth;
	for (;;)
	{
		char *p = vb_fgets(vb, keep, fp);
		char *eol = p? strchr(p, '\n'): NULL;

		if (eol == NULL)
		{
			if (parm->z.verbose)
				fl_report(LOG_ALERT,
					"id=%s: header too long (%.20s...)",
					parm->dyn.info.id, vb_what(vb, fp));
			return parm->dyn.rtc = -1;
		}

		int const next = eol > p? fgetc(fp): '\n';
		int const cont = next != EOF && next != '\n';
		char *const start = vb->buf;
		keep = eol - start;
		if (cont && isspace(next)) // wrapped
		{
			*eol++ = '\r';
			*eol++ = '\n';
			*eol = next;
			keep += 3;
			++newlines;
			continue;
		}

		/*
		* full field is in buffer, keep bytes excluding trailing \n
		* (neither dkim_header nor replacements want trailing \n)
		*/
		if (keep)
		{
			*eol = 0;
			if (parm->dyn.stats)
				collect_stats(parm, start);

			if (dkim)
			{
				char *nt = NULL, *s;
				int rc = 0;
				if (search_received && (s = hdrval(start, "Received")) != NULL)
				{
					if ((rc = replace_received_auth(parm, &nt, start, s, keep)) > 0)
						search_received = false;
				}
				else if ((s = hdrval(start, "To")) != NULL ||
					(s = hdrval(start, "Reply-To")) != NULL ||
					(s = hdrval(start, "From")) != NULL ||
					(s = hdrval(start, "Cc")) != NULL)
				{
					rc = replace_courier_wrap(&nt, start);
				}

				if (rc > 0)
				{
					replacement *new_r = malloc(sizeof (replacement));
					if (new_r)
					{
						replacement **r = repl;
						while (*r)
							r = &(*r)->next;
						new_r->next = NULL;
						*r = new_r;
						new_r->offset = offset;
						new_r->new_text = nt;
						new_r->length = keep - newlines;
						if (nt)
							rc = my_dkim_header(parm, dkim, nt, strlen(nt));
					}
					else
					{
						free(nt);
						rc = -1;
					}
				}
				else
					rc = my_dkim_header(parm, dkim, start, keep);

				if (rc < 0)
					return parm->dyn.rtc = -1;
			}
		}

		if (!cont)
			break;

		offset += keep - newlines + 1;
		newlines = 0;
		start[0] = next;
		keep = 1;
	}
	
	/*
	* all header fields processed.
	* check results thus far.
	*/
	
	if (dkim)
	{
		DKIM_STAT status = dkim_eoh(dkim);
		if (status != DKIM_STAT_OK)
		{
			if (parm->z.verbose >= 3)
			{
				char const *err = dkim_getresultstr(status);
				fl_report(LOG_INFO,
					"id=%s: signing dkim_eoh: %s (stat=%d)",
					parm->dyn.info.id, err? err: "(NULL)", (int)status);
			}
			// return parm->dyn.rtc = -1;
		}
	}

	return parm->dyn.rtc;
}

static int copy_body(dkimfl_parm *parm, DKIM *dkim)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(parm && dkim);

	FILE* fp = fl_get_file(parm->fl);
	assert(fp);
	char buf[8192];
	
	while (fgets(buf, sizeof buf - 1, fp))
	{
		char *eol = strchr(buf, '\n');
		if (eol)
		{
			*eol++ = '\r';
			*eol++ = '\n';
			*eol = 0;
		}
		else
			eol = &buf[sizeof buf - 1];
		
		size_t const len = eol - &buf[0];
		DKIM_STAT status = dkim_body(dkim, buf, len);
		if (status != DKIM_STAT_OK)
		{
			if (parm->z.verbose)
			{
				char const *err = dkim_geterror(dkim);
				if (err == NULL)
					err = dkim_getresultstr(status);
				fl_report(LOG_CRIT,
					"id=%s: dkim_body failed on %zu bytes: %s (%d)",
					parm->dyn.info.id, len, err? err: "unknown", (int)status);
			}
			return parm->dyn.rtc = -1;
		}

		if (dkim_minbody(dkim) == 0)
			break;
	}

	return parm->dyn.rtc;
}

static void
copy_replacement(dkimfl_parm *parm, FILE *fp, FILE *fp_out, replacement *repl)
{
	uint64_t offset = 0;
	while (repl)
	{
		char buf[4096];
		size_t in = sizeof buf;
		bool last = false;
		assert(offset <= repl->offset);

		if (offset + in >= repl->offset)
		{
			in = repl->offset - offset;
			last = true;
		}

		if (in &&
			(in = fread(buf, 1, in, fp)) > 0 &&
			fwrite(buf, in, 1, fp_out) != 1)
				break;

		offset += in;

		if (last)
		{
			size_t l = chomp_cr(repl->new_text);
			if (l && fwrite(repl->new_text, l, 1, fp_out) != 1)
				break;

			// read and discard the original header (except the trailing \n)
			offset += repl->length;
			while (repl->length > 0)
			{
				in = sizeof buf < repl->length? sizeof buf: repl->length;
				repl->length -= in;
				if (fread(buf, 1, in, fp) != in)
					fl_report(LOG_ERR,
						"cannot advance %zu in mail file: %s", in, strerror(errno));
			}

			repl = repl->next;
		}
	}

	if (repl)
		parm->dyn.rtc = -1;
}

static void recipient_s_domains(dkimfl_parm *parm)
// count recipients of outgoing messages and build domain list for database,
// flag parm->dyn.special if the postmaster is the only recipient.
{
	assert(parm);
	assert(parm->fl);

	unsigned rcpt_count = 0;
	int special_candidate = 0;
	domain_prescreen *dps_head = NULL;
	fl_rcpt_enum *fre = fl_rcpt_start(parm->fl);
	if (fre)
	{
		char *rcpt;
		while ((rcpt = fl_rcpt_next(fre)) != NULL)
		{
			char *dom = strchr(rcpt, '@');
			if (dom++)
			{
				if (++rcpt_count == 1 && parm->dyn.domain)
					special_candidate =
						stricmp(dom, parm->dyn.domain) == 0 &&
						dom - rcpt == 11 &&
						strincmp(rcpt, "postmaster@", 11) == 0;

				domain_prescreen* dps = get_prescreen(&dps_head, dom);
				if (dps == NULL) // memory fault
				{
					clear_prescreen(dps_head);
					return;
				}
			}
		}
		fl_rcpt_clear(fre);
	}

	if (dps_head == NULL)
		fl_report(LOG_ERR,
			"id=%s: unable to collect recipients from ctl file",
			parm->dyn.info.id);
	else
	{
		if (parm->dyn.stats)
		{
			parm->dyn.stats->domain_head = dps_head;
			parm->dyn.stats->rcpt_count = rcpt_count? rcpt_count: 1; // how come?
		}
		else
			clear_prescreen(dps_head);
		parm->dyn.special = rcpt_count == 1 && special_candidate;
	}
}

static inline int user_is_blocked(dkimfl_parm *parm)
{
	return parm->user_blocked =
		search_list(&parm->blocklist, parm->dyn.info.authsender);
}

static inline int is_postmaster(char const *from)
{
	char *addr;
	if (from == NULL || (addr = strdup(from)) == NULL)
		return 0;

	char *domain, *user;
	int rtc = dkim_mail_parse(addr,
		cast_u_char_parm_array(&user), cast_u_char_parm_array(&domain)) == 0 &&
			stricmp(user, "postmaster") == 0;
	free(addr);
	return rtc;
}

static inline void stats_outgoing(dkimfl_parm *parm)
{
	if (parm->dyn.stats)
	{
		parm->dyn.stats->outgoing = 1;
		char *s = parm->dyn.stats->envelope_sender = fl_get_sender(parm->fl);
		if (s && *s == 0)
			parm->dyn.stats->complaint_flag |= 1;
		if (is_postmaster(parm->dyn.stats->from))
			parm->dyn.stats->complaint_flag |= 2;
		if (parm->dyn.stats->rcpt_count == 0)
			recipient_s_domains(parm);
	}
}

static void sign_message(dkimfl_parm *parm)
/*
* possibly sign the message, set rtc 1 if signed, -1 if failed,
* leave rtc as-is (0) if there is no need to rewrite.
*/
{
	assert(parm);
	assert(parm->dyn.key == NULL);
	assert(parm->dyn.selector == NULL);
	assert(parm->dyn.domain == NULL);
	
	if (vb_init(&parm->dyn.vb) ||
		read_key_choice(parm))
	{
		parm->dyn.rtc = -1;
		return;
	}

	/*
	* Reject the message if the user is banned from sending,
	* but allow (emergency?) messages --special-- that is, the
	* only recipient is the postmaster at the signing domain.
	*/
	if (user_is_blocked(parm))
	{
		recipient_s_domains(parm);

		if (parm->dyn.special)
		{
			assert(parm->dyn.domain); // since check in recipient_s_domains
			if (parm->z.verbose >= 3)
				fl_report(LOG_INFO,
					"id=%s: allowing blocked user %s to send to postmaster@%s",
					parm->dyn.info.id,
					parm->dyn.info.authsender,
					parm->dyn.domain);
		}
		else
		{
			static const char null_domain[] = "--domain misconfigured--";
			static const char templ[] =
				"550 BLOCKED: can send to <postmaster@%s> only.\n";

			clean_stats(parm);
			if (parm->dyn.domain == NULL)
				parm->dyn.domain = (char*) null_domain;
			char *smtp_reason = malloc(sizeof templ + strlen(parm->dyn.domain));
			if (smtp_reason)
			{
				sprintf(smtp_reason, templ, parm->dyn.domain);
				fl_pass_message(parm->fl, smtp_reason);
				fl_free_on_exit(parm->fl, smtp_reason);
				parm->dyn.rtc = 2;
			}
			else
				parm->dyn.rtc = -1;

			if (parm->z.verbose >= 3 || parm->dyn.rtc < 0)
				fl_report(parm->dyn.rtc < 0? LOG_CRIT: LOG_INFO,
					"id=%s: %s user %s from sending",
					parm->dyn.info.id,
					parm->dyn.rtc == 2? "blocked": "MEMORY FAULT trying to block",
					parm->dyn.info.authsender);
			if (parm->dyn.domain == null_domain)
				parm->dyn.domain = NULL;
		}
	}

	if (parm->dyn.key == NULL || parm->dyn.domain == NULL)
	{
		if (parm->z.verbose >= 2)
			fl_report(LOG_INFO,
				"id=%s: not signing for %s: no %s",
				parm->dyn.info.id,
				parm->dyn.info.authsender,
				parm->dyn.domain? "key": "domain");

		// add to db even if not signed
		if (parm->dyn.stats)
		{
			sign_headers(parm, NULL, NULL);
			stats_outgoing(parm);
		}
	}
	else if (parm->dyn.rtc == 0)
	{
		char *selector = parm->dyn.selector? parm->dyn.selector:
			parm->z.selector? parm->z.selector: "s";

		DKIM_STAT status;
		DKIM *dkim = dkim_sign(parm->dklib, parm->dyn.info.id, NULL,
			parm->dyn.key, selector, parm->dyn.domain,
			parm->z.header_canon_relaxed? DKIM_CANON_RELAXED: DKIM_CANON_SIMPLE,
			parm->z.body_canon_relaxed? DKIM_CANON_RELAXED: DKIM_CANON_SIMPLE,
			parm->z.sign_rsa_sha1? DKIM_SIGN_RSASHA1: DKIM_SIGN_RSASHA256,
			ULONG_MAX /* signbytes */, &status);

		if (parm->z.verbose >= 6 && dkim && status == DKIM_STAT_OK)
			fl_report(LOG_INFO,
				"id=%s: signing for %s with domain %s, selector %s",
				parm->dyn.info.id,
				parm->dyn.info.authsender,
				parm->dyn.domain,
				selector);
		memset(parm->dyn.key, 0, strlen(parm->dyn.key));
		free(parm->dyn.key);
		parm->dyn.key = NULL;
		if (parm->dyn.selector)
		{
			free(parm->dyn.selector);
			parm->dyn.selector = NULL;
		}
		
		if (dkim == NULL || status != DKIM_STAT_OK)
		{
			if (parm->z.verbose)
			{
				char const *err = dkim_getresultstr(status);
				fl_report(LOG_ERR,
					"id=%s: dkim_sign failed (%d, %sNULL): %s",
					parm->dyn.info.id,
					(int)status,
					dkim? "non-": "",
					err? err: "unknown");
			}
			parm->dyn.rtc = -1;
			return;
		}

		// A-R with auth=pass; if signed, must get hashed before sign_headers
		static char const auth_pass_fmt[] =
			"Authentication-Results: %s;%s auth=pass (details omitted)";
		char *auth_pass = NULL;
		if (parm->z.add_auth_pass)
		{
			char const *nl = "";
			size_t l = strlen(parm->dyn.domain) + sizeof auth_pass_fmt;
			if (l > 77)
			{
				nl = "\r\n";
				l += 2;
			}
			if ((auth_pass = malloc(l)) == NULL)
			{
				fl_report(LOG_ALERT, "MEMORY FAULT");
				parm->dyn.rtc = -1;
			}
			else
			{
				l = sprintf(auth_pass, auth_pass_fmt, parm->dyn.domain, nl);
				my_dkim_header(parm, dkim, auth_pass, l);
			}
		}

		replacement *repl = NULL;

		if (parm->dyn.rtc == 0 &&
			sign_headers(parm, dkim, &repl) == 0 &&
			copy_body(parm, dkim) == 0)
		{
			vb_clean(&parm->dyn.vb);
			status = dkim_eom(dkim, NULL);
			if (status != DKIM_STAT_OK)
			{
				if (parm->z.verbose)
				{
					char const *err = dkim_geterror(dkim);
					if (err == NULL)
						err = dkim_getresultstr(status);
					fl_report(LOG_ERR,
						"id=%s: dkim_eom failed (%d): %s",
							parm->dyn.info.id, (int)status, err? err: "unknown");
				}
				parm->dyn.rtc = -1;
			}
		}
		
		stats_outgoing(parm);  // after sign_headers to check From:

		if (parm->dyn.rtc == 0)
		{
			FILE *fp = fl_get_write_file(parm->fl);
			unsigned char *hdr = NULL;
			size_t len;
			status =
				dkim_getsighdr_d(dkim, sizeof DKIM_SIGNHEADER + 1, &hdr, &len);
			if (fp == NULL || status != DKIM_STAT_OK)
			{
				parm->dyn.rtc = -1;
				dkim_free(dkim);
				return;
			}

			// Write signature as first field
			chomp_cr(hdr);
			fprintf(fp, DKIM_SIGNHEADER ": %s\n", hdr);
			dkim_free(dkim);
			dkim = NULL;

			// A-R, possibly signed, is second field
			if (auth_pass)
			{
				chomp_cr(auth_pass);
				fputs(auth_pass, fp);
				fputc('\n', fp);
				free(auth_pass);
				auth_pass = NULL;
			}

			FILE *in = fl_get_file(parm->fl);
			assert(in);
			rewind(in);

			copy_replacement(parm, in, fp, repl);
				
			if (parm->dyn.rtc == 0)
			{
				if (filecopy(in, fp) == 0)
					parm->dyn.rtc = 1;
				else
					parm->dyn.rtc = -1;
			}

			while (repl)
			{
				replacement *r = repl->next;
				free(repl->new_text);
				free(repl);
				repl = r;
			}
		}
	}
}

// verify

typedef struct verify_parms
{
	char *org_domain;
	domain_prescreen *domain_head, **domain_ptr;
	vbr_info *vbr;  // store of all VBR-Info fields

	vbr_check_result vbr_result;  // vbr_result.resp is malloc'd

	// not malloc'd or maintained elsewhere
	dkimfl_parm *parm;
	char *dkim_domain;

	char const *policy_type, *policy_result, *policy_comment;

	// dps for relevant methods/policies
	domain_prescreen *author_dps, *vbr_dps, *whitelisted_dps,
		*dnswl_dps, *reputation_dps;

	void *dkim_or_file;
	dmarc_rec dmarc;
	int step;

	int dnswl_count;

	// number of DKIM signing domains, elements of domain_ptr
	int ndoms;

	int policy;
	int presult;
	int do_adsp, do_dmarc;
	size_t received_spf;

	unsigned int org_domain_in_dwa: 1;
	unsigned int aligned_spf_pass: 1;
	unsigned int domain_flags:1;
	unsigned int have_spf_pass:1;
	unsigned int have_trusted_voucher:1;

} verify_parms;

static int is_trusted_voucher(char const **const tv, char const *const voucher)
// return non-zero if voucher is in the trusted_voucher list
// the returned value is 1 + the index of trust, for sorting and mv2tv
{
	if (tv && voucher)
		for (int i = 0; tv[i] != NULL; ++i)
			if (stricmp(voucher, tv[i]) == 0)
				return i + 1;

	return 0;
}

static int
has_trusted_voucher(verify_parms const *vh, vbr_info const *const vbr)
// return a non-zero number proportional to trust if any mv is a trusted voucher
{
	assert(vh);
	assert(vh->parm);

	if (vbr && vbr->mv)
	{
		char const ** const tv = vh->parm->z.trusted_vouchers;

		for (char *const *mv = vbr->mv; *mv; ++mv)
		{
			int const itv = is_trusted_voucher(tv, *mv);
			if (itv)
				return itv;
		}
	}

	return 0;
}

static int count_trusted_vouchers(char const **const tv)
{
	int i = 0;
	if (tv)
		for (; tv[i] != NULL; ++i)
			continue;
	return i;
}

static inline char* mv2tv(char *mv, char const **const tv)
{
	int i = is_trusted_voucher(tv, mv) - 1;
	return (char*) (i >= 0? tv[i]: NULL);
}

static void clean_vh(verify_parms *vh)
{
	clear_prescreen(vh->domain_head);
	vbr_info_clear(vh->vbr);
	free(vh->domain_ptr);
	free(vh->vbr_result.resp);
	free(vh->dmarc.rua);
	if (vh->org_domain_in_dwa == 0)
		free(vh->org_domain);
}

static int check_db_connected(dkimfl_parm *parm)
/*
* Track db_connected.  Connection is only attempted if dwa was inited.
* On connection, pass the authenticated user and the client IP, if any.
*
* This function must be called before attempting any query.
*
* Return -1 on hardfail, 0 otherwise.
*/
{
	assert(parm);
	assert(parm->fl);

	db_work_area *const dwa = parm->dwa;
	if (dwa == NULL || parm->dyn.db_connected)
		return 0;
		
	if (db_connect(dwa) != 0)
		return -1;

	parm->dyn.db_connected = 1;

	char *s = NULL;
	if ((s = parm->dyn.info.authsender) != NULL) // outgoing
	{
		char *dom = strchr(s, '@');
		if (dom)
			*dom = 0;
		db_set_authenticated_user(dwa, s, dom? dom + 1: NULL);
		if (dom)
			*dom = '@';
	}

	if ((s = parm->dyn.info.frommta) != NULL &&
		strincmp(s, "dns;", 4) == 0)
/*
for esmtp, this is done by courieresmtpd.c as:

   if (!host)	host="";
   argv[n]=buf=courier_malloc(strlen(host)+strlen(tcpremoteip)+strlen(
      helobuf)+sizeof("dns;  ( [])"));

   strcat(strcat(strcpy(buf, "dns; "), helobuf), " (");
   if (*host)
      strcat(strcat(buf, host), " ");
   strcat(strcat(strcat(buf, "["), tcpremoteip), "])");

and then conveyed to ctlfile 'f' (COMCTLFILE_FROMMTA).  E.g.

   fdns; helobuf (rdns.host.example [192.0.2.1])
*/
	{
		s = strrchr(s + 4, '[');
		if (s && *++s)
		{
			char *e = strchr(s, ']');
			if (e)
			{
				*e = 0;
				db_set_client_ip(dwa, s);
				*e = ']';
			}
		}
	}
	else if (fl_whence(parm->fl) == fl_whence_other && // working stdalone
		(s = getenv("REMOTE_ADDR")) != NULL)
	{
		db_set_client_ip(dwa, s);
	}

	return 0;
}

static inline int change_sign(int old, int newval)
{
	return (old <= 0 && newval > 0) || (old > 0 && newval <= 0);
}

static int domain_flags(verify_parms *vh)
/*
* Called either before or after checking signatures.
* Set domain_val to sort domains.  Check organizational domain and alignment
* assuming relaxed policy --to be undone if a non-relaxed policy is discovered.
* Retrieve per-domain whitelisting and adsp/dmarc settings.
*/
{
	assert(vh && vh->parm);
	assert(vh->step == 0);
	DKIM *const dkim = vh->step? NULL: vh->dkim_or_file;

	if (vh->domain_flags == 0)
	{
		char *from = vh->dkim_domain;
		if (from == NULL)
			vh->dkim_domain = from = dkim_getdomain(dkim);

		int const vbr_count =
			count_trusted_vouchers(vh->parm->z.trusted_vouchers);
		int const vbr_factor = vbr_count < 2? 0: 1000/(vbr_count - 1);

		size_t org_domain_len = 0;
		publicsuffix_trie const *const pst = vh->parm->pst;
		db_work_area *const dwa = vh->parm->dwa;
		if (from)
		{
			domain_prescreen *dps = get_prescreen(&vh->domain_head, from);
			if (dps)
				dps->u.f.is_from = dps->u.f.is_aligned = 1;
			else
				return vh->parm->dyn.rtc = -1;
			if (pst)
			{
				char *od = vh->org_domain;
				if (od == NULL)
					vh->org_domain = od = org_domain(pst, from);
				if (od != NULL)
				{
					org_domain_len = strlen(od);
					if (dwa && vh->org_domain_in_dwa == 0)
					{
						db_set_org_domain(dwa, od);
						vh->org_domain_in_dwa = 1;
					}

					if (stricmp(from, od) != 0 &&
						(dps = get_prescreen(&vh->domain_head, od)) == NULL)
							return vh->parm->dyn.rtc = -1;

					dps->u.f.is_org_domain = dps->u.f.is_aligned = 1;
				}
			}
		}

		if (dwa && check_db_connected(vh->parm) < 0)
			return -1;

		for (domain_prescreen *dps = vh->domain_head; dps; dps = dps->next)
		{
			dps->domain_val = 0;
			if (dps->u.f.is_from)
			{
				dps->domain_val += 2500;    // author's domain
			}
			else if (dps->u.f.is_org_domain)
			{
				dps->domain_val += 2000;    // author's organizational domain
			}
			else
			{
				size_t len = strlen(dps->name);
				if (len >= org_domain_len && org_domain_len > 0 &&
					stricmp(dps->name + len - org_domain_len, vh->org_domain) == 0)
				{
					dps->u.f.is_aligned = 1;
					dps->domain_val += 1500;
					assert(len != org_domain_len); // otherwise is_org_domain
				}
			}

			if (dwa)
			{
				int dmarc, adsp,
					c = db_get_domain_flags(dwa, dps->name,
						&dps->whitelisted, &dmarc, &adsp);
				if (c > 0)
				{
					if (dps->whitelisted > 1)
					{
						if (dps->whitelisted > 2)
						{
							dps->domain_val += 500;
							dps->u.f.is_trusted = 1;
						}
						dps->domain_val += 500;
						dps->u.f.is_whitelisted = 1;
					}
					dps->domain_val += 500;
					dps->u.f.is_known = 1;
					if (c > 1 && dps->u.f.is_aligned)
					{
						int old = vh->do_dmarc;
						dmarc += old;
						vh->do_dmarc = dmarc;
						if (change_sign(old, dmarc) &&
							vh->parm->z.verbose >= 8)
								fl_report(LOG_WARNING,
									"id=%s: %sabling DMARC for %s: %d -> %d",
									vh->parm->dyn.info.id,
									dmarc > 0? "en": "dis", dps->name, old, dmarc);
						if (c > 2 && dps->u.f.is_from)
						{
							old = vh->do_adsp;
							adsp += old;
							vh->do_adsp = adsp;
							if (change_sign(old, adsp) &&
								vh->parm->z.verbose >= 8)
									fl_report(LOG_WARNING,
										"id=%s: %sabling ADSP for %s: %d -> %d",
										vh->parm->dyn.info.id,
										adsp > 0? "en": "dis", dps->name, old, adsp);
						}
					}
				}
				else
					dps->whitelisted = 0;
			}

			vbr_info *const vbr = vbr_info_get(vh->vbr, dps->name);
			if (vbr)
			{
				dps->u.f.has_vbr = 1;   // sender's adverized vouching
				dps->domain_val += 5;
				if (vbr_count)
				{
					/*
					* for trusted vouching, add a value ranging linearly
					* from 1200 for trust=1 down to 200 for trust=vbr_count
					* assuming 1 <= trust <= vbr_count
					*/
					int const trust = has_trusted_voucher(vh, vbr);
					if (trust)
					{
						dps->domain_val += vbr_factor * (vbr_count - trust) + 200;
						dps->u.f.vbr_is_trusted = 1;
						vh->have_trusted_voucher = 1;
					}
				}
			}

			if (dps->u.f.is_dnswl)
				dps->domain_val += 200;     // dnswl relay's signature

			if (dps->u.f.is_mfrom && dps->spf >= spf_neutral)
				dps->domain_val += 100;     // sender's domain signature

			if (dps->u.f.is_helo && dps->spf >= spf_neutral)
				dps->domain_val += 15;      // relay's signature
		}

		vh->domain_flags = 1;
	}

	return 0;
}

static int
domain_sort(verify_parms *vh, DKIM_SIGINFO** sigs, int nsigs)
/*
* Setup the domain prescreen that will eventually be passed to the database.
* Domains are drawn from the signature array; domains from other authentication
* methods yielding a domain name (from, mfrom, helo, and dnswl) are already in
* the linked list beginning at vh->domain_head = dps_head.
*
* domain_ptr is an array of sorted pointers to dps structures.  Only signing
* domains are in there.
*
* Two temporary arrays are used, sigs_mirror is
* a signature-to-domain map, and sigs copy is a swap area.
*
* Signatures are not yet verified at this time (sort affects verify order).
*
* return -1 for fatal error, number of domains otherwise
*/
{
	assert(vh && vh->parm);

	int ndoms = nsigs;
	int good = 1;

	domain_prescreen** domain_ptr = calloc(ndoms+1, sizeof(domain_prescreen*));
	domain_prescreen** sigs_mirror = calloc(nsigs+1, sizeof(domain_prescreen*));
	DKIM_SIGINFO** sigs_copy = calloc(nsigs+1, sizeof(DKIM_SIGINFO*));

	domain_prescreen **dps_head = &vh->domain_head;
	if (!(domain_ptr && sigs_mirror && sigs_copy))
		good = 0;

	// size_t const helolen = helo? strlen(helo): 0;

	ndoms = 0;

	/*
	* 1st pass: Create prescreens with name-based domain evaluation.
	* Fill in sigs_mirror and domain_ptr.
	*/
	if (good)
		for (int c = 0; c < nsigs; ++c)
		{
			char *const domain = dkim_sig_getdomain(sigs[c]);
			if (domain)
			{
				domain_prescreen *dps = get_prescreen(dps_head, domain);
				if (dps == NULL)
				{
					good = 0;
					break;
				}

				sigs_mirror[c] = dps;

				if (dps->nsigs++ == 0)  // first time domain seen in this loop
				{
					domain_ptr[ndoms++] = dps;
				}
			}
		}

	if (good && domain_flags(vh))
		good = 0;

	if (!good)
	{
		free(domain_ptr);
		free(sigs_mirror);
		free(sigs_copy);
		return -1;
	}

	/*
	* Sort domain_ptr, based on domain flags.  Use gnome sort, as we
	* expect 2 ~ 4 elements.  (It starts getting sensibly slow with
	* 1000 elements --1ms on nocona xeon.)
	*/

	for (int c = 0; c < ndoms;)
	{
		if (c == 0 || domain_ptr[c]->domain_val <= domain_ptr[c-1]->domain_val)
			++c;
		else
		{
			domain_prescreen *const dps = domain_ptr[c];
			domain_ptr[c] = domain_ptr[c-1];
			domain_ptr[c-1] = dps;
			--c;
		}
	}

	/*
	* Allocate indexes in the sorted sig array.  Reuse sigval as next_index.
	* store dkim_order in dps.
	*/

	int next_ndx = 0;
	size_t dkim_order = 0;
	for (int c = 0; c < ndoms; ++c)
	{
		domain_prescreen *const dps = domain_ptr[c];
		dps->sigval = dps->start_ndx = next_ndx;
		next_ndx += dps->nsigs;
		assert(dps->nsigs > 0);
		dps->dkim_order = ++dkim_order;
	}

	/*
	* Make a copy of sigs, then
	* 2nd pass: Rewrite sigs array based on allocated indexes.
	* That way, domains are ordered by preference, while signatures for each
	* domain are gathered in their original order.
	*/

	if (nsigs)
	{
		memcpy(sigs_copy, sigs, nsigs * sizeof(DKIM_SIGINFO*));
		for (int c = 0; c < nsigs; ++c)
		{
			domain_prescreen *const dps = sigs_mirror[c];
			DKIM_SIGINFO *const sig = sigs_copy[c];
			sigs[dps->sigval++] = sig;
		}
	}

	free(sigs_mirror);
	free(sigs_copy);

	vh->ndoms = ndoms;
	if (ndoms)
	{
		vh->domain_ptr = realloc(domain_ptr, ndoms * sizeof(domain_prescreen*));
		if (vh->parm->dyn.stats)
		{
			vh->parm->dyn.stats->signatures_count = nsigs;

			if (vh->parm->z.log_dkim_order_above > 0 &&
				vh->parm->z.log_dkim_order_above < ndoms &&
				vh->parm->z.verbose >= 3)
					fl_report(LOG_WARNING,
						"id=%s: %d DKIM signing domains, current dkim order is %d.",
						vh->parm->dyn.info.id,
						ndoms,
						vh->parm->z.log_dkim_order_above);
		}
	}
	else
	{
		free(domain_ptr);
		clean_stats(vh->parm);
	}

	return ndoms;
}

static DKIM_STAT dkim_sig_sort(DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
{
	verify_parms *const vh = dkim_get_user_context(dkim);

	assert(dkim && sigs && vh);

	if (nsigs > vh->parm->z.max_signatures)
	{
		fl_pass_message(vh->parm->fl, "550 Too many DKIM signatures\n");
		vh->parm->dyn.rtc = 2;
		if (vh->parm->z.verbose >= 3)
			fl_report(LOG_ERR,
				"id=%s: %d DKIM signatures, max is %d, message rejected.",
				vh->parm->dyn.info.id,
				nsigs,
				vh->parm->z.max_signatures);
		return DKIM_CBSTAT_REJECT;
	}

	int rtc = domain_sort(vh, sigs, nsigs);
	if (rtc < 0)
	{
		vh->parm->dyn.rtc = -1;
		return DKIM_CBSTAT_TRYAGAIN;
	}
	return DKIM_CBSTAT_CONTINUE;
}

static int run_vbr_check(verify_parms *vh, domain_prescreen const *const dps)
{
	assert(vh);
	assert(vh->parm);

	dkimfl_parm *parm = vh->parm;
	size_t const queries = vh->vbr_result.queries;

	vh->vbr_result.vbr = NULL;
	vh->vbr_result.mv = NULL;
	vh->vbr_result.tv = vh->parm->z.trusted_vouchers;
	char const *const domain = dps->name;
	int rc = vbr_check(vh->vbr, domain, &is_trusted_voucher, &vh->vbr_result);
	if (rc != 0 && parm->z.verbose >= 3)
	{
		if (queries == vh->vbr_result.queries && vh->vbr_result.vbr != NULL)
		// no certifiers are trusted for this domain
		{
			char *verifiers = vbr_info_vouchers(vh->vbr_result.vbr);
			fl_report(LOG_INFO, "non-trusted VBR certifier(s) for %s: %s",
				domain, verifiers? verifiers: "(null)");
			free(verifiers);
		}
		else if (rc == 3 && vh->vbr_result.mv != NULL)
			fl_report(LOG_NOTICE,
				"%s claims VBR-Info by trusted VBR certifier %s, who says NXDOMAIN",
					domain, vh->vbr_result.mv);
	}
	return rc;
}

static inline dkim_result sig_is_good(DKIM_SIGINFO *const sig)
{
	unsigned int const sig_flags = dkim_sig_getflags(sig);
	unsigned int const bh = dkim_sig_getbh(sig);
	DKIM_SIGERROR const rc = dkim_sig_geterror(sig);

	if (sig_flags & DKIM_SIGFLAG_IGNORE) return dkim_policy;
	if ((sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
		bh == DKIM_SIGBH_MATCH &&
		rc == DKIM_SIGERROR_OK)
			return dkim_pass;

	// we didn't process this sig
	if ((sig_flags & DKIM_SIGFLAG_PROCESSED) == 0 ||
		rc == DKIM_SIGERROR_UNKNOWN && bh == DKIM_SIGBH_UNTESTED)
			return dkim_none;

	// idea: if it's wrong in the DNS it is an error, otherwise a failure.
	switch (rc)
	{
		case DKIM_SIGERROR_KEYFAIL:
			return dkim_temperror;

		case DKIM_SIGERROR_NOKEY:
		case DKIM_SIGERROR_DNSSYNTAX:
		case DKIM_SIGERROR_KEYVERSION:
		case DKIM_SIGERROR_KEYUNKNOWNHASH:
		case DKIM_SIGERROR_NOTEMAILKEY:
		case DKIM_SIGERROR_KEYTYPEMISSING:
		case DKIM_SIGERROR_KEYTYPEUNKNOWN:
			return dkim_permerror;

		default:
			return (sig_flags & DKIM_SIGFLAG_TESTKEY)? dkim_neutral: dkim_fail;
	}
}

static DKIM_STAT dkim_sig_final(DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
/*
* Check author domain, whitelisted, trusted vbr.
*/
{
	verify_parms *const vh = (verify_parms*)dkim_get_user_context(dkim);
	assert(dkim && sigs && vh);

	int const ndoms = vh->ndoms;
	domain_prescreen **const domain_ptr = vh->domain_ptr;

	int const do_all = vh->parm->z.report_all_sigs;
	char *const reputation_root = vh->parm->z.do_reputation?
		vh->parm->z.reputation_root: NULL;

	/*
	* run all sigs if any of the following is true:
	*  - all of them are to be reported on the message
	*  - we use a database and report them there
	*  - we have trusted vouchers to check
	*  - we need reputation to accept the message
	*/
	int const verify_all = do_all ||
		!vh->parm->z.verify_one_domain &&
		(vh->parm->dwa != NULL || vh->have_trusted_voucher ||
			vh->parm->dyn.action_header != NULL && reputation_root);

	int do_more_sigs = 1;

	for (int c = 0; c < ndoms; ++c)
	{
		domain_prescreen *const dps = domain_ptr[c];
		dps->sigval = 0; // reuse for number of verified signatures
		if (dps->nsigs > 0)
		{
			for (int n = 0; n < dps->nsigs; ++n)
			{
				int const ndx = n + dps->start_ndx;
				assert(ndx >= 0 && ndx < nsigs);
				DKIM_SIGINFO *const sig = sigs[ndx];
				unsigned int const sig_flags = dkim_sig_getflags(sig);
				if (do_more_sigs &&
					(sig_flags & DKIM_SIGFLAG_IGNORE) == 0 &&
					dkim_sig_process(dkim, sig) == DKIM_STAT_OK &&
					(dps->dkim = sig_is_good(sig)) == dkim_pass)
				{
					dps->u.f.sig_is_ok = 1;
					if (dps->sigval++ == 0)
					{
						dps->first_good = n;
						if (reputation_root)
						{
							int rep = 0;
							if (0 ==
								my_get_reputation(dkim, sig, reputation_root, &rep))
							{
								dps->u.f.is_reputed_signer = 1;
								dps->reputation = rep;
							}
						}
					}

					if (!do_all)
					{
						do_more_sigs = verify_all;
						break;
					}
				}
			}

			if (dps->sigval == 0)
			/*
			* We assumed signatures were valid and we erred.  This domain is not
			* DKIM-authenticated, so undo flagging.  An alternative approach is to
			* check whitelisting / trusted VBR after signature validation.  We
			* check  in advance, and then attempt signature validation in the
			* resulting order:  Signature validation costs more than local lookup.
			*/
			{
				assert(dps->u.f.vbr_is_ok == 0); // signature required

				if (dps->u.f.is_dnswl == 0 && dps->u.f.spf_pass == 0)
				{
					dps->whitelisted = 0;
					dps->u.f.is_trusted = 0;
					dps->u.f.is_whitelisted = 0;
					dps->u.f.is_known = 0;
				}
			}
		}
	}

	return DKIM_CBSTAT_CONTINUE;
	(void)nsigs; // only used in assert
}

typedef struct a_r_reader_parm
{
	char const *authserv_id, *discarded; // only valid during the call
	domain_prescreen *dnswl_dps; // output (was dnswl_domain)
	dkimfl_parm *parm; // input param
	domain_prescreen **domain_head; // input for get_prescreen
	int resinfo_count, dnswl_count;
	union ip_number
	{
		int32_t ip;
		uint8_t ip_c[4];
	} u;
} a_r_reader_parm;

static int a_r_reader(void *v, int step, name_val* nv, size_t nv_count)
{
	a_r_reader_parm *arp = v;

	assert(arp);
	assert(arp->parm);
	assert(arp->domain_head);

	int rtc = 0;

	if (nv == NULL) // last call
	{
		rtc = step;

		if (arp->dnswl_dps || arp->u.ip) // found at least one
		{
			if (arp->discarded && arp->parm->z.verbose >= 6)
				fl_report(LOG_INFO,
					"id=%s: discarded %s and other %d trusted zone(s) in "
						"Authentication-Results by %s",
					arp->parm->dyn.info.id,
					arp->discarded,
					arp->dnswl_count - 2,
					arp->authserv_id? arp->authserv_id: "(null authserv-id)");
		}
		else if (arp->parm->z.verbose >= 2)
		/*
		* ALLOW_EXCLUSIVE and trust_a_r should mirror each other.
		* ALLOW_EXCLUSIVE is configured in Courier's sysconfdir/esmtpd.
		* For mumbling on further alternatives, see the comments after
		* maybe_attack and dkim_unrename, below.
		*/
			fl_report(rtc? LOG_ERR: LOG_NOTICE,
				"id=%s: Authentication-Results by %s: %s",
				arp->parm->dyn.info.id,
				arp->authserv_id? arp->authserv_id: "(null authserv-id)",
				rtc != 0 ? "unparseable data":
					arp->resinfo_count <= 0? "empty":
						"please check ALLOW settings");
	}
	else if (step < 0)
	{
		arp->authserv_id = nv[0].name;
	}
	else
	{
		arp->resinfo_count += 1;

		if (nv_count > 0 &&
			stricmp(nv[0].name, "dnswl") == 0 &&
			stricmp(nv[0].value, "pass") == 0)
		{
			char const *dns_zone = NULL, *policy_txt = NULL, *policy_ip = NULL;
			for (size_t i = 1; i < nv_count; ++i)
			{
				if (stricmp(nv[i].name, "dns.zone") == 0)
					dns_zone = nv[i].value;
				else if (stricmp(nv[i].name, "policy.txt") == 0)
					policy_txt = nv[i].value;
				else if (stricmp(nv[i].name, "policy.ip") == 0)
					policy_ip = nv[i].value;
			}

			char const **const zone = arp->parm->z.trusted_dnswl;
			if (zone && dns_zone)
			{
				int trusted = 0;
				for (size_t i = 0; zone[i] != NULL; ++i)
					if (stricmp(zone[i], dns_zone) == 0)
					{
						trusted = 1;
						break;
					}

				if (trusted)
				{
					arp->dnswl_count += 1;

					if (policy_txt && arp->dnswl_dps == NULL)
					{
						char cp[64]; // domain length
						for (size_t i = 0; i < sizeof cp; ++i)
						{
							int const ch = *(unsigned char*)&policy_txt[i];
							if (ch == 0 || isspace(ch))
							{
								if (i > 0)
								{
									cp[i] = 0;

									if ((arp->dnswl_dps =
										get_prescreen(arp->domain_head, cp)) != NULL)
											arp->dnswl_dps->u.f.is_dnswl = 1;
									else
										arp->parm->dyn.rtc = -1;

									if (arp->parm->z.verbose >= 6)
										fl_report(LOG_INFO,
											"id=%s: domain %s whitelisted by %s",
											arp->parm->dyn.info.id, cp, dns_zone);
								}
								break;
							}
							if (isalnum(ch) || strchr(".-_", ch) != NULL)
								cp[i] = ch;
							else
								break;
						}
					}
					else if (arp->dnswl_dps && arp->discarded == NULL)
						arp->discarded = dns_zone;

					if (policy_ip && arp->u.ip == 0)
					{
						size_t n = 0;
						char const *p = policy_ip;
						unsigned bad = 0, u = 0;

						for (;;)
						{
							unsigned const ch = *(unsigned char *)p++;
							if (ch == '.' || ch == 0)
							{
								if (u < 256 && n < 4)
									arp->u.ip_c[n++] = u;
								else
									bad = 1;
								u = 0;
								if (ch == 0)
									break;
							}
							else if (isalnum(ch))
								u = 10 * u + ch - '0';
						}

						if (bad || arp->u.ip == arp->parm->z.dnswl_invalid_ip)
						{
							if (arp->parm->z.verbose >= 1)
								fl_report(LOG_CRIT,
									"Zone %s lookup has invalid IP %s",
									dns_zone, policy_ip);
							arp->u.ip = 0;
						}
					}
					else if (arp->dnswl_dps && arp->discarded == NULL)
						arp->discarded = dns_zone;
				}
			}
		}
	}
	return rtc;
}

static int verify_headers(verify_parms *vh)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(vh && vh->parm);

	dkimfl_parm *const parm = vh->parm;
	size_t keep = 0;
	var_buf *vb = &parm->dyn.vb;
	FILE* fp = fl_get_file(parm->fl);
	assert(fp);
	DKIM *const dkim = vh->step? NULL: vh->dkim_or_file;
	FILE *const out = vh->step? vh->dkim_or_file: NULL;

	int seen_received = 0;
	int const do_vbr = parm->z.trusted_vouchers != NULL;

	for (;;)
	{
		char *p = vb_fgets(vb, keep, fp);
		char *eol = p? strchr(p, '\n'): NULL;

		if (eol == NULL)
		{
			if (parm->z.verbose)
				fl_report(LOG_ALERT,
					"id=%s: header too long (%.20s...)",
					parm->dyn.info.id, vb_what(vb, fp));
			if (vb->buf == NULL)
				clean_stats(parm);
			return parm->dyn.rtc = -1;
		}

		int const next = eol > p? fgetc(fp): '\n';
		int const cont = next != EOF && next != '\n';
		char *const start = vb->buf;
		if (cont && isspace(next)) // wrapped
		{
			if (dkim)
			{
				*eol++ = '\r';
				*eol = '\n';
			}
			*++eol = next;
			keep = eol + 1 - start;
			continue;
		}

		/*
		* full header, including trailing \n, is in buffer
		* process it
		*/
		int zap = 0;
		size_t dkim_unrename = 0;
		char *s;

		// malformed headers can go away...
		if (!isalpha(*(unsigned char*)start))
			zap = 1;

		// A-R fields
		else if ((s = hdrval(start, "Authentication-Results")) != NULL)
		{
			if (!parm->z.trust_a_r)
			{
				if ((s = skip_cfws(s)) == NULL)
					zap = 1; // bogus
				else
				{
					char *const authserv_id = s;
					int ch;
					while (isalnum(ch = *(unsigned char*)s) ||
						strchr(".-_", ch) != NULL)
							++s;
					if (s == authserv_id)
						zap = 1; // bogus
					else
					{
						int maybe_attack = 0;
						*s = 0;
						/*
						* Courier puts A-R after "Received" (but before Received-SPF).
						* After "Received", a matching authserv_id might be malicious.
						* For the time being, we discard it.
						*
						* A further possibility is to check the Received-SPF, assuming
						* that it is configured and thus always present:  If Courier's
						* A-R is before that, then it is authentic.  The advantage to
						* do so would be to keep trusted A-R fields.
						*/
						if (parm->dyn.authserv_id &&
							stricmp(authserv_id, parm->dyn.authserv_id) == 0)
								maybe_attack = zap = 1;
						if (dkim == NULL && parm->z.verbose >= 2) // log on 2nd pass
						{
							if (maybe_attack)
								fl_report(LOG_NOTICE,
									"id=%s: removing Authentication-Results from %s",
									parm->dyn.info.id, authserv_id);
							else if (parm->z.verbose >= 6)
								fl_report(LOG_INFO,
									"id=%s: found Authentication-Results by %s",
									parm->dyn.info.id, authserv_id);
						}
						// TODO: check a list of trusted/untrusted id's
						*s = ch;
					}
				}
			}
			// acquire trusted results on 1st pass
			else if (dkim)
			{
				a_r_reader_parm arp;
				memset(&arp, 0, sizeof arp);
				arp.parm = parm;
				arp.domain_head = &vh->domain_head;
				if (a_r_parse(s, &a_r_reader, &arp) == 0)
				{
					if (arp.dnswl_dps && arp.u.ip)
						arp.dnswl_dps->dnswl_value =
							arp.u.ip_c[parm->z.dnswl_octet_index];
					vh->dnswl_count += arp.dnswl_count;
				}
			}
		}

		// Only on first step, acquire relevant header info, and unrename
		else if (dkim)
		{
			// cache courier's SPF results, get authserv_id, count Received
			if (strincmp(start, "Received", 8) == 0)
			{
				if ((s = hdrval(start, "Received")) != NULL)
				{
					if (parm->dyn.stats)
						parm->dyn.stats->received_count += 1;

					if (parm->dyn.authserv_id == NULL && seen_received == 0)
					{
						seen_received = 1;
						while (s && parm->dyn.authserv_id == NULL)
						{
							s = strstr(s, " by ");
							if (s)
							{
								s += 4;
								while (isspace(*(unsigned char*)s))
									++s;
								char *const authserv_id = s;
								int ch;
								while (isalnum(ch = *(unsigned char*)s) ||
									strchr(".-_", ch) != NULL)
									++s;
								char *ea = s;
								while (isspace(*(unsigned char*)s))
									++s;
								*ea = 0;
								if (strincmp(s, "with ", 5) == 0 && s > ea &&
									(parm->dyn.authserv_id = strdup(authserv_id)) == NULL)
								{
									clean_stats(parm);
									return parm->dyn.rtc = -1;
								}

								*ea = ch;
							}
						}
					}
				}

				else if (!parm->z.no_spf && vh->received_spf < 3 &&
					(s = hdrval(start, "Received-SPF")) != NULL)
				{
					++vh->received_spf;
					while (isspace(*(unsigned char*)s))
						++s;
					spf_result spf = spf_result_string(s);
					s = strstr(s, "SPF=");
					if (s)
					{
						s += 4;  //               1234567
						char *sender = strstr(s, "sender=");
						if (sender)
						{
							sender += 7;
							char *esender = strchr(sender, '@');
							if (esender)
								sender = esender + 1;
							esender = strchr(sender, ';');
							if (esender)
							{
								*esender = 0;
								domain_prescreen *dps =
									get_prescreen(&vh->domain_head, sender);
								if (dps)
								{
									// multiple spf result can race, choose the higher
									if (spf > dps->spf)
										dps->spf = spf;

									if (spf == spf_pass)
										dps->u.f.spf_pass = 1;

									if (strincmp(s, "HELO", 4) == 0)
										dps->u.f.is_helo = 1;

									else if (strincmp(s, "MAILFROM", 8) == 0)
										dps->u.f.is_mfrom = 1;

									else if (strincmp(s, "FROM", 4) == 0)
										dps->u.f.is_spf_from = 1;

								}
								else
								{
									return parm->dyn.rtc = -1;
								}
								*esender = ';';
							}
						}
					}
				}
			}

			//  collect VBR-Info
			else if ((s = hdrval(start, "VBR-Info")) != NULL)
			{
				if (do_vbr)
				{
					int const rtc = vbr_info_add(&vh->vbr, s);
					if (rtc < 0)
					{
						fl_report(LOG_ALERT, "MEMORY FAULT");
						return parm->dyn.rtc = -1;
					}
					else if (rtc && parm->z.verbose >= 3)
						fl_report(LOG_INFO, "id=%s: bad VBR-Info: %s",
							parm->dyn.info.id, s);
				}
			}

			/*
			* unrename Authentication-Results:  There are different
			* opinions on signing such fields, or the "X-Original-"
			* variant thereof.  To the opposite, the "Old-" variant
			* seems to be specific of Courier or servers acting in
			* a similar fashion.  Thus, the probability of breaking
			* a signature by unrenaming seems to be lower than that
			* of breaking it by not doing so.
			*/
			else if ((s = hdrval(start, "Old-Authentication-Results")) != NULL)
			{
				dkim_unrename = 4;
			}

			// (only if stats enabled)
			// save stats' content_type and content_encoding, check mailing_list
			else if (parm->dyn.stats)
				collect_stats(parm, start);

			// action header
			if (parm->z.action_header && parm->dyn.action_header == NULL &&
				(s = hdrval(start, parm->z.action_header)) != NULL &&
				(parm->dyn.action_header = strdup_normalize(s, 0)) == NULL)
			{
				fl_report(LOG_ALERT, "MEMORY FAULT");
				return parm->dyn.rtc = -1;
			}
		}

		if (!zap)
		{
			int err = 0;
			DKIM_STAT status;
			size_t const len = eol - start - dkim_unrename;
			if (dkim)
			{
				status = dkim_header(dkim, start + dkim_unrename, len);
				err = status != DKIM_STAT_OK;
				if (err && status == DKIM_STAT_SYNTAX)
				{
					err = 0;
					if (parm->z.verbose >= 5)
					{
						char *bad_eol = strchr(start, '\r');
						if (bad_eol)
							*bad_eol = 0;
						fl_report(LOG_ERR,
							"id=%s: bad header field \"%s\": Syntax error (5)",
							parm->dyn.info.id, start);
					}
				}
			}
			else
			{
				err = fwrite(start, len + 1, 1, out) != 1;
				status = DKIM_STAT_OK; // happy compiler
			}

			if (err)
			{
				if (parm->z.verbose)
				{
					char const *errs, *what;
					if (dkim)
					{
						what = "dkim_header";
						errs = dkim_getresultstr(status);
						err = (int)status;
					}
					else
					{
						what = "fwrite";
						errs = strerror(errno);
						err = errno;
					}
					fl_report(LOG_ALERT,
						"id=%s: %s failed on %zu bytes: %s (%d)",
						parm->dyn.info.id, what, len,
						errs? errs: "unknown", err);
				}
				return parm->dyn.rtc = -1;
			}			
		}

		if (!cont)
			break;

		start[0] = next;
		keep = 1;
	}
	
	/*
	* all headers processed
	* check results thus far.
	*/

	if (dkim)
	{
		vh->dkim_domain = dkim_getdomain(dkim);
		dkim_set_user_context(dkim, vh);

		DKIM_STAT status = dkim_eoh(dkim);
		if (status != DKIM_STAT_OK)
		{
			if (parm->z.verbose >= 7 ||
				parm->z.verbose >= 5 && status != DKIM_STAT_NOSIG)
			{
				char const *err = dkim_getresultstr(status);
				fl_report(LOG_INFO,
					"id=%s: verifying dkim_eoh: %s (stat=%d)",
					parm->dyn.info.id, err? err: "(NULL)", (int)status);
			}
			// parm->dyn.rtc set by callback
		}

		if (parm->dyn.authserv_id == NULL && parm->z.verbose)
			fl_report(LOG_ERR,
				"id=%s: missing courier's Received field",
				parm->dyn.info.id);
	}
	else if (ferror(out))
	{
		if (parm->z.verbose)
			fl_report(LOG_ALERT,
				"id=%s: frwite failed with %s",
				parm->dyn.info.id, strerror(errno));
		return parm->dyn.rtc = -1;
	}

	return parm->dyn.rtc;
}

typedef struct dkim_result_summary
{
	char *id; //malloc'd
	char const *result, *err;
} dkim_result_summary;

static int print_signature_resinfo(FILE *fp, domain_prescreen *dps, int nsig,
	dkim_result_summary *drs, DKIM *dkim)
// Last argument, dkim, to get sig in order to use header.b, if dps->nsigs > 1.
// Start printing the semicolon+newline that terminate either the previous
// resinfo or the authserv-id, then print the signature details.
// No print for ignored signatures.
// Return 1 or 0, the number of resinfo's written.
{
	assert(dps);

	DKIM_SIGINFO *sig, **sigs = NULL;
	int nsigs;

	if (dps->nsigs <= 0 ||
		dkim_getsiglist(dkim, &sigs, &nsigs) != DKIM_STAT_OK ||
		sigs == NULL ||
		nsigs <= dps->start_ndx + nsig)
			return 0;

	sig = sigs[nsig + dps->start_ndx];

	unsigned int sig_flags;
	if (sig == NULL ||
		((sig_flags = dkim_sig_getflags(sig)) & DKIM_SIGFLAG_IGNORE) != 0)
			return 0;

	char buf[80], *id = NULL, htype = 0;
	memset(buf, 0, sizeof buf);
	if (dkim_sig_getidentity(NULL, sig, buf, sizeof buf) == DKIM_STAT_OK)
	{
		id = buf;
		htype = 'i';
	}
	else if ((id = dkim_sig_getdomain(sig)) != NULL)
		htype = 'd';

	char buf2[80], *id2 = NULL;
	size_t sz2 = sizeof buf2;
	memset(buf2, 0, sizeof buf2);
#if HAVE_DKIM_GET_SIGSUBSTRING
// dkim_get_sigsubstring was added for version 2.1.0
	if (dkim && dps && dps->nsigs > 1 &&
		dkim_get_sigsubstring(dkim, sig, buf2, &sz2) == DKIM_STAT_OK &&
		sz2 < sizeof buf2)
			id2 = &buf2[0];
#endif

	if (id == NULL)
	{
		id = id2;
		htype = 'b';
		id2 = NULL;
	}

	if (id == NULL || htype == 0) //useless to report an unidentifiable signature
		return 0;

	int const is_test = (sig_flags & DKIM_SIGFLAG_TESTKEY) != 0;
	dkim_result dr = sig_is_good(sig);
	char const *result = get_dkim_result(dr), *err = NULL;

	if (dr == dkim_neutral || dr == dkim_fail)
	{
		unsigned int const bh = dkim_sig_getbh(sig);
		DKIM_SIGERROR const rc = dkim_sig_geterror(sig);
		if (rc == DKIM_SIGERROR_OK)
			if ((sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
				bh == DKIM_SIGBH_MISMATCH)
					err = "body hash mismatch";
			else
				err = "bad signature";
		else
			err = dkim_sig_geterrorstr(rc);
	}

#if 0
	char const *const failresult = is_test? "neutral": "fail";
	switch (rc)
	{
		case DKIM_SIGERROR_OK:
			if ((sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
				bh == DKIM_SIGBH_MATCH)
					result = "pass";
			else
			{
				if ((sig_flags & DKIM_SIGFLAG_PROCESSED) != 0)
					result = failresult;
				else
					result = "permerror";

				if ((sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
					bh == DKIM_SIGBH_MISMATCH)
						err = "body hash mismatch";
				else
					err = "bad signature";
			}
			break;
		case DKIM_SIGERROR_UNKNOWN:
			result = "permerror";
			break;
		default:
			if ((sig_flags & DKIM_SIGFLAG_PROCESSED) != 0)
				result = failresult;
			else
				result = "permerror";
			err = dkim_sig_geterrorstr(rc);
			break;
	}
#endif

	fprintf(fp, ";\n  dkim=%s ", result);

	union flags_as_an_int_or_bitfields u;
	u.all = 0;
	if (dps)
	{
		u.f.is_whitelisted = dps->u.f.is_whitelisted;
		u.f.vbr_is_ok = dps->u.f.vbr_is_ok;
	}

	if (err || is_test || u.all)
	{
		int cont = 0;
		fputc('(', fp);
		if (is_test)
		{
			fputs("test key", fp);
			cont = 1;
		}
		if (err)
		{
			if (cont) fputs(", ", fp);
			fputs(err, fp);
			cont = 1;
		}
		if (u.f.is_whitelisted)
		{
			if (cont) fputs(", ", fp);
			fputs("whitelisted", fp);
			cont = 1;
		}
		if (u.f.vbr_is_ok)
		{
			if (cont) fputs(", ", fp);
			fputs("vbr", fp);
		}
		fputs(") ", fp);		
	}
	fprintf(fp, "header.%c=%s", htype, id);
	if (id2)
		fprintf(fp, "\n    header.b=%s", id2);

	if (drs)
	{
		drs->id = strdup(id);
		drs->result = result;
		drs->err = err;
	}

	return 1;
}

static int write_file(verify_parms *vh, FILE *fp, DKIM_STAT status)
/*
* fp is open for writing
*/
{
	assert(vh);
	assert(vh->step == 0);
	assert(fp);
	assert(vh->policy_type);
	assert(vh->policy_result);
	assert(vh->policy_comment);

	dkimfl_parm *const parm = vh->parm;
	DKIM *dkim = vh->dkim_or_file;

	/*
	* according to RFC 5451, Section 7.1, point 5, the A-R field
	* should always appear above the corresponding Received field.
	*/
	fprintf(fp, "Authentication-Results: %s", parm->dyn.authserv_id);
	int auth_given = 0;
	int log_written = 0;

	char *spf_domain[2] = {NULL, NULL};

	if (vh->have_spf_pass)
		for (domain_prescreen *dps = vh->domain_head; dps; dps = dps->next)
			if (dps->spf == spf_pass)
			{
				if (dps->u.f.is_helo)
					spf_domain[0] = dps->name;
				if (dps->u.f.is_mfrom)
					spf_domain[1] = dps->name;
			}

	/*
	* The only authentication may happen to be BOFHSPFFROM, not written:
	* will get "Authentication-Results: authserv.id; none" in that case.
	*/
	if (spf_domain[0] || spf_domain[1])
	{
		fprintf(fp, ";\n  spf=pass smtp.%s=%s",
			spf_domain[1]? "mailfrom": "helo",
			spf_domain[1]? spf_domain[1]: spf_domain[0]);
		++auth_given;
	}

	if (vh->ndoms)
	{
		dkim_result_summary drs;
		memset(&drs, 0, sizeof drs);
		int d_auth = 0;

		domain_prescreen *print_dps = NULL;
		
		if (parm->z.report_all_sigs)
		{
			dkim_result_summary *pdrs = &drs;
			if (vh->domain_ptr && vh->ndoms)
			{
				for (int c = 0; c < vh->ndoms; ++c)
				{
					domain_prescreen *dps = vh->domain_ptr[c];
					for (int ndx = 0; ndx < dps->nsigs; ++ndx)
					{
						d_auth += print_signature_resinfo(fp, dps, ndx, pdrs, dkim);
						if (drs.id)
							pdrs = NULL; // keep the first id for logging
					}
				}
			}
			
			if (d_auth == 0)
			{
				fprintf(fp, ";\n  dkim=%s", drs.result = "none");
				d_auth = 1;
			}
		}
		else
		{
			for (int c = 0; c < vh->ndoms; ++c)
				if (vh->domain_ptr[c]->u.f.sig_is_ok)
				{
					print_dps = vh->domain_ptr[c];
					break;
				}

			if (print_dps == NULL)
			{
				print_dps = vh->domain_ptr[0];
				print_dps->first_good = 0;
			}

			d_auth = print_signature_resinfo(fp, print_dps,
				print_dps->first_good, &drs, dkim);
		}

		if (d_auth > 0 && parm->z.verbose >= 3)
		{
			fl_report(LOG_INFO,
				"id=%s: verified:%s dkim=%s (id=%s, %s%sstat=%d)%s%s rep=%d",
				parm->dyn.info.id,
				(spf_domain[0] || spf_domain[1])? " spf=pass,": "",
				drs.result,
				drs.id? drs.id: "-",
				drs.err? drs.err: "", drs.err? ", ": "",
				(int)status,
				vh->policy_type, vh->policy_result,
				vh->reputation_dps? vh->reputation_dps->reputation: 0);
			log_written += 1;
		}

		free(drs.id);
		if (!parm->z.report_all_sigs)
		{
			if (vh->whitelisted_dps && vh->whitelisted_dps != print_dps)
				d_auth += print_signature_resinfo(fp, vh->whitelisted_dps,
					vh->whitelisted_dps->first_good, NULL, dkim);
			if (vh->vbr_dps && vh->vbr_dps != print_dps &&
				vh->vbr_dps != vh->whitelisted_dps)
					d_auth += print_signature_resinfo(fp, vh->vbr_dps,
						vh->vbr_dps->first_good, NULL, dkim);
		}
		auth_given += d_auth;
	}

	if (*vh->policy_result)
	{
		char const *method;
		int printed = 0;

		if (POLICY_IS_DMARC(vh->policy))
		{
			method = "dmarc";
			if (vh->dkim_domain)
				printed = fprintf(fp, ";\n  dmarc=%s%s header.from=%s",
					vh->policy_result, vh->policy_comment, vh->dkim_domain);
		}
		else
		/*
		* RFC 5617 just says "contents of the From: header field,
		* with comments removed."
		*
		* Note: This method can say nxdomain, DMARC cannot.
		*/
		{
			method = "dkim-adsp";
#if HAVE_DKIM_GETUSER
			char const *const user = dkim_getuser(dkim);
			if (user && vh->dkim_domain)
				printed = fprintf(fp, ";\n  dkim-adsp=%s header.from=%s@%s",
					vh->policy_result, user, vh->dkim_domain);
#endif			
		}

		if (printed == 0)
			fprintf(fp, ";\n  %s=%s%s", method,
				vh->policy_result, vh->policy_comment);
		++auth_given;
		if (parm->z.verbose >= 4)
		{
			fl_report(LOG_INFO,
				"id=%s: policy:%s %s%s",
				parm->dyn.info.id, method, vh->policy_result, vh->policy_comment);
			log_written += 1;
		}
	}

	if (vh->reputation_dps)
	{
		domain_prescreen const *const dps = vh->reputation_dps;
		fprintf(fp, ";\n  x-dkim-rep=%s (%d from %s) header.d=%s",
			dps->reputation >= parm->z.reputation_fail? "fail":
			dps->reputation <= parm->z.reputation_pass? "pass": "neutral",
				dps->reputation, parm->z.reputation_root, dps->name);
		++auth_given;
	}

	if (vh->vbr_result.resp)
	{
		fprintf(fp,
			";\n  vbr=pass header.mv=%s header.md=%s (%s)",
			vh->vbr_result.mv, vh->vbr_result.vbr->md, vh->vbr_result.resp);
		++auth_given;
	}

	if (auth_given <= 0)
		fputs("; none", fp);
	fputc('\n', fp);

	if (log_written == 0 && parm->z.verbose >= 7)
	{
		fl_report(LOG_INFO,
			"id=%s: verified: %d auth method(s) written",
			parm->dyn.info.id,
			auth_given);
	}

	/*
	* now for the rest of the header, and body
	*/
	vh->step = 1;
	vh->dkim_or_file = fp;
	rewind(fl_get_file(parm->fl));
	int rtc = verify_headers(vh);
	if (rtc == 0 &&
		fputc('\n', fp) != EOF &&
		filecopy(fl_get_file(parm->fl), fp) == 0)
			return parm->dyn.rtc = 1;

	if (rtc == 0) // verify_headers logged any error already
		fl_report(LOG_CRIT,
			"id=%s: file I/O error: %s",
			parm->dyn.info.id, strerror(errno));
	return parm->dyn.rtc = -1;
}

static FILE*
save_file(dkimfl_parm *parm, char const *envelope_sender, char **fname_ptr)
// NULL = logged error, otherwise preheader written
{
	assert(parm);
	assert(parm->fl);
	assert(parm->z.save_drop);
	assert(parm->dyn.action_header);

	static const char templ[] = "/zdrop-";
	char const *const dir = parm->z.save_drop;
	char const *const name = parm->dyn.action_header;

	static const size_t name_len_min = 10, name_len_max = 80;
	size_t const dir_len = strlen(dir);
	size_t const name_len = strlen(name);
	size_t const namesize = dir_len + sizeof templ + 10 +
		(name_len > name_len_max? name_len_max: name_len);

	char *const fname = (char*)malloc(namesize);

	if (fname == NULL)
		return NULL;

	memcpy(fname, dir, dir_len);
	memcpy(fname + dir_len, templ, sizeof templ);

	char *p = fname + dir_len + sizeof templ - 1,
	// max space available for name; 6 for XXXXXX
		*const end = fname + namesize - 7;

	char const *s = name;
	size_t cp_name = 0;
	while (p < end)
	{
		int ch = *(unsigned char*)s++;
		if (ch == 0 ||
			isspace(ch) && cp_name > name_len_min)
				break;

		if (!isalnum(ch) && ch != '.' && ch != '-')
			ch = '_';
		*p++ = ch;
		++cp_name;
	}
	if (p < end)
		*p++ = '-';
	//         123456
	strcpy(p, "XXXXXX");
	assert(strlen(fname) < namesize);

	int fno = mkstemp(fname);
	if (fno == -1)
		fl_report(LOG_ERR, "mkstemp fails on %s: %s",
			fname, strerror(errno));
	else
	{
		FILE *fp = fdopen(fno, "w+");
		if (fp)
		{
			fprintf(fp, "%s\n", envelope_sender);

			fl_rcpt_enum *fre = fl_rcpt_start(parm->fl);
			if (fre)
			{
				char *rcpt;
				while ((rcpt = fl_rcpt_next(fre)) != NULL)
					fprintf(fp, "%s\n", rcpt);

				fl_rcpt_clear(fre);
				fputc('\n', fp); // empty line ends pre-header
				*fname_ptr = fname;
				return fp;
			}

			fclose(fp);
		}
		else
		{
			fl_report(LOG_ERR, "fdopen fails: %s", strerror(errno));
			close(fno);
		}

		unlink(fname);
	}

	free(fname);
	return NULL;
}

static void verify_message(dkimfl_parm *parm)
/*
* add/remove A-R records, set rtc 1 if ok, 2 if rejected, -1 if failed,
* leave rtc as-is (0) if there is no need to rewrite.
*/
{
	verify_parms vh;
	memset(&vh, 0, sizeof vh);
	vh.presult = DKIM_PRESULT_NONE;
	vh.policy = DKIM_POLICY_NONE;
	vh.do_adsp = parm->z.honor_author_domain != 0;
	vh.do_dmarc = parm->z.honor_dmarc != 0;

	DKIM_STAT status;
	DKIM *dkim = dkim_verify(parm->dklib, parm->dyn.info.id, NULL, &status);
	if (dkim == NULL || status != DKIM_STAT_OK)
	{
		char const *err = dkim? dkim_geterror(dkim): NULL;
		fl_report(LOG_CRIT,
			"id=%s: cannot init OpenDKIM: %s",
			parm->dyn.info.id, err? err: "NULL");
		parm->dyn.rtc = -1;
		clean_stats(parm);
		return;
	}

	vh.dkim_or_file = dkim;
	vh.parm = parm;
	verify_headers(&vh);

	if (parm->dyn.authserv_id == NULL || parm->dyn.rtc != 0)
	{
		clean_stats(parm);
		clean_vh(&vh);
		dkim_free(dkim);
		if (parm->dyn.rtc == 0)
			fl_report(LOG_ERR,
				"id=%s: missing Courier Received: ignoring message",
				parm->dyn.info.id);
		return;
	}

	if (dkim_minbody(dkim) > 0)
		copy_body(parm, dkim);

	status = dkim_eom(dkim, NULL);

	switch (status)
	{
		case DKIM_STAT_OK:
			// pass
			break;

		case DKIM_STAT_NOSIG:
			// none
			vh.dkim_domain = dkim_getdomain(dkim);

		case DKIM_STAT_BADSIG: // should be treated as NOSIG...
			break;

		case DKIM_STAT_NORESOURCE:
		case DKIM_STAT_INTERNAL:
		case DKIM_STAT_CBTRYAGAIN:
		case DKIM_STAT_KEYFAIL:
		{
#if HAVE_LIBOPENDKIM_2A1
			if (parm->z.verbose >= 3)
			{
				char const * err = dkim_geterror(dkim);
				if (err == NULL)
					err = dkim_getresultstr(status);
				fl_report(LOG_ERR,
					"id=%s: temporary verification failure: %s",
					parm->dyn.info.id, err? err: "NULL");
			}

			// temperror except for missing CNAME (which is permerror)
			parm->dyn.rtc = -1;
#else
			char const *err = dkim_geterror(dkim);
			if (err == NULL)
				err = dkim_getresultstr(status);
			if (parm->z.verbose >= 3)
			{
				fl_report(LOG_ERR,
					"id=%s: temporary verification failure: %s",
					parm->dyn.info.id, err? err: "NULL");
			}

			// temperror except for missing CNAME (which is permerror)
			if (status != DKIM_STAT_KEYFAIL || 
				err == NULL || strstr(err, "CNAME") == NULL)
					parm->dyn.rtc = -1;
#endif
			break;
		}

		case DKIM_STAT_SYNTAX:
		case DKIM_STAT_NOKEY:
		case DKIM_STAT_CANTVRFY:
		case DKIM_STAT_REVOKED:
		default:
		{
			// permerror
			if (parm->z.verbose >= 4)
			{
				char const *err = dkim_geterror(dkim);
				if (err == NULL)
					err = dkim_getresultstr(status);
				fl_report(LOG_ERR,
					"id=%s: permanent verification failure: %s",
					parm->dyn.info.id, err? err: "NULL");
			}
			break;
		}
	}

	/*
	* Policy results and whitelisting
	*/
	vh.policy_type = vh.policy_result = vh.policy_comment = "";
	if (vh.domain_flags == 0)
		domain_flags(&vh);

	/*
	* pass unauthenticated From: to database
	*/
	if (parm->dyn.rtc == 0 && vh.dkim_domain && parm->dyn.stats)
		if (parm->z.publicsuffix)
			parm->dyn.stats->scope = save_unauthenticated_dmarc;
		else if (parm->z.save_from_anyway)
			parm->dyn.stats->scope = save_unauthenticated_from;

	/*
	* DMARC/ADSP policy check
	*/
	if (parm->dyn.rtc == 0 && vh.dkim_domain != NULL)
	{
		if (vh.do_dmarc >= vh.do_adsp)
		{
			vh.presult = get_dmarc(vh.dkim_domain, vh.org_domain, &vh.dmarc);
			if (vh.presult == 0)
				vh.policy = vh.dmarc.effective_p;

			if (parm->z.verbose >= 7)
			{
				char *disp = vh.dkim_domain;
				if (vh.org_domain && strcmp(vh.dkim_domain, vh.org_domain) != 0)
				{
					size_t len = strlen(vh.dkim_domain), le = strlen(vh.org_domain);
					char *p = len > le? malloc(len + 3): NULL;
					if (p)
					{
						size_t diff = len - le;
						disp = p;
						*p++ = '[';
						memcpy(p, vh.dkim_domain, diff);
						p += diff;
						*p++ = ']';
						memcpy(p, vh.org_domain, le + 1);
					}
				}
				fl_report(LOG_INFO,
					"DMARC %sabled (%d), policy %s for %s",
						vh.do_dmarc > 0? "en": "dis", vh.do_dmarc,
						presult_explain(vh.presult), disp);
				if (disp != vh.dkim_domain)
					free(disp);
			}
		}

		if (vh.presult != 0 && vh.presult != 3 && vh.do_dmarc <= vh.do_adsp)
		{
			vh.presult = my_get_adsp(vh.dkim_domain, &vh.policy);

			if (parm->z.verbose >= 7)
				fl_report(LOG_INFO,
					"ADSP %sabled (%d), policy %s for %s",
						vh.do_adsp > 0? "en": "dis", vh.do_adsp,
						presult_explain(vh.presult), vh.dkim_domain);
		}

		if (vh.presult <= -2 &&
			(vh.do_dmarc > 0 || vh.do_adsp > 0 || parm->z.reject_on_nxdomain))
		{
			if (parm->z.verbose >= 3)
				fl_report(LOG_ERR,
					"id=%s: temporary author domain verification failure: %s",
					parm->dyn.info.id,
					vh.presult == -2? "DNS server": "garbled data");
			parm->dyn.rtc = -1;
		}
	}

	int from_sig_is_ok = 0, aligned_sig_is_ok = 0, aligned_spf_is_ok = 0;
	for (domain_prescreen *dps = vh.domain_head; dps; dps = dps->next)
	{
		if (dps->u.f.is_whitelisted &&
			(dps->u.f.sig_is_ok || dps->u.f.spf_pass) &&
			(vh.whitelisted_dps == NULL ||
				vh.whitelisted_dps->whitelisted < dps->whitelisted ||
				vh.whitelisted_dps->domain_val < dps->domain_val))
					vh.whitelisted_dps = dps;

		if (dps->u.f.vbr_is_trusted && 
			(dps->u.f.sig_is_ok || dps->u.f.spf_pass))
		{
			if (run_vbr_check(&vh, dps) == 0)
			{
				dps->u.f.vbr_is_ok = 1;
				dps->vbr_mv = mv2tv(vh.vbr_result.mv, vh.vbr_result.tv);
			}

			if (vh.vbr_dps == NULL || vh.vbr_dps->domain_val < dps->domain_val)
				vh.vbr_dps = dps;
		}

		if (dps->u.f.is_dnswl &&
			(vh.dnswl_dps == NULL ||
				vh.dnswl_dps->dnswl_value < dps->dnswl_value ||
				vh.dnswl_dps->domain_val < dps->domain_val))
					vh.dnswl_dps = dps;

		if (dps->u.f.is_reputed_signer &&
			(vh.reputation_dps == NULL ||
				vh.reputation_dps->reputation > dps->reputation ||
				vh.reputation_dps->domain_val < dps->domain_val))
					vh.reputation_dps = dps;

		if (dps->u.f.is_from)
		{
			from_sig_is_ok |= dps->u.f.sig_is_ok;
			if (POLICY_IS_DMARC(vh.policy) && vh.dmarc.found_at_org == 0)
				dps->u.f.is_dmarc = 1;

			if (vh.author_dps == NULL)
				vh.author_dps = dps;
		}
		else if (dps->u.f.is_org_domain &&
			POLICY_IS_DMARC(vh.policy) && vh.dmarc.found_at_org == 1)
				dps->u.f.is_dmarc = 1;

		if (dps->u.f.is_spf_from && !dps->u.f.is_from && parm->z.verbose >= 5)
			fl_report(LOG_INFO,
				"id=%s: different From: is it %s (OpenDKIM) or %s (Courier SPF)?",
				parm->dyn.info.id,
				vh.dkim_domain? vh.dkim_domain: "NULL",
				dps->name);
			
		if (dps->u.f.is_aligned)
		{
			aligned_sig_is_ok |=
				(dps->u.f.is_from || vh.dmarc.adkim != 's') && dps->u.f.sig_is_ok;

			// spf_pass on From: domain is not officially valid
			int aligned_spf = 
				(dps->u.f.is_from || vh.dmarc.aspf != 's') && dps->u.f.spf_pass;
			if (!(dps->u.f.is_mfrom || dps->u.f.is_helo))
				aligned_spf <<= 1;

			aligned_spf_is_ok |= aligned_spf;
		}

		if (dps->u.f.spf_pass)
			vh.have_spf_pass = 1;
	}
	int aligned_auth_is_ok = aligned_sig_is_ok | aligned_spf_is_ok;

	/*
	* Reputation wrapup:
	* Reputation is always assigned to the from domain, based on a signer
	*/
	if (parm->dyn.rtc == 0 && vh.reputation_dps && vh.author_dps)
	{
		vh.author_dps->u.f.is_reputed = 1;
		vh.author_dps->reputation = vh.reputation_dps->reputation;
	}

	/*
	* Apply policy if it implies to reject or drop message
	*/
	if (parm->dyn.rtc == 0)
	{
		if (vh.dkim_domain != NULL && vh.presult >= 0)
		{
			/*
			* http://tools.ietf.org/html/draft-kucherawy-dmarc-base-13#section-6.3
			*
			* quarantine:  The Domain Owner wishes to have email that fails the
			*    DMARC mechanism check to be treated by Mail Receivers as
			*    suspicious.  Depending on the capabilities of the Mail
			*    Receiver, this can mean "place into spam folder", "scrutinize
			*    with additional intensity", and/or "flag as suspicious".
			*
			* Here, we assume that quarantine is going to be honored downstream,
			* based on A-R, if do_dmarc is set.
			*
			* If NXDOMAIN, pretend to have a strict ADSP policy, so as to enable
			* adsp-nxdomain.
			*/

			if (vh.presult == 3)
				vh.policy = ADSP_POLICY_ALL;

			bool policy_fail = POLICY_IS_STRICT(vh.policy) &&
				(POLICY_IS_DMARC(vh.policy) && aligned_auth_is_ok == 0 ||
				POLICY_IS_ADSP(vh.policy) && from_sig_is_ok == 0);

			if (parm->dyn.stats)
			{
				if (vh.presult == 3)
				{
					parm->dyn.stats->nxdomain = 1;
				}
				else if (POLICY_IS_DMARC(vh.policy))
				{
					if (vh.dmarc.rua)
					{
						uint32_t ri =
							adjust_ri(vh.dmarc.ri, parm->z.honored_report_interval);
						if (vh.dmarc.ri != 0 &&
							ri != vh.dmarc.ri && parm->z.verbose >= 5)
						{
							domain_prescreen *dps = vh.domain_head;
							for (; dps && dps->u.f.is_dmarc == 0; dps = dps->next)
								continue;
							fl_report(LOG_INFO,
								"ri of %s adjusted from %u to %u "
								"(honored_report_interval = %d)",
									dps? dps->name: "unknown domain", vh.dmarc.ri, ri,
									parm->z.honored_report_interval);
						}
						parm->dyn.stats->dmarc_ri = ri;
						parm->dyn.stats->original_ri = vh.dmarc.ri;
						char *bad = NULL,
							*rua = vh.dmarc.rua? adjust_rua(&vh.dmarc.rua, &bad): NULL;
						if (bad && parm->z.verbose >= 5)
						{
							domain_prescreen *dps = vh.domain_head;
							for (; dps && dps->u.f.is_dmarc == 0; dps = dps->next)
								continue;
							fl_report(LOG_INFO,
								"rua URI of %s not supported: %s (supported: %s)",
									dps? dps->name: "unknown domain", bad,
									rua? rua: "none");
						}
						free(bad);
						parm->dyn.stats->dmarc_rua = rua;
					}
					parm->dyn.stats->dmarc_record = write_dmarc_rec(&vh.dmarc);

					parm->dyn.stats->dmarc_found = vh.presult == 0;
					parm->dyn.stats->dmarc_subdomain = vh.dmarc.found_at_org != 0;
					parm->dyn.stats->dmarc_dkim = aligned_sig_is_ok;
					parm->dyn.stats->dmarc_spf = aligned_spf_is_ok & 1;
					parm->dyn.stats->dkim_any = vh.ndoms > 0;
					parm->dyn.stats->spf_any = vh.received_spf > 0;

					// default values:
					assert(parm->dyn.stats->dmarc_reason == dmarc_reason_none);
					assert(parm->dyn.stats->dmarc_dispo == 0);
				}
				else
				{
					parm->dyn.stats->adsp_any = 1;
					parm->dyn.stats->adsp_found = vh.presult == 0;
					parm->dyn.stats->adsp_unknown = vh.policy == ADSP_POLICY_UNKNOWN;
					parm->dyn.stats->adsp_all = vh.policy == ADSP_POLICY_ALL;
					parm->dyn.stats->adsp_discardable =
						vh.policy == ADSP_POLICY_DISCARDABLE;
					parm->dyn.stats->adsp_fail = policy_fail;
				}
			}

			/*
			* unless disabled by parameter or whitelisted, do action:
			* reject if dkim_domain is not valid, ADSP == all, or DMARC == reject,
			* discard if ADSP == discardable;
			*/
			if (policy_fail)
			{
				bool deliver_message = 0;

				if (POLICY_IS_DMARC(vh.policy) && vh.dmarc.pct != 100 &&
					random() % 100 >= vh.dmarc.pct)
				{
					deliver_message = true;
					if (parm->dyn.stats)
						parm->dyn.stats->dmarc_reason = dmarc_reason_sampled_out;
					if (parm->z.verbose >= 7)
						fl_report(LOG_INFO,
							"id=%s: %s dmarc=fail, but toss >= %d%%",
							parm->dyn.info.id, vh.dkim_domain, vh.dmarc.pct);
				}
				else if ((POLICY_IS_DMARC(vh.policy) && vh.do_dmarc > 0) ||
					(POLICY_IS_ADSP(vh.policy) && vh.do_adsp > 0) ||
					(parm->z.reject_on_nxdomain && vh.presult == 3))
				{
					char const *log_reason, *smtp_reason = NULL;
				
					if (vh.presult == 3)
					{
						log_reason = "invalid domain";
						smtp_reason = "550 Invalid author domain\n";
					}
					else if (vh.policy == ADSP_POLICY_ALL)
					{
						log_reason = "adsp=all policy for";
						smtp_reason = "550 DKIM signature required by ADSP\n";
					}
					else if (vh.policy == DMARC_POLICY_REJECT)
					{
						log_reason = "dmarc=reject policy for";
						smtp_reason = "550 Reject after DMARC policy.\n";
					}
					else if (vh.policy == DMARC_POLICY_QUARANTINE)
					{
						log_reason = "dmarc=quarantine policy for";
						vh.policy_comment = " (QUARANTINE)";
						deliver_message = 1;
						if (parm->dyn.stats)
							parm->dyn.stats->dmarc_dispo = 1;
					}
					else if (vh.policy == ADSP_POLICY_DISCARDABLE)
						log_reason = "adsp=discardable policy:";
					else
					{
						log_reason = "INTERNAL ERROR!";
						fl_report(LOG_CRIT,
							"%s: policy=%d, presult=%d, do_dmarc=%d, do_adsp=%d",
							log_reason,
							vh.policy, vh.presult, vh.do_dmarc, vh.do_adsp);
						deliver_message = true;
					}

					if (parm->z.verbose >= 3)
					{
						if (vh.whitelisted_dps)
							fl_report(LOG_INFO,
								"id=%s: %s %s, but %s is whitelisted (auth: %s)",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain,
								vh.whitelisted_dps->name,
								vh.whitelisted_dps->u.f.sig_is_ok? "DKIM": "SPF");
						else if (vh.vbr_dps)
							fl_report(LOG_INFO,
								"id=%s: %s %s, but %s is VBR vouched by %s (auth: %s)",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain,
								vh.vbr_result.vbr->md,
								vh.vbr_result.mv,
								vh.vbr_dps->u.f.sig_is_ok? "DKIM": "SPF");
						else if (vh.dnswl_count > 0)
							fl_report(LOG_INFO,
								"id=%s: %s %s, but I found %d DNSWL record(s) --%s",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain,
								vh.dnswl_count,
								vh.dnswl_dps?
									vh.dnswl_dps->name: "no domain name, though");
						else if (vh.author_dps && vh.author_dps->u.f.is_reputed)
							fl_report(LOG_INFO,
								"id=%s: %s %s, even if %s is in %s (%d)",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain,
								vh.author_dps->name,
								parm->z.reputation_root,
								vh.author_dps->reputation);
						else
							fl_report(LOG_INFO,
								"id=%s: %s %s, no VBR and no whitelist",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain);
					}

					if (vh.vbr_dps || vh.whitelisted_dps || vh.dnswl_count > 0)
					{
						deliver_message = true;
						if (POLICY_IS_DMARC(vh.policy) && parm->dyn.stats)
							parm->dyn.stats->dmarc_reason =
								dmarc_reason_trusted_forwarder;
					}

					if (!deliver_message)
					{
						if (smtp_reason) //reject
						{
							fl_pass_message(parm->fl, smtp_reason);
							if (parm->dyn.stats)
							{
								parm->dyn.stats->reject = 1;
								parm->dyn.stats->dmarc_dispo = 2;
							}
						}
						else // drop, and stop filtering
						{
							fl_pass_message(parm->fl, "050 Message dropped.\n");
							fl_drop_message(parm->fl, "adsp=discard");
							if (parm->dyn.stats)
								parm->dyn.stats->drop = 1;
						}

						parm->dyn.rtc = 2;
					}
				}
				else if (parm->dyn.stats)
					parm->dyn.stats->dmarc_reason = dmarc_reason_local_policy;
			}
			else if (POLICY_IS_DMARC(vh.policy) &&
				aligned_sig_is_ok == 0 && aligned_spf_is_ok == 2)
			// policy did not fail only because of BOFHSPFFROM
			{
				if (parm->z.verbose >= 3)
					fl_report(LOG_INFO,
						"id=%s: %s pass only because BOFHSPFFROM",
						parm->dyn.info.id, vh.dkim_domain);
				if (parm->dyn.stats)
					parm->dyn.stats->dmarc_reason = dmarc_reason_other;
			}
		}
	}

	/*
	* Header action and possible reject/drop
	*/
	if (parm->dyn.action_header)
	{
		assert(parm->z.action_header);

		int good = 0;

		if (vh.whitelisted_dps &&
			vh.whitelisted_dps->whitelisted >= parm->z.whitelisted_pass)
		{
			good = 1;
			if (parm->z.verbose >= 3)
				fl_report(LOG_INFO,
					"id=%s: %s: %s, but %s is whitelisted (%d)",
					parm->dyn.info.id,
					parm->z.action_header,
					parm->dyn.action_header,
					vh.whitelisted_dps->name,
					vh.whitelisted_dps->whitelisted);
		}
		else if (vh.vbr_dps)
		{
			good = 1;
			if (parm->z.verbose >= 3)
				fl_report(LOG_INFO,
					"id=%s: %s: %s, but %s is vouched (%s)",
					parm->dyn.info.id,
					parm->z.action_header,
					parm->dyn.action_header,
					vh.vbr_dps->name,
					vh.vbr_dps->vbr_mv);
		}
		else if (vh.dnswl_dps &&
			vh.dnswl_dps->dnswl_value >= (uint8_t)parm->z.dnswl_worthiness_pass)
		{
			good = 1;
			if (parm->z.verbose >= 3)
				fl_report(LOG_INFO,
					"id=%s: %s: %s, but %s is in dnswl (%u)",
					parm->dyn.info.id,
					parm->z.action_header,
					parm->dyn.action_header,
					vh.dnswl_dps->name,
					vh.dnswl_dps->dnswl_value);
		}
		else if (vh.author_dps && vh.author_dps->u.f.is_reputed &&
			vh.author_dps->reputation <= parm->z.reputation_pass)
		{
			good = 1;
			if (parm->z.verbose >= 3)
				fl_report(LOG_INFO,
					"id=%s: %s: %s, but %s is in %s (%d)",
					parm->dyn.info.id,
					parm->z.action_header,
					parm->dyn.action_header,
					vh.author_dps->name,
					parm->z.reputation_root,
					vh.author_dps->reputation);
		}

		if (good == 0)
		{
			if (parm->z.header_action_is_reject)
			{
				static const char templ[] = "550 %s.\n";
				char *smtp_reason =
					malloc(strlen(parm->z.action_header) + sizeof templ);
				if (smtp_reason == NULL)
					parm->dyn.rtc = -1;
				else
				{
					sprintf(smtp_reason, templ, parm->z.action_header);
					fl_pass_message(parm->fl, smtp_reason);
					fl_free_on_exit(parm->fl, smtp_reason);
					if (parm->dyn.stats)
						parm->dyn.stats->reject = 1;

					if (parm->z.verbose >= 3)
						fl_report(LOG_INFO,
							"id=%s: 550 %s (was: %s)",
							parm->dyn.info.id,
							parm->z.action_header,
							parm->dyn.action_header);

					parm->dyn.rtc = 2;
				}
			}
			else // drop, and stop filtering
			{
				int droperr = 0;
				if (parm->z.save_drop)
				{
					char *envelope_sender = fl_get_sender(parm->fl), *fname = NULL;
					FILE *fp = save_file(parm, envelope_sender, &fname);
					droperr = 1;
					if (fp)
					{
						if (write_file(&vh, fp, status) >= 0)
							droperr = ferror(fp);

						droperr |= fclose(fp);
						if (droperr == 0 && parm->z.verbose >= 4 && fname)
							fl_report(LOG_INFO,
								"dropped message saved in %s", my_basename(fname));
					}

					if (parm->dyn.rtc >= 0)
					{
						if (droperr)
						{
							fl_report(LOG_ERR, "error on %s: %s",
								fname? fname: "drop file", strerror(errno));
							parm->dyn.rtc = -1;
						}
					}

					if (parm->dyn.stats)
						parm->dyn.stats->envelope_sender = envelope_sender;
					else
						free(envelope_sender);
					free(fname);
				}

				if (parm->dyn.rtc >= 0)
				{
					parm->dyn.rtc = 2;
					fl_pass_message(parm->fl, "050 Message dropped.\n");
					fl_drop_message(parm->fl, parm->z.action_header);
					if (parm->dyn.stats)
						parm->dyn.stats->drop = 1;
				}
			}
		}
	}

	/*
	* prepare DMARC/ADSP results
	*/
	if (parm->dyn.rtc == 0)
	{
		if (vh.presult == 3)
		{
			if (POLICY_IS_ADSP(vh.policy))
			{
				vh.policy_type = " adsp=";
				vh.policy_result = "nxdomain";
			}
			else
				vh.policy_type = " policy=nxdomain";
		}
		else if (POLICY_IS_DMARC(vh.policy))
		{
			if (vh.policy != DMARC_POLICY_NONE)
			{
				vh.policy_result = aligned_auth_is_ok? "pass": "fail";
				if (vh.policy == DMARC_POLICY_QUARANTINE)
				{
					vh.policy_type = " dmarc:quarantine=";
				}
				else // if (vh.policy == DMARC_POLICY_REJECT)
				{
					vh.policy_type = " dmarc:reject=";
				}
			}
		}
		else if (vh.policy == ADSP_POLICY_ALL)
		{
			vh.policy_type = " adsp:all=";
			vh.policy_result = from_sig_is_ok? "pass": "fail";
		}
		else if (vh.policy == ADSP_POLICY_DISCARDABLE)
		{
			vh.policy_type = " adsp:discardable=";
			vh.policy_result = from_sig_is_ok? "pass": "discard";
		}
	}

	/*
	* write the A-R field if required anyway, spf, or signatures
	*/
	if (parm->dyn.rtc == 0 &&
		(parm->z.add_a_r_anyway || vh.ndoms
			|| vh.have_spf_pass || *vh.policy_result))
	{
		FILE *fp = fl_get_write_file(parm->fl);
		if (fp == NULL)
		{
			parm->dyn.rtc = -1;
			clean_stats(parm);
			clean_vh(&vh);
			dkim_free(dkim);
			return;
		}
		write_file(&vh, fp, status);
	}

	if (parm->dyn.rtc < 0)
		clean_stats(parm);
	else if (parm->dyn.stats)
	{
		if (parm->dyn.stats->envelope_sender == NULL)
			parm->dyn.stats->envelope_sender = fl_get_sender(parm->fl);

		parm->dyn.stats->domain_head = vh.domain_head;
		vh.domain_head = NULL;

		parm->dyn.stats->vbr_result_resp = vh.vbr_result.resp;
		vh.vbr_result.resp = NULL;
	}
	clean_vh(&vh);
	dkim_free(dkim);
}

// after filter functions

static int update_blocked_user_list(dkimfl_parm *parm)
/*
* (Re)load list from disk (also run in parent).
* return -1 on error, +1 on update, 0 otherwise;
*/
{
	char const *const fname = parm->z.blocked_user_list;
	int updated = 0, rtc = -1;
	if (fname)
	{
		char const *failed_action = NULL;
		struct stat st;

		if (stat(fname, &st))
		{
			if (errno == ENOENT) // no file, no blocked users
			{
				updated = rtc = parm->blocklist.data ||
					parm->blocklist.size ||
					parm->blocklist.mtime;
				free(parm->blocklist.data);
				parm->blocklist.data = NULL;
				parm->blocklist.size = 0;
				parm->blocklist.mtime = 0;
			}
			else
				failed_action = "stat";
		}
		else if (st.st_mtime != parm->blocklist.mtime ||
			(size_t)st.st_size != parm->blocklist.size)
		{
			if (st.st_size == 0)
			{
				free(parm->blocklist.data);
				parm->blocklist.data = NULL;
				parm->blocklist.size = 0;
				parm->blocklist.mtime = st.st_mtime;
				updated = rtc = 1;
			}
			else if ((uint64_t)st.st_size >= SIZE_MAX)
			{
				fl_report(LOG_ALERT, "file %s: size %ldu too large: max = %lu\n",
					fname, st.st_size, SIZE_MAX);
			}
			else
			{
				char *data = malloc(st.st_size + 1);
				if (data == NULL)
					failed_action = "malloc";
				else
				{
					FILE *fp = fopen(fname, "r");
					if (fp == NULL)
						failed_action = "fopen";
					else
					{
						size_t in = fread(data, 1, st.st_size, fp);
						if ((ferror(fp) | fclose(fp)) != 0)
							failed_action = "fread";
						else if (in != (size_t)st.st_size)
						{
							if (parm->z.verbose >= 2)
								fl_report(LOG_NOTICE,
									"race condition reading %s (size from %zu to %zu)",
									fname, st.st_size, in);
						}
						else
						{
							free(parm->blocklist.data);
							data[in] = 0;
							parm->blocklist.data = data;
							parm->blocklist.size = st.st_size;
							parm->blocklist.mtime = st.st_mtime;
							updated = rtc = 1;
						}
					}
				}
			}
		}
		else rtc = 0;

		if (failed_action)
			fl_report(LOG_ALERT, "cannot %s %s: %s",
				failed_action, fname, strerror(errno));
		else if (updated && parm->z.verbose >= 2 || parm->z.verbose >= 8)
		{
			struct tm tm;
			localtime_r(&parm->blocklist.mtime, &tm);
			fl_report(updated? LOG_INFO: LOG_DEBUG,
				"%s %s version of %04d-%02d-%02dT%02d:%02d:%02d (%zu bytes) on %s",
				fname,
				updated? "updated to": "still at",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec,
				parm->blocklist.size,
				fl_whence_string(parm->fl));
		}
	}

	return rtc;
}

static void block_user(dkimfl_parm *parm, char *reason)
{
	assert(parm);
	assert(reason);
	assert(!parm->user_blocked);
	assert(parm->dyn.info.authsender);

	time_t now = time(0); // approx. query time, for list entry

	/*
	* check there is an on-disk copy of blocked_user_list,
	* refresh the in-memory copy of the list, and
	* ensure the user is still not blocked,
	*/
	char const *const fname = parm->z.blocked_user_list;
	int rtc;
	if (fname == NULL ||
		(rtc = update_blocked_user_list(parm)) < 0 ||
		rtc > 0 && search_list(&parm->blocklist, parm->dyn.info.authsender) != 0)
			return;

	/*
	* write to disk a temp copy of the list,
	* add the user to it, and
	* move it back to blocked_user_list.
	*/
	char const *failed_action = NULL;
	int failed_errno = 0;
	size_t l = strlen(fname);
	char *fname_tmp = malloc(l + 20);
	if (fname_tmp)
	{
		memcpy(fname_tmp, fname, l);
		fname_tmp[l] = 0;
		strcat(&fname_tmp[l], ".XXXXXX");
		int fd = mkstemp(fname_tmp);
		if (fd >= 0)
		{
			FILE *fp = fdopen(fd, "w");
			if (fp)
			{
				if (parm->blocklist.data &&
					fwrite(parm->blocklist.data, parm->blocklist.size, 1, fp) != 1)
				{
					failed_action = "fwrite";
					failed_errno = errno;
				}
				else
				{
					char *t = strchr(reason, '\n');
					if (t)
						*t = 0;
					struct tm tm;
					localtime_r(&now, &tm);
					fprintf(fp, "%s on %04d-%02d-%02dT%02d:%02d:%02d %s\n",
						parm->dyn.info.authsender,
						tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
						tm.tm_hour, tm.tm_min, tm.tm_sec,
						reason);						
				}
				if ((ferror(fp) | fclose(fp)) && failed_action == NULL)
				{
					failed_action = "fprintf";
					failed_errno = errno;
				}

				if (failed_action == NULL)
				{
					if (rename(fname_tmp, fname) == 0)
					{
						// make this noticeable anyway
						if (parm->z.verbose >= 1)
							fl_report(LOG_CRIT, "id=%s: user %s added to %s: %s",
								parm->dyn.info.id,
								parm->dyn.info.authsender,
								fname,
								reason);
					}
					else
					{
						failed_action = "rename";
						failed_errno = errno;
					}
				}
			}
			else
			{
				failed_action = "fdopen";
				failed_errno = errno;
			}
		}
		else
		{
			failed_action = "mkstemp";
			failed_errno = errno;
		}
		free(fname_tmp);
	}
	else
	{
		failed_action = "malloc";
		if ((failed_errno = errno) == 0)
			failed_errno = ENOMEM;
	}

	if (failed_action)
		fl_report(LOG_CRIT, "cannot %s %s: %s",
			failed_action, fname, strerror(failed_errno));
}

static inline dkimfl_parm *get_parm(fl_parm *fl)
{
	assert(fl);
	dkimfl_parm **parm = (dkimfl_parm**)fl_get_parm(fl);
	assert(parm && *parm);
	return *parm;
}

static void after_filter_stats(fl_parm *fl)
{
	dkimfl_parm *parm = get_parm(fl);

	if (parm && parm->dwa && parm->dyn.stats)
	{
		if (check_db_connected(parm) == 0)
		{
			parm->dyn.stats->pst = parm->pst;
			db_set_stats_info(parm->dwa, parm->dyn.stats);
			if (parm->dyn.stats->outgoing && !parm->user_blocked)
			{
				char *block = db_check_user(parm->dwa);
				/*
				* If block is not null and not zero, write block
				*/
				if (block)
				{
					char *p = block, *t = NULL;
					while (isspace(*(unsigned char*)p))
						++p;
					long l = strtol(p, &t, 0);
					if (l || t == p && *p)
						block_user(parm, p);
					free(block);
				}
			}
		}
		some_dwa_cleanup(parm);
	}
	clean_stats(parm);
}

static inline void enable_dwa(dkimfl_parm *parm)
{
	if (parm->dwa &&
		(parm->dyn.stats = malloc(sizeof *parm->dyn.stats)) != NULL)
	{
		memset(parm->dyn.stats, 0, sizeof *parm->dyn.stats);
		parm->dyn.stats->ino_mtime_pid = parm->dyn.info.id;
	}
}

static void dkimfilter(fl_parm *fl)
{
	static char default_jobid[] = "NULL";
	dkimfl_parm *parm = get_parm(fl);
	parm->fl = fl;

	fl_get_msg_info(fl, &parm->dyn.info);
	if (parm->dyn.info.id == NULL)
		parm->dyn.info.id = default_jobid;

	if (parm->dyn.info.is_relayclient)
	{
		if (parm->split != split_verify_only &&
			parm->dyn.info.authsender)
		{
			if (parm->use_dwa_after_sign)
				enable_dwa(parm);
			sign_message(parm);
		}
	}
	else if (parm->split != split_sign_only)
	{
		if (vb_init(&parm->dyn.vb))
			parm->dyn.rtc = -1;
		else
		{
			if (parm->use_dwa_verifying)
				enable_dwa(parm);
			verify_message(parm);
		}
	}
	vb_clean(&parm->dyn.vb);

	static char const resp_tempfail[] =
		"432 Mail filter temporarily unavailable.\n";
	int verbose_threshold = 4;
	switch (parm->dyn.rtc)
	{
		case -1: // unrecoverable error
			if (parm->z.tempfail_on_error)
			{
				fl_pass_message(fl, resp_tempfail);
				verbose_threshold = 3;
			}
			else
				fl_pass_message(fl, "250 Failed.\n");

			clean_stats(parm);
			break;

		case 0: // not rewritten
			fl_pass_message(fl, "250 not filtered.\n");
			break;

		case 1: // rewritten
			fl_pass_message(fl, "250 Ok.\n");
			break;

		case 2:
			// rejected, message already given to fl_pass_message, or dropped;
			// available info already logged if verbose >= 3
			break;

		default:
			assert(0);
			break;
	}

	if (parm->dyn.stats)
		fl_set_after_filter(parm->fl, after_filter_stats);
	else if (parm->dwa)
		some_dwa_cleanup(parm);

	assert(fl_get_passed_message(fl) != NULL);

	if (parm->z.verbose >= verbose_threshold)
	{
		char const *msg = fl_get_passed_message(fl);
		int l = strlen(msg) - 1;
		assert(l > 0 && msg[l] == '\n');
		fl_report(LOG_INFO,
			"id=%s: response: %.*s", parm->dyn.info.id, l, msg);
	}

	if (parm->dyn.info.id == default_jobid)
		parm->dyn.info.id = NULL;
}

/*
* print parm
*/
static void report_config(fl_parm *fl)
{
	dkimfl_parm *parm = get_parm(fl);

	void *parm_target[PARM_TARGET_SIZE];
	parm_target[parm_t_id] = &parm->z;
	parm_target[db_parm_t_id] = db_parm_addr(parm->dwa);	

	print_parm(parm_target);
}

/*
* faked DNS lookups by libopendkim, test2 function
* (for gdb debugging: use --batch-run and then exit+)
*/
static void set_keyfile(fl_parm *fl)
{
	assert(fl);
	
	dkim_query_t qtype = DKIM_QUERY_FILE;
	dkimfl_parm *parm = get_parm(fl);
	static char keyfile[] = "KEYFILE";
	
	assert(parm);

	int nok = dkim_options(parm->dklib, DKIM_OP_SETOPT,
			DKIM_OPTS_QUERYMETHOD, &qtype, sizeof qtype) |
		dkim_options(parm->dklib, DKIM_OP_SETOPT,
			DKIM_OPTS_QUERYINFO, keyfile, strlen(keyfile));
	
	set_adsp_query_faked('k');

	if (nok || parm->z.verbose >= 8)
		fl_report(nok? LOG_ERR: LOG_INFO,
			"DKIM query method%s set to file \"%s\"",
			nok? " not": "", keyfile);
}

/*
* test3 can be used to set an invalid domain
* in case no policyfile is found, or the policy specified therein.
*/
static void set_policyfile(fl_parm *fl)
{
	set_adsp_query_faked('p');
	(void)fl;
}

/*
* faked VBRFILE and REPFILE test4
*/
static void set_vbrfile(fl_parm *fl)
{
	flip_vbr_query_was_faked();
	flip_reputation_query_was_faked();
	(void)fl;
}

static const char pid_dir[] = ZDKIMFILTER_PID_DIR;

static int pid_file_name(dkimfl_parm *parm, char *fname)
{
	assert(parm && parm->prog_name);
	if (strlen(parm->prog_name) + sizeof pid_dir + 5 >= PATH_MAX)
	{
		errno = ENAMETOOLONG;
		return 1;
	}

	strcpy(fname, pid_dir);
	fname[sizeof pid_dir - 1] = '/';
	strcat(strcpy(fname + sizeof pid_dir, parm->prog_name), ".pid");
	return 0;
}

static void write_pid_file_and_check_split_and_init_pst(fl_parm *fl)
// this is init_complete, called once before fl_main loop
{
	assert(fl);
	dkimfl_parm *parm = get_parm(fl);
	assert(parm);

	// random is used for DMARC pct=
	srandom((unsigned int)time(NULL));

	char const *failed_action = NULL;
	char pid_file[PATH_MAX];
	if (pid_file_name(parm, pid_file))
		failed_action = "name";
	else
	{
		FILE *fp = fopen(pid_file, "w");
		if (fp)
		{
			fprintf(fp, "%lu\n", (unsigned long) getpid());
			if ((ferror(fp) | fclose(fp)) != 0)
				failed_action = "write";
			parm->pid_created = 1;
		}
		else
			failed_action = "open";
	}
	if (failed_action)
		fl_report(LOG_ALERT, "cannot %s %s/%s.pid: %s",
			failed_action, pid_dir, parm->prog_name, strerror(errno));

	check_split(parm);
	if (parm->split != split_sign_only && parm->z.publicsuffix)
		parm->pst = publicsuffix_init(parm->z.publicsuffix, NULL);
}

static void delete_pid_file(dkimfl_parm *parm)
{
	if (parm->pid_created)
	{
		char pid_file[PATH_MAX];
		if (pid_file_name(parm, pid_file) != 0 ||
			unlink(pid_file) != 0)
				fprintf(stderr, "ERR: avfilter: cannot delete %s/%s.pid: %s\n",
					pid_dir, parm->prog_name, strerror(errno));
	}
}

static void check_blocked_user_list(fl_parm *fl)
/*
* this gets called once on init and thereafter on every message
*/
{
	assert(fl);
	dkimfl_parm *parm = get_parm(fl);
	assert(parm);

	parm->fl = fl;
	update_blocked_user_list(parm);
}

static int init_dkim(dkimfl_parm *parm)
{
	parm->dklib = dkim_init(NULL, NULL);
	if (parm->dklib == NULL)
	{
		fl_report(LOG_ERR, "dkim_init fault");
		return 1;
	}

	int nok = 0;
	if (!parm->z.no_signlen || !parm->z.report_all_sigs)
	{
		unsigned int options = 0;
		nok |= dkim_options(parm->dklib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
			&options, sizeof options) != DKIM_STAT_OK;
		if (!parm->z.no_signlen)
			options |= DKIM_LIBFLAGS_SIGNLEN;
		if (!parm->z.report_all_sigs)
			options |= DKIM_LIBFLAGS_VERIFYONE;
		if (parm->z.add_ztags)
			options |= DKIM_LIBFLAGS_ZTAGS;
		nok |= dkim_options(parm->dklib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
			&options, sizeof options) != DKIM_STAT_OK;
	}
	
	if (parm->z.dns_timeout > 0) // DEFTIMEOUT is 10 secs
	{
		nok |= dkim_options(parm->dklib, DKIM_OP_SETOPT, DKIM_OPTS_TIMEOUT,
			&parm->z.dns_timeout, sizeof parm->z.dns_timeout) != DKIM_STAT_OK;
	}
	
	if (parm->z.tmp)
	{
		nok |= dkim_options(parm->dklib, DKIM_OP_SETOPT, DKIM_OPTS_TMPDIR,
			parm->z.tmp, sizeof parm->z.tmp) != DKIM_STAT_OK;
	}

	if (parm->z.min_key_bits)
	{
		nok |= dkim_options(parm->dklib, DKIM_OP_SETOPT, DKIM_OPTS_MINKEYBITS,
			&parm->z.min_key_bits, sizeof parm->z.min_key_bits) != DKIM_STAT_OK;
	}

	nok |= dkim_set_prescreen(parm->dklib, dkim_sig_sort) != DKIM_STAT_OK;
	nok |= dkim_set_final(parm->dklib, dkim_sig_final) != DKIM_STAT_OK;
	nok |= dkim_options(parm->dklib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
		parm->z.sign_hfields?
			cast_const_u_char_parm_array(parm->z.sign_hfields):
			dkim_should_signhdrs,
				sizeof parm->z.sign_hfields) != DKIM_STAT_OK;

	nok |= dkim_options(parm->dklib, DKIM_OP_SETOPT, DKIM_OPTS_SKIPHDRS,
		parm->z.skip_hfields?
			cast_const_u_char_parm_array(parm->z.skip_hfields):
			dkim_should_not_signhdrs,
				sizeof parm->z.skip_hfields) != DKIM_STAT_OK;

	if (nok)
	{
		fl_report(LOG_ERR, "Unable to set lib options");
		dkim_close(parm->dklib);
		parm->dklib = NULL;
		return 1;
	}

	return 0;
}

#if HAVE_OPENDBX
#define DEFAULT_NO_DB 0
#else
#define DEFAULT_NO_DB 1
#endif

static void reload_config(fl_parm *fl)
/*
* on sighup, assume installed filter --no arguments.
* config_fname is retained for testing, though.
*/
{
	assert(fl);
	dkimfl_parm **parm = (dkimfl_parm**)fl_get_parm(fl);
	assert(parm && *parm);

	int rtc = 1;
	dkimfl_parm *new_parm = calloc(1, sizeof *new_parm);
	if (new_parm == NULL)
		fl_report(LOG_ERR, "MEMORY FAULT");
	else if (parm_config(new_parm, (*parm)->config_fname, DEFAULT_NO_DB))
		fl_report(LOG_ERR, "Unable to read new config file");
	else if (init_dkim(new_parm) == 0)
	{
		rtc = 0;
		new_parm->pid_created = (*parm)->pid_created;
		if (new_parm->z.verbose >= 2)
			fl_report(LOG_INFO,
				"New config file read from %s", (*parm)->config_fname);
		new_parm->prog_name = (*parm)->prog_name;
		check_split(new_parm);
		if (new_parm->z.publicsuffix && new_parm->split != split_sign_only)
		{
			new_parm->pst =
				publicsuffix_init(new_parm->z.publicsuffix, (*parm)->pst);
			(*parm)->pst = NULL;
		}
	}

	if (rtc)
	{
		some_cleanup(new_parm);
		free(new_parm);
	}
	else
	{
		dkimfl_parm *old_parm = *parm;
		if (old_parm->dklib)
			dkim_close(old_parm->dklib);
		some_cleanup(old_parm);
		free(old_parm);

		*parm = new_parm;
	}
}

static fl_init_parm functions =
{
	dkimfilter,
	write_pid_file_and_check_split_and_init_pst,
	check_blocked_user_list,
	reload_config, NULL, NULL,
	report_config, set_keyfile, set_policyfile, set_vbrfile
};

int main(int argc, char *argv[])
{
	int rtc = 0, i, no_db = DEFAULT_NO_DB;
	char *config_file = NULL;

	for (i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		
		if (strcmp(arg, "-f") == 0)
		{
			config_file = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "--no-db") == 0)
		{
			no_db = 1;
		}
		else if (strcmp(arg, "--version") == 0)
		{
			printf(PACKAGE_NAME ", version " PACKAGE_VERSION "\n"
				"Compiled with"
#if defined NDEBUG
				"out"
#endif
				" debugging support\n"
				"Compiled with OpenDKIM library version: %#lX\n"
#if HAVE_DKIM_LIBVERSION
				"Linked with OpenDKIM library version: %#lX (%smatch)\n"
#endif
				"Reported SSL/TLS version: %#lX\n",
				(long)(OPENDKIM_LIB_VERSION),
#if HAVE_DKIM_LIBVERSION
				(unsigned long)dkim_libversion(),
				(unsigned long)dkim_libversion() ==
					(unsigned long)(OPENDKIM_LIB_VERSION)? "": "DO NOT ",
#endif
				dkim_ssl_version());
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			printf("zdkimfilter command line args:\n"
			/*  12345678901234567890123456 */
				"  -f config-filename      override %s\n"
				"  --no-db                 omit database processing\n"
				"  --help                  print this stuff and exit\n"
				"  --version               print version string and exit\n",
					default_config_file);
			fl_main(NULL, NULL, argc - i + 1, argv + i - 1, 0, 0);
			return 0;
		}
		else if (strcmp(arg, "--batch-test") == 0)
			fl_log_no_pid = 1;
	}

	dkimfl_parm *parm = calloc(1, sizeof *parm);
	if (parm == NULL || parm_config(parm, config_file, no_db))
	{
		rtc = 2;
		fl_report(LOG_ERR, parm? "Unable to read config file": "MEMORY FAULT");
	}
	else
		parm->prog_name = my_basename(argv[0]);

#if HAVE_DKIM_LIBVERSION
	if (parm->z.verbose >= 2 &&
		(unsigned long)dkim_libversion() !=	(unsigned long)(OPENDKIM_LIB_VERSION))
			fl_report(LOG_WARNING,
				"Mismatched library versions: compile=%#lX link=%#lX",
				(unsigned long)(OPENDKIM_LIB_VERSION),
				(unsigned long)dkim_libversion());
#endif

	if (rtc == 0)
	{
		if (init_dkim(parm))
			rtc = 2;
		else
		{
			rtc =
				fl_main(&functions, &parm,
					argc, argv, parm->z.all_mode, parm->z.verbose);
			if (parm)
				delete_pid_file(parm);
		}
	}

	if (parm)
	{
		if (parm->dklib)
			dkim_close(parm->dklib);
		some_cleanup(parm);
		free(parm);
	}
	return rtc;
}
