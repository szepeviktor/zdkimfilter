/*
* zdkimfilter - written by ale in milano on Thu 11 Feb 2010 03:48:15 PM CET 
* Sign outgoing, verify incoming mail messages

Copyright (C) 2010-2012 Alessandro Vesely

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
#include <opendkim/dkim.h>
#if !defined DKIM_PRESULT_AUTHOR
#define DKIM_PRESULT_AUTHOR DKIM_PRESULT_FOUND
#define HAVE_LIBOPENDKIM_22 22
#endif
#if HAVE_DKIM_REP_DKIM_REP_H
#include <dkim-rep/dkim-rep.h>
#endif

#include <stddef.h>
#include <time.h>
#include <stdbool.h>
#include "filterlib.h"
#include "filedefs.h"
#include "myvbr.h"
#include "redact.h"
#include "vb_fgets.h"
#include "parm.h"
#include "database.h"
#include "filecopy.h"
#include "util.h"
#include <assert.h>


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
	stats_info *stats;
	var_buf vb;
	fl_msg_info info;
	int rtc;
	char db_connected;
	char special; // never block outgoing messages to postmaster@domain only.
	char nu[2];
} per_message_parm;

typedef struct dkimfl_parm
{
	DKIM_LIB *dklib;
	fl_parm *fl;
	db_work_area *dwa;

	per_message_parm dyn;
	blocked_user_list blocklist;
	parm_t z;

	// other
	char pid_created;
	char use_dwa_after_sign, use_dwa_verifying;
	char user_blocked;
} dkimfl_parm;

static inline const u_char **
cast_const_u_char_parm_array(const char **a) {return (const u_char **)a;}

static inline u_char **
cast_u_char_parm_array(char **a) {return (u_char **)a;}

static char const parm_z_domain_keys[] = COURIER_SYSCONF_INSTALL "/filters/keys";
static char const *parm_z_reputation_root =
#if defined DKIM_REP_ROOT
	DKIM_REP_ROOT;
#elif defined DKIM_REP_DEFROOT
	DKIM_REP_DEFROOT;
#else
	NULL;
#endif

static void config_default(dkimfl_parm *parm) // only non-zero...
{
	parm->z.domain_keys = (char*)parm_z_domain_keys;
	parm->z.reputation_root = (char*)parm_z_reputation_root;
	parm->z.reputation_fail = 32767;
	parm->z.reputation_pass = -32768;
	parm->z.verbose = 3;
	parm->z.max_signatures = 128;
}

static void config_cleanup_default(dkimfl_parm *parm)
{
	if (parm->z.domain_keys == parm_z_domain_keys)
		parm->z.domain_keys = NULL;
	if (parm->z.reputation_root == parm_z_reputation_root)
		parm->z.reputation_root = NULL;
}


static void no_trailing_slash(char *s)
{
	if (s)
	{
		size_t l = strlen(s);
		while (l > 0 && s[l-1] == '/')
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

	if (parm->z.verbose < 0)
		parm->z.verbose = 0;

	no_trailing_slash(parm->z.domain_keys);
	no_trailing_slash(parm->z.tmp);
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

	return errs;
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

	if (target && *target == NULL)
	{
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
			char *d = *target = malloc(t - s + 1);
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
			else // memory faults are silently ignored for stats
				clean_stats(parm);
		}
	}
	
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

static int sign_headers(dkimfl_parm *parm, DKIM *dkim)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(parm);

	size_t keep = 0;
	var_buf *vb = &parm->dyn.vb;
	FILE* fp = fl_get_file(parm->fl);
	assert(fp);
	DKIM_STAT status;
	
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
			continue;
		}

		if (parm->dyn.stats)
			collect_stats(parm, start);

		/*
		* full field is in buffer (dkim_header does not want the trailing \n)
		*/
		if (keep && dkim &&
			(status = dkim_header(dkim, start, keep)) != DKIM_STAT_OK)
		{
			if (parm->z.verbose)
			{
				char const *err = dkim_getresultstr(status);
				fl_report(LOG_CRIT,
					"id=%s: signing dkim_header failed on %zu bytes: %s (%d)",
					parm->dyn.info.id, keep,
					err? err: "unknown", (int)status);
			}
			return parm->dyn.rtc = -1;
		}

		if (!cont)
			break;

		start[0] = next;
		keep = 1;
	}
	
	/*
	* all header fields processed.
	* check results thus far.
	*/
	
	if (dkim)
	{
		status = dkim_eoh(dkim);
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
		char *name = strrchr(buf2, '/');
		if (name)
			++name;
		else
			name = buf2;
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

static void copy_until_redacted(dkimfl_parm *parm, FILE *fp, FILE *fp_out)
{
	assert(parm);
	assert(parm->z.redact_received_auth);
	assert(fp);
	assert(fp_out);

	var_buf vb;
	if (vb_init(&vb))
	{
		parm->dyn.rtc = -1;
		return;
	}

	size_t keep = 0;
	for (;;)
	{
		char *p = vb_fgets(&vb, keep, fp);
		char *eol = p? strchr(p, '\n'): NULL;

		if (eol == NULL)
		{
			if (parm->z.verbose)
				fl_report(LOG_ALERT,
					"id=%s: header too long (%.20s...)",
					parm->dyn.info.id, vb_what(&vb, fp));
			parm->dyn.rtc = -1;
			break;
		}

		int const next = eol > p? fgetc(fp): '\n';
		int const cont = next != EOF && next != '\n';
		char *const start = vb.buf;
		if (cont && isspace(next)) // wrapped
		{
			*++eol = next;
			keep = eol + 1 - start;
			continue;
		}

		/*
		* full 0-terminated header field, including trailing \n, is in buffer;
		* search for the identbuf argv (see courier/module.esmtp/courieresmtpd.c)
		*/
		char const *s = hdrval(start, "Received");
		if (s)
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
				* found: write the redacted field and break
				*/
				{
					char *red =
						redacted(parm->z.redact_received_auth,
							parm->dyn.info.authsender);
					int ok =
						fwrite(start, addr - start, 1, fp_out) == 1 &&
						(red == NULL || fputs(red, fp_out) >= 0) &&
						fwrite(eaddr, eol + 1 - eaddr, 1, fp_out) == 1 &&
						ungetc(next, fp) == next;
						// fputc(next, fp_out) == next;

					if (!ok)
						parm->dyn.rtc = -1;

					free(red);
					break;
				}
			}
		}

		/*
		* copy the field as is and continue header processing
		*/
		if (fwrite(start, eol + 1 - start, 1, fp_out) != 1)
		{
			parm->dyn.rtc = -1;
			break;
		}

		if (!cont)
		{
			if (fputc(next, fp_out) != next)
				parm->dyn.rtc = -1;
			break;
		}

		start[0] = next;
		keep = 1;
	}

	vb_clean(&vb);
}

static void recipient_s_domains(dkimfl_parm *parm)
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

static inline void stats_outgoing(dkimfl_parm *parm)
{
	if (parm->dyn.stats)
	{
		parm->dyn.stats->outgoing = 1;
		parm->dyn.stats->envelope_sender = fl_get_sender(parm->fl);
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
			sign_headers(parm, NULL);
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

		stats_outgoing(parm);

		// (not)TODO: if parm.no_signlen, instead of copy_body, stop at either
		// "-- " if plain text, or end of first mime alternative otherwise
		if (parm->dyn.rtc == 0 &&
			sign_headers(parm, dkim) == 0 &&
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
			
			unsigned char *s = hdr, *d = hdr;
			int ch;
			while ((ch = *s++) != 0)
				if (ch != '\r') *d++ = ch;
			*d = 0;
			
			fprintf(fp, DKIM_SIGNHEADER ": %s\n", hdr);
			dkim_free(dkim);
			dkim = NULL;

			FILE *in = fl_get_file(parm->fl);
			assert(in);
			rewind(in);

			if (parm->z.redact_received_auth)
				copy_until_redacted(parm, in, fp);
				
			if (parm->dyn.rtc == 0)
			{
				if (filecopy(in, fp) == 0)
					parm->dyn.rtc = 1;
				else
					parm->dyn.rtc = -1;
			}
		}
	}
}

// verify

typedef struct verify_parms
{
	char *sender_domain, *helo_domain; // imply SPF "pass"
	char *dnswl_domain;
	domain_prescreen *domain_head, **domain_ptr;
	vbr_info *vbr;  // store of all VBR-Info fields

	vbr_check_result vbr_result;  // vbr_result.resp is malloc'd
	
	// not malloc'd or maintained elsewhere
	dkimfl_parm *parm;
	char *dkim_domain;
	DKIM_SIGINFO *sig, *author_sig, *vbr_sig, *whitelisted_sig;
	domain_prescreen *dps, *author_dps, *vbr_dps, *whitelisted_dps,
		*sender_dps, *helo_dps;
	dkim_policy_t policy;

	void *dkim_or_file;
	int step;

	// number of domains, elements of domain_ptr
	int ndoms;
	
	// dkim domains with special characteristics
	int have_whitelisted;
	int have_trusted_vbr;

	int presult;
	int dkim_reputation;
	size_t received_spf;
	// char sig_is_author;
	char dkim_reputation_flag;

} verify_parms;

static int is_trusted_voucher(char const **const tv, char const *const voucher)
// return non-zero if voucher is in the trusted_voucher list
// the returned value is 1 + the index of trust, for sorting
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

static void clean_vh(verify_parms *vh)
{
	clear_prescreen(vh->domain_head);
	vbr_info_clear(vh->vbr);
	free(vh->sender_domain);
	free(vh->helo_domain);
	free(vh->domain_ptr);
	free(vh->vbr_result.resp);
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

static int
domain_sort(verify_parms *vh, DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
/*
*
* return -1 for fatal error, number of domains otherwise
*/
{
	if (vh->dkim_domain == NULL)
		vh->dkim_domain = dkim_getdomain(dkim);
	char const save_from_anyway = vh->parm->z.save_from_anyway;
	char *const from = vh->dkim_domain;
	char *const mfrom = vh->sender_domain;
	char *const helo = vh->helo_domain;
	char from_k = from == NULL, mfrom_k = mfrom == NULL, helo_k = helo == NULL;

	int ndoms = nsigs + 2 - mfrom_k - helo_k;
	if (save_from_anyway)
		ndoms += 1 - from_k;

	domain_prescreen** domain_ptr = calloc(ndoms+1, sizeof(domain_prescreen*));
	domain_prescreen** sigs_mirror = calloc(nsigs+1, sizeof(domain_prescreen*));
	DKIM_SIGINFO** sigs_copy = calloc(nsigs+1, sizeof(DKIM_SIGINFO*));
	if (!(domain_ptr && sigs_mirror && sigs_copy))
	{
		fl_report(LOG_ALERT, "MEMORY FAULT");
		ndoms = -1;
	}

	db_work_area *const dwa = vh->parm->dwa;
	if (dwa && ndoms > 0 &&
		check_db_connected(vh->parm) < 0)
			ndoms = -1;

	if (ndoms < 0)
	{
		free(domain_ptr);
		free(sigs_mirror);
		free(sigs_copy);
		return ndoms;
	}

	int const vbr_count = count_trusted_vouchers(vh->parm->z.trusted_vouchers);
	int const vbr_factor = vbr_count < 2? 0: 1000/(vbr_count - 1);

	size_t const helolen = vh->helo_domain? strlen(vh->helo_domain): 0;

	domain_prescreen *dps_head = NULL;
	ndoms = 0;

	/*
	* 1st pass: Create prescreens with name-based domain evaluation.
	* Fill in sigs_mirror and domain_ptr.
	*/
	for (int c = 0; c < nsigs; ++c)
	{
		char *const domain = dkim_sig_getdomain(sigs[c]);
		if (domain)
		{
			domain_prescreen *dps = get_prescreen(&dps_head, domain);
			if (dps == NULL)
			{
				fl_report(LOG_ALERT, "MEMORY FAULT");
				clear_prescreen(dps_head);
				free(domain_ptr);
				free(sigs_mirror);
				free(sigs_copy);
				return -1;
			}

			sigs_mirror[c] = dps;

			if (dps->nsigs++ == 0)  // first time domain seen
			{
				domain_ptr[ndoms++] = dps;

				if (from_k == 0 && stricmp(from, domain) == 0)
				{
					from_k = dps->u.f.is_from = 1;
					dps->sigval += 2500;    // author domain signature
					// vh->have_author_sig += 1;
				}

				if (dwa &&
					(dps->whitelisted = db_is_whitelisted(dwa, domain)) > 0)
				{
					if (dps->whitelisted > 1)
					{
						if (dps->whitelisted > 2)
						{
							dps->sigval += 500;
							dps->u.f.is_trusted = 1;
						}
						dps->sigval += 500;
						dps->u.f.is_whitelisted = 1;
						vh->have_whitelisted += 1;
					}
					dps->sigval += 500;
					dps->u.f.is_known = 1;
				}

				vbr_info *const vbr = vbr_info_get(vh->vbr, domain);
				if (vbr)
				{
					dps->u.f.has_vbr = 1;   // sender's adverized vouching
					dps->sigval += 5;
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
							dps->sigval += vbr_factor * (vbr_count - trust) + 200;
							dps->u.f.vbr_is_trusted = 1;
							vh->have_trusted_vbr += 1;
						}
					}
				}

				if (mfrom_k == 0 && stricmp(mfrom, domain) == 0)
				{
					mfrom_k = dps->u.f.is_mfrom = 1;
					vh->sender_dps = dps;
					dps->sigval += 100;     // sender's domain signature
				}

				if (helo_k == 0 && stricmp(helo, domain) == 0)
				{
					helo_k = dps->u.f.is_helo = 1;
					vh->helo_dps = dps;
					dps->sigval += 15;
				}
				else if (helolen)
				{
					size_t dl = strlen(domain);
					if (helolen > dl)
					{
						char *const helocmp = &helo[helolen - dl];
						// should check helo is not co.uk or similar...
						if (stricmp(helocmp, domain) == 0)
						{
							dps->sigval += 8; // helo domain signature
							dps->u.f.looks_like_helo = 1;
						}
					}
				}
			}
		}
	}

	/*
	* Sort domain_ptr, based on evaluation.  Use gnome sort, as we
	* expect 2 ~ 4 elements.  (It starts getting sensibly slow with
	* 1000 elements --1ms on nocona xeon.)
	*/

	for (int c = 0; c < ndoms;)
	{
		if (c == 0 || domain_ptr[c]->sigval <= domain_ptr[c-1]->sigval)
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
	* Allocate indexes in the sorted sigs array.  Reuse sigval as next_index.
	*/

	int next_ndx = 0;
	for (int c = 0; c < ndoms; ++c)
	{
		domain_prescreen *const dps = domain_ptr[c];
		dps->sigval = dps->start_ndx = next_ndx;
		next_ndx += dps->nsigs;
	}

	/*
	* Make a copy of sigs, then
	* 2nd pass: Rewrite it based on allocated indexes.
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

	/*
	* If SPF-authenticated domains were not among the signers, add them
	* to domain list and check whether any of them is whitelisted.
	*/

	free(sigs_mirror);
	free(sigs_copy);

	if (save_from_anyway && dwa && from_k == 0)
	{
		domain_prescreen *dps = get_prescreen(&dps_head, from);
		if (dps)
		{
			if (dps->u.all == 0)
				domain_ptr[ndoms++] = dps;	
			dps->u.f.is_from = 1;
		}
		else
			ndoms = -1;
	}

	if (ndoms >= 0 && dwa && mfrom_k == 0)
	{
		domain_prescreen *dps = get_prescreen(&dps_head, mfrom);
		if (dps)
		{
			if (dps->u.all == 0)
				domain_ptr[ndoms++] = dps;	
			vh->sender_dps = dps;
			dps->u.f.is_mfrom = 1;
			if (dwa &&
				(dps->whitelisted = db_is_whitelisted(dwa, dps->name)) > 1)
					dps->u.f.is_whitelisted = 1;

			vbr_info *const vbr = vbr_info_get(vh->vbr, dps->name);
			if (vbr)
			{
				dps->u.f.has_vbr = 1;
				if (vbr_count && has_trusted_voucher(vh, vbr))
					dps->u.f.vbr_is_trusted = 1;
			}
		}
		else
			ndoms = -1;
	}

	if (ndoms >= 0 && dwa && helo_k == 0)
	{
		domain_prescreen *dps = get_prescreen(&dps_head, helo);
		if (dps)
		{
			if (dps->u.all == 0)
				domain_ptr[ndoms++] = dps;
			vh->helo_dps = dps;
			dps->u.f.is_helo = 1;
			if (dwa &&
				(dps->whitelisted = db_is_whitelisted(dwa, dps->name)) > 1)
					dps->u.f.is_whitelisted = 1;
		}
		else
			ndoms = -1;
	}

	if (ndoms < 0)
	{
		fl_report(LOG_ALERT, "MEMORY FAULT");
		clear_prescreen(dps_head);
		free(domain_ptr);
		return -1;
	}

	vh->ndoms = ndoms;
	if (ndoms)
	{
		vh->domain_ptr = realloc(domain_ptr, ndoms * sizeof(domain_prescreen*));
		vh->domain_head = dps_head;
		if (vh->parm->dyn.stats)
			vh->parm->dyn.stats->signatures_count = nsigs;
	}
	else
	{
		assert(dps_head == NULL);
		free(domain_ptr);
		clean_stats(vh->parm);
	}

	return ndoms;
}

static DKIM_STAT dkim_sig_sort(DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
{
	verify_parms *const vh = (verify_parms*)dkim_get_user_context(dkim);

	assert(dkim && sigs && vh);

	if (nsigs > vh->parm->z.max_signatures)
	{
		fl_pass_message(vh->parm->fl, "554 Too many DKIM signatures\n");
		vh->parm->dyn.rtc = 2;
		if (vh->parm->z.verbose >= 3)
			fl_report(LOG_ERR,
				"id=%s: %d DKIM signatures, max is %d, message rejected.",
				vh->parm->dyn.info.id,
				nsigs,
				vh->parm->z.max_signatures);
		return DKIM_CBSTAT_REJECT;
	}

	int rtc = domain_sort(vh, dkim, sigs, nsigs);
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

static inline int sig_is_good(DKIM_SIGINFO *const sig)
{
	unsigned int const sig_flags = dkim_sig_getflags(sig);
	unsigned int const bh = dkim_sig_getbh(sig);
	DKIM_SIGERROR const rc = dkim_sig_geterror(sig);
	return (sig_flags & DKIM_SIGFLAG_IGNORE) == 0 &&
		(sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
		bh == DKIM_SIGBH_MATCH &&
		rc == DKIM_SIGERROR_OK;
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
	
	int whitelisted = vh->have_whitelisted;
	int trusted_vbr = vh->have_trusted_vbr;
	int const do_all = vh->parm->z.report_all_sigs;
	int done_one = 0;

	for (int c = 0; c < ndoms; ++c)
	{
		domain_prescreen *const dps = domain_ptr[c];
		dps->sigval = 0; // reuse for number of verified signatures
		if (dps->nsigs > 0) // TODO option for verifying only dps->u.all != 0
		{
			for (int n = 0; n < dps->nsigs; ++n)
			{
				int const ndx = n + dps->start_ndx;
				assert(ndx >= 0 && ndx < nsigs);
				DKIM_SIGINFO *const sig = sigs[ndx];
				unsigned int const sig_flags = dkim_sig_getflags(sig);
				if ((sig_flags & DKIM_SIGFLAG_IGNORE) == 0 &&
					dkim_sig_process(dkim, sig) == DKIM_STAT_OK &&
					sig_is_good(sig))
				{
					done_one = 1;
					dps->u.f.sig_is_ok = 1;
					dps->sigval += 1;
					if (vh->dps == NULL)
					{
						vh->sig = sig;
						vh->dps = dps;
					}

					if (dps->u.f.is_from && vh->author_dps == NULL)
					{
						vh->author_sig = sig;
						vh->author_dps = dps;
					}

					if (trusted_vbr > 0 && dps->u.f.vbr_is_trusted)
					{
						--trusted_vbr;
						if (run_vbr_check(vh, dps) == 0)
						{
							vh->vbr_sig = sig;
							vh->vbr_dps = dps;
							dps->u.f.vbr_is_ok = 1;
							dps->vbr_mv = vh->vbr_result.mv;
							trusted_vbr = 0; // one is enough
						}
					}

					if (whitelisted && dps->u.f.is_whitelisted)
					{
						vh->whitelisted_sig = sig;
						vh->whitelisted_dps = dps;
						whitelisted = 0;
					}

					if (!do_all)
						break;
				}
				else
				/*
				* It was useless to check whitelisting / trusted VBR on unverified
				* domains, and we now undo that counting.  An alternative approach
				* could have provided for checking those after signature validation.
				* We check whitelisting / trusted VBR in advance, and then attempt
				* signature validation in the resulting order:  Signature validation
				* costs more than local lookup.
				*/
				{
					if (dps->u.f.is_whitelisted)
						--whitelisted;
					if (dps->u.f.vbr_is_trusted)
						--trusted_vbr;
				}
			}
		}
		if (done_one && do_all == 0 && whitelisted == 0 && trusted_vbr == 0)
			break;
	}

	return DKIM_CBSTAT_CONTINUE;
	(void)nsigs; // only used in assert
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
	DKIM *const dkim = vh->step? NULL: (DKIM*)vh->dkim_or_file;
	FILE *const out = vh->step? (FILE*)vh->dkim_or_file: NULL;
	
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
		char *s;

		// malformed headers can go away...
		if (!isalpha(*(unsigned char*)start))
			zap = 1;

		// A-R fields
		else if ((s = hdrval(start, "Authentication-Results")) != NULL)
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
				else  if (parm->z.dont_trust_a_r)
				{
					int maybe_attack = 0;
					*s = 0;
					/*
					* Courier puts A-R after "Received" (but before Received-SPF).
					* After first "Received", if the authserv_id matches it may
					* be an attack.
					*/
					if (parm->dyn.authserv_id &&
						stricmp(authserv_id, parm->dyn.authserv_id) == 0)
							maybe_attack = zap = 1;
					if (dkim == NULL && parm->z.verbose >= 2) // log on 2nd pass only
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
				else if (dkim) // acquire trusted results on 1st pass
				{
				}
			}
		}
		
		// Only on first step, acquire relevant header info
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
								while (isalnum(ch = *(unsigned char*)s) || ch == '.')
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

				else if (!parm->z.no_spf && vh->received_spf < 2 &&
					(s = hdrval(start, "Received-SPF")) != NULL)
				{
					++vh->received_spf;
					while (isspace(*(unsigned char*)s))
						++s;
					if (strincmp(s, "pass", 4) == 0)
					{
						s = strstr(s, "SPF=");
						if (s)
						{
							s += 4;  //               1234567
							char *sender = strstr(s, "sender=");
							if (sender)
							{
								sender += 7;
								char *esender = strchr(sender, ';');
								if (esender)
								{
									*esender = 0;
									if (vh->helo_domain == NULL &&
										strincmp(s, "HELO", 4) == 0)
											vh->helo_domain = strdup(sender);
									else if (vh->sender_domain == NULL &&
										strincmp(s, "MAILFROM", 8) == 0)
									{
										s = strchr(sender, '@');
										if (s)
											++s;
										else
											s = sender;
										vh->sender_domain = strdup(s);
									}
									*esender = ';';
								}
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
			// (only if stats enabled)
			// save stats' content_type and content_encoding, check mailing_list
			else if (parm->dyn.stats)
				collect_stats(parm, start);
		}

		if (!zap)
		{
			int err = 0;
			DKIM_STAT status;
			size_t const len = eol - start;
			if (dkim)
				err = (status = dkim_header(dkim, start, len)) != DKIM_STAT_OK;
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

static int print_signature_resinfo(FILE *fp, DKIM_SIGINFO *const sig,
	dkim_result_summary *drs, DKIM *dkim, domain_prescreen *dps)
// Last but one argument, dkim, in order to use header.b, if dps->nsigs > 1.
// Start printing the semicolon+newline that terminate either the previous
// resinfo or the authserv-id, then print the signature details.
// No print for ignored signatures.
// Return 1 or 0, the number of resinfo's written.
{
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
#if defined HAVE_LIBOPENDKIM_22
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
	char const *const failresult = is_test? "neutral": "fail";
	char const *result = NULL, *err = NULL;

	unsigned int const bh = dkim_sig_getbh(sig);
	DKIM_SIGERROR const rc = dkim_sig_geterror(sig);

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

static int
my_get_reputation(DKIM* dkim, DKIM_SIGINFO* sig, char *root, int *rep)
{
#if defined DKIM_REP_ROOT
	if (dkim_get_reputation(dkim, sig, root, rep) == DKIM_STAT_OK)
		return 0;
#elif defined DKIM_REP_DEFROOT
	int rtc = -1;
	DKIM_REP dr = dkim_rep_init(NULL, NULL, NULL);
	if (dr)
	{
		void *qh = NULL;
		dkim_rep_setdomain(dr, root);
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

	DKIM_STAT status;
	DKIM *dkim = dkim_verify(parm->dklib, parm->dyn.info.id, NULL, &status);
	if (dkim == NULL || status != DKIM_STAT_OK)
	{
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

	/*
	* Wrap up for non-dkim domains
	*/
	if (parm->dyn.rtc == 0 && vh.domain_head == NULL)
	{
		int rtc = domain_sort(&vh, dkim, NULL, 0);
		if (rtc < 0)
			parm->dyn.rtc = -1;
	}

	/*
	* If no DKIM domain is vouched but SPF passed, try that
	*/
	if (parm->dyn.rtc == 0 &&
		vh.vbr_dps == NULL &&
		vh.sender_dps != NULL &&
		vh.sender_dps->u.f.vbr_is_trusted &&
		run_vbr_check(&vh, vh.sender_dps) == 0)
			vh.vbr_dps = vh.sender_dps;

	/*
	* If no DKIM domain is whitelisted but SPF passed, try that
	* SPF helo is ok!
	*/
	if (parm->dyn.rtc == 0 && vh.whitelisted_dps == NULL &&
		(vh.sender_dps || vh.helo_dps))
	{
		if (vh.sender_dps != NULL &&
			vh.sender_dps->u.f.is_whitelisted)
				vh.whitelisted_dps = vh.sender_dps;
		else if (vh.helo_dps != NULL &&
			vh.helo_dps->u.f.is_whitelisted)
				vh.whitelisted_dps = vh.helo_dps;
	}

	switch (status)
	{
		case DKIM_STAT_OK:
			// pass
			break;

		case DKIM_STAT_NOSIG:
			// none
			break;

		case DKIM_STAT_BADSIG:
		case DKIM_STAT_CANTVRFY:
		case DKIM_STAT_REVOKED:
			// fail or neutral
			break;

		case DKIM_STAT_NORESOURCE:
		case DKIM_STAT_INTERNAL:
		case DKIM_STAT_CBTRYAGAIN:
		case DKIM_STAT_KEYFAIL:
			parm->dyn.rtc = -1;
			// temperror
			break;

		case DKIM_STAT_SYNTAX:
		default:
			// permerror
			break;
	}

	/*
	* ADSP check and possibly reject/drop
	*/
	if (parm->dyn.rtc == 0)
	{
		if ((vh.dkim_domain != NULL ||
				(vh.dkim_domain = dkim_getdomain(dkim)) != NULL) &&
			dkim_policy(dkim, &vh.policy,
#if OPENDKIM_DKIM_POLICY_ARGS == 4
			/* not doing ATSP (yet) */ NULL,
#endif
													NULL) == DKIM_STAT_OK)
		{
			vh.presult = dkim_getpresult(dkim);
			bool const adsp_fail =
				(vh.policy == DKIM_POLICY_DISCARDABLE ||
					vh.policy == DKIM_POLICY_ALL) &&
				/* redundant: vh.presult == DKIM_PRESULT_AUTHOR && */
				vh.author_sig == NULL;
			if (parm->dyn.stats)
			{
				parm->dyn.stats->adsp_found = vh.presult == DKIM_PRESULT_AUTHOR;
				parm->dyn.stats->adsp_unknown = vh.policy == DKIM_POLICY_UNKNOWN;
				parm->dyn.stats->adsp_all = vh.policy == DKIM_POLICY_ALL;
				parm->dyn.stats->adsp_discardable =
					vh.policy == DKIM_POLICY_DISCARDABLE;
				parm->dyn.stats->adsp_fail = adsp_fail;
				parm->dyn.stats->adsp_whitelisted = adsp_fail &&
					(vh.vbr_dps != NULL || vh.whitelisted_dps != NULL);
			}

			/*
			* unless disabled by parameter or whitelisted, do action:
			* reject if dkim_domain is not valid, or ADSP == all,
			* discard if ADSP == discardable;
			*/
			if (parm->z.honor_author_domain && adsp_fail ||
				parm->z.reject_on_nxdomain && vh.presult == DKIM_PRESULT_NXDOMAIN)
			{
				char const *log_reason, *smtp_reason = NULL;
				
				if (vh.presult == DKIM_PRESULT_NXDOMAIN)
				{
					log_reason = "invalid domain";
					smtp_reason = "554 Invalid author domain\n";
				}
				else if (vh.policy != DKIM_POLICY_DISCARDABLE)
				{
					log_reason = "adsp=all policy for";
					smtp_reason = "554 DKIM signature required by ADSP\n";
				}
				else
					log_reason = "adsp=discardable policy:";

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
					else
						fl_report(LOG_INFO,
							"id=%s: %s %s, no VBR and no whitelist",
							parm->dyn.info.id,
							log_reason,
							vh.dkim_domain);
				}

				if (vh.vbr_dps == NULL && vh.whitelisted_dps == NULL)
				{
					if (smtp_reason) //reject
					{
						fl_pass_message(parm->fl, smtp_reason);
						if (parm->dyn.stats)
							parm->dyn.stats->reject = 1;
					}
					else // drop, and stop filtering
					{
						fl_pass_message(parm->fl, "050 Message dropped.\n");
						fl_drop_message(parm->fl, "adsp=discard\n");
						if (parm->dyn.stats)
							parm->dyn.stats->drop = 1;
					}
					
					parm->dyn.rtc = 2;
				}
			}
		}
	}

	/*
	* Reputation
	*/
	if (parm->dyn.rtc == 0 &&
		parm->z.do_reputation && status == DKIM_STAT_OK && vh.sig)
	{
		int rep;
		/*
		* (don't) reject on passing configured value
		*/
		if (my_get_reputation(dkim, vh.sig, parm->z.reputation_root, &rep) == 0)
		{
			vh.dkim_reputation = rep;
			vh.dkim_reputation_flag = 1;
			if (vh.author_dps)
			{
				vh.author_dps->u.f.is_reputed = 1;
				vh.author_dps->reputation = rep;
			}

			if (vh.dps)
			{
				vh.dps->u.f.is_reputed_signer = 1;
				vh.dps->reputation = rep;
			}
#if 0				
			if (rep > parm->reputation_reject)
			{
				fl_pass_message(parm->fl, "550 Bad reputation?\n");
				parm->dyn.rtc = 2;
			}
#endif
		}
	}

	/*
	* prepare ADSP results
	*/
	char const *policy_type = "", *policy_result = "";
	if (parm->dyn.rtc == 0)
	{
		if (vh.presult == DKIM_PRESULT_NXDOMAIN)
		{
			policy_type = " adsp=";
			policy_result = "nxdomain";
		}
		else if (vh.policy == DKIM_POLICY_ALL)
		{
			policy_type = " adsp:all=";
			policy_result = vh.author_sig && status == DKIM_STAT_OK?
				"pass": "fail";
		}
		else if (vh.policy == DKIM_POLICY_DISCARDABLE)
		{
			policy_type = " adsp:discardable=";
			policy_result = vh.author_sig && status == DKIM_STAT_OK?
				"pass": "discard";
		}
	}

	/*
	* prepare the first failed signature if none was verified
	*/
	if (vh.dps == NULL &&
		vh.domain_ptr && vh.domain_ptr[0] && vh.domain_ptr[0]->nsigs)
	{
		DKIM_SIGINFO **sigs;
		int nsigs;
		if (dkim_getsiglist(dkim, &sigs, &nsigs) == DKIM_STAT_OK)
		{
			vh.dps = vh.domain_ptr[0];
			assert(vh.dps->start_ndx < nsigs);
			vh.sig = sigs[vh.dps->start_ndx];
		}
	}

	/*
	* write the A-R field if required anyway, spf, or signatures
	*/
	if (parm->dyn.rtc == 0 &&
		(parm->z.add_a_r_anyway ||
			vh.sender_domain || vh.helo_domain || vh.dps ||
			vh.author_sig || vh.vbr_dps || vh.whitelisted_dps ||
			*policy_result))
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

		/*
		* according to RFC 5451, Section 7.1, point 5, the A-R field
		* should always appear above the corresponding Received field.
		*/
		fprintf(fp, "Authentication-Results: %s", parm->dyn.authserv_id);
		int auth_given = 0;
		int log_written = 0;
		
		if (vh.sender_domain || vh.helo_domain)
		{
			fprintf(fp, ";\n  spf=pass smtp.%s=%s",
				vh.sender_domain? "mailfrom": "helo",
				vh.sender_domain? vh.sender_domain: vh.helo_domain);
			++auth_given;
		}

		if (vh.dps)
		{
			dkim_result_summary drs;
			memset(&drs, 0, sizeof drs);
			int d_auth = 0;
			
			if (parm->z.report_all_sigs)
			{
				DKIM_SIGINFO **sigs;
				int nsigs;
				dkim_result_summary *pdrs = &drs;
				if (vh.domain_ptr &&
					dkim_getsiglist(dkim, &sigs, &nsigs) == DKIM_STAT_OK)
				{
					for (int c = 0; c < vh.ndoms; ++c)
					{
						domain_prescreen *dps = vh.domain_ptr[c];
						int ndx = dps->start_ndx;
						int const upto_ndx = ndx + dps->nsigs;
						for (; ndx < upto_ndx; ++ndx)
						{
							DKIM_SIGINFO *const sig = sigs[ndx];
							d_auth += 
								print_signature_resinfo(fp, sig, pdrs, dkim, dps);
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
				d_auth = print_signature_resinfo(fp, vh.sig, &drs, dkim, vh.dps);

			if (d_auth > 0 && parm->z.verbose >= 3)
			{
				fl_report(LOG_INFO,
					"id=%s: verified:%s dkim=%s (id=%s, %s%sstat=%d)%s%s rep=%d",
					parm->dyn.info.id,
					(vh.sender_domain || vh.helo_domain)? " spf=pass,": "",
					drs.result,
					drs.id? drs.id: "-",
					drs.err? drs.err: "", drs.err? ", ": "",
					(int)status,
					policy_type, policy_result,
					vh.dkim_reputation);
				log_written += 1;
			}

			free(drs.id);
			if (!parm->z.report_all_sigs)
			{
				if (vh.whitelisted_dps && vh.whitelisted_dps != vh.dps)
					d_auth += print_signature_resinfo(fp, vh.whitelisted_sig, NULL,
						dkim, vh.whitelisted_dps);
				if (vh.vbr_dps && vh.vbr_dps != vh.dps &&
					vh.vbr_dps != vh.whitelisted_dps)
						d_auth += print_signature_resinfo(fp, vh.vbr_sig, NULL,
							dkim, vh.vbr_dps);
			}
			auth_given += d_auth;
		}

		if (*policy_result)
		{
#if HAVE_LIBOPENDKIM_22
			char const *const user = dkim_getuser(dkim);
			if (user && vh.dkim_domain)
				fprintf(fp, ";\n  dkim-adsp=%s header.from=%s@%s",
					policy_result, user, vh.dkim_domain);
			else
#endif			
				fprintf(fp, ";\n  dkim-adsp=%s", policy_result);
			++auth_given;
		}
		
		if (vh.dkim_reputation_flag && vh.dps)
		{
			fprintf(fp, ";\n  x-dkim-rep=%s (%d from %s) header.d=%s",
				vh.dkim_reputation >= parm->z.reputation_fail? "fail":
				vh.dkim_reputation <= parm->z.reputation_pass? "pass": "neutral",
					vh.dkim_reputation, parm->z.reputation_root, vh.dps->name);
			++auth_given;
		}

		if (vh.vbr_result.resp)
		{
			fprintf(fp,
				";\n  vbr=pass header.mv=%s header.md=%s (%s)",
				vh.vbr_result.mv, vh.vbr_result.vbr->md, vh.vbr_result.resp);
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
		vh.step = 1;
		vh.dkim_or_file = fp;
		rewind(fl_get_file(parm->fl));
		if (verify_headers(&vh) == 0 &&
			fputc('\n', fp) != EOF &&
			filecopy(fl_get_file(parm->fl), fp) == 0)
				parm->dyn.rtc = 1;
		else
			parm->dyn.rtc = -1;
	}

	if (parm->dyn.rtc < 0)
		clean_stats(parm);
	else if (parm->dyn.stats)
	{
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

static void after_filter_stats(fl_parm *fl)
{
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);

	if (parm && parm->dwa && parm->dyn.stats)
	{
		if (check_db_connected(parm) == 0)
		{
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
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	parm->fl = fl;

	fl_get_msg_info(fl, &parm->dyn.info);
	if (parm->dyn.info.id == NULL)
		parm->dyn.info.id = default_jobid;

	if (parm->dyn.info.is_relayclient)
	{
		if (parm->dyn.info.authsender)
		{
			if (parm->use_dwa_after_sign)
				enable_dwa(parm);
			sign_message(parm);
		}
	}
	else
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
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);

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
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	static char keyfile[] = "KEYFILE";
	
	assert(parm);

	int nok = dkim_options(parm->dklib, DKIM_OP_SETOPT,
			DKIM_OPTS_QUERYMETHOD, &qtype, sizeof qtype) |
		dkim_options(parm->dklib, DKIM_OP_SETOPT,
			DKIM_OPTS_QUERYINFO, keyfile, strlen(keyfile));
	
	if (nok || parm->z.verbose >= 8)
		fl_report(nok? LOG_ERR: LOG_INFO,
			"DKIM query method%s set to file \"%s\"",
			nok? " not": "", keyfile);
}

static char policyfile[] = "POLICYFILE";

DKIM_CBSTAT my_policy_lookup(DKIM *dkim, unsigned char *query,
	_Bool excheck, unsigned char *buf, size_t buflen, int *qstat)
{
	assert(qstat);
	verify_parms *const vh = (verify_parms*)dkim_get_user_context(dkim);
	if (vh && vh->parm && vh->parm->z.verbose >= 8)
		fl_report(LOG_DEBUG, "query: %s", query);
	
	struct stat st;
	if (stat(policyfile, &st) != 0 || !S_ISREG(st.st_mode))
	{
		if (excheck)
		{
			*qstat = 3; // NXDOMAIN
			return DKIM_CBSTAT_CONTINUE;
		}
		return DKIM_CBSTAT_NOTFOUND;
	}

	*qstat = 0; // NOERROR
	if (excheck)
		return DKIM_CBSTAT_CONTINUE;

	if (st.st_size >= 0 && buflen > (unsigned)st.st_size)
	{
		FILE *fp = fopen(policyfile, "r");
		if (fp)
		{
			if (fread(buf, st.st_size, 1, fp) != 1)
				*qstat = 2; // SERVFAIL?
			fclose(fp);
			buf[st.st_size] = 0;
			return DKIM_CBSTAT_CONTINUE;
		}
	}
	
	return DKIM_CBSTAT_ERROR;
}

/*
* using the callback above, test3 can be used to set an invalid domain
* in case no policyfile is found, or the policy specified therein.
*/
static void set_policyfile(fl_parm *fl)
{
	assert(fl);

	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);

	assert(parm);
	
	DKIM_STAT status = dkim_set_policy_lookup(parm->dklib, &my_policy_lookup);
	if (status != DKIM_STAT_OK || parm->z.verbose >= 8)
		fl_report(status != DKIM_STAT_OK? LOG_ERR: LOG_INFO,
			"DKIM policy method%s set to file \"%s\"",
			status != DKIM_STAT_OK? " not": "", policyfile);
}

/*
* faked VBRFILE test4
*/
static void set_vbrfile(fl_parm *fl)
{
	flip_vbr_query_was_faked();
	(void)fl;
}

static const char pid_file[] = ZDKIMFILTER_PID_FILE;
static void write_pid_file(fl_parm *fl)
{
	assert(fl);
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	assert(parm);

	FILE *fp = fopen(pid_file, "w");
	char const *failed_action = NULL;
	if (fp)
	{
		fprintf(fp, "%lu\n", (unsigned long) getpid());
		if ((ferror(fp) | fclose(fp)) != 0)
			failed_action = "write";
		parm->pid_created = 1;
	}
	else
		failed_action = "open";
	if (failed_action)
		fl_report(LOG_ALERT, "cannot %s %s: %s",
			failed_action, pid_file, strerror(errno));
}

static void delete_pid_file(dkimfl_parm *parm)
{
	if (parm->pid_created &&
		unlink(pid_file) != 0)
			fprintf(stderr, "ERR: avfilter: cannot delete %s: %s\n",
				pid_file, strerror(errno));
}

static void check_blocked_user_list(fl_parm *fl)
/*
* this gets called once on init and thereafter on every message
*/
{
	assert(fl);
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	assert(parm);

	parm->fl = fl;
	update_blocked_user_list(parm);
}

static fl_init_parm functions =
{
	dkimfilter,
	write_pid_file,
	check_blocked_user_list,
	NULL, NULL, NULL,
	report_config, set_keyfile, set_policyfile, set_vbrfile
};

int main(int argc, char *argv[])
{
	int rtc = 0, i, no_db = 0;
#if !HAVE_OPENDBX
	no_db = 1;
#endif
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
#if defined HAVE_LIBOPENDKIM_22
				"Linked with OpenDKIM library version: %#lX (%smatch)\n"
#endif
				"Reported SSL/TLS version: %#lX\n",
				(long)(OPENDKIM_LIB_VERSION),
#if defined HAVE_LIBOPENDKIM_22
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

	dkimfl_parm parm;
	memset(&parm, 0, sizeof parm);
	// parm.fl = fl;
	if (parm_config(&parm, config_file, no_db))
	{
		rtc = 2;
		fl_report(LOG_ERR, "Unable to read config file");
	}

	if (parm.z.verbose >= 4 &&
		parm.z.redact_received_auth && !redact_is_fully_featured())
			fl_report(LOG_WARNING,
				"Option redact_received_header is set in %s,"
				" but it is not fully featured.",
					config_file? config_file: default_config_file);

#if defined HAVE_LIBOPENDKIM_22
	if (parm.z.verbose >= 2 &&
		(unsigned long)dkim_libversion() !=	(unsigned long)(OPENDKIM_LIB_VERSION))
			fl_report(LOG_WARNING,
				"Mismatched library versions: compile=%#lX link=%#lX",
				(unsigned long)(OPENDKIM_LIB_VERSION),
				(unsigned long)dkim_libversion());
#endif

	parm.dklib = dkim_init(NULL, NULL);
	if (parm.dklib == NULL)
	{
		rtc = 2;
		fl_report(LOG_ERR, "dkim_init fault");
	}

	if (rtc == 0)
	{
		int nok = 0;
		if (!parm.z.no_signlen || !parm.z.report_all_sigs)
		{
			unsigned int options = 0;
			nok |= dkim_options(parm.dklib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
				&options, sizeof options) != DKIM_STAT_OK;
			if (!parm.z.no_signlen)
				options |= DKIM_LIBFLAGS_SIGNLEN;
			if (!parm.z.report_all_sigs)
				options |= DKIM_LIBFLAGS_VERIFYONE;
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
				&options, sizeof options) != DKIM_STAT_OK;
		}
		
		if (parm.z.dns_timeout > 0) // DEFTIMEOUT is 10 secs
		{
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_TIMEOUT,
				&parm.z.dns_timeout, sizeof parm.z.dns_timeout) != DKIM_STAT_OK;
		}
		
		if (parm.z.tmp)
		{
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_TMPDIR,
				parm.z.tmp, sizeof parm.z.tmp) != DKIM_STAT_OK;
		}

		nok |= dkim_set_prescreen(parm.dklib, dkim_sig_sort) != DKIM_STAT_OK;
		nok |= dkim_set_final(parm.dklib, dkim_sig_final) != DKIM_STAT_OK;
		nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
			parm.z.sign_hfields?
				cast_const_u_char_parm_array(parm.z.sign_hfields):
				dkim_should_signhdrs,
					sizeof parm.z.sign_hfields) != DKIM_STAT_OK;

		nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_SKIPHDRS,
			parm.z.skip_hfields?
				cast_const_u_char_parm_array(parm.z.skip_hfields):
				dkim_should_not_signhdrs,
					sizeof parm.z.skip_hfields) != DKIM_STAT_OK;

		if (nok)
		{
			rtc = 2;
			fl_report(LOG_ERR, "Unable to set lib options");
		}
	}

	if (rtc == 0)
	{
		rtc =
			fl_main(&functions, &parm, argc, argv, parm.z.all_mode, parm.z.verbose);
		delete_pid_file(&parm);
	}

	if (parm.dklib)
		dkim_close(parm.dklib);
	some_cleanup(&parm);
	return rtc;
}
