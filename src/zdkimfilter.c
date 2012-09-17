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

If you modify zdkimfilter, or any covered work, by linking or combining it
with OpenDKIM, containing parts covered by the applicable licence, the licensor
or zdkimfilter grants you additional permission to convey the resulting work.
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
#include <unistd.h>
#include <fcntl.h>
#include <opendkim/dkim.h>
#if !defined DKIM_PRESULT_AUTHOR
#define DKIM_PRESULT_AUTHOR DKIM_PRESULT_FOUND
#define HAVE_LIBOPENDKIM_22 22
#endif
#include <stddef.h>
#include <time.h>
#include <stdbool.h>
#include "filterlib.h"
#include "filedefs.h"
#include "myvbr.h"

#include <assert.h>

// utilities -----
static int stricmp(const char *a, const char *b)
{
	int c, d;
	do c = *a++, d = *b++;
	while (c != 0 && d != 0 && (c == d || (c = tolower(c)) == (d = tolower(d))));

	return c < d ? -1 : c > d;
}

int strincmp(const char *a, const char *b, size_t n)
{
	while (n)
	{
		int c = *a++, d = *b++;
		if (c == 0 || d == 0 || (c != d && (c = tolower(c)) != (d = tolower(d))))
			return c < d ? -1 : c > d;
		--n;
	}
	return 0;
}

static char *hdrval(char *a, const char *b)
// b must be without trailing ':'
// return pointer after column if headers match, NULL otherwise
{
	assert(a && b && strchr(b, ':') == NULL);
	
	int c, d;
	do c = *(unsigned char const*)a++, d = *(unsigned char const*)b++;
	while (c != 0 && d != 0 && (c == d || tolower(c) == tolower(d)));
	
	if (d != 0 || c == 0)
		return NULL;

	while (c != ':')
		if (!isspace(c) || (c = *(unsigned char const*)a++) == 0)
			return NULL;

	return a;
}

static char *skip_comment(char *s)
{
	assert(s && *s == '(');
	
	int comment = 1;
	for (;;)
	{
		switch (*(unsigned char*)++s)
		{
			case 0:
				return NULL;

			case '(':
				++comment;
				break;

			case ')':
				if (--comment <= 0)
					return s;
				break;

			case '\\': // quoted pair, backslash cannot be last char
				++s;    // since there must be a newline anyway
				break;

			default:
				break;
		}
	}
}

static char *skip_cfws(char *s)
{
	while (s)
	{
		int ch;
		while (isspace(ch = *(unsigned char*)s))
			++s;
		if (ch == '(')
		{
			if ((s = skip_comment(s)) != NULL)
			{
				assert(*s == ')');
				++s;
			}
		}
		else if (ch)
			return s;
		else
			s = NULL;
	}
	return s;
}

static int filecopy(FILE *in, FILE *out)
{
	char buf[8192];
	size_t sz;
	while ((sz = fread(buf, 1, sizeof buf, in)) > 0)
		if (fwrite(buf, sz, 1, out) != 1)
			return -1;
	return ferror(in)? -1: 0;
}

typedef struct var_buf
{
	char *buf;
	size_t alloc;
} var_buf;

#define VB_LINE_MAX 5000
#if defined NDEBUG
#define VB_INIT_ALLOC 8192
#else
#define VB_INIT_ALLOC (VB_LINE_MAX/2)
#endif

static inline int vb_init(var_buf *vb)
// 0 on success
{
	assert(vb);
	return (vb->buf = (char*)malloc(vb->alloc = VB_INIT_ALLOC)) == NULL;
}

static inline void vb_clean(var_buf *vb)
// 0 on success
{
	assert(vb);
	if (vb->buf)
	{
		free(vb->buf);
		vb->buf = NULL;
	}
}

static inline char const *vb_what(var_buf const* vb, FILE *fp)
{
	assert(vb && fp);
	if (feof(fp)) return "EOF reached";
	return vb->buf? vb->buf: "malloc failed";
}

#if !defined SSIZE_MAX
#define SSIZE_MAX ((~((size_t) 0)) / 2)
#endif

static char* vb_fgets(var_buf *vb, size_t keep, FILE *fp)
// return buf + keep if OK, NULL on error
{
	assert(vb && vb->buf && vb->alloc);
	assert(keep < vb->alloc);
	assert(fp);

	size_t avail = vb->alloc - keep;

	if (avail < VB_LINE_MAX)
	{
		char *new_buf;
		if (vb->alloc > SSIZE_MAX ||
			(new_buf = realloc(vb->buf, vb->alloc *= 2)) == NULL)
		{
			free(vb->buf);
			return vb->buf = NULL;
		}

		vb->buf = new_buf;
		avail = vb->alloc - keep;
	}
	
	return fgets(vb->buf + keep, avail - 1, fp);
}

// ----- end utilities

typedef struct stats_info
{
	DKIM *dkim;
	char *ct, *cte;
	char *client_ip;
	char *jobid;
	
	// TODO: complete vbr processing
	char *vbr_result;
	unsigned vbr_info;

	unsigned rhcnt;
	unsigned adsp_found:2;
	unsigned adsp_unknown:2;
	unsigned adsp_all:2;
	unsigned adsp_discardable:2;
	unsigned adsp_fail:2;
	unsigned fromlist:2;
} stats_info;

static void clean_stats_info_content(stats_info *stats)
// only called by clean_stats
{
	if (stats)
	{
		if (stats->dkim)
		{
			dkim_free(stats->dkim);
			stats->dkim = NULL;
		}
		free(stats->ct);
		free(stats->cte);
		free(stats->vbr_result);
		// don't free(stats->client_ip); it is in dyn.info
		// don't free(stats->id); it is in dyn.info
	}
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
	char nu[4];
} per_message_parm;

typedef struct dkimfl_parm
{
	DKIM_LIB *dklib;
	fl_parm *fl;
	char *domain_keys;
	char *selector;
	char *default_domain;
	char *tmp;
	char *stats_file;
	const char **sign_hfields;
	const char **skip_hfields;
	const char **domain_whitelist;
	const char **key_choice_header;
	const char **trusted_vouchers;

	// end of pointers (some malloc'd but never free'd)
	per_message_parm dyn;
	int verbose;
	int dns_timeout;
	int stats_wait;
	int reputation_fail, reputation_pass;
	char add_a_r_anyway;
	char no_spf;
	char no_signlen;
	char tempfail_on_error;
	char no_author_domain;
	char no_reputation;
	char no_dwl;
	char all_mode;
	char sign_rsa_sha1;
	char header_canon_relaxed;
	char body_canon_relaxed;
	
	// other
	char pid_created;
} dkimfl_parm;

static inline const u_char **
cast_u_char_parm_array(const char **a) {return (const u_char **)a;}

#define DEFAULT_STATS_WAIT 1200 /* 20 minutes */
static void config_default(dkimfl_parm *parm) // only non-zero...
{
	static char const keys[] = COURIER_SYSCONF_INSTALL "/filters/keys";
	parm->domain_keys = (char*) keys; // won't be freed
	parm->reputation_fail = 32767;
	parm->reputation_pass = -32768;
	parm->verbose = 3;
	parm->stats_wait = DEFAULT_STATS_WAIT;
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
	if (parm->reputation_fail < parm->reputation_pass)
	{
		fl_report(LOG_WARNING,
			"reputation_fail = %d < reputation_pass = %d: swapped?",
				parm->reputation_fail, parm->reputation_pass);
		parm->reputation_fail = INT_MAX;
	}

	if (parm->dns_timeout < 0)
	{
		fl_report(LOG_WARNING,
			"dns_timeout cannot be negative (%d)", parm->dns_timeout);
		parm->dns_timeout = 0;
	}

	if (parm->stats_wait <= 0)
	{
		if (parm->stats_wait <= 0)
			fl_report(LOG_WARNING,
				"stats_wait must be positive (was %d)", parm->stats_wait);
		parm->stats_wait = DEFAULT_STATS_WAIT;
	}

	if (parm->verbose < 0)
		parm->verbose = 0;

	no_trailing_slash(parm->domain_keys);
	no_trailing_slash(parm->tmp);
	if (parm->tmp && strncmp(parm->tmp, "/tmp/", 5) == 0)
	{
		struct stat st;
		int rtc = stat(parm->tmp, &st);
		if (rtc && errno == ENOENT)
		{
			if (mkdir(parm->tmp, 0770))
				fl_report(LOG_CRIT,
					"mkdir %s failed: %s",
						parm->tmp, strerror(errno));
			rtc = stat(parm->tmp, &st);
		}
		if (rtc || !S_ISDIR(st.st_mode) ||
			euidaccess(parm->tmp, R_OK|W_OK|X_OK))
		{
			fl_report(LOG_WARNING,
				"disabling tmp = %s", parm->tmp);
			free(parm->tmp);
			parm->tmp = NULL;
		}
	}
}

typedef struct config_conf
{
	char const *name, *descr;
	int (*assign_fn)(dkimfl_parm*,struct config_conf const*, char*);
	size_t offset, size;
} config_conf;

#define PARM_PTR(T) *(T*)(((char*)parm) + c->offset)

static int assign_ptr(dkimfl_parm *parm, config_conf const *c, char*s)
{
	assert(parm && c && s && c->size == sizeof(char*));
	char *v = strdup(s);
	if (v == NULL)
	{
		fl_report(LOG_ALERT, "MEMORY FAULT");
		return -1;
	}
	PARM_PTR(char*) = v;
	return 0;
}

static int assign_char(dkimfl_parm *parm, config_conf const *c, char*s)
{
	assert(parm && c && s && c->size == sizeof(char));
	char ch = *s, v;
	if (strchr("YyTt1", ch)) v = 1; //incl. ch == 0
	else if (strchr("Nn0", ch)) v = 0;
	else return -1;
	PARM_PTR(char) = v;
	return 0;
}

static int assign_int(dkimfl_parm *parm, config_conf const *c, char*s)
{
	assert(parm && c && s && c->size == sizeof(unsigned int));
	char *t = NULL;
	errno = 0;
	long l = strtol(s, &t, 0);
	if (l > INT_MAX || l < INT_MIN || !t || *t || errno == ERANGE) return -1;
	
	PARM_PTR(int) = (int)l;
	return 0;
}

static int hfields(char *h, const char **a)
{
	assert(h);

	char *s = h;
	int ch, count = 0;
	
	for (;;)
	{
		while (isspace(ch = *(unsigned char*)s))
			++s;
		if (ch == 0)
			break;

		char *field = s;
		++count;
		++s;
		while (!isspace(ch = *(unsigned char*)s) && ch != 0)
			++s;
	
		if (a)
		{
			*a++ = field;
			*s++ = 0;
		}
		if (ch == 0)
			break;
	}
	return count;
}

static int assign_array(dkimfl_parm *parm, config_conf const *c, char*s)
{
	assert(parm && c && s && c->size == sizeof(char**));

	const char **a = NULL;
	int count = hfields(s, NULL);
	if (count > 0)
	{
		size_t l = strlen(s) + 1, n = (count + 1) * sizeof(char*);
		char *all = malloc(l + n);
		if (all == NULL)
		{
			fl_report(LOG_ALERT, "MEMORY FAULT");
			return -1;
		}
		a = (const char**)all;
		all += n;
		strcpy(all, s);
		a[count] = NULL;		
		count -= hfields(all, a);
	}
	assert(count == 0);

	PARM_PTR(const char **) = a;
	return 0;
}

#define STRING2(P) #P
#define STRING(P) STRING2(P)
#define CONFIG(P,D,F) {STRING(P), D, F, \
	offsetof(dkimfl_parm, P), sizeof(((dkimfl_parm*)0)->P)}

static config_conf const conf[] =
{
	CONFIG(domain_keys, "key's directory", assign_ptr),
	CONFIG(selector, "global", assign_ptr),
	CONFIG(default_domain, "dns", assign_ptr),
	CONFIG(tmp, "temp directory", assign_ptr),
	CONFIG(stats_file, "stats file path", assign_ptr),
	CONFIG(sign_hfields, "space-separated, no colon", assign_array),
	CONFIG(skip_hfields, "space-separated, no colon", assign_array),
	CONFIG(domain_whitelist, "space-separated domains", assign_array),
	CONFIG(key_choice_header, "key choice header", assign_array),
	CONFIG(trusted_vouchers, "space-separated, no colon", assign_array),
	CONFIG(verbose, "int", assign_int),
	CONFIG(dns_timeout, "secs", assign_int),
	CONFIG(stats_wait, "secs", assign_int),	
	CONFIG(reputation_fail, "high int", assign_int),
	CONFIG(reputation_pass, "low int", assign_int),
	CONFIG(add_a_r_anyway, "Y/N", assign_char),
	CONFIG(no_spf, "Y/N", assign_char),
	CONFIG(no_signlen, "Y/N", assign_char),
	CONFIG(tempfail_on_error, "Y/N", assign_char),
	CONFIG(no_author_domain, "Y=disable ADSP", assign_char),
	CONFIG(no_reputation, "Y=skip reputation lookup", assign_char),
	CONFIG(no_dwl, "Y=skip VBR-Info processing", assign_char),
	CONFIG(all_mode, "Y/N", assign_char),
	CONFIG(sign_rsa_sha1, "Y/N, N for rsa-sha256", assign_char),
	CONFIG(header_canon_relaxed, "Y/N, N for simple", assign_char),
	CONFIG(body_canon_relaxed, "Y/N, N for simple", assign_char),
	{NULL, NULL, NULL, 0, 0}
};

static void report_config(fl_parm *fl)
{
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	config_conf const *c = &conf[0];
	while (c->name)
	{
		int i = 0;

		printf("%-20s = ", c->name);
		if (c->size == 1U)
			fputc(PARM_PTR(char)? 'Y': 'N', stdout);
		else if (c->assign_fn == assign_ptr)
		{
			char const * const p = PARM_PTR(char*);
			fputs(p? p: "NULL", stdout);
		}
		else if (c->assign_fn == assign_array)
		{
			char const ** const a = PARM_PTR(char const**);
			if (a == NULL)
				fputs("NULL", stdout);
			else
			{
				printf("(%s)\n", c->descr);
				for (; a[i]; ++i)
					printf("%22d %s\n", i, a[i]);

				i = 1;
			}
		}
		else
			printf("%d", PARM_PTR(int));

		if (i == 0)
			printf(" (%s)\n", c->descr);
		++c;
	}
}

#undef CONFIG
#undef PARM_PTR

static config_conf const* conf_name(char const *p)
{
	for (config_conf const *c = conf; c->name; ++c)
		if (stricmp(c->name, p) == 0)
			return c;

	return NULL;
}

static char const default_config_file[] =
		COURIER_SYSCONF_INSTALL "/filters/zdkimfilter.conf";

static int parm_config(dkimfl_parm *parm, char const *fname)
// initialization, 0 on success
{
	int line_no = 0;
	if (fname == NULL)
		fname = default_config_file;

	config_default(parm);
	errno = 0;

	FILE *fp = fopen(fname, "r");
	if (fp == NULL)
	{
		if (fname == default_config_file && errno == ENOENT)
			return 0; // can do without it

		fl_report(LOG_ALERT,
			"Cannot read %s: %s", fname, strerror(errno));
		return -1;
	}
	
	var_buf vb;
	if (vb_init(&vb))
	{
		fclose(fp);
		return -1;
	}

	int errs = 0;
	size_t keep = 0;
	char *p;

	while ((p = vb_fgets(&vb, keep, fp)) != NULL)
	{
		char *eol = p + strlen(p) - 1;
		int ch = 0;
		++line_no;

		while (eol >= p && isspace(ch = *(unsigned char*)eol))
			*eol-- = 0;

		if (ch == '\\')
		{
			*eol = ' '; // this replaces the backslash
			keep += eol + 1 - p;
			continue;
		}

		/*
		* full logic line
		*/
		keep = 0;

		char *s = p = vb.buf;
		while (isspace(ch = *(unsigned char*)s))
			++s;
		if (ch == '#' || ch == 0)
			continue;

		char *const name = s;
		while (isalnum(ch = *(unsigned char*)s) || ch == '_')
			++s;
		*s = 0;
		config_conf const *c = conf_name(name);
		if (c == NULL)
		{
			fl_report(LOG_ERR,
				"Invalid name %s at line %d in %s", name, line_no, fname);
			++errs;
			continue;
		}
	
		*s = ch;
		while (isspace(ch = *(unsigned char*)s) || ch == '=')
			++s;
	
		char *const value = s;
	
		if ((*c->assign_fn)(parm, c, value) != 0)
		{
			fl_report(LOG_ERR,
				"Invalid value %s for %s at line %d in %s",
					value, c->name, line_no, fname);
			++errs;
		}
	}

	vb_clean(&vb);
	fclose(fp);
	if (errs == 0)
		config_wrapup(parm);

	return errs;
}

static int sign_headers(dkimfl_parm *parm, DKIM *dkim)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(parm && dkim);

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
			if (parm->verbose)
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

		/*
		* full header is in buffer (dkim_header does not want the trailing \n)
		*/
		if (keep && (status = dkim_header(dkim, start, keep)) != DKIM_STAT_OK)
		{
			if (parm->verbose)
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
	* all headers processed
	* check results thus far.
	*/
	
	status = dkim_eoh(dkim);
	if (status != DKIM_STAT_OK)
	{
		if (parm->verbose >= 3)
		{
			char const *err = dkim_getresultstr(status);
			fl_report(LOG_INFO,
				"id=%s: signing dkim_eoh: %s (stat=%d)",
				parm->dyn.info.id, err? err: "(NULL)", (int)status);
		}
		// return parm->dyn.rtc = -1;
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
			if (parm->verbose)
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
	
	if ((dkl = strlen(parm->domain_keys)) +
		(fl = strlen(fname)) + 2 >= PATH_MAX)
	{
		errno = ENAMETOOLONG;
		goto error_exit;
	}
	
	memcpy(buf, parm->domain_keys, dkl);
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
		if (errno != EINVAL && parm->verbose || parm->verbose >= 8)
			fl_report(errno == EINVAL? LOG_INFO: LOG_ALERT,
				"id=%s: cannot readlink for %s: no selector in %zd: %s",
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
		if (parm->verbose)
			fl_report(LOG_ERR,
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
		domain = parm->default_domain; // is that how local domains work?

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

	if (parm->key_choice_header == NULL)
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
	
	while (parm->key_choice_header[choice_max] != NULL)
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
		char const* const h = parm->key_choice_header[i];
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
			char const *const  h = parm->key_choice_header[i];
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
				if (parm->verbose)
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
						if ((dkim_mail_parse(val, &user, &domain)) == 0)
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
						if (parm->verbose >= 8)
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

	if (parm->dyn.key == NULL)
	{
		if (parm->verbose >= 2)
			fl_report(LOG_INFO,
				"id=%s: not signing for %s: no %s",
				parm->dyn.info.id,
				parm->dyn.info.authsender,
				parm->dyn.domain? "key": "domain");
	}
	else
	{
		char *selector = parm->dyn.selector? parm->dyn.selector:
			parm->selector? parm->selector: "s";

		DKIM_STAT status;
		DKIM *dkim = dkim_sign(parm->dklib, parm->dyn.info.id, NULL,
			parm->dyn.key, selector, parm->dyn.domain,
			parm->header_canon_relaxed? DKIM_CANON_RELAXED: DKIM_CANON_SIMPLE,
			parm->body_canon_relaxed? DKIM_CANON_RELAXED: DKIM_CANON_SIMPLE,
			parm->sign_rsa_sha1? DKIM_SIGN_RSASHA1: DKIM_SIGN_RSASHA256,
			ULONG_MAX /* signbytes */, &status);

		if (parm->verbose >= 6 && dkim && status == DKIM_STAT_OK)
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
			if (parm->verbose)
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

		// TODO: if parm.no_signlen, instead of copy_body, stop at either
		// "-- " if plain text, or end of first mime alternative otherwise
		if (sign_headers(parm, dkim) == 0 &&
			copy_body(parm, dkim) == 0)
		{
			vb_clean(&parm->dyn.vb);
			status = dkim_eom(dkim, NULL);
			if (status != DKIM_STAT_OK)
			{
				if (parm->verbose)
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
			if (filecopy(in, fp) == 0)
				parm->dyn.rtc = 1;
			else
				parm->dyn.rtc = -1;
		}
	}
}

// verify

typedef struct verify_parms
{
	char *sender_domain, *helo_domain; // imply SPF "pass"
	vbr_info *vbr;  // store of all VBR-Info fields

	vbr_check_result vbr_result;  // resp is malloc'd
	
	// not malloc'd or maintained elsewhere
	dkimfl_parm *parm;
	char *dkim_domain, *dkim_result;
	DKIM_SIGINFO *sig, *vbr_sig, *whitelisted_sig;
	char *sig_domain, *whitelisted_domain; // vbr_domain in vbr_result.vbr->md
	dkim_policy_t policy;

	void *dkim_or_file;
	int step;

	int presult;
	int dkim_reputation;
	size_t auth_sigs;
	size_t received_spf;
	size_t trusted_sigs;
	char sig_is_author;
	char dkim_reputation_flag;

} verify_parms;

// odd-aligned constant may replace vbr_sig or whitelisted_sig
static DKIM_SIGINFO *const not_sig_but_spf = (DKIM_SIGINFO*)0xb16b00b5;

static int
domain_is_whitelisted(verify_parms const *vh, char const *const domain)
{
	assert(vh);
	assert(vh->parm);
	
	char const ** const wl = vh->parm->domain_whitelist;
	if (wl == NULL || domain == NULL)
		return 0; // no whitelist given

	for (int i = 0; wl[i] != 0; ++i)
		if (stricmp(wl[i], domain) == 0)
			return 1;

	return 0;
}

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
		char const ** const tv = vh->parm->trusted_vouchers;

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

static DKIM_STAT dkim_sig_sort(DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
// callback to check useful signatures
{
	verify_parms *const vh = (verify_parms*)dkim_get_user_context(dkim);
	
	assert(dkim && sigs && vh);
	int *val = (int*)malloc(nsigs * sizeof(int));
	if (val == NULL)
		return DKIM_CBSTAT_TRYAGAIN;

	int const vbr_count = count_trusted_vouchers(vh->parm->trusted_vouchers);
	int const vbr_factor = vbr_count < 2? 0: 1000/(vbr_count - 1);

	size_t const helolen = vh->helo_domain? strlen(vh->helo_domain): 0;

	// will this always be supported here?
	if (vh->dkim_domain == NULL)
		vh->dkim_domain = dkim_getdomain(dkim);
	
	// establish a value for each signature
	for (int c = 0; c < nsigs; ++c)
	{
		int sigval = 0;
		DKIM_SIGERROR err = dkim_sig_geterror(sigs[c]);
		if (err == DKIM_SIGERROR_UNKNOWN || err == DKIM_SIGERROR_OK)
		{
			char *domain = dkim_sig_getdomain(sigs[c]);
			if (domain)
			{
				if (vh->dkim_domain && stricmp(vh->dkim_domain, domain) == 0)
				{
					sigval += 2000;    // author domain signature
					++vh->auth_sigs;
				}

				if (domain_is_whitelisted(vh, domain))
					sigval += 1000;    // trusted signer

				vbr_info *const vbr = vbr_info_get(vh->vbr, domain);
				if (vbr)
				{
					sigval += 5;       // sender's adverized vouching
					if (vbr_count)
					{
						/*
						* for trusted vouching, add a value ranging linearly
						* from 1200 for trust=1 down to 200 for trust=vbr_count
						* assuming 1 <= trust <= vbr_count
						*/
						int trust = has_trusted_voucher(vh, vbr);
						if (trust)
						{
							sigval += vbr_factor * (vbr_count - trust) + 200;
							++vh->trusted_sigs;
						}
					}
				}

				if (vh->sender_domain && stricmp(vh->sender_domain, domain) == 0)
					sigval += 100;     // sender's domain signature

				if (helolen)
				{
					size_t dl = strlen(domain);
					char *helocmp = vh->helo_domain;
					if (helolen > dl)
						helocmp += helolen - dl;
					// should check it's not co.uk or similar...
					if (stricmp(helocmp, domain) == 0)
						sigval += 10;   // helo domain signature
				}
			}
		}

#if 0
		// domain may have a reputation...
		if (sigval <= 0)
			dkim_sig_ignore(sigs[c]);
#endif
		val[c] = sigval;
	}

	// sort signatures high values first (gnome sort)
	int c = 0;
	while (c < nsigs)
		if (c == 0 || val[c] <= val[c-1])
			++c;
		else
		{
			DKIM_SIGINFO *tsig = sigs[c];
			sigs[c] = sigs[c-1];
			sigs[c-1] = tsig;
			int tint = val[c];
			val[c] = val[c-1];
			val[c-1] = tint;
			--c;
		}

	free(val);
	return DKIM_CBSTAT_CONTINUE;
}

static void clean_stats(dkimfl_parm *parm)
{
	assert(parm);
	assert(parm->dyn.stats);
	
	clean_stats_info_content(parm->dyn.stats);
	free(parm->dyn.stats);
	parm->dyn.stats = NULL;
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
	
	for (;;)
	{
		char *p = vb_fgets(vb, keep, fp);
		char *eol = p? strchr(p, '\n'): NULL;

		if (eol == NULL)
		{
			if (parm->verbose)
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

		// count A-R fields that have to be removed
		else if ((s = hdrval(start, "Authentication-Results")) != NULL)
		{
			if ((s = skip_cfws(s)) == NULL)
				zap = 1; // bogus
			else
			{
				char *const authserv_id = s;
				int ch;
				while (isalnum(ch = *(unsigned char*)s) || ch == '.')
					++s;
				if (s == authserv_id)
					zap = 1; // bogus
				else
				{
					int maybe_attack = 0;
					*s = 0;
					/*
					* An A-R field before any "Received" must have been set by us.
					* After first "Received", if the authserv_id matches it may
					* be an attack (or our mail coming back from a mailing list).
					*/
					if (parm->dyn.authserv_id &&
						stricmp(authserv_id, parm->dyn.authserv_id) == 0)
							maybe_attack = zap = 1;
					if (dkim == NULL && parm->verbose >= 2) // log on 2nd pass only
					{
						if (maybe_attack)
							fl_report(LOG_NOTICE,
								"id=%s: removing Authentication-Results from %s",
								parm->dyn.info.id, authserv_id);
						else if (parm->verbose >= 6)
							fl_report(LOG_INFO,
								"id=%s: found Authentication-Results by %s",
								parm->dyn.info.id, authserv_id);
					}
					// TODO: check a list of trusted/untrusted id's
					*s = ch;
				}
			}
		}
		
		// (only on first pass and Received*)
		// cache courier's SPF results, get authserv_id, count Received
		else if (dkim && strincmp(start, "Received", 8) == 0)
		{
			if ((s = hdrval(start, "Received")) != NULL)
			{
				if (parm->dyn.stats)
					parm->dyn.stats->rhcnt += 1;

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

			else if (!parm->no_spf && vh->received_spf < 2 &&
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

		// (only on first pass and stats enabled)
		// save stats' ct and cte, check fromlist, collect VBR-Info
		else if (dkim && parm->dyn.stats)
		{
			char **target = NULL;
			if ((s = hdrval(start, "Content-Type")) != NULL)
				target = &parm->dyn.stats->ct;
			else if ((s = hdrval(start, "Content-Transfer-Encoding")) != NULL)
				target = &parm->dyn.stats->cte;

			if (target)
			{
				// trim left
				while (isspace(*(unsigned char*)s))
					++s;
				// find terminator
				char *const tok = s;
				int ch;
				while ((ch = *(unsigned char*)s) != 0 && ch != ';')
					++s;
				// trim right
				while (s > tok && isspace(*(unsigned char*)(s - 1)))
					--s;
				// duplicate possibly signed value
				ch = *s;
				*s = 0;
				*target = strdup(tok);
				*s = ch;
				// avoid newlines and tabs inside the field
				if ((s = *target) != NULL)
				{
					while ((ch = *(unsigned char*)s) != 0)
					{
						if (isspace(ch))
							*s = ' ';
						++s;
					}
				}
				else
					clean_stats(parm);
			}
			
			else if ((s = hdrval(start, "Precedence")) != NULL)
			{
				while (isspace(*(unsigned char*)s))
					++s;
				size_t len;
				int ch;
				if (strincmp(s, "list", 4) == 0 &&
					((len = strlen(s)) <= 4 ||
						(ch = ((unsigned char*)s)[5]) == ';' || isspace(ch)))
							parm->dyn.stats->fromlist = 1;
			}
			
			else if (strincmp(start, "List-", 5) == 0)
			{
				if (hdrval(start, "List-Id") ||
					hdrval(start, "List-Post") ||
					hdrval(start, "List-Unsubscribe"))
						parm->dyn.stats->fromlist = 1;
			}
			
			else if (hdrval(start, "Mailing-List"))
				parm->dyn.stats->fromlist = 1;

			else if ((s = hdrval(start, "VBR-Info")) != NULL)
			{
				int const rtc = vbr_info_add(&vh->vbr, s);
				if (rtc < 0)
				{
					fl_report(LOG_ALERT, "MEMORY FAULT");
					return parm->dyn.rtc = -1;
				}
				else if (rtc && parm->verbose >= 3)
					fl_report(LOG_INFO, "id=%s: bad VBR-Info: %s",
						parm->dyn.info.id, s);
			}
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
				if (parm->verbose)
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
		dkim_set_final(parm->dklib, dkim_sig_sort);
		
		DKIM_STAT status = dkim_eoh(dkim);
		if (status != DKIM_STAT_OK)
		{
			if (parm->verbose >= 7 ||
				parm->verbose >= 5 && status != DKIM_STAT_NOSIG)
			{
				char const *err = dkim_getresultstr(status);
				fl_report(LOG_INFO,
					"id=%s: verifying dkim_eoh: %s (stat=%d)",
					parm->dyn.info.id, err? err: "(NULL)", (int)status);
			}
			// return parm->dyn.rtc = -1;
		}
		
		if (parm->dyn.authserv_id == NULL && parm->verbose)
			fl_report(LOG_ERR,
				"id=%s: missing courier's Received field",
				parm->dyn.info.id);
	}
	else if (ferror(out))
	{
		if (parm->verbose)
			fl_report(LOG_ALERT,
				"id=%s: frwite failed with %s",
				parm->dyn.info.id, strerror(errno));
		return parm->dyn.rtc = -1;
	}

	return parm->dyn.rtc;
}

static inline int sig_is_good(DKIM_SIGINFO *const sig)
{
	unsigned int const sig_flags = dkim_sig_getflags(sig);
	unsigned int const bh = dkim_sig_getbh(sig);
	DKIM_SIGERROR const err = dkim_sig_geterror(sig);
	return (sig_flags & DKIM_SIGFLAG_IGNORE) == 0 &&
		(sig_flags & DKIM_SIGFLAG_PASSED) != 0 &&
		bh == DKIM_SIGBH_MATCH &&
		err == DKIM_SIGERROR_OK;
}

static int run_vbr_check(verify_parms *vh, char const *const domain)
{
	assert(vh);
	assert(vh->parm);

	dkimfl_parm *parm = vh->parm;
	size_t const queries = vh->vbr_result.queries;

	vh->vbr_result.vbr = NULL;
	vh->vbr_result.mv = NULL;
	vh->vbr_result.tv = vh->parm->trusted_vouchers;
	int rc = vbr_check(vh->vbr, domain, &is_trusted_voucher, &vh->vbr_result);
	if (rc != 0 && parm->verbose >= 3)
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
	if (parm->dyn.authserv_id == NULL)
	{
		clean_stats(parm);
		vbr_info_clear(vh.vbr);
		vh.vbr = NULL;
	}
	else if (parm->dyn.rtc == 0)
	{
		if (dkim_minbody(dkim) > 0)
			copy_body(parm, dkim);

		status = dkim_eom(dkim, NULL);

		// author domain signature (if passed) is on top
		vh.sig = dkim_getsignature(dkim);
		vh.sig_domain = vh.sig? dkim_sig_getdomain(vh.sig): NULL;
		vh.sig_is_author = vh.sig_domain && vh.dkim_domain &&
			stricmp(vh.sig_domain, vh.dkim_domain) == 0;

		/*
		* VBR and whitelist
		*/
		if ((parm->no_dwl == 0 || parm->domain_whitelist) && status == DKIM_STAT_OK)
		{
			DKIM_SIGINFO **sigs;
			int nsigs;
			if (dkim_getsiglist(dkim, &sigs, &nsigs) == DKIM_STAT_OK)
			{
				int at_or_after = 0;
				for (int c = 0; c < nsigs; ++c)
				{
					DKIM_SIGINFO *const sig = sigs[c];
					if (sig == vh.sig)
						at_or_after = 1;
					if (at_or_after)
					{
						char *const domain = dkim_sig_getdomain(sig);
						if (domain != NULL && sig_is_good(sig))
						{
							if (!parm->no_dwl && vh.vbr_sig == NULL &&
								run_vbr_check(&vh, domain) == 0)
							{
								vh.vbr_sig = sig;
								if (vh.whitelisted_sig != NULL ||
									parm->domain_whitelist == NULL)
										break;
							}
							
							if (parm->domain_whitelist && vh.whitelisted_sig == NULL &&
								domain_is_whitelisted(&vh, domain))
							{
								vh.whitelisted_sig = sig;
								vh.whitelisted_domain = domain;
								if (vh.vbr_sig != NULL || parm->no_dwl)
									break;
							}
						}
					}
				}
			}
		}

		// if no DKIM domain is vouched but SPF passed, try that
		if (vh.vbr_sig == NULL && vh.sender_domain != NULL && parm->no_dwl == 0 &&
			run_vbr_check(&vh, vh.sender_domain) == 0)
				vh.vbr_sig = not_sig_but_spf;

		// if no DKIM domain is whitelisted but SPF passed, try that
		if (vh.whitelisted_sig == NULL && vh.sender_domain != NULL &&
			domain_is_whitelisted(&vh, vh.sender_domain))
		{
			vh.whitelisted_sig = not_sig_but_spf;
			vh.whitelisted_domain = vh.sender_domain;
		}

		
		switch (status)
		{
			case DKIM_STAT_OK:
				vh.dkim_result = "pass";
				break;

			case DKIM_STAT_NOSIG:
				vh.dkim_result = "none";
				break;

			case DKIM_STAT_BADSIG:
			case DKIM_STAT_CANTVRFY:
			case DKIM_STAT_REVOKED:
				//vh.dkim_result = NULL for fail or neutral
				break;

			case DKIM_STAT_NORESOURCE:
			case DKIM_STAT_INTERNAL:
			case DKIM_STAT_CBTRYAGAIN:
			case DKIM_STAT_KEYFAIL:
				parm->dyn.rtc = -1;
				vh.dkim_result = "temperror";
				break;

			case DKIM_STAT_SYNTAX:
			default:
				vh.dkim_result = "permerror";
				break;
		}

		if (parm->dyn.rtc == 0)
		{
			if ((vh.dkim_domain != NULL ||
					(vh.dkim_domain = dkim_getdomain(dkim)) != NULL) &&
				dkim_policy(dkim, &vh.policy, NULL) == DKIM_STAT_OK)
			{
				vh.presult = dkim_getpresult(dkim);
				bool const adsp_fail =
					(vh.policy == DKIM_POLICY_DISCARDABLE ||
						vh.policy == DKIM_POLICY_ALL) &&
					/* redundant: vh.presult == DKIM_PRESULT_AUTHOR && */
					(!vh.sig_is_author || status != DKIM_STAT_OK);
				if (parm->dyn.stats)
				{
					parm->dyn.stats->adsp_found = vh.presult == DKIM_PRESULT_AUTHOR;
					parm->dyn.stats->adsp_unknown = vh.policy == DKIM_POLICY_UNKNOWN;
					parm->dyn.stats->adsp_all = vh.policy == DKIM_POLICY_ALL;
					parm->dyn.stats->adsp_discardable =
						vh.policy == DKIM_POLICY_DISCARDABLE;
					parm->dyn.stats->adsp_fail = adsp_fail;
				}

				/*
				* unless disabled by parameter or whitelisted, do action:
				* reject if dkim_domain is not valid, or ADSP == all,
				* discard if ADSP == discardable;
				*/
				if (!parm->no_author_domain &&
						(vh.presult == DKIM_PRESULT_NXDOMAIN || adsp_fail))
/*							((vh.policy == DKIM_POLICY_DISCARDABLE ||
								vh.policy == DKIM_POLICY_ALL) &&
							vh.presult == DKIM_PRESULT_AUTHOR &&
							(!vh.sig_is_author || status != DKIM_STAT_OK))))
*/
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

					if (parm->verbose >= 3)
					{
						if (vh.whitelisted_domain)
							fl_report(LOG_INFO,
								"id=%s: %s %s, but %s is whitelisted (auth: %s)",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain,
								vh.whitelisted_domain,
								vh.whitelisted_sig == not_sig_but_spf? "SPF": "DKIM");
						else if (vh.vbr_sig)
							fl_report(LOG_INFO,
								"id=%s: %s %, but %s is VBR vouched by %s (auth: %s)",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain,
								vh.vbr_result.vbr->md,
								vh.vbr_result.mv,
								vh.vbr_sig == not_sig_but_spf? "SPF": "DKIM");
						else
							fl_report(LOG_INFO,
								"id=%s: %s %s, no VBR and no whitelist",
								parm->dyn.info.id,
								log_reason,
								vh.dkim_domain);
					}

					if (vh.vbr_sig == NULL && vh.whitelisted_sig == NULL)
					{
						if (smtp_reason) //reject
							fl_pass_message(parm->fl, smtp_reason);
						else // drop, and stop filtering
						{
							fl_pass_message(parm->fl, "050 Message dropped.\n");
							fl_drop_message(parm->fl, "adsp=discard\n");
						}
						
						parm->dyn.rtc = 2;
					}
				}
			}
		}
		
		if (parm->dyn.rtc == 0 &&
			!parm->no_reputation && status == DKIM_STAT_OK && vh.sig)
		{
			int rep;
			/*
			* (don't) reject on passing configured value
			*/
			if (dkim_get_reputation(dkim, vh.sig, DKIM_REP_ROOT, &rep) ==
				DKIM_STAT_OK)
			{
				vh.dkim_reputation = rep;
				vh.dkim_reputation_flag = 1;
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
				policy_result = vh.sig_is_author && status == DKIM_STAT_OK?
					"pass": "fail";
			}
			else if (vh.policy == DKIM_POLICY_DISCARDABLE)
			{
				policy_type = " adsp:discardable=";
				policy_result = vh.sig_is_author && status == DKIM_STAT_OK?
					"pass": "discard";
			}
		}

		/*
		* write the A-R field if required anyway, spf, or signature
		*/
		if (parm->dyn.rtc == 0 &&
			(parm->add_a_r_anyway ||
				vh.sender_domain || vh.helo_domain ||
				vh.sig || vh.vbr_sig || vh.whitelisted_sig ||
				*policy_result))
		{
			FILE *fp = fl_get_write_file(parm->fl);
			if (fp == NULL)
			{
				parm->dyn.rtc = -1;
				if (parm->dyn.stats)
					parm->dyn.stats->dkim = dkim;
				else
					dkim_free(dkim);

				vbr_info_clear(vh.vbr);
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

			if (vh.sig)
			{
				char buf[80], *id = NULL, htype;
				memset(buf, 0, sizeof buf);
				if (dkim_sig_getidentity(dkim, vh.sig, buf, sizeof buf) ==
					DKIM_STAT_OK)
				{
					id = buf;
					htype = 'i';
				}
				else if ((id = vh.sig_domain) != NULL)
					htype = 'd';
				
				if (id)
				{
					char const *err = NULL;
					
					if (status != DKIM_STAT_OK)
					{
						DKIM_SIGERROR rc = dkim_sig_geterror(vh.sig);
						if (rc == DKIM_SIGERROR_OK)
						{
							if (dkim_sig_getbh(vh.sig) == DKIM_SIGBH_MISMATCH)
								err = "body hash mismatch";
							else
								err = dkim_getresultstr(status);
						}
						else
							err = dkim_sig_geterrorstr(rc);
					}

					if (vh.dkim_result)
					{
						fprintf(fp, ";\n  dkim=%s ", vh.dkim_result);
						if (err)
							fprintf(fp, "(%s) ", err);
					}
					else
					{
						unsigned int const flags = dkim_sig_getflags(vh.sig);
						int const is_test = (flags & DKIM_SIGFLAG_TESTKEY) != 0;
						vh.dkim_result = is_test? "neutral": "fail";
						fprintf(fp, ";\n  dkim=%s ", vh.dkim_result);
						if (err && is_test)
							fprintf(fp, "(test key, %s) ", err);
						else if (err)
							fprintf(fp, "(%s) ", err);
						else if (is_test)
							fputs("(test key) ", fp);
					}

					fprintf(fp, "header.%c=%s", htype, id);
					++auth_given;
					
					if (parm->verbose >= 3)
					{
						fl_report(LOG_INFO,
							"id=%s: verified:%s dkim=%s (id=%s, %s%sstat=%d)%s%s rep=%d",
							parm->dyn.info.id,
							(vh.sender_domain || vh.helo_domain)? " spf=pass,": "",
							vh.dkim_result,
							id,
							err? err: "", err? ", ": "",
							(int)status,
							policy_type, policy_result,
							vh.dkim_reputation);
						log_written += 1;
					}
				}
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
			
			if (vh.dkim_reputation_flag && vh.sig_domain)
			{
				fprintf(fp, ";\n  x-dkim-rep=%s (%d from %s) header.d=%s",
					vh.dkim_reputation >= parm->reputation_fail? "fail":
					vh.dkim_reputation <= parm->reputation_pass? "pass": "neutral",
						vh.dkim_reputation, DKIM_REP_ROOT, vh.sig_domain);
				++auth_given;
			}

			if (vh.vbr_result.resp)
			{
				fprintf(fp,
					";\n  vbr=pass header.mv=%s header.md=%s (%s)",
					vh.vbr_result.mv, vh.vbr_result.vbr->md, vh.vbr_result.resp);
				if (parm->dyn.stats)
					parm->dyn.stats->vbr_result = vh.vbr_result.resp;
				else
				{
					free(vh.vbr_result.resp);
					vh.vbr_result.resp = NULL;
				}
				++auth_given;
			}

			if (auth_given <= 0)
				fputs("; none", fp);
			fputc('\n', fp);
			if (parm->dyn.stats)
				parm->dyn.stats->dkim = dkim;
			else
				dkim_free(dkim);
			dkim = NULL;

			if (log_written == 0 && parm->verbose >= 7)
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
	}

	if (dkim)
		if (parm->dyn.stats)
			parm->dyn.stats->dkim = dkim;
		else
			dkim_free(dkim);

	free(vh.vbr_result.resp); // TODO: check dyn.stats above!!!!!!!
	vbr_info_clear(vh.vbr);
}

static void set_client_ip(dkimfl_parm *parm)
{
	char *s;
	
	if (parm->dyn.stats && parm->dyn.stats->dkim == NULL)
		clean_stats(parm);
	
	if (parm->dyn.stats && (s = parm->dyn.info.frommta) != NULL &&
		strincmp(s, "dns;", 4) == 0)
	{
		s += 4;
		int ch;
		while ((ch = *(unsigned char*)s) != 0 && isspace(ch))
			++s;
		parm->dyn.stats->client_ip = s;
	}
}

static char *lcdomain(char*domain)
{
	if (domain)
	{
		char *d = strdup(domain);
		if (d)
		{
			char *s = d;
			int ch;
			while ((ch = *s) != 0)
			{
				if (isascii(ch) && isupper(ch))
					*s = tolower(ch);
				++s;
			}
			return d;
		}
	}
	return NULL;
}

static void write_stats(dkimfl_parm *parm, FILE *fp)
{
	DKIM *dkim = parm->dyn.stats->dkim;
	DKIM_SIGINFO **sigs;
	int nsigs = 0;
	int status = dkim_getsiglist(dkim, &sigs, &nsigs);
	if (status != DKIM_STAT_OK)
	{
		if (parm->verbose)
			fl_report(LOG_ALERT,
				"id=%s: dkim_getsiglist() failed",
				parm->dyn.info.id);
		return;
	}

	char *fromdomain = dkim_getdomain(dkim);
	if (fromdomain == NULL)
	{
		if (parm->verbose >= 8)
			fl_report(LOG_DEBUG,
				"id=%s: dkim_getdomain() failed",
				parm->dyn.info.id);
		return;
	}

	fromdomain = lcdomain(fromdomain);
	if (fromdomain == NULL)
	{
		if (parm->verbose)
			fl_report(LOG_ALERT,
				"id=%s: strdup() failed",
				parm->dyn.info.id);
		return;
	}

	stats_info const*const stats = parm->dyn.stats;
	fprintf(fp, "M%s\t%s\t%s\t%s\t0\t%ld",
		stats->jobid,
		parm->dyn.authserv_id,
		fromdomain,
		stats->client_ip? stats->client_ip: "unknown",
		/* 0 = not anon, */
		(long)time(NULL));

	off_t canonlen = 0;
	off_t signlen = 0;
	off_t msglen = 0;
	if (nsigs > 0)
		dkim_sig_getcanonlen(dkim, sigs[0], &msglen, &canonlen, &signlen);

#if !defined NDEBUG
	if (parm->verbose)
	{
		bool validauthorsig = false;
		for (int c = 0; c < nsigs; ++c)
		{
			if (stricmp(dkim_sig_getdomain(sigs[c]), fromdomain) == 0 &&
				 dkim_sig_geterror(sigs[c]) == DKIM_SIGERROR_OK)
			{
				validauthorsig = true;
				break;
			}
		}
	
		bool const my_adsp_fail = !validauthorsig &&
			(stats->adsp_all || stats->adsp_discardable);
		if (stats->adsp_fail != my_adsp_fail)
			fl_report(LOG_ERR,
				"id=%s: ADSP wrong: my=%d, passed=%d",
				parm->dyn.info.id,
				my_adsp_fail, stats->adsp_fail);
	}
#endif

	fprintf(fp, "\t%lu\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%u\t%s\t%s\n",
		msglen,
		nsigs,
		stats->adsp_found,
		stats->adsp_unknown,
		stats->adsp_all,
		stats->adsp_discardable,
		stats->adsp_fail,
		stats->fromlist,
		stats->rhcnt,
		stats->ct? stats->ct: "text/plain",
		stats->cte? stats->cte: "7bit");
	free(fromdomain);

	for (int c = 0; c < nsigs; ++c)
	{
		dkim_alg_t alg = 0;
		dkim_sig_getsignalg(sigs[c], &alg);
		dkim_canon_t bc = 0;
		dkim_canon_t hc = 0;
		dkim_sig_getcanons(sigs[c], &hc, &bc);

		char *sigdomain = lcdomain(dkim_sig_getdomain(sigs[c]));
		fprintf(fp, "S%s\t%d\t%d\t%d",
			sigdomain? sigdomain: "-", alg, hc, bc);
		free(sigdomain);

		unsigned int const flags = dkim_sig_getflags(sigs[c]);
		dkim_sig_getcanonlen(dkim, sigs[c], &msglen, &canonlen, &signlen);
		fprintf(fp, "\t%d\t%d\t%d\t%ld",
			(flags & DKIM_SIGFLAG_IGNORE) != 0,
			(flags & DKIM_SIGFLAG_PASSED) != 0,
			dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MISMATCH,
			(long)signlen);

#if HAVE_LIBOPENDKIM_22
		char *p = dkim_sig_gettagvalue(sigs[c], true, "t");
		fprintf(fp, "\t%d", p != NULL);
		
		p = dkim_sig_gettagvalue(sigs[c], true, "g");
		fprintf(fp, "\t%d\t%d",
			p != NULL,
			p != NULL && *p != '\0' && *p != '*');


		/* DK-compatible keys */
		fprintf(fp, "\t%d",
			dkim_sig_gettagvalue(sigs[c], true, "v") == NULL &&
				p && *p == '\0');
		
		/* syntax error codes */
		fprintf(fp, "\t%d", dkim_sig_geterror(sigs[c]));

		fprintf(fp, "\t%d\t%d\t%d\t%d",
			dkim_sig_gettagvalue(sigs[c], false, "t") != NULL,
			dkim_sig_gettagvalue(sigs[c], false, "x") != NULL,
			dkim_sig_gettagvalue(sigs[c], false, "z") != NULL,
			dkim_sig_getdnssec(sigs[c]));

		p = dkim_sig_gettagvalue(sigs[c], false, "h");
		fputc('\t', fp);
		if (p == NULL)
			fputc('-', fp);
		else
		{
			int ch;
			while ((ch = *(unsigned char*)p) != 0)
			{
				if (isascii(ch) && isupper(ch))
					ch = tolower(ch);
				putc(ch, fp);
				++p;
			}
		}
#else /* HAVE_LIBOPENDKIM_22 */
		fprintf(fp, "\t-\t-\t-\t-\t%d\t-\t-\t-\t%d\t-",
			dkim_sig_geterror(sigs[c]),
			dkim_sig_getdnssec(sigs[c]));
#endif
		fputs("\t-\n", fp); /* DIFFHEADERS  not supported */
	}
}

static void after_filter_stats(fl_parm *fl)
{
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	
	set_client_ip(parm);
	while (parm->dyn.stats)
	{
		FILE *fp = fopen(parm->stats_file, "a");
		if (fp)
		{
			int fd = fileno(fp), rc, save_errno;
			struct flock lock;
		
			memset(&lock, 0, sizeof lock);
			lock.l_type = F_WRLCK;
			lock.l_whence = SEEK_SET;
			lock.l_len = 1;

			fl_init_signal(init_signal_lock); // catch USR1 and ALRM
			fl_alarm(parm->stats_wait);
			rc = fcntl(fd, F_SETLKW, &lock);
			save_errno = errno;
			fl_alarm(0);
			fl_reset_signal(); // ignore USR1, ALRM terminates
			if (rc == 0)
			{
				write_stats(parm, fp);
			}
			else if (save_errno == EINTR)
			{
				/*
				* if file has been moved, reopen old name;
				* if alarm fired, slip through.
				*/
				if (fl_keep_running())
				{
					fclose(fp);
					continue;
				}
			}
			else if (parm->verbose)
			{
				fl_report(LOG_ALERT,
					"id=%s: cannot lock %s: %s",
					parm->dyn.info.id,
					parm->stats_file,
					strerror(errno));
			}

			fclose(fp); // this releases the lock as well
		}
		else if (parm->verbose)
		{
			fl_report(LOG_ALERT,
				"id=%s: cannot open %s: %s",
				parm->dyn.info.id,
				parm->stats_file,
				strerror(errno));
		}

		clean_stats(parm);
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
			sign_message(parm);
	}
	else
	{
		if (vb_init(&parm->dyn.vb))
			parm->dyn.rtc = -1;
		else
		{
			/*
			* if a stats file is configured, prepare stats info and
			* in case no error occurs, request after_filter processing.
			*
			* functions may call clean_stats to stop it
			*/
			if (parm->dyn.info.id != default_jobid &&
				parm->stats_file &&
				(parm->dyn.stats = malloc(sizeof *parm->dyn.stats)) != NULL)
			{
				memset(parm->dyn.stats, 0, sizeof *parm->dyn.stats);
				parm->dyn.stats->jobid = parm->dyn.info.id;
			}
			verify_message(parm);
			if (parm->dyn.stats)
				fl_set_after_filter(parm->fl, after_filter_stats);
		}
	}
	vb_clean(&parm->dyn.vb);

	static char const resp_tempfail[] =
		"432 Mail filter temporarily unavailable.\n";
	int verbose_threshold = 4;
	switch (parm->dyn.rtc)
	{
		case -1: // unrecoverable error
			if (parm->tempfail_on_error)
			{
				fl_pass_message(fl, resp_tempfail);
				verbose_threshold = 3;
			}
			else
				fl_pass_message(fl, "250 Failed.\n");
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
	}

	assert(fl_get_passed_message(fl) != NULL);

	if (parm->verbose >= verbose_threshold)
	{
		char const *msg = fl_get_passed_message(fl);
		int l = strlen(msg) - 1;
		assert(l > 0 && msg[l] == '\n');
		fl_report(LOG_INFO,
			"id=%s: response: %.*s", parm->dyn.info.id, l, msg);
	}

	// TODO: free dyn allocated stuff (almost useless at this point)
}

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
	
	if (nok || parm->verbose >= 8)
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
	if (vh && vh->parm && vh->parm->verbose >= 8)
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
	if (status != DKIM_STAT_OK || parm->verbose >= 8)
		fl_report(status != DKIM_STAT_OK? LOG_ERR: LOG_INFO,
			"DKIM policy method%s set to file \"%s\"",
			status != DKIM_STAT_OK? " not": "", policyfile);
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
		fprintf(stderr,
			"ALERT: zdkimfilter: cannot %s %s: %s\n",
			failed_action, pid_file, strerror(errno));
}

static void delete_pid_file(dkimfl_parm *parm)
{
	if (parm->pid_created &&
		unlink(pid_file) != 0)
			fprintf(stderr, "ERR: avfilter: cannot delete %s: %s\n",
				pid_file, strerror(errno));
}


static fl_init_parm functions =
{
	dkimfilter,
	write_pid_file,
	NULL, NULL, NULL,
	report_config, set_keyfile, set_policyfile, NULL	
};

int main(int argc, char *argv[])
{
	int rtc = 0, i;
	char *config_file = NULL;

	for (i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		
		if (strcmp(arg, "-f") == 0)
		{
			config_file = ++i < argc ? argv[i] : NULL;
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
				"Reported OpenSSL version: %#lX\n",
				(long)(OPENDKIM_LIB_VERSION),
#if defined HAVE_LIBOPENDKIM_22
				dkim_libversion(),
				dkim_libversion() ==	(unsigned long)(OPENDKIM_LIB_VERSION)? "":
					"DO NOT ",
#endif
				dkim_ssl_version());
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			printf("zdkimfilter command line args:\n"
			/*  12345678901234567890123456 */
				"  -f config-filename      override %s\n"
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
	if (parm_config(&parm, config_file))
	{
		rtc = 2;
		fl_report(LOG_ERR, "Unable to read config file");
	}

#if defined HAVE_LIBOPENDKIM_22
	if (parm.verbose >= 2 &&
		dkim_libversion() !=	(unsigned long)(OPENDKIM_LIB_VERSION))
			fl_report(LOG_WARNING,
				"Mismatched library versions: compile=%#lX link=%#lX",
				(unsigned long)(OPENDKIM_LIB_VERSION),
				dkim_libversion());
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
		if (!parm.no_signlen)
		{
			unsigned int options = 0;
			nok |= dkim_options(parm.dklib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
				&options, sizeof options) != DKIM_STAT_OK;
			options |= DKIM_LIBFLAGS_SIGNLEN;
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
				&options, sizeof options) != DKIM_STAT_OK;
		}
		
		if (parm.dns_timeout > 0) // DEFTIMEOUT is 10 secs
		{
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_TIMEOUT,
				&parm.dns_timeout, sizeof parm.dns_timeout) != DKIM_STAT_OK;
		}
		
		if (parm.tmp)
		{
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_TMPDIR,
				parm.tmp, sizeof parm.tmp) != DKIM_STAT_OK;
		}
		
		nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
			parm.sign_hfields?
				cast_u_char_parm_array(parm.sign_hfields):
				dkim_should_signhdrs,
					sizeof parm.sign_hfields) != DKIM_STAT_OK;

		nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_SKIPHDRS,
			parm.skip_hfields?
				cast_u_char_parm_array(parm.skip_hfields):
				dkim_should_not_signhdrs,
					sizeof parm.skip_hfields) != DKIM_STAT_OK;

		if (nok)
		{
			rtc = 2;
			fl_report(LOG_ERR, "Unable to set lib options");
		}
	}

	if (rtc == 0)
	{
		rtc =
			fl_main(&functions, &parm, argc, argv, parm.all_mode, parm.verbose);
		delete_pid_file(&parm);
	}

	// TODO: free memory allocated by parm_config (almost useless)
	if (parm.dklib)
		dkim_close(parm.dklib);
	return rtc;
}
