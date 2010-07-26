/*
* zdkimfilter - written by ale in milano on Thu 11 Feb 2010 03:48:15 PM CET 
* Sign outgoing, verify incoming mail messages

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
with OpenDKIM, containing parts covered by the applicable licence, the licensor
or zdkimfilter grants you additional permission to convey the resulting work.
*/
#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
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
#include <opendkim/dkim.h>
#include <config.h>
#include <stddef.h>
#include "filterlib.h"
#include "filedefs.h"

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
// ----- end utilities

typedef struct per_message_parm
{
	dkim_sigkey_t key;
	char *selector;
	char *authserv_id;
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
	const u_char **sign_hfields;
	const u_char **skip_hfields;
	const u_char **spf_whitelist;
	const u_char **dkim_whitelist;

	// end of pointers (some malloc'd but never free'd)
	per_message_parm dyn;
	int verbose;
	int dns_timeout;
	int reputation_fail, reputation_pass;
	char add_a_r_anyway;
	char no_spf;
	char no_signlen;
	char tempfail_on_error;
	char no_author_domain;
	char no_reputation;
	char all_mode;
	char sign_rsa_sha1;
	char header_canon_relaxed;
	char body_canon_relaxed;
	
} dkimfl_parm;

static void config_default(dkimfl_parm *parm) // only non-zero...
{
	static char const keys[] = COURIER_SYSCONF_INSTALL "/filters/keys";
	parm->domain_keys = (char*) keys; // won't be freed
	parm->reputation_fail = 32767;
	parm->reputation_pass = -32768;
	parm->verbose = 3;
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

static int hfields(char *h, const u_char **a)
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
	assert(parm && c && s && c->size == sizeof(u_char**));

	const u_char **a = NULL;
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
		a = (const u_char**)all;
		all += n;
		strcpy(all, s);
		a[count] = NULL;		
		count -= hfields(all, a);
	}
	assert(count == 0);

	PARM_PTR(const u_char **) = a;
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
	CONFIG(sign_hfields, "space-separated, no colon", assign_array),
	CONFIG(skip_hfields, "space-separated, no colon", assign_array),
	CONFIG(spf_whitelist, "space-separated domains", assign_array),
	CONFIG(dkim_whitelist, "space-separated domains", assign_array),
	CONFIG(verbose, "int", assign_int),
	CONFIG(dns_timeout, "secs", assign_int),
	CONFIG(reputation_fail, "high int", assign_int),
	CONFIG(reputation_pass, "low int", assign_int),
	CONFIG(add_a_r_anyway, "Y/N", assign_char),
	CONFIG(no_spf, "Y/N", assign_char),
	CONFIG(no_signlen, "Y/N", assign_char),
	CONFIG(tempfail_on_error, "Y/N", assign_char),
	CONFIG(no_author_domain, "Y=skip \"From:\" check", assign_char),
	CONFIG(no_reputation, "Y=skip reputation lookup", assign_char),
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
			u_char const ** const a = PARM_PTR(u_char const**);
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
	else
	{
		char buf[8192], *p = &buf[0], *const start = &buf[0],
			*const ebuf = &buf[sizeof buf - 1];
		int errs = 0;

		while (fgets(p, ebuf - p, fp))
		{
			int ch = 0;
			++line_no;
			char *eol = strchr(p, '\n');
			if (eol == NULL)
				goto error_exit;

			while (eol >= p && isspace(ch = *(unsigned char*)eol))
				*eol-- = 0;

			if (ch == '\\')
			{
				*eol = ' '; // this replaces the backslash
				p = eol + 1;
				if (p >= ebuf)
					goto error_exit;
				continue;
			}

			char *s = p = start;
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
		
		fclose(fp);
		if (errs == 0)
			config_wrapup(parm);

		return errs;
	}

	error_exit:
	{
		fl_report(LOG_ERR,
			"Line too long at line %d in %s", line_no, fname);
		fclose(fp);
		return -1;
	}
}

static int read_key(dkimfl_parm *parm, char *fname)
// read private key and selector from disk, return 0 or parm->dyn.rtc = -1
{
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
		{
			if (parm->verbose >= 7)
				fl_report(LOG_INFO,
					"id=%s: not signing for %s: no key",
					parm->dyn.info.id,
					fname);
			return 0;
		}
		goto error_exit;
	}
	
	if ((key = malloc(st.st_size + 1)) == NULL ||
		(fp = fopen(buf, "r")) == NULL ||
		fread(key, st.st_size, 1, fp) != 1)
			goto error_exit;
	
	fclose(fp);
	fp = NULL;
	key[st.st_size] = 0;

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
		if (errno != EINVAL && parm->tempfail_on_error)
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

static int sign_headers(dkimfl_parm *parm, DKIM *dkim)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(parm && dkim);

	FILE* fp = fl_get_file(parm->fl);
	assert(fp);
	char buf[8192], *p = &buf[0], *const start = &buf[0];
	DKIM_STAT status;
	
	while (fgets(p, sizeof buf - 1 - (p - start), fp))
	{
		char *eol = strchr(p, '\n');

		if (eol == NULL)
		{
			if (parm->verbose)
				fl_report(LOG_ALERT,
					"id=%s: header too long (%.20s...)",
					parm->dyn.info.id, start);
			return parm->dyn.rtc = -1;
		}

		int const next = fgetc(fp);
		int const cont = next != EOF && next != '\n';
		if (cont && isspace(next)) // wrapped
		{
			*eol++ = '\r';
			*eol++ = '\n';
			*eol = next;
			p = eol + 1;
			continue;
		}

		/*
		* full header, including trailing \n, is in buffer
		*/
		size_t const len = eol - start;
		if ((status = dkim_header(dkim, start, len)) != DKIM_STAT_OK)
		{
			if (parm->verbose)
			{
				char const *err = dkim_getresultstr(status);
				fl_report(LOG_CRIT,
					"id=%s: signing dkim_header failed on %zu bytes: %s (%d)",
					parm->dyn.info.id, len,
					err? err: "unknown", (int)status);
			}
			return parm->dyn.rtc = -1;
		}

		if (!cont)
			break;

		p = start;
		*p++ = next;
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

static void sign_message(dkimfl_parm *parm)
/*
* possibly sign the message, set rtc 1 if signed, -1 if failed,
* leave rtc as-is (0) if there is no need to rewrite.
*/
{
	assert(parm && parm->dyn.key == NULL);

	char *domain = strchr(parm->dyn.info.authsender, '@');
	if (domain)
		++domain;
	else
		domain = parm->default_domain; // is that how local domains work?

	if (domain == NULL)
	{
		if (parm->verbose >= 2)
			fl_report(LOG_INFO,
				"id=%s: not signing for %s: no domain",
				parm->dyn.info.id,
				parm->dyn.info.authsender);
	}
	else if (read_key(parm, domain) == 0 && parm->dyn.key)
	{
		char *selector = parm->dyn.selector? parm->dyn.selector:
			parm->selector? parm->selector: "s";

		DKIM_STAT status;
		DKIM *dkim = dkim_sign(parm->dklib, parm->dyn.info.id, NULL,
			parm->dyn.key, selector, domain,
			parm->header_canon_relaxed? DKIM_CANON_RELAXED: DKIM_CANON_SIMPLE,
			parm->body_canon_relaxed? DKIM_CANON_RELAXED: DKIM_CANON_SIMPLE,
			parm->sign_rsa_sha1? DKIM_SIGN_RSASHA1: DKIM_SIGN_RSASHA256,
			ULONG_MAX /* signbytes */, &status);

		if (parm->verbose >= 6 && dkim && status == DKIM_STAT_OK)
			fl_report(LOG_INFO,
				"id=%s: signing for %s with domain %s, selector %s",
				parm->dyn.info.id,
				parm->dyn.info.authsender,
				domain,
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

typedef struct verify_parms
{
	char *sender_domain, *helo_domain; // imply SPF "pass"
	
	// not malloc'd
	dkimfl_parm *parm;
	char *dkim_domain, *dkim_result;
	DKIM_SIGINFO *sig;
	char *sig_domain;
	dkim_policy_t policy;

	void *dkim_or_file;
	int step;

	int presult;
	int dkim_reputation;
	size_t a_r_count, d_s_count, auth_sigs;
	size_t received_spf;
	char sig_is_author;
	char dkim_reputation_flag;
	
} verify_parms;

static int
signer_is_whitelisted(verify_parms const *vh, char const *const domain)
{
	assert(vh);
	assert(vh->parm);
	
	u_char const ** const wl = vh->parm->dkim_whitelist;
	if (wl == NULL || domain == NULL)
		return 0; // no whitelist given

	for (int i = 0; wl[i] != 0; ++i)
		if (stricmp(wl[i], domain) == 0)
			return 1;

	return 0;
}

static int sender_is_whitelisted(verify_parms const *vh)
{
	assert(vh);
	assert(vh->parm);
	
	u_char const ** const wl = vh->parm->spf_whitelist;
	char const *const s = vh->sender_domain;
	if (wl == NULL || s == NULL)
		return 0; // no whitelist given

	for (int i = 0; wl[i] != 0; ++i)
		if (stricmp(wl[i], s) == 0)
			return 1;

	return 0;
}

static DKIM_STAT dkim_sig_sort(DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
// callback to check useful signatures
{
	verify_parms *const vh = (verify_parms*)dkim_get_user_context(dkim);
	
	assert(dkim && sigs && vh);
	int *val = (int*)malloc(nsigs * sizeof(int));
	if (val == NULL)
		return DKIM_CBSTAT_TRYAGAIN;

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
					sigval += 1000; // author domain signature
					++vh->auth_sigs;
				}

				if (vh->sender_domain && stricmp(vh->sender_domain, domain) == 0)
					sigval += 100; // sender's domain signature

				if (helolen)
				{
					size_t dl = strlen(domain);
					char *helocmp = vh->helo_domain;
					if (helolen > dl)
						helocmp += helolen - dl;
					// should check it's not co.uk or similar...
					if (stricmp(helocmp, domain) == 0)
						sigval += 10; // helo domain signature
				}
				
				if (signer_is_whitelisted(vh, domain))
					sigval += 500; // trusted domain signature
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

static int verify_headers(verify_parms *vh)
// return parm->dyn.rtc = -1 for unrecoverable error,
// parm->dyn.rtc (0) otherwise
{
	assert(vh && vh->parm);

	dkimfl_parm *const parm = vh->parm;
	FILE* fp = fl_get_file(parm->fl);
	assert(fp);
	char buf[8192], *p = &buf[0], *const start = &buf[0];
	DKIM *const dkim = vh->step? NULL: (DKIM*)vh->dkim_or_file;
	FILE *const out = vh->step? (FILE*)vh->dkim_or_file: NULL;
	
	int seen_received = 0;
	
	while (fgets(p, sizeof buf - 1 - (p - start), fp))
	{
		char *eol = strchr(p, '\n');

		if (eol == NULL)
		{
			if (parm->verbose)
				fl_report(LOG_ALERT,
					"id=%s: header too long (%.20s...)",
					parm->dyn.info.id, start);
			return parm->dyn.rtc = -1;
		}

		int const next = fgetc(fp);
		int const cont = next != EOF && next != '\n';
		if (cont && isspace(next)) // wrapped
		{
			if (dkim)
			{
				*eol++ = '\r';
				*eol = '\n';
			}
			*++eol = next;
			p = eol + 1;
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
		
		// count signatures
		else if (hdrval(start, DKIM_SIGNHEADER))
			++vh->d_s_count;

		// count A-R fields that have to be removed
		else if ((s = hdrval(start, "Authentication-Results")) != NULL)
		{
			if ((s = skip_cfws(s)) == NULL)
				zap = 1;
			else
			{
				char *const authserv_id = s, ch;
				while (isalnum(ch = *(unsigned char*)s) || ch == '.')
					++s;
				if (s == authserv_id)
					zap = 1;
				else
				{
					int my_zap = 0;
					*s = 0;
					/*
					* An A-R field before any received must have been set by us
					*/
					if (parm->dyn.authserv_id &&
						stricmp(authserv_id, parm->dyn.authserv_id) == 0)
							my_zap = zap = 1;
					if (dkim == NULL && parm->verbose >= 2) // log on 2nd pass only
					{
						if (my_zap)
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
			vh->a_r_count += zap;
		}
		
		// (only on first pass) cache courier's SPF results, get authserv_id
		else if (dkim && strincmp(start, "Received", 8) == 0)
		{
			if (!parm->no_spf && vh->received_spf < 2 &&
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
			
			if (parm->dyn.authserv_id == NULL && seen_received == 0 &&
				(s = hdrval(start, "Received")) != NULL)
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
						char *const authserv_id = s, ch;
						while (isalnum(ch = *(unsigned char*)s) || ch == '.')
							++s;
						char *ea = s;
						while (isspace(*(unsigned char*)s))
							++s;
						*ea = 0;
						if (strincmp(s, "with ", 5) == 0 && s > ea &&
							(parm->dyn.authserv_id = strdup(authserv_id)) == NULL)
								return parm->dyn.rtc = -1;
						
						*ea = ch;						
					}
				}
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

		p = start;
		*p++ = next;
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
		return;
	}

	vh.dkim_or_file = dkim;
	vh.parm = parm;
	if (verify_headers(&vh) == 0 && parm->dyn.authserv_id)
	/* not testing:
		(vh.a_r_count || vh.d_s_count ||
			parm->add_a_r_anyway || ))
	*/
	{
		if (dkim_minbody(dkim) > 0)
			copy_body(parm, dkim);

		status = dkim_eom(dkim, NULL);
		vh.sig = dkim_getsignature(dkim);
		vh.sig_domain = vh.sig? dkim_sig_getdomain(vh.sig): NULL;
		vh.sig_is_author = vh.sig_domain && vh.dkim_domain &&
			stricmp(vh.sig_domain, vh.dkim_domain) == 0;
		
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
			if (dkim_policy(dkim, &vh.policy, NULL) == DKIM_STAT_OK)
			{
				if (vh.dkim_domain == NULL)
					vh.dkim_domain = dkim_getdomain(dkim);

				vh.presult = dkim_getpresult(dkim);

				/*
				* unless disabled by parameter or whitelisted, do action:
				* reject if dkim_domain is not valid, or ADSP == all,
				* discard if ADSP == discardable;
				*/
				if (!parm->no_author_domain &&
						(vh.presult == DKIM_PRESULT_NXDOMAIN ||
							((vh.policy == DKIM_POLICY_DISCARDABLE ||
								vh.policy == DKIM_POLICY_ALL) &&
							vh.presult == DKIM_PRESULT_AUTHOR &&
							(!vh.sig_is_author || status != DKIM_STAT_OK))))
				{
					char const *log_reason, *smtp_reason = NULL;
					int spf_whitelisted = sender_is_whitelisted(&vh);
					int dkim_whitelisted =
						status == DKIM_STAT_OK &&
						vh.sig_domain != NULL &&
						signer_is_whitelisted(&vh, vh.sig_domain);
					
					if (vh.presult == DKIM_PRESULT_NXDOMAIN)
					{
						log_reason = "invalid domain";
						smtp_reason = "554 Invalid author domain\n";
					}
					else if (vh.policy != DKIM_POLICY_DISCARDABLE)
					{
						log_reason = "adsp=all policy:";
						smtp_reason = "554 DKIM signature required by ADSP\n";
					}
					else
						log_reason = "adsp=discardable policy:";

					if (parm->verbose >= 3)
						fl_report(LOG_INFO,
							"id=%s: %s %s, %swhitelisted (%sspf_:%s, %sdkim_:%s)",
							parm->dyn.info.id,
							log_reason,
							vh.dkim_domain? vh.dkim_domain: "(NULL)",
							spf_whitelisted || dkim_whitelisted? "": "NOT ",
							spf_whitelisted? "have ": "",
							vh.sender_domain? vh.sender_domain: "--no",
							dkim_whitelisted? "have ": "",
							status == DKIM_STAT_OK && vh.sig_domain?
								vh.sig_domain: "--no");

					if (!spf_whitelisted && !dkim_whitelisted)
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
		* check ADSP
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
				vh.sender_domain || vh.helo_domain || vh.sig || *policy_result))
		{
			FILE *fp = fl_get_write_file(parm->fl);
			if (fp == NULL)
			{
				parm->dyn.rtc = -1;
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

			if (*policy_result) // TODO: add the "header.from" field
			{
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
			
			if (auth_given <= 0)
				fputs("; none", fp);
			fputc('\n', fp);
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
		dkim_free(dkim);
}

static void dkimfilter(fl_parm *fl)
{
	dkimfl_parm *parm = (dkimfl_parm *)fl_get_parm(fl);
	parm->fl = fl;

	fl_get_msg_info(fl, &parm->dyn.info);
	if (parm->dyn.info.id == NULL)
		parm->dyn.info.id = "NULL";

	if (parm->dyn.info.is_relayclient)
	{
		if (parm->dyn.info.authsender)
			sign_message(parm);
	}
	else
	{
		verify_message(parm);
	}

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

	// TODO: free dyn allocated stuff
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

static fl_init_parm functions =
{
	dkimfilter,
	NULL,
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
				"Reported OpenSSL version: %#lX\n",
				(long)(OPENDKIM_LIB_VERSION), dkim_ssl_version());
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
			is_batch_test = 1;
	}

	dkimfl_parm parm;
	memset(&parm, 0, sizeof parm);
	// parm.fl = fl;
	if (parm_config(&parm, config_file))
	{
		rtc = 2;
		fl_report(LOG_ERR, "Unable to read config file");
	}

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
			parm.sign_hfields? parm.sign_hfields: dkim_should_signhdrs,
			sizeof parm.sign_hfields) != DKIM_STAT_OK;

		nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_SKIPHDRS,
			parm.skip_hfields? parm.skip_hfields: dkim_should_not_signhdrs,
			sizeof parm.skip_hfields) != DKIM_STAT_OK;

		if (nok)
		{
			rtc = 2;
			fl_report(LOG_ERR, "Unable to set lib options");
		}
	}

	if (rtc == 0)
		rtc =
			fl_main(&functions, &parm, argc, argv, parm.all_mode, parm.verbose);

	// TODO: free memory allocated by parm_config (almost useless)
	if (parm.dklib)
		dkim_close(parm.dklib);
	return rtc;
}
