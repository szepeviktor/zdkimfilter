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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h> // for LOG_DEBUG,... constants

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
// ----- utilities

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
	char const *domain_keys;
	char *selector;
	char *default_domain;

	// end of pointers (some malloc'd but never free'd)
	per_message_parm dyn;
	int verbose;
	unsigned int dns_timeout;
	unsigned reputation_fail, reputation_pass;
	char add_a_r_anyway;
	char no_spf;
	char no_signlen;
	char tempfail_on_error;
	char check_domain;
	char check_reputation;
	
} dkimfl_parm;

static void config_default(dkimfl_parm *parm) // only non-zero...
{
	static char const keys[] = COURIER_SYSCONF_INSTALL "/filters/keys";
	parm->domain_keys = keys;
	parm->reputation_fail = parm->reputation_pass = UINT_MAX;
	parm->verbose = 4;
}

typedef struct config_conf
{
	char *name;
	size_t offset, size;
} config_conf;

static void assign_ptr(dkimfl_parm *parm, config_conf const *c, char*s)
{
}

static void assign_char(dkimfl_parm *parm, config_conf const *c, char*s)
{
}

static void assign_uint(dkimfl_parm *parm, config_conf const *c, char*s)
{
}

#define STRING2(P) #P
#define STRING(P) STRING2(P)
#define CONFIG(P) {STRING(P), offsetof(dkimfl_parm, P), sizeof(((dkimfl_parm*)0)->P)}

static config_conf const conf[] =
{
	CONFIG(domain_keys),
	CONFIG(selector),
	CONFIG(default_domain),
	CONFIG(verbose),
	CONFIG(dns_timeout),
	CONFIG(reputation_fail),
	CONFIG(reputation_pass),
	CONFIG(add_a_r_anyway),
	CONFIG(no_spf),
	CONFIG(no_signlen),
	CONFIG(tempfail_on_error),
	CONFIG(check_domain),
	CONFIG(check_reputation),
	{NULL, 0, 0}
};
#undef CONFIG

static config_conf const* conf_name(char const *p)
{
	for (config_conf const *c = conf; c->name; ++c)
		if (stricmp(c->name, p) == 0)
			return c;

	return NULL;
}

static int parm_config(dkimfl_parm *parm)
// initialization, 0 on success
{
	static char const conf[] =
		COURIER_SYSCONF_INSTALL "/filters/zdkimfilter.conf";

	config_default(parm);
	size_t const non_ptr = offsetof(dkimfl_parm, dyn);
	FILE *fp = fopen(conf, "r");
	if (fp)
	{
		char buf[4096];
		int line_no = 0, errs = 0;
		while (fgets(buf, sizeof buf, fp))
		{
			char *s = &buf[0];
			int ch;
			++line_no;
			if (strchr(s, '\n') == NULL)
			{
				fl_report(LOG_ERR,
					"Line too long at line %d in %s", line_no, conf);
				fclose(fp);
				return -1;
			}
			while (isspace(ch = *(unsigned char*)s))
				++s;
			if (ch == '#')
				continue;

			char *const name = s;
			while (isalnum(ch = *(unsigned char*)s) || ch == '_')
				++s;
			*s = 0;
			config_conf const *c = conf_name(name);
			if (c == NULL)
			{
				fl_report(LOG_ERR,
					"Invalid name %s at line %d in %s", name, line_no, conf);
				++errs;
				continue;
			}
			
			*s = ch;
			while (isspace(ch = *(unsigned char*)s) || ch == '=')
				++s;
			
			if (c->offset < non_ptr)
				assign_ptr(parm, c, s);
			else
				switch (c->size)
				{
					case sizeof(char):
						assign_char(parm, c, s);
						break;
					case sizeof(unsigned):
						assign_uint(parm, c, s);
						break;
					default:
						assert(0);
						break;
				}
		}
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
			if (parm->verbose >= 4)
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
		if (errno != EINVAL || parm->verbose >= 4)
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
	*    example.com -> example.com.my-selector
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
			if ((selector = strdup(name)) == NULL)
				goto error_exit_no_msg;
		}
	}
	parm->dyn.key = (dkim_sigkey_t) key;
	parm->dyn.selector = selector;
	return 0;

	error_exit:
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
		if (dkim_header(dkim, start, len) != DKIM_STAT_OK)
		{
			if (parm->verbose)
				fl_report(LOG_ALERT,
					"id=%s: %s failed on %zu bytes",
					parm->dyn.info.id, dkim? "dkim_header": "fwrite", len);
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
	
	DKIM_STAT status = dkim_eoh(dkim);
	if (status != DKIM_STAT_OK)
	{
		if (parm->verbose)
			fl_report(LOG_ALERT,
				"id=%s: dkim_eoh failed with %d",
				parm->dyn.info.id, (int)status);
		return parm->dyn.rtc = -1;
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
		if (dkim_body(dkim, buf, len) != DKIM_STAT_OK)
		{
			if (parm->verbose)
				fl_report(LOG_ALERT,
					"id=%s: dkim_body failed on %zu bytes",
					parm->dyn.info.id, len);
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

	if (domain && read_key(parm, domain) == 0 && parm->dyn.key)
	{
		char *selector = parm->dyn.selector? parm->dyn.selector:
			parm->selector? parm->selector: "s";

		DKIM_STAT status;
		DKIM *dkim = dkim_sign(parm->dklib, parm->dyn.info.id, NULL,
			parm->dyn.key, selector, domain,
			DKIM_CANON_SIMPLE, DKIM_CANON_SIMPLE, DKIM_SIGN_RSASHA1,
			ULONG_MAX /* signbytes */, &status);

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
					fl_report(LOG_ALERT,
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
	unsigned dkim_reputation;
	size_t a_r_count, d_s_count, auth_sigs;
	size_t received_spf;
	char sig_is_author;
	
} verify_parms;

static DKIM_STAT dkim_sig_sort(DKIM *dkim, DKIM_SIGINFO** sigs, int nsigs)
// callback to check useful signatures
{
	verify_parms *const vh = (verify_parms*)dkim_get_user_context(dkim);
	
	assert(dkim && sigs && vh);
	int *val = (int*)malloc(nsigs * sizeof(int));
	if (val == NULL)
		return DKIM_CBSTAT_TRYAGAIN;

	size_t const helolen = vh->helo_domain? strlen(vh->helo_domain): 0;
	
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
				
				// TODO: add somethign if domain is in a set of trusted domains
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
					*s = 0;
					if (parm->dyn.authserv_id &&
						stricmp(authserv_id, parm->dyn.authserv_id) == 0)
							zap = 1;
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
							char *esender = strchr(esender, ';');
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
				while (parm->dyn.authserv_id == NULL)
				{
					s = strstr(s, " by ");
					if (s)
					{
						while (isspace(*(unsigned char*)s))
							++s;
						char *const authserv_id = s + 4, ch;
						while (isalnum(ch = *(unsigned char*)s) || ch == '.')
							++s;
						char *ea = s;
						*ea = 0;
						while (isspace(*(unsigned char*)s))
							++s;
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
			size_t const len = eol - start;
			if (dkim)
				err = dkim_header(dkim, start, len) != DKIM_STAT_OK;
			else
				err = fwrite(start, len + 1, 1, out) != 1;

			if (err)
			{
				if (parm->verbose)
					fl_report(LOG_ALERT,
						"id=%s: %s failed on %zu bytes",
						parm->dyn.info.id, dkim? "dkim_header": "fwrite", len);
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
			if (parm->verbose)
				fl_report(LOG_ALERT,
					"id=%s: dkim_eoh failed with %d",
					parm->dyn.info.id, (int)status);
			return parm->dyn.rtc = -1;
		}
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
	if (verify_headers(&vh) == 0 && parm->dyn.authserv_id &&
		(vh.a_r_count || vh.d_s_count || parm->add_a_r_anyway))
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

		if (parm->dyn.rtc == 0 && parm->check_domain)
		{
			if (dkim_policy(dkim, &vh.policy, NULL) == DKIM_STAT_OK)
			{
				vh.presult = dkim_getpresult(dkim);

				/*
				* reject if dkim_domain is not valid
				*/
				if (vh.presult == DKIM_PRESULT_NXDOMAIN)
				{
					fl_pass_message(parm->fl, "550 Invalid author domain\n");
					parm->dyn.rtc = 2;
				}

				/*
				* reject if absence of good signature mandates it
				*/
				else if (vh.policy == DKIM_POLICY_DISCARDABLE &&
					vh.presult == DKIM_PRESULT_AUTHOR &&
					(!vh.sig_is_author || status != DKIM_STAT_OK))
				{
					fl_pass_message(parm->fl,
						"550 DKIM signature required by policy\n");
					parm->dyn.rtc = 2;
				}
			}
		}
		
		if (parm->dyn.rtc == 0 &&
			parm->check_reputation && status == DKIM_STAT_OK && vh.sig)
		{
			int rep;
			/*
			* (don't) reject on passing configured value
			*/
			if (dkim_get_reputation(dkim, vh.sig, DKIM_REP_ROOT, &rep) ==
				DKIM_STAT_OK)
			{
				vh.dkim_reputation = rep;
#if 0				
				if (rep > parm->reputation_reject)
				{
					fl_pass_message(parm->fl, "550 Bad reputation?\n");
					parm->dyn.rtc = 2;
				}
#endif
			}
		}

		if (parm->dyn.rtc == 0)
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
					char const *const err = status == DKIM_STAT_OK? NULL:
						dkim_sig_geterrorstr(dkim_sig_geterror(vh.sig));
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
						fprintf(fp, ";\n dkim=%s ", is_test? "neutral": "fail");
						if (err && is_test)
							fprintf(fp, "(test key, %s) ", err);
						else if (err)
							fprintf(fp, "(%s) ", err);
						else if (is_test)
							fputs("(test key) ", fp);
					}

					fprintf(fp, "header.%c=%s", htype, id);
					++auth_given;
				}
			}
			
			if (vh.policy == DKIM_POLICY_ALL ||
				vh.policy == DKIM_POLICY_DISCARDABLE)
			{
				fprintf(fp, ";\n  x-dkim-adsp=%s",
					vh.sig_is_author && status == DKIM_STAT_OK? "pass": "fail");
				++auth_given;
			}
			
			if (vh.dkim_reputation && vh.sig_domain)
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

			/*
			* now for the rest of the header, and body
			*/
			vh.step = 1;
			vh.dkim_or_file = fl_get_file(parm->fl);
			assert(vh.dkim_or_file);
			rewind((FILE*)vh.dkim_or_file);
			if (verify_headers(&vh) == 0 &&
				fputc('\n', fp) != EOF &&
				filecopy((FILE*)vh.dkim_or_file, fp) == 0)
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
	static char const resp_ok[] = "200 Ok.\n";
	static char const resp_tempfail[] =
		"432 Mail filter temporarily unavailable.\n";

	dkimfl_parm parm;
	memset(&parm, 0, sizeof parm);

	parm.dklib = dkim_init(NULL, NULL); // should this be before fork?
	parm.fl = fl;
	if (parm.dklib == NULL || parm_config(&parm))
		parm.dyn.rtc = -1;
	else
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
		
		if (parm.dns_timeout) // DEFTIMEOUT is 10 secs
		{
			nok |= dkim_options(parm.dklib, DKIM_OP_SETOPT, DKIM_OPTS_TIMEOUT,
				&parm.dns_timeout, sizeof parm.dns_timeout) != DKIM_STAT_OK;
		}
		
		if (nok)
			parm.dyn.rtc = -1;
	}
	
	if (parm.dyn.rtc == 0)
	{
		fl_get_msg_info(fl, &parm.dyn.info);
		if (parm.dyn.info.is_relayclient)
		{
			if (parm.dyn.info.authsender)
				sign_message(&parm);
		}
		else
		{
			verify_message(&parm);
		}
	}

	switch (parm.dyn.rtc)
	{
		case -1: // unrecoverable error
			if (parm.tempfail_on_error)
			{
				fl_pass_message(fl, resp_tempfail);
				break;
			}
			// else through
		case 0: // not rewritten
		case 1: // rewritten
			fl_pass_message(fl, resp_ok);
			break;

		case 2: // rejected, message already passed
			break;
	}
	dkim_close(parm.dklib);
}

static fl_init_parm functions =
{
	dkimfilter,
	NULL,
	NULL, NULL, NULL,
	NULL, NULL, NULL, NULL	
};

int main(int argc, char *argv[])
{
	int rtc, i;

	for (i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		
		if (strcmp(arg, "--version") == 0)
		{
			puts(PACKAGE_STRING);
			printf("Compiled with OpenDKIM library version: %#lX\n"
				"Reported OpenSSL version: %#lX\n",
				(long)(OPENDKIM_LIB_VERSION), dkim_ssl_version());
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			fputs("zdkimfilter command line args:\n"
			/*  12345678901234567890123456 */
				"  --help                  print this stuff and exit\n"
				"  --version               print version string and exit\n",
					stdout);
			fl_main(NULL, NULL, argc - i + 1, argv + i - 1, 0, 0);
			return 0;
		}
	}
	
	rtc = fl_main(&functions, NULL, argc, argv, 1,
#if !defined NDEBUG  /* verbose */
	10
#else
	4
#endif
	);

	return rtc;
}
