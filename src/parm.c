/*
* parm.c - written by ale in milano on 27sep2012
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
#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <stddef.h>
#include <stdarg.h>
#include "parm.h"
#include "vb_fgets.h"
#include <assert.h>

/*
* logging weariness:
* zdkimfilter logs using fl_report, designed after Courier's error stream.
* dkimsign emulates Courier behavior to run on syslog.
* other command utilities can get/set the logfun/program_name:
* fl_report, syslog, and stderrlog are viable candidates.
*/

static const char *program_name = "zfilter";
static logfun_t do_report = &stderrlog;

const char* set_program_name(const char * new_name)
{
	const char* rt = program_name;
	if (new_name)
		program_name = new_name;
	return rt;
}

logfun_t set_parm_logfun(logfun_t new_report)
{
	logfun_t rt = do_report;
	if (new_report)
		do_report = new_report;
	return rt;
}

void stderrlog(int severity, char const* fmt, ...)
{
	char const *logmsg;
	switch (severity)
	{
		case LOG_EMERG:
		//	logmsg = "EMERG";
		//	break;

		case LOG_ALERT:
			logmsg = "ALERT";
			break;

		case LOG_CRIT:
			logmsg = "CRIT";
			break;

		case LOG_ERR:
		default:
			logmsg = "ERR";
			break;

		case LOG_WARNING:
			logmsg = "WARN";
			break;

		case LOG_NOTICE:
		//	logmsg = "NOTICE";
		//	break;

		case LOG_INFO:
			logmsg = "INFO";
			break;

		case LOG_DEBUG:
			logmsg = "DEBUG";
			break;
	}
	
	fprintf(stderr, "%s: %s: ", logmsg, program_name);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

typedef struct config_conf
{
	char const *name, *descr;
	int (*assign_fn)(void*, struct config_conf const*, char*);
	size_t offset, size;
	parm_target_t type_id;
} config_conf;

#define PARM_PTR(T) *(T*)(((char*)parm) + c->offset)

static int
assign_ptr(void *parm, config_conf const *c, char*s)
{
	assert(parm && c && s && c->size == sizeof(char*));
	char *v = strdup(s);
	if (v == NULL)
	{
		(*do_report)(LOG_ALERT, "MEMORY FAULT");
		return -1;
	}
	PARM_PTR(char*) = v;
	return 0;
}

static int
assign_char(void *parm, config_conf const *c, char*s)
{
	assert(parm && c && s && c->size == sizeof(char));
	char ch = *s, v;
	if (strchr("YyTt1", ch)) v = 1; //incl. ch == 0
	else if (strchr("Nn0", ch)) v = 0;
	else return -1;
	PARM_PTR(char) = v;
	return 0;
}

static int
assign_int(void *parm, config_conf const *c, char*s)
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

static int
assign_array(void *parm, config_conf const *c, char*s)
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
			(*do_report)(LOG_ALERT, "MEMORY FAULT");
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
#define CONFIG(T,P,D,F) {STRING(P), D, F, \
	offsetof(T, P), sizeof(((T*)0)->P), T##_id }

static config_conf const conf[] =
{
	CONFIG(parm_t, all_mode, "Y/N", assign_char),
	CONFIG(parm_t, verbose, "int", assign_int),
	CONFIG(parm_t, domain_keys, "key's directory", assign_ptr),
	CONFIG(parm_t, header_canon_relaxed, "Y/N, N for simple", assign_char),
	CONFIG(parm_t, body_canon_relaxed, "Y/N, N for simple", assign_char),
	CONFIG(parm_t, sign_rsa_sha1, "Y/N, N for rsa-sha256", assign_char),
	CONFIG(parm_t, key_choice_header, "key choice header", assign_array),
	CONFIG(parm_t, default_domain, "dns", assign_ptr),
	CONFIG(parm_t, selector, "global", assign_ptr),
	CONFIG(parm_t, sign_hfields, "space-separated, no colon", assign_array),
	CONFIG(parm_t, skip_hfields, "space-separated, no colon", assign_array),
	CONFIG(parm_t, no_signlen, "Y/N", assign_char),
	CONFIG(parm_t, redact_received_auth, "any text", assign_ptr), // used by redact.c
	CONFIG(parm_t, tmp, "temp directory", assign_ptr), // to be used by dkimsign.c
	CONFIG(parm_t, tempfail_on_error, "Y/N", assign_char),
	CONFIG(parm_t, no_spf, "Y/N", assign_char),
	CONFIG(parm_t, save_from_anyway, "Y/N", assign_char),
	CONFIG(parm_t, add_a_r_anyway, "Y/N", assign_char),
	CONFIG(parm_t, report_all_sigs, "Y/N", assign_char),
	CONFIG(parm_t, max_signatures, "int", assign_int),
	CONFIG(parm_t, honor_author_domain, "Y=enable ADSP", assign_char),
	CONFIG(parm_t, reject_on_nxdomain, "Y=procrustean ADSP", assign_char),
	CONFIG(parm_t, no_reputation, "Y=skip reputation lookup", assign_char),
	CONFIG(parm_t, reputation_fail, "high int", assign_int),
	CONFIG(parm_t, reputation_pass, "low int", assign_int),
	CONFIG(parm_t, trusted_vouchers, "space-separated, no colon", assign_array),
	CONFIG(parm_t, dns_timeout, "secs", assign_int),

	CONFIG(db_parm_t, db_backend, "conn", assign_ptr),
	CONFIG(db_parm_t, db_host, "conn", assign_ptr),
	CONFIG(db_parm_t, db_port, "conn", assign_ptr),
	CONFIG(db_parm_t, db_opt_tls, "A/N/T if given", assign_ptr),
	CONFIG(db_parm_t, db_opt_multi_statements, "Y/N if given", assign_char),
	CONFIG(db_parm_t, db_opt_compress, "Y/N if given", assign_char),
	CONFIG(db_parm_t, db_opt_mode, "", assign_ptr),
	CONFIG(db_parm_t, db_opt_paged_results, "int", assign_int),
	CONFIG(db_parm_t, db_timeout, "secs", assign_int),
	CONFIG(db_parm_t, db_database, "", assign_ptr),
	CONFIG(db_parm_t, db_user, "credentials", assign_ptr),
	CONFIG(db_parm_t, db_password, "credentials", assign_ptr),
	CONFIG(db_parm_t, db_sql_whitelisted, "", assign_ptr),
	CONFIG(db_parm_t, db_sql_select_domain, "", assign_ptr),
	CONFIG(db_parm_t, db_sql_update_domain, "", assign_ptr),
	CONFIG(db_parm_t, db_sql_insert_domain, "", assign_ptr),
	CONFIG(db_parm_t, db_sql_insert_msg_ref, "", assign_ptr),
	CONFIG(db_parm_t, db_sql_insert_message, "", assign_ptr),

	{NULL, NULL, NULL, 0, 0, 0}
};

// utilities -----
static int stricmp(const char *a, const char *b)
{
	int c, d;
	do c = *a++, d = *b++;
	while (c != 0 && d != 0 && (c == d || (c = tolower(c)) == (d = tolower(d))));

	return c < d ? -1 : c > d;
}

void print_parm(void *parm_target[PARM_TARGET_SIZE])
{
	config_conf const *c = &conf[0];
	while (c->name)
	{
		int i = 0;
		void *parm = parm_target[c->type_id];

		if (parm)
		{
			printf("%-24s = ", c->name);
			if (c->size == 1U)
			{
				char v = PARM_PTR(char);
				char const*rv;
				switch (v)
				{
					case 0: rv = "N"; break;
					case 1: rv = "Y"; break;
					default: rv = "not given"; break;
				}
				fputs(rv, stdout);
			}
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
					if (c->descr && c->descr[0])
						printf(" (%s)", c->descr);
					fputc('\n', stdout);
					for (; a[i]; ++i)
						printf("%26d %s\n", i, a[i]);

					i = 1;
				}
			}
			else
				printf("%d", PARM_PTR(int));

			if (i == 0)
			{
				if (c->descr && c->descr[0])
					printf(" (%s)", c->descr);
				fputc('\n', stdout);
			}
		}
		++c;
	}
}

void clear_parm(void *parm_target[PARM_TARGET_SIZE])
{
	config_conf const *c = &conf[0];
	while (c->name)
	{
		void *parm = parm_target[c->type_id];

		if (parm)
		{
			if (c->assign_fn == assign_ptr ||
				c->assign_fn == assign_array)
			{
				free(PARM_PTR(void*));
				PARM_PTR(void*) = NULL;
			}
		}
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

int read_all_values(void *parm_target[PARM_TARGET_SIZE], char const *fname)
// initialization, 0 on success
{
	assert(parm_target);
	assert(fname);

	int line_no = 0;
	errno = 0;

	FILE *fp = fopen(fname, "r");
	if (fp == NULL)
	{
		(*do_report)(LOG_ALERT,
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
			(*do_report)(LOG_ERR,
				"Invalid name %s at line %d in %s", name, line_no, fname);
			++errs;
			continue;
		}
	
		*s = ch;
		while (isspace(ch = *(unsigned char*)s) || ch == '=')
			++s;
	
		char *const value = s;
		void *const parm = parm_target[c->type_id];
	
		if (parm != NULL && (*c->assign_fn)(parm, c, value) != 0)
		{
			(*do_report)(LOG_ERR,
				"Invalid value %s for %s at line %d in %s",
					value, c->name, line_no, fname);
			++errs;
		}
	}

	vb_clean(&vb);
	fclose(fp);

	return errs;
}

char* read_single_value(char const *pname, char const *fname)
// read a single value from parameter file
// return malloced string or NULL
// errno == 0 for undefined parameter, otherwise fname/memory problem
{
	char *value = NULL;
	if (fname == NULL)
		fname = default_config_file;

	errno = 0;

	FILE *fp = fopen(fname, "r");
	if (fp == NULL)
		return NULL;
	
	var_buf vb;
	if (vb_init(&vb))
	{
		fclose(fp);
		errno = ENOBUFS;
		return NULL;
	}

	size_t keep = 0;
	char *p;

	while ((p = vb_fgets(&vb, keep, fp)) != NULL)
	{
		char *eol = p + strlen(p) - 1;
		int ch = 0;

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

		if (strncasecmp(pname, name, s - name) == 0)
		{
			while (isspace(ch = *(unsigned char*)s) || ch == '=')
				++s;
	
			if ((value = strdup(s)) == NULL)
				errno = ENOBUFS;

			break;
		}
	}

	vb_clean(&vb);
	fclose(fp);

	return value;
}
