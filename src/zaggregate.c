/*
* zaggregate.c - written by vesely in milan on 19mar2015
* produce dmarc aggregate reports
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2015, 2019 Alessandro Vesely

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
#include <stdlib.h>
#include <syslog.h>
#include <ctype.h>
#include <stdbool.h>
#include <inttypes.h>

#include <zlib.h>
#include <time.h>

#if HAVE_UUID
#include <uuid/uuid.h>
#endif

#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include "database.h"
#include "myadsp.h"
#include "cstring.h"
#include <assert.h>

// there's no .h for this
cstring* urlencode(char const *);


#if HAVE_OPENDBX

static logfun_t do_log = &stderrlog;

// display time
static char *human_time(time_t tt)
// rfc3339 representation, parenthesized with leading space
{
	char buf[80];
	struct tm tm;

	if (localtime_r(&tt, &tm))
	{
#if HAVE_TIMEZONE
		long adddst = tm.tm_isdst > 0? 3600: 0;
#endif
		snprintf(buf, sizeof buf,
			" (%04d-%02d-%02dT%02d:%02d:%02d"
#if HAVE_TIMEZONE
			"%+02ld:%02ld"
#endif
			")",
			tm.tm_year + 1900,
			tm.tm_mon+1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec
#if HAVE_TIMEZONE
			, -(timezone - adddst) /3600L, timezone %3600L
#endif
		);
		return strdup(buf);
	}
	return NULL;
}

static volatile int signal_break = 0, signal_child = 0, signal_pipe = 0;

static void sig_catcher(int sig)
{
	switch(sig)
	{
		case SIGPIPE:
			++signal_pipe;
			break;
		case SIGINT:
		case SIGTERM:
			signal_break = sig;
			break;
		case SIGCHLD:
			++signal_child;
			break;
		default:
			break;
	}
}

static void init_signal(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);

	act.sa_handler = sig_catcher;
	act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	sigaction(SIGCHLD, &act, NULL);

	act.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &act, NULL);

	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

static int copy_file(FILE *src, FILE *dst)
{
	assert(src);
	assert(dst);

	char buf[1024], *s;
	while ((s = fgets(buf, sizeof buf, src)) != NULL)
	{
		size_t const in = strlen(s);
		if (fwrite(s, 1, in, dst) != in || signal_break != 0)
			break;
	}

	return ferror(src) || ferror(dst);
}

static inline int is_parent_domain_of(char const *domain, char const *subdom)
{
	assert(domain);
	assert(subdom);

	size_t len = strlen(domain), sublen = strlen(subdom), l;

	return (len == sublen && strcmp(subdom, domain) == 0) || // same or,
		(len < sublen && // subdomain proper
		subdom[(l=sublen-len) - 1] == '.' &&
		strcmp(&subdom[l], domain) == 0);
}

// simple xmt output
typedef struct xml_tree
{
	cstring *cstr;
	char const *tag[5];
	int (*flush)(cstring*, void*, int);
	void *flush_arg;
	size_t depth;
} xml_tree;

static inline int xml_flush(xml_tree* xml, int end)
{
	if (xml->flush)
		return (*xml->flush)(xml->cstr, xml->flush_arg, end);
	return -1;
}

static void indent(xml_tree *xml, size_t depth)
{
	for (size_t ind = 0; ind < depth; ++ind)
		if (xml->cstr)
			xml->cstr = cstr_addch(xml->cstr, '\t');
}

static void stag(xml_tree *xml, char const* tag)
{
	assert(xml);
	assert(xml->depth < sizeof xml->tag/sizeof xml->tag[0]);
	assert(xml->depth > 0 || cstr_length(xml->cstr) == 0);
	assert(xml->depth == 0 || xml->cstr != NULL);

	if (xml->depth == 0)
	{
		if (xml->cstr == NULL)
			xml->cstr = cstr_init(1024);
		if (xml->cstr)
			xml->cstr = cstr_setstr(xml->cstr,
				"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
	}
	indent(xml, xml->depth);
	if (xml->cstr)
		xml->cstr = cstr_printf(xml->cstr, "<%s>\n",
			xml->tag[xml->depth++] = tag);
}

static void etag(xml_tree *xml)
{
	assert(xml);
	assert(xml->depth <= sizeof xml->tag/sizeof xml->tag[0]);
	assert(xml->depth > 0);

	indent(xml, --xml->depth);
	if (xml->cstr)
		xml->cstr = cstr_printf(xml->cstr, "</%s>\n", xml->tag[xml->depth]);	
}

static void xtag(xml_tree *xml, char const *tag, char const *content)
{
	assert(xml);
	assert(xml->depth <= sizeof xml->tag/sizeof xml->tag[0]);

	indent(xml, xml->depth);
	if (xml->cstr)
		xml->cstr = cstr_printf(xml->cstr, "<%s>%s</%s>\n",
			tag, content? content: "", tag);
}

static void xtagn(xml_tree *xml, char const *tag, char const *content, int len)
{
	assert(xml);
	assert(xml->depth <= sizeof xml->tag/sizeof xml->tag[0]);

	indent(xml, xml->depth);
	if (xml->cstr)
		xml->cstr = cstr_printf(xml->cstr, "<%s>%.*s</%s>\n",
			tag, len, content? content: "", tag);
}

static void uint32_xtag(xml_tree *xml, char const *tag, uint32_t content)
{
	assert(xml);
	assert(xml->depth < sizeof xml->tag/sizeof xml->tag[0]);
	assert(xml->depth > 0);

	indent(xml, xml->depth);
	if (xml->cstr)
		xml->cstr = cstr_printf(xml->cstr, "<%s>%u</%s>\n", tag, content, tag);
}

static char const bailout[] = ", bailing out...";

static int record_select(int nfield, char const *field[], void* vxml)
/*
* Receive fields from domain selection query.

db_sql_dmarc_agg_record SELECT INET_NTOA(CONV(HEX(m.ip),16,10)) AS source, COUNT(*) AS n,\
m.dmarc_dispo AS disposition, m.dmarc_dkim AS d_dkim, m.dmarc_spf AS d_spf,\
m.dmarc_reason AS reason, da.domain AS author,\
dspf.domain AS spf, rspf.spf AS spf_re,\
dhelo.domain AS helo, rhelo.spf AS helo_re,\
d1.domain AS dkim1, r1.dkim_selector AS dkim1_se, r1.dkim AS dkim1_re,\
...
FROM message_in AS m\
LEFT JOIN (msg_ref AS rd INNER JOIN domain AS dd ON rd.domain = dd.id)\
  ON m.id = rd.message_in AND FIND_IN_SET('dmarc', rd.auth)\
LEFT JOIN (msg_ref AS ra INNER JOIN domain AS da ON ra.domain = da.id)\
  ON m.id = ra.message_in AND FIND_IN_SET('author', ra.auth)\
LEFT JOIN (msg_ref AS rspf INNER JOIN domain AS dspf ON rspf.domain = dspf.id)\
  ON m.id = rspf.message_in AND FIND_IN_SET('spf', rspf.auth)\
LEFT JOIN (msg_ref AS rhelo INNER JOIN domain AS dhelo ON rhelo.domain = dhelo.id)\
  ON m.id = rhelo.message_in AND FIND_IN_SET('spf_helo', rhelo.auth)\
LEFT JOIN (msg_ref AS r1 INNER JOIN domain AS d1 ON r1.domain = d1.id)\
  ON m.id = r1.message_in AND r1.dkim_order = 1\
...

* Receiver order must be:
*
*  ip [0],             INET_NTOA(CONV(HEX(m.ip),16,10)) AS source
*  count [1],          COUNT(*) AS n
*  dispo [2],          m.dmarc_dispo AS disposition
*  d_dkim [3],         m.dmarc_dkim AS d_dkim
*  d_spf [4],          m.dmarc_spf AS d_spf
*  reason [5],         m.dmarc_reason AS reason
*  domain [6],         da.domain AS author
*  spf [7],            dspf.domain AS spf
*  spf_result [8],     rspf.spf AS spf_re
*  spf_helo [9],       dhelo.domain AS helo,
*  spf_result [10],    rhelo.spf AS helo_re
*  and, repeated any   number of times, NULL values skipped,
*  dkim [11],          d1.domain AS dkim1
*  dkim_selector [12]  r1.dkim_selector AS dkim1_se
*  dkim_result [13],   r1.dkim AS dkim1_re
*/
{
	if (nfield < 10)
	{
		(*do_log)(LOG_ERR, "only %d record field(s)%s", nfield, bailout);
		return -1;
	}

	xml_tree *xml = vxml;

	stag(xml, "record");
	stag(xml, "row");
	xtag(xml, "source_ip", field[0]);
	xtag(xml, "count", field[1]);

	stag(xml, "policy_evaluated");
	xtag(xml, "disposition", field[2]);
	xtag(xml, "dkim", field[3]);
	xtag(xml, "spf", field[4]);

	// reason, if given, is type + [space comment]
	if (field[5] && strcmp(field[5], "none") != 0)
	{
		stag(xml, "reason");

		char const *c = field[5];
		int ch;
		while (isalnum(ch = *(unsigned char*)c) || ch == '_')
			++c;
		xtagn(xml, "type", field[5], c - field[5]);
		if (isspace(ch))
			xtag(xml, "comment", c+1);
		etag(xml); // reason
	}
	etag(xml); // policy evaluated
	etag(xml); // row

	stag(xml, "identifiers");
	xtag(xml, "header_from", field[6]);
	etag(xml);

	stag(xml, "auth_results");
	for (int i = 11; i+1 < nfield; i += 3)
		if (field[i] && field[i+1] && *field[i+1] && field[i+2])
		{
			stag(xml, "dkim");
			xtag(xml, "domain", field[i]);
			xtag(xml, "selector", field[i+1]);
			xtag(xml, "result", field[i+2]);
			etag(xml); // dkim
		}

	stag(xml, "spf");
	if (field[7] && field[8] && field[9] && field[10])
	{
		bool pass8 = strcmp(field[8], "pass") == 0,
			pass10 = strcmp(field[10], "pass") == 0;
		if (pass8 == pass10)
		{
			// if both or neither are pass, output helo only if
			// it is better aligned than mfrom
			if (field[6] &&
				is_parent_domain_of(field[6], field[9]) &&
				!is_parent_domain_of(field[6], field[7]))
					field[7] = NULL;
		}
		else if (pass10)
			field[7] = NULL;
	}

	if (field[7] && field[8])
	{
		xtag(xml, "domain", field[7]);
		xtag(xml, "result", field[8]);
		xtag(xml, "scope", "mfrom");
	}
	else if (field[9] && field[10])
	{
		xtag(xml, "domain", field[9]);
		xtag(xml, "result", field[10]);
		xtag(xml, "scope", "helo");
	}
	else
	{
		xtag(xml, "domain", "");
		xtag(xml, "result", "none");
	}
	etag(xml); // spf
	etag(xml); // auth_results
	etag(xml); // record

	return xml_flush(xml, 0);
}

typedef struct zag_parm
{
	db_work_area *dwa;
	char const *config_file;
	parm_t z;
	char **pargv;
	int pargc;
	int verbose: 6;
	int force: 1;
	int use_uuid: 1;
	int use_z: 1;
	int use_tmpfile: 1;
	int no_set_dmarc_agg: 1;
	int one_rcpt: 1;
	int nu: 20;
	int good, bad;

	time_t period;
	time_t period_end;
	size_t n_dom_in, n_dom_out;
} zag_parm;

typedef struct dmarc_addr
{
	char *addr;
	uint64_t limit;
} dmarc_addr;

typedef struct dmarc_rua
{
	char *rua; // these are where addr and poldomain point into
	char const *poldomain;
} dmarc_rua;

typedef struct base64
{
	z_stream zout;
	unsigned char restbuf[4];
	size_t rest, col;
} base64;

typedef struct domain_run
{
	zag_parm *zag;
	char const *domain; // from db query
	dmarc_rua *rua;     // array of rua strings
	dmarc_addr *addr;   // array with pointers into rua strings
	char *drec;
	size_t n_addr;
	size_t n_rua;

	cstring *fname, *efname;
	FILE *out;

	uint64_t total_out; // size of compressed + encoded report
	base64 b64;

	pid_t child;
	xml_tree xml;
	size_t n_record;
	char use_z, use_file, child_killed;
} domain_run;

static void clean_dom(domain_run *dom)
{
	assert(dom);

	if (dom->use_z)
		deflateEnd(&dom->b64.zout);
	if (dom->out)
		fclose(dom->out);
	if (dom->use_file)
	{
		if (dom->fname)
			unlink(cstr_get(dom->fname));
		if (dom->efname)
			unlink(cstr_get(dom->efname));
	}
	for (size_t i = 0; i < dom->n_rua; ++i)
		free(dom->rua[i].rua);
	free(dom->rua);
	free(dom->drec);
	free(dom->addr);
	free(dom->fname);
	free(dom->efname);
	free(dom->xml.cstr);
}

static const int DEAD_CHILD = 0xdeadc1d;
static int flush_common(domain_run *dom, cstring *cstr, int end)
{
	assert(dom);

	if (cstr) // good
	{
		cstr_trunc(cstr, 0);
		if (end == 0)
			dom->n_record += 1;
		return signal_break;
	}

	(*do_log)(LOG_ERR, "cannot write %s for %s: %s",
		dom->use_file? "file": "pipe", dom->domain, strerror(errno));

	fclose(dom->out);
	dom->out = NULL;
	return dom->child_killed? DEAD_CHILD: -1;
}

static int flush_out(cstring *cstr, void *vdom, int end)
{
	assert(vdom);
	if (cstr == NULL || vdom == NULL)
		return -1;

	domain_run *dom = vdom;
	size_t const size = cstr_length(cstr);
	if (dom->out && size &&
		fwrite(cstr_get(cstr), size, 1, dom->out) != 1)
			cstr = NULL;

	return flush_common(dom, cstr, end);
}

static int flush_out_z(cstring *cstr, void *vdom, int end)
// z implies base64
{
	assert(vdom);
	if (cstr == NULL || vdom == NULL)
		return -1;

#define B64_BYTE(T) base64_symbol[(T) % 64]
static unsigned char base64_symbol[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	domain_run *dom = vdom;
	if (dom->out)
	{
		z_stream *zout = &dom->b64.zout;
		zout->avail_in = cstr_length(cstr);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
		zout->next_in = cstr->data;
#pragma GCC diagnostic pop

		unsigned char buf[4096];
		size_t rest = dom->b64.rest, col = dom->b64.col;
		if (rest) memcpy(buf, dom->b64.restbuf, rest);

		do
		{
			zout->avail_out = sizeof buf - rest;
			zout->next_out = buf + rest;
			deflate(zout, end? Z_FINISH: Z_NO_FLUSH);

			size_t have = sizeof buf - zout->avail_out;
			if (have)
			{
				size_t size = 2 + 4*(have+2)/3;
				size += (size + 75)/76;
				char base64[size], *out = base64;
				unsigned char *in = buf;
				for (rest = have; rest >= 3; rest -= 3)
				{
					uint32_t const t =
						(uint32_t)in[0] << 16 | (uint32_t)in[1] << 8 | in[2];
					in += 3;
					*out++ = B64_BYTE(t >> 18);
					*out++ = B64_BYTE(t >> 12);
					*out++ = B64_BYTE(t >> 6);
					*out++ = B64_BYTE(t);
					if ((col += 4) >= 76)
					{
						*out++ = '\n';
						col = 0;
					}
				}

				if (rest)
				{
					if (end && zout->avail_out != 0)
					{
						uint32_t t = (uint32_t)in[0] << 16;
						if (rest > 1)
							t |= (uint32_t)in[1] << 8;

						*out++ = B64_BYTE(t >> 18);
						*out++ = B64_BYTE(t >> 12);
						*out++ = rest > 1? B64_BYTE(t >> 6): '=';
						*out++ = '=';
						rest = 0;
					}
					else
						memmove(buf, in, rest);
				}

				if (end && col && zout->avail_out != 0)
					*out++ = '\n';

				assert(out <= &base64[size]);
				if ((size = out - &base64[0]) > 0)
				{
					dom->total_out += size;
					if (dom->addr[0].limit < dom->total_out &&
						dom->child && dom->child_killed == 0)
					{
						if (dom->zag->z.verbose >= 1)
							(*do_log)(LOG_ERR,
								"limit %" PRIu64 " exceeded for %s, killing pipe",
								dom->addr[0].limit, dom->domain);

						if (kill(-dom->child, SIGTERM)) // process group
							(*do_log)(LOG_ERR, "cannot kill pipe: %s",
								strerror(errno));
						else
							dom->child_killed = 1;

						return DEAD_CHILD;
					}

					if (fwrite(base64, size, 1, dom->out) != 1 || ferror(dom->out))
						return flush_common(dom, NULL, end);
				}
			}
		} while (zout->avail_out == 0);
		assert(zout->avail_in == 0);
		assert(rest < 3);
		assert(rest == 0 || end == 0); // no rest if end
		if (rest) memcpy(dom->b64.restbuf, buf, rest);
		dom->b64.col = col;
		dom->b64.rest = rest;
	}

#undef B64_BYTE

	return flush_common(dom, cstr, end);
}

static FILE* run_child(domain_run *dom)
{
	assert(dom);

	int fd[2];
	char const *badcall = "pipe";
	if (pipe(fd) == 0)
	{
		if ((dom->child = fork()) != -1)
		{
			if (dom->child == 0) // child
			{
				setpgid(0, 0); // kill the pipeline on error
				close(fd[1]);
				if (fd[0] != 0)
				{
					close(0);
					if (dup(fd[0]) != 0)
					{
						(*do_log)(LOG_ERR, "cannot dup(%d): %s",
							fd[0], strerror(errno));
						exit(1);
					}
					close(fd[0]);
				}
				execv(dom->zag->pargv[0], dom->zag->pargv);
				(*do_log)(LOG_ERR, "cannot execv %s: %s",
					dom->zag->pargv[0], strerror(errno));
				exit(1);
			}

			//// parent
			setpgid(dom->child, 0);
			close(fd[0]);
			FILE *out = fdopen(fd[1], "w");
			if (out)
				setlinebuf(out);
			else
			{
				(*do_log)(LOG_ERR, "cannot fdopen(%d): %s",
					fd[1], strerror(errno));
				close(fd[1]);
			}
			return out;
		}

		badcall = "fork";
	}

	(*do_log)(LOG_ERR, "cannot %s: %s", badcall, strerror(errno));
	return NULL;
}

static int pipe_on_first_record(cstring *cstr, void *vdom, int end)
{
	assert(vdom);
	if (cstr == NULL || vdom == NULL)
		return -1;

	domain_run *dom = vdom;
	assert(dom->out == NULL);

	if (end) // empty report: don't run child at all
	{
		cstr_trunc(cstr, 0);
		return 0;
	}

	if ((dom->out = run_child(dom)) != NULL)
		return (*(dom->xml.flush = dom->use_z? &flush_out_z: &flush_out))
			(cstr, vdom, end);

	return -1;
}

static size_t check_addr(domain_run *dom, char *p, int rndx)
/*
* Verify limit and external recipients.  Add good addr to dom->addr.
* In case of override, add new rua to dom->rua instead of dom->addr
* (it will be added to dom->addr in a subsequent call with rndx > 0).
*
* Return 0=ok (possibly not added), 1=protocol violation, -1=memory fault
*/
{
	assert(dom);
	assert(dom->rua);

	int const verbose = dom->zag->z.verbose;
	char const *domain = dom->rua[rndx].poldomain;
	uint64_t limit = UINT64_MAX;
	char *l = strchr(p, '!');
	if (l)
	{
		char *const bang = l;
		*bang = 0;
		limit = 0;
		int ch;
		while ((ch = *(unsigned char*)++l) != 0)
		{
			if (isdigit(ch))
				limit = 10*limit + ch - '0';
			else if (strchr("kmgt", ch)) // lowercase since adjust_rua
			{
				switch (ch)
				{
					case 't': limit *= 1024;
					case 'g': limit *= 1024;
					case 'm': limit *= 1024;
					case 'k': limit *= 1024;
					default: break;
				}
			}
			else
				break;
		}

		if (ch != 0 || limit == 0)
		{
			if (verbose >= 2)
			{
				*bang = '!';
				(*do_log)(LOG_NOTICE,
					"Invalid address %s (bad limit) in rua of %s",
					p, domain);
			}
			p = NULL;
		}
	}

	if (p)
	{
		char *rcptdom = strchr(p, '@');
		// adjust_rua() implies the following is true:
		assert(rcptdom && rcptdom[1] != 0 && strchr(rcptdom+1, '@') == NULL);
		if (rcptdom == NULL || *rcptdom == 0)
		{
			(*do_log)(LOG_ERR, "internal error rua=%s", p);
			p = NULL;
		}
		else if (!is_parent_domain_of(domain, ++rcptdom))
		{
			if (rndx)
			/*
			* Further, if the confirming record includes a URI whose host is
			* again different than the domain publishing that override, the
			* Mail Receiver generating the report MUST NOT generate a report
			* to either the original or the override URI.
			*                 http://tools.ietf.org/html/rfc7489#section-7.1
			*/
			{
				if (verbose >= 1)
					(*do_log)(LOG_ERR,
						"domain %s's external rcpt %s has yet another domain",
						dom->domain, p);
				return 1;
			}

			char *override = NULL, *badout = NULL;
			int rtc = verify_dmarc_addr(domain, rcptdom, &override, &badout);
			if (rtc == 0)
			{
				if (badout)
				{
					if (verbose >= 5)
						(*do_log)(LOG_NOTICE,
							"unsupported URI(s) \"%s\" "
							"in external rcpt override (%s authorize %s)",
								badout, rcptdom, domain);
					free(badout);
					badout = NULL;
				}

				if (override)
				{
					size_t n = dom->n_rua + 1;
					dmarc_rua *rua = realloc(dom->rua, n * sizeof(dmarc_rua));
					if (rua == NULL)
					{
						free(override);
						return -1;
					}

					dom->n_rua = n--;
					dom->rua = rua;
					rua[n].rua = override;
					rua[n].poldomain = rcptdom;
					if (verbose >= 8)
						(*do_log)(LOG_INFO,
							"external rcpt %s -> \"%s\" authorize domain %s",
							p, override, domain);
					p = NULL;
				}
				else if (verbose >= 8)
					(*do_log)(LOG_INFO, "external rcpt %s authorize domain %s",
						p, domain);
			}
			else
			/*
			* Where the above algorithm fails to confirm that the external
			* reporting was authorized by the Report Receiver, the URI MUST be
			* ignored by the Mail Receiver generating the report.
			*                   http://tools.ietf.org/html/rfc7489#section-7.1
			*/
			{
				if (verbose >= 1)
					(*do_log)(LOG_WARNING, "invalid external rcpt %s from %s: %s",
						p, domain,
						rtc == -1? "internal error":
						rtc == -2? "SERVFAIL or remote temperror":
						rtc == -3? "bad data from DNS":
						rtc == -4? "NXDOMAIN":
						rtc == -5? "not authorized by rcpt domain": "unknown");
				p = NULL;
			}
		}
	}

	if (p)
	{
		if (db_check_dmarc_rcpt(dom->zag->dwa, p) == 0) // good address
		{
			size_t n = dom->n_addr + 1;
			size_t size = n * sizeof(dmarc_addr);
			dmarc_addr *addr = dom->addr?
				realloc(dom->addr, size): malloc(size);
			if (addr == NULL)
				return -1;

			dom->addr = addr;
			dom->n_addr = n--;
			addr[n].addr = p;
			addr[n].limit = limit;
		}
		else if (verbose >= 5)
			(*do_log)(LOG_NOTICE,
				"Invalid address %s (bounced) in rua of %s",
					p, domain);
	}

	return 0;
}

static int each_rua(domain_run *dom, size_t rndx)
/*
* A domain can have rua=mailto:addr1,addr2,... all of which stay at
* rua[0].  In case of override, rua[1], rua[2], ... are added and
* checked on a subsequent call to this function with rndx > 0.
*/
{
	assert(dom);
	assert(dom->rua);
	assert(rndx < dom->n_rua);

	int rtc = 0;
	char *p, *next;

	for (p = dom->rua[rndx].rua; p; p = next)
	{
		if ((next = strchr(p, ',')) != NULL)
			*next++ = 0;
		if ((rtc |= check_addr(dom, p, rndx)) < 0)
			return -1;
	}

	return rtc;
}

typedef enum {write_all, write_accept, write_discard} write_rcpt;
static cstring *write_to_header(domain_run *dom, write_rcpt wr)
/*
* Write the To: header field based on dom->addr.  Behavior depends on wr:
* write_all: write all available addresses,
* write_accept: write only addresses whose limit is above current size,
* write_discard: write only addresses whose limit is exceeded.
*/
{
	assert(dom);

	cstring *to_header = cstr_init(dom->n_addr * (64/3 + 3 + 20)); // guess

	uint64_t report_size = dom->use_z? dom->total_out: UINT64_MAX;
	
	size_t n_addr = 0;
	for (size_t i = 0; i < dom->n_addr; ++i)
		if (dom->addr[i].addr)
		{
			if (wr)
			{
				if (wr == write_accept)
				{
					if (dom->addr[i].limit < report_size)
					{
						if (dom->zag->z.verbose >= 6)
							(*do_log)(LOG_ERR,
								"rcpt %s discarded: limit %" PRIu64 " < %" PRIu64,
								dom->addr[i].addr, dom->addr[i].limit, report_size);
						continue;
					}
				}
				else if (dom->addr[i].limit >= report_size)
					continue;
			}

			if (to_header)
			{
				to_header = cstr_printf(to_header, "%s %s",
					n_addr == 0? "To:": ",", dom->addr[i].addr);
				if (to_header && dom->addr[i].limit != UINT64_MAX)
					to_header = cstr_printf(to_header, " (limit=%" PRIu64 ")",
						dom->addr[i].limit);
				++n_addr;
			}
		}

	if (to_header && n_addr == 0 && wr <= write_accept) // no address written
	{
		if (dom->zag->z.verbose >= 1)
		{
			if (wr)
				to_header = cstr_printf(to_header, " at limit %" PRIu64, report_size);
			(*do_log)(LOG_INFO, "no rcpt left%s for domain %s",
				to_header? cstr_get(to_header): "", dom->domain);
		}
		free(to_header);
		to_header = NULL;
	}
	return to_header;
}

static int chk_signal(domain_run *dom)
{
	assert(dom);

	if (dom->zag->z.verbose >= 1)
		(*do_log)(LOG_WARNING, "Killed by signal %s", strsignal(signal_break));

	clean_dom(dom);
	return 1;
}

static bool reap_child(domain_run *dom, char const *dar_domain)
{
	bool report_considered_sent = false;
	const zag_parm *zag = dom->zag;
	while (dom->child)
	{
		int status;
		pid_t pid = waitpid(dom->child, &status, 0);
		if (pid == dom->child)
		{
			if (WIFEXITED(status))
			{
				int rc = WEXITSTATUS(status);
				if (zag->z.verbose >= (rc? 3: 7))
					(*do_log)(rc? LOG_INFO: LOG_DEBUG,
						"%s for %s exit code=%d", zag->pargv[0], dar_domain, rc);
				report_considered_sent = rc == 0;
			}
			else if (WIFSIGNALED(status))
			{
				int sig = WTERMSIG(status);
				if (zag->z.verbose >= 3)
					(*do_log)(LOG_WARNING,
						"%s for %s: %s%s",
						zag->pargv[0], dar_domain, strsignal(sig),
						dom->child_killed? " (I killed pipe myself)": "");
			}
		}
		else if (errno == EINTR)
		{
			if (signal_break)
			{
				if (zag->z.verbose >= 1)
					(*do_log)(LOG_INFO, "killing process group %d",
						dom->child);
				if (kill(-dom->child, SIGTERM))
					(*do_log)(LOG_ERR, "cannot kill: %s",
						strerror(errno));
				else
					dom->child_killed = 1;
			}
			continue;
		}

		dom->child = 0;
		break;
	}

	return report_considered_sent;
}

static int do_pipe(domain_run *dom)
{
	int rtc = 0;
	rewind(dom->out);
	FILE *out = run_child(dom);
	if (out)
	{
		if ((rtc = copy_file(dom->out, out)) != 0)
			(*do_log)(LOG_ERR, "cannot send tmpfile through pipe: %s",
				strerror(errno));
		if (fclose(out) != 0)
			(*do_log)(LOG_ERR, "cannot close pipe: %s", strerror(errno));
	}
	return rtc;
}

static int domain_select(int nfield, char const *field[], void* vzag)
/*
* Receive fields from domain selection query.  These must be:
*
*   domain_ref, domain name, 
*    [ last_report, dmarc_ri, dmarc_rua, dmarc_rec ]
*
* (at least the first two are needed, the last )
* Produce a report either on a file or through a pipe.
* Return non-zero to abort receiving further domains.
*/
{
	zag_parm *zag = vzag;

	if (nfield < 2)
	{
		(*do_log)(LOG_ERR, "only %d field(s)%s", nfield, bailout);
		return -1;
	}

	signal_break = signal_child = signal_pipe = 0;
	zag->n_dom_in += 1;
	dmarc_agg_record dar;
	memset(&dar, 0, sizeof dar);

	/*
	* Check fields 0 (domain_ref) and 1 (domain name)
	*/
	dar.domain_ref = field[0];
	if ((dar.domain = field[1]) == NULL)
	{
		int out = ++zag->bad - 2*zag->good > 2;
		(*do_log)(LOG_ERR, "NULL domain for ref %s%s",
			dar.domain_ref? dar.domain_ref: "NULL", out? bailout: ".");
		return out;
	}

	/*
	* Check optional field 2 (last_report); if not given, behavior is as if
	* this is the first report to this domain.
	*/
	time_t last_report = 0;
	if (nfield >= 3)
	{
		char *t = NULL;
		char const *f2 = field[2];
		long l = f2? strtol(f2, &t, 10): 0;
		if (t && *t == 0 && l >= 0 && l <= zag->period_end + zag->period)
			last_report = (time_t)l;
		else
		{
			int out = ++zag->bad - 2*zag->good > 2;
			if (f2 == NULL) f2 = "NULL";
			(*do_log)(LOG_ERR, "Invalid last_report \"%s\" for %s%s",
				f2, dar.domain, out? bailout: ".");
			return out;
		}
	}

	domain_run dom;
	memset(&dom, 0, sizeof dom);
	dom.zag = zag;
	dom.domain = dar.domain;
	if ((dom.rua = malloc(sizeof(dmarc_rua))) == NULL)
		return -1;

	/*
	* Check optional fields 3 (dmarc_ri), 4 (rua), and 5 (other dmarc stuff).
	* If these fields are not given, or if they were truncated due to database
	* column length definition, a new DMARC record is retrieved from the DNS.
	* (Note that DNS lookup's are also needed to confirm external destinations.)
	*/
	dom.n_rua = 1;
	dom.rua[0].rua = NULL;
	dom.rua[0].poldomain = dar.domain;
	time_t dmarc_ri = 0;
	if (nfield < 6 || field[4] == NULL || field[5] == NULL ||
		(dom.drec = strdup(field[5])) == NULL || check_remove_sentinel(dom.drec) ||
		(dom.rua[0].rua = strdup(field[4])) == NULL ||
			check_remove_sentinel(dom.rua[0].rua))
	{
		dmarc_rec dmarc;
		dmarc_domains dd;
		memset(&dmarc, 0, sizeof dmarc);
		memset(&dd, 0, sizeof dd);
		if ((dd.domain = strdup(dar.domain)) != NULL &&
			(get_dmarc(&dd, &dmarc) != 0))
		{
			int out = ++zag->bad - 2*zag->good > 2;
			(*do_log)(LOG_ERR, "Cannot retrieve DMARC record for %s%s",
				dar.domain, out? bailout: ".");
			clean_dom(&dom);
			free(dd.domain);
			return out;
		}

		free(dd.domain);

		if (dmarc.rua == NULL)
		{
			if (zag->z.verbose >= 1)
				(*do_log)(LOG_WARNING, "No rua= in DMARC record retrieved for %s",
					dar.domain);
			clean_dom(&dom);
			return 0;
		}

		dmarc_ri = adjust_ri(dmarc.ri, zag->period);
		free(dom.rua[0].rua);
		dom.rua[0].rua = adjust_rua(&dmarc.rua, NULL);
		free(dom.drec);
		dom.drec = write_dmarc_rec(&dmarc);
		if (dom.rua[0].rua == NULL || dom.drec == NULL)
		{
			(*do_log)(LOG_ERR, "Bad DMARC record for %s, skipping.",
				dar.domain);
			clean_dom(&dom);
			return 0;
		}

		check_remove_sentinel(dom.drec);
		check_remove_sentinel(dom.rua[0].rua);
	}
	else
	{
		char *t = NULL;
		char const *f3 = field[3];
		long l = f3? strtol(f3, &t, 10): 0;
		if (t && *t == 0 && l > 0 && l <= 86400)
			dmarc_ri = adjust_ri((int)l, zag->period);
		else
		{
			int out = ++zag->bad - 2*zag->good > 2;
			if (f3 == NULL) f3 = "NULL";
			(*do_log)(LOG_ERR, "Invalid dmarc_ri \"%s\" for %s%s",
				f3, dar.domain, out? bailout: ".");
			clean_dom(&dom);
			return out;
		}
	}

	/*
	* WHERE is supposed to be like so (but dmarc_ri may change):
	* last_report <= $(period_end) - dmarc_ri AND
	* last_recv > last_report AND
	* last_recv > $(period_end) - 86400
	*/

	dar.period_end = zag->period_end;
	dar.period_start = dar.period_end - dmarc_ri;
	int logged = 0;
	if (last_report) // && zag->force == 0)
	{
		if (dar.period_end <= last_report) // how come?
		{
			if (zag->z.verbose >= 4)
			{
				char *l = human_time(last_report);
				(*do_log)(LOG_NOTICE, "Last report already %ld%s, skipping %s",
					last_report, l? l: "", dar.domain);
				free(l);
			}
			clean_dom(&dom);
			return 0;
		}


		time_t diff = dar.period_end - last_report;
		time_t rem = diff % dmarc_ri;
		if (rem != 0)
		{
			if (zag->z.verbose >= 6)
			{
				time_t next = last_report + dmarc_ri;
				char *n = human_time(next);
				(*do_log)(LOG_NOTICE, "Next report due %ld%s, skipping %s",
					last_report, n? n: "", dar.domain);
				free(n);
			}
			clean_dom(&dom);
			return 0;
		}

		if (dar.period_start < last_report)
		{
			if (last_report < dar.period_start + zag->period)
			{
				dar.period_start = last_report;
				if (zag->z.verbose >= 4)
				{
					char *e = human_time(dar.period_end),
						*s = human_time(dar.period_start);
					(*do_log)(LOG_WARNING, "Short period of %s: starting "
						"last_report=%ld%s, end=%ld%s, diff=%ld, adjusted ri=%ld",
							dar.domain,
							dar.period_start, s? s: "",
							dar.period_end, e? e: "",
							dar.period_end - dar.period_start, dmarc_ri);
					free(s);
					free(e);
					logged = 1;
				}
			}
			else
			{
				int out = ++zag->bad - 2*zag->good > 2;
				char *e = human_time(dar.period_end), *l = human_time(last_report);
				(*do_log)(LOG_WARNING, "Unable to determine period for %s: "
					"have end=%ld%s, last=%ld%s, diff=%ld, rem=%ld, honored=%d%s",
						dar.domain, dar.period_end, e? e: "", last_report, l? l: "",
						diff, rem, zag->z.honored_report_interval, out? bailout: ".");
				free(l);
				free(e);
				clean_dom(&dom);
				return out;
			}
		}
	}
	else if (zag->period_end % dmarc_ri != 0)
	{
		if (zag->z.verbose >= 6)
		{
			time_t due = zag->period_end - zag->period_end % dmarc_ri + dmarc_ri;
			char *d = human_time(due);
			(*do_log)(LOG_NOTICE, "First report to %s due %ld%s, skipping.",
				dar.domain, due, d? d: "");
			free(d);
		}
		clean_dom(&dom);
		return 0;
	}

	if (zag->z.verbose >= 5 && logged == 0)
	{
		char *s = human_time(dar.period_start), *e = human_time(dar.period_end);
		(*do_log)(LOG_INFO, "period of %s: from %ld%s to %ld%s",
			dar.domain, dar.period_start, s? s: "", dar.period_end, e? e: "");
		free(e);
		free(s);
	}

	for (size_t i = 0; i < dom.n_rua; ++i)
	{
		int rtc = each_rua(&dom, i);
		if (rtc)
		{
			clean_dom(&dom);
			return rtc < 0;
		}
	}

	if (dom.n_addr == 0)
	{
		if (zag->z.verbose >= 5)
			(*do_log)(LOG_INFO, "no rcpt for %s", dar.domain);
		clean_dom(&dom);
		return 0;
	}

	/*
	* Sort addresses by increasing limit.  Use gnome sort, as we expect few
	* elements.
	*/
	for (size_t i = 0; i < dom.n_addr;)
	{
		if (i == 0 || dom.addr[i].limit >= dom.addr[i-1].limit)
			++i;
		else
		{
			dmarc_addr temp = dom.addr[i];
			dom.addr[i] = dom.addr[i-1];
			dom.addr[i-1] = temp;
			--i;
		}
	}
	// lowest limit
	char limit_str[64/3 + 3];
	snprintf(limit_str, sizeof limit_str, "%" PRIu64, dom.addr[0].limit);

	/*
	* The aggregate data MUST be an XML file that SHOULD be subjected to
	* GZIP compression.  Declining to apply compression can cause the
	* report to be too large for a receiver to process (a commonly observed
	* receiver limit is ten megabytes); doing the compression increases the
	* chances of acceptance of the report at some compute cost.  The
	* aggregate data SHOULD be present using the media type "application/
	* gzip" if compressed (see [GZIP]), and "text/xml" otherwise.  The
	* filename is typically constructed using the following ABNF:
	*
	*  filename = receiver "!" policy-domain "!" begin-timestamp
	*             "!" end-timestamp [ "!" unique-id ] "." extension
	*
	*                    http://tools.ietf.org/html/rfc7489#section-7.2.1.1
	*/
	char *org_email = getenv("ORG_EMAIL"),
		*receiver = org_email? strchr(org_email, '@'): NULL;

	if (receiver)
		receiver += 1;
	else
	{
		(*do_log)(LOG_ERR, "Missing or invalid ORG_EMAIL environment variable");
		receiver = "example.com";
	}

	dom.fname = cstr_init(256);
	if (dom.fname)
		dom.fname = cstr_printf(dom.fname, "%s!%s!%ld!%ld",
			receiver, dar.domain, dar.period_start, dar.period_end);

#if HAVE_UUID
	char report_id[40];
	if (zag->use_uuid)
	{
		uuid_t u;
		uuid_generate(u);
		uuid_unparse(u, report_id);
		char *id_out = &report_id[0];
		int ch; // take off minus signs
		for (char *id_in = id_out; (ch = *(unsigned char*)id_in) != 0; ++id_in)
			if (isalnum(ch))
				*id_out++ = ch;
		*id_out = 0;
		uuid_clear(u);
		if (dom.fname)
			dom.fname = cstr_addch(dom.fname, '!');
		if (dom.fname)
			dom.fname = cstr_addstr(dom.fname, report_id);
	}
	else
		report_id[0] = 0;
#endif

	size_t const fname_base_length = cstr_length(dom.fname);
	if (dom.fname)
		dom.fname = cstr_addstr(dom.fname, ".xml");
	if (zag->use_z && dom.fname)
		dom.fname = cstr_addstr(dom.fname, ".gz");
	if (dom.fname == NULL || setenv("FILENAME", cstr_get(dom.fname), 1) != 0)
	{
		(*do_log)(LOG_ERR, "cannot setenv filename: %s", strerror(errno));
		clean_dom(&dom);
		return -1;
	}

	FILE *envout = NULL;
	if (zag->pargv == NULL)
	/*
	* If no pipe, use two files.  *.env has environment variables, while
	* *.xml[.gz.b64] has the data.  Files are created here and deleted in
	* clean_dom(), in case of error.
	*/
	{
		if (dom.fname)
			dom.efname = cstr_dup(dom.fname);
		if (dom.efname)
		{
			cstr_trunc(dom.efname, fname_base_length);
			dom.efname = cstr_addstr(dom.efname, ".env");
		}
		dom.efname = cstr_final(dom.efname);

		if (zag->use_z && dom.fname)
			dom.fname = cstr_addstr(dom.fname, ".b64");

		if (dom.fname && dom.efname)
		{
			if ((envout = fopen(cstr_get(dom.efname), "w")) == NULL)
				(*do_log)(LOG_ERR, "cannot write %s: %s",
					cstr_get(dom.efname), strerror(errno));
			else if ((dom.out = fopen(cstr_get(dom.fname), "w")) == NULL)
				(*do_log)(LOG_ERR, "cannot write %s: %s",
					cstr_get(dom.efname), strerror(errno));
		}

		if (envout == NULL || dom.out == NULL)
		{
			if (envout)
			{
				fclose(envout);
				unlink(cstr_get(dom.efname));
			}
			clean_dom(&dom);
			return 0;
		}

		fprintf(envout, "%s=\"%s\"\n", "FILENAME", getenv("FILENAME"));
		dom.use_file = 1;
	}

	if (zag->use_z)
	/*
	* On the fly compression and base64 encoding is initialized here.
	*/
	{
		dom.b64.zout.data_type = Z_TEXT;
		int rc = deflateInit2(&dom.b64.zout, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
			16 + 15 , 8, Z_DEFAULT_STRATEGY);
		if (rc != Z_OK)
		{
			char const *rc_v;
			switch (rc)
			{
				case Z_STREAM_ERROR: rc_v = "STREAM"; break;
				case Z_MEM_ERROR: rc_v = "MEM"; break;
				case Z_VERSION_ERROR: rc_v = "VERSION"; break;
				default: rc_v = ""; break;
			}
			(*do_log)(LOG_ERR, "cannot init zlib: Z_%s_ERROR: %s",
				rc_v, dom.b64.zout.msg? dom.b64.zout.msg: "dunno why");
			clean_dom(&dom);
			return 0;
		}

		gz_header head;
		memset(&head, 0, sizeof head);
		head.text = 1;
		head.time = time(0);
		head.os = 255;
		deflateSetHeader(&dom.b64.zout, &head);
		dom.use_z = 1;
	}

#define CHECK_SIGNAL do {\
	if (signal_break) return chk_signal(&dom); } while(0)
	CHECK_SIGNAL;

	/*
	* Data can be piped to a child or saved to a file.
	* (See four cases commented below.)
	*/
	dom.xml.flush_arg = &dom;
	dom.xml.flush = dom.use_z? &flush_out_z: &flush_out;
	dom.xml.cstr = cstr_init(1024);
	if (dom.xml.cstr == NULL || dom.fname == NULL ||
		(dom.efname == NULL && zag->pargv == NULL))
	{
		clean_dom(&dom);
		(*do_log)(LOG_CRIT, "MEMORY FAULT");
		return -1;
	}

	bool report_considered_sent = false;
	bool delayed_pipe_mode = false;
	bool pipe_each_addr = false;
	if (!dom.use_file)
	{
		pipe_each_addr = zag->one_rcpt;
		if (pipe_each_addr || zag->use_tmpfile ||
			dom.addr[0].limit != dom.addr[dom.n_addr-1].limit)
		{
			if ((dom.out = tmpfile()) == NULL)
			{
				(*do_log)(LOG_ERR, "cannot tmpfile(): %s", strerror(errno));
				clean_dom(&dom);
				return 0;
			}
			delayed_pipe_mode = true;
		}
		else
			dom.xml.flush = &pipe_on_first_record;
	}

	/*
	* Write the environment.  FILENAME was written before because it may
	* differ from the real filename on disk. TO_HEADER can be delayed
	* until it is known whether per-recipient size limits prevent sending.
	* (For direct piping, the child will have to be killed in such case.)
	* However, size checking is only done if use_z is in effect.  If not,
	* it makes no sense to make assumptions on what compression/encoding
	* is going to be used.
	*/
#define SETENV(N, V) do {\
	if (envout) fprintf(envout, "%s=\"%s\"\n", (N), (V));\
	else setenv((N), (V), 1); } while (0)

	SETENV("CONTENT_TYPE", dom.use_z? "application/gzip": "text/xml");
	SETENV("CONTENT_TRANSFER_ENCODING", dom.use_z? "base64": "7bit");
	SETENV("DOMAIN", dar.domain);
	SETENV("LIMIT", limit_str);
	if (!pipe_each_addr)
		SETENV("URLENCODED_RCPT", "");

	if (!delayed_pipe_mode && !dom.use_file)
	{
		cstring *to_header = write_to_header(&dom, write_all);
		if (to_header == NULL)
		{
			if (envout) fclose(envout);
			clean_dom(&dom);
			return 0;
		}
		SETENV("TO_HEADER", cstr_get(to_header));
		free(to_header);
	}

	/*
	* Write the report
	*/
	stag(&dom.xml, "feedback");
	stag(&dom.xml, "report_metadata");
	xtag(&dom.xml, "org_name", getenv("ORG_NAME"));
	xtag(&dom.xml, "email", org_email);

	char *extra_contact = getenv("EXTRA_CONTACT");
	if (extra_contact)
		xtag(&dom.xml, "extra_contact_info", extra_contact);

#if HAVE_UUID
	if (report_id[0])
	{
		xtag(&dom.xml, "report_id", report_id);
		SETENV("MESSAGE_ID", report_id);
	}
#endif
#undef SETENV

	stag(&dom.xml, "date_range");
	uint32_xtag(&dom.xml, "begin", dar.period_start);
	uint32_xtag(&dom.xml, "end", dar.period_end);
	etag(&dom.xml); // date_range
	etag(&dom.xml); // report_metadata

	stag(&dom.xml, "policy_published");
	xtag(&dom.xml, "domain", dar.domain);
	for (char *p = dom.drec; p;)
	{
		if (*p == ' ')
			++p;

		char *cont = strchr(p, '=');
		if (cont == NULL)
			break;

		*cont++ = 0;
		char *e = strchr(cont, ';');
		if (e)
			*e++ = 0;

		xtag(&dom.xml, p, cont);
		p = e;
	}
	etag(&dom.xml); // policy_published

	// rtc can be SIGINT (2) SIGTERM (15) or a negative, fatal error
	// flushing may result in DEAD_CHILD for an aborted send.
	// We return 0 except for fatal error.
	int rtc = db_run_dmarc_agg_record(zag->dwa, &dar, &record_select, &dom.xml);
	etag(&dom.xml); // feedback - end of report

	if (rtc == 0)
		rtc = xml_flush(&dom.xml, 1 /* end of report */);

	if (rtc == 0)
		zag->good += 1;
	if (zag->z.verbose >= 5)
		(*do_log)(LOG_INFO,
			"%zu row(s) for domain %s, rtc=%d", dom.n_record, dar.domain, rtc);

	if (rtc == DEAD_CHILD)
		rtc = 0; // want more domains

	/*
	* If dom.out is still opened, no write error occurred and the report
	* is written or piped, except if rtc.  There can be four cases.
	*/
	if (dom.out && rtc == 0)
	{
		if (pipe_each_addr)
		/*
		* The report is on a tempfile, and has to be piped to the
		* sending process.  Option -1 was given, one recipient per
		* process and bounce address.
		*/
		{
			for (size_t i = 0; rtc == 0 && i < dom.n_addr; ++i)
			{
				CHECK_SIGNAL;

				char *addr = dom.addr[i].addr;
				cstring *urlencoded_rcpt = urlencode(addr);
				cstring *to_header = cstr_init(5 + strlen(addr));
				to_header = cstr_printf(to_header, "To: %s", addr);
				if (urlencoded_rcpt == NULL || to_header == NULL)
				{
					clean_dom(&dom);
					return 0;
				}

				setenv("URLENCODED_RCPT", cstr_get(urlencoded_rcpt), 1);
				free(urlencoded_rcpt);
				setenv("TO_HEADER", cstr_get(to_header), 1);
				free(to_header);

				rtc |= do_pipe(&dom);

				// add to period if at least one is sent
				if (dom.child)
					report_considered_sent |= reap_child(&dom, dar.domain);
			}

			fclose(dom.out);
			dom.out = NULL;
		}
		else if (delayed_pipe_mode)
		/*
		* The report is on a tempfile, by option -t or because of
		* multiple size limits.  The file has to be piped, once, only
		* to those recipients which accept its size.
		*/
		{
			CHECK_SIGNAL;

			cstring *to_header = write_to_header(&dom, write_accept);
			if (to_header == NULL)
			{
				clean_dom(&dom);
				return 0;
			}

			setenv("TO_HEADER", cstr_get(to_header), 1);
			free(to_header);
			
			report_considered_sent = do_pipe(&dom);
			fclose(dom.out);
			dom.out = NULL;

			if (dom.child)
				report_considered_sent = reap_child(&dom, dar.domain);
		}
		else if (dom.use_file)
		/*
		* The report is written on file, as well as the environment.
		* The caller knows what to do with those files.
		*/
		{
			CHECK_SIGNAL;

			cstring *to_header = write_to_header(&dom, write_accept);
			if (to_header == NULL)
			{
				if (envout) fclose(envout);
				clean_dom(&dom);
				return 0;
			}
			fprintf(envout, "%s=\"%s\"\n", "TO_HEADER", cstr_get(to_header));
			free(to_header);

			if (fclose(envout) != 0)
				(*do_log)(LOG_ERR, "cannot close %s: %s",
					cstr_get(dom.efname), strerror(errno));
			if (fclose(dom.out) != 0)
				(*do_log)(LOG_ERR, "cannot close %s: %s",
					cstr_get(dom.fname), strerror(errno));
			envout = dom.out = NULL;

			dom.use_file = 0; // prevent cleanup, files rm by caller
			report_considered_sent = true;
		}
		else
		/*
		* Direct pipe, required by --pipe and not disabled by other
		* options or size limits.
		*/
		{
			assert(dom.n_record > 0); // otherwise wouldn't have piped it!
			if (fclose(dom.out) != 0)
				(*do_log)(LOG_ERR, "cannot close pipe: %s", strerror(errno));
			dom.out = NULL;

			if (dom.child)
				report_considered_sent = reap_child(&dom, dar.domain);
		}
	}

	if (envout)
	{
		fclose(envout);
		envout = NULL;
	}

	CHECK_SIGNAL;
#undef CHECK_SIGNAL

	if (report_considered_sent)
	{
		if (!zag->no_set_dmarc_agg)
			db_set_dmarc_agg(zag->dwa, &dar);
		zag->n_dom_out += 1;
	}	

	clean_dom(&dom);
	return rtc;
}

static int do_args(int argc, char *argv[], zag_parm *zag)
{
	set_program_name("zaggregate");
	set_parm_logfun(&stderrlog);

	char const **expect = NULL;
	int errs = 0;

	for (int i = 1; i < argc; ++i)
	{
		char *arg = argv[i];
		if (arg[0] == '-' && arg[1] != '-')
		{
			int ch;
			while ((ch = *++arg) != 0)
			{
				switch(ch)
				{
					case '1':
						zag->one_rcpt = 1;
						break;

					case 'f':
						expect = &zag->config_file;
						break;

					case 'l':
						openlog("zaggregate", LOG_PID, LOG_MAIL);
						set_parm_logfun(do_log = &syslog);
						break;

					case 't':
						zag->use_tmpfile = 1;
						break;
#if HAVE_UUID
					case 'u':
						zag->use_uuid = 1;
						break;
#endif
					case 'v':
						zag->verbose += 1;
						break;

					case 'z':
						zag->use_z = 1;
						break;

					default:
						(*do_log)(LOG_CRIT,
							"Invalid option \"%c\" in \"%s\"\n",
							ch, argv[i]);
						++errs;
						break;
				}
			}

			if (expect)
			{
				if (++i >= argc)
				{
					(*do_log)(LOG_CRIT,
						"Expected argument after \"%s\"\n", argv[i - 1]);
					break;
				}
				*expect = argv[i];
				expect = NULL;
			}
		}
		else if (strcmp(arg, "--version") == 0)
		{
			printf(PACKAGE_NAME ", version " PACKAGE_VERSION "\n"
				"Compiled with"
#if defined NDEBUG
				"out"
#endif
				" debugging support\n"
				"Compiled with zlib version: " ZLIB_VERSION "\n"
				"Linked with zlib version: %s (%smatch)\n",
				zlibVersion(),
				strcmp(ZLIB_VERSION, zlibVersion()) == 0? "": "DO NOT ");
			return 1;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			printf("zaggregate command line args:\n"
			/*  12345678901234567890123456 */
				"  -f config-filename      override %s\n"
				"  -l                      use syslog\n"
				"  -t                      use tmpfile\n"
#if HAVE_UUID
				"  -u                      use uuid for filename\n"
#endif
				"  -v                      verbose (database debug)\n"
				"  -z                      compress output\n"
				"  --pipe                  remaining arguments form a pipeline\n"
				"  --help                  print this stuff and exit\n"
				"  --version               print version string and exit\n"
				"  --dry-run               don't update DB after report committed\n"
				"  --fake-dns              use \"KEYFILE\", not DNS, to verify rua\n",
					default_config_file);
			return 1;
		}
		else if (strcmp(arg, "--pipe") == 0)
		{
			if (++i >= argc)
			{
				(*do_log)(LOG_ERR, "missing argument after \"--pipe\"");
				++errs;
			}
			else
			{
				zag->pargc = argc - i;
				zag->pargv = argv + i;
			}
			break;
		}
		else if (strcmp(arg, "--dry-run") == 0)
			zag->no_set_dmarc_agg = 1;
		else if (strcmp(arg, "--fake-dns") == 0)
			set_adsp_query_faked('k');
		else
		{
			(*do_log)(LOG_CRIT, "Invalid option \"%s\"\n", arg);
			++errs;
		}
	}

	if (errs)
		return errs;

	if (zag->config_file == NULL)
		zag->config_file = default_config_file;

	return 0;
}

int main(int argc, char *argv[])
{
	zag_parm zag;
	memset(&zag, 0, sizeof zag);

	if (do_args(argc, argv, &zag))
		return 1;

	if ((zag.dwa = db_init()) == NULL)
		return 1;

	void *parm_target[PARM_TARGET_SIZE];
	parm_target[parm_t_id] = &zag.z;
	parm_target[db_parm_t_id] = db_parm_addr(zag.dwa);

	int rtc = 0;
	zag.z.honored_report_interval = DEFAULT_REPORT_INTERVAL;

	assert(zag.config_file);
	if (*zag.config_file == 0 ||
		(rtc = read_all_values(parm_target, zag.config_file)) != 0 ||
		zag.z.honored_report_interval <= 0 ||
		zag.z.honored_report_interval > 86400)
	{
		if (*zag.config_file && rtc == 0)
			(*do_log)(LOG_ERR, "invalid honored_report_interval %d",
				zag.z.honored_report_interval);

		db_clear(zag.dwa);
		return 1;
	}

	if (query_init() < 0)
	{
		db_clear(zag.dwa);
		return 1;
	}

	// adjust verbosity
	if (zag.verbose == 0 && zag.z.verbose > 9)
		zag.verbose = zag.z.verbose - 9;
	if (zag.verbose)
	{
		set_database_verbose(zag.verbose, 0);
		if (zag.z.verbose == 0)
			zag.z.verbose = 3 * zag.verbose;
	}

	// check periodicity
	zag.period = adjust_period(zag.z.honored_report_interval);
	if (zag.period != zag.z.honored_report_interval)
		(*do_log)(zag.z.honored_report_interval > 86400 ||
			zag.z.honored_report_interval < 0? LOG_CRIT: LOG_WARNING,
			"Bad honored_report_interval=%d, adjusted to %ld.  CHECK CRON!",
				zag.z.honored_report_interval, zag.period);

	// run
	init_signal();
	if ((rtc = db_zag_wrapup(zag.dwa, NULL)) == 0 &&
		(rtc = db_connect(zag.dwa)) == 0)
	{
		// round down period to honored_report_interval multiples
		time(&zag.period_end);
		zag.period_end -= zag.period_end % zag.period;
		if (zag.z.verbose >= 4)
		{
			char *p = human_time(zag.period_end);
			(*do_log)(LOG_INFO,
				"aggregate period %ld%s", zag.period_end, p? p: "");
			free(p);
		}

		rtc = db_run_dmarc_agg_domain(zag.dwa,
			zag.period_end, zag.period, &domain_select, &zag);
		if (zag.z.verbose >= 1)
			(*do_log)(rtc == 0? LOG_INFO: LOG_ERR,
				"%zu domain(s) selected, %d good, %d bad, %zu report(s) committed",
				zag.n_dom_in, zag.good, zag.bad, zag.n_dom_out);
	}

	clear_parm(parm_target);
	db_clear(zag.dwa);
	query_done();
	return rtc != 0;
}

#else // HAVE_OPENDBX
int main()
{
	puts("This program does nothing!\nPlease install OpenDBX then reconfigure");
	return 0;
}
#endif
