/*
** filterlib.c - written in milano by vesely on 19 oct 2001
** for sophos anti virus for courier-mta global filters (with
** variations from Courier's libfilter.c) and modified for
** zdkimfilter
**
** This is a modular software, not object oriented:
** compile with:
**       "-DFILTER_NAME=blah_blah"
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2010-2017 Alessandro Vesely

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
#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <limits.h>

#include "filedefs.h"
#include "filecopy.h"

#if defined(FILTER_NAME)
#define STRING2(P) #P
#define STRING(P) STRING2(P)
#define THE_FILTER STRING(FILTER_NAME)
#else
#define THE_FILTER "filterlib"
#endif

#include "filterlib.h"
#include <assert.h>

static volatile int
	signal_timed_out = 0,
	signal_break = 0,
	signal_hangup = 0,
	live_children = 0;

typedef struct ctl_fname_chain
{
	 struct ctl_fname_chain *next;
	 char fname[1]; // actually large as needed
} ctl_fname_chain;

struct filter_lib_struct
{
	void *parm;

	char const *resp;
	void *free_on_exit[3];
	int in, out;
	char *data_fname, *write_fname;
	FILE *data_fp, *write_fp;
	ctl_fname_chain *cfc;
	char *argv0;
	fl_msg_info *info_to_free;

	fl_callback filter_fn;
	fl_callback after_filter;
	sigset_t blockmask, allowset;

	int ctl_count;
	unsigned int all_mode:4;
	unsigned int verbose:4;
	unsigned int testing:4;
	unsigned int batch_test:4;
	unsigned int no_fork:2;
	unsigned int write_file:2;
	fl_whence_value whence;
};

/* ----- sig handlers ----- */

static int sig_verbose = 0;
static void child_reaper(int sig)
{
	int status;
	pid_t child;

	(void)sig;

	int save_errno = errno;
	while ((child = waitpid(-1, &status, WNOHANG)) > 0)
	{
		--live_children;

#if !defined(NDEBUG)
		if (sig_verbose >= 8)
		{
			char buf[80];
			unsigned s = snprintf(buf, sizeof buf,
				THE_FILTER ": %d exited, %d remaining\n",
				(int)child, live_children);
			if (s >= sizeof buf)
			{
				buf[sizeof buf - 1] = '\n';
				s = sizeof buf;
			}
			write(2, buf, s);
		}
#endif
	}
	errno = save_errno;
}

int fl_log_no_pid;
static inline int my_getpid(void)
{
	return fl_log_no_pid? 0: (int)getpid();
}

static void sig_catcher(int sig)
{
#if !defined(NDEBUG)
	if (sig_verbose >= 1)
	{
		char buf[80];
		unsigned s = snprintf(buf, sizeof buf,
			THE_FILTER "[%d]: received signal %d: keep=%d\n",
			my_getpid(), sig, fl_keep_running());
		if (s >= sizeof buf)
		{
			buf[sizeof buf - 1] = '\n';
			s = sizeof buf;
		}
		write(2, buf, s);
	}
#endif
	switch(sig)
	{
		case SIGALRM:
			signal_timed_out = 1;
			break;

		case SIGHUP:
		case SIGUSR1:
		case SIGUSR2:
			signal_hangup = sig;
			break;

		case SIGPIPE:
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			signal_break = sig;
			break;
		default:
			break;
	}
}

void fl_alarm(unsigned seconds)
{
#if !defined(NDEBUG)
	/* check the signal handler has been set up */
	struct sigaction oact;
	if (sigaction(SIGALRM, NULL, &oact) != 0 ||
		oact.sa_handler != &sig_catcher)
			fprintf(stderr, "SIGALRM not correct!!\n");
#endif
	signal_timed_out = 0;
	alarm(seconds);
}

int fl_keep_running(void)
{
	return signal_timed_out == 0 && signal_break == 0;
}

/* ----- ctl_fname_chain handling ----- */

static ctl_fname_chain* cfc_shift(ctl_fname_chain **cfc)
{
	ctl_fname_chain *s = *cfc;
	if (s)
		*cfc = s->next;
	return s; // freed by caller
}

static int cfc_unshift(ctl_fname_chain **cfc, char const *fname, size_t len)
{
	ctl_fname_chain *const u = (ctl_fname_chain*)
		malloc(len + sizeof(ctl_fname_chain));
	if (u)
	{
		u->next = *cfc;
		memcpy(u->fname, fname, len);
		u->fname[len] = 0;
		*cfc = u;
		return 0;
	}
	return 1;
}

/* ----- fl_* aux functions ----- */
static const char* const whence_string[] =
{
	"stdalone",
	"init",
	"main loop",
	"before fork",
	"after fork",
	"in child"
};
typedef char compile_time_check_that_whence_string_has_value_max_elements
[(FL_WHENCE_VALUE_MAX == sizeof whence_string/sizeof whence_string[0])? 1: -1];

fl_whence_value fl_whence(fl_parm *fl)
{
	assert(fl);
	return fl->whence;
}

char const* fl_whence_string(fl_parm *fl)
{
	assert(fl);
	unsigned const w = fl->whence;
	assert(w < FL_WHENCE_VALUE_MAX);
	return w < FL_WHENCE_VALUE_MAX? whence_string[w]: "NULL";
}

void *fl_get_parm(fl_parm*fl)
{
	assert(fl);
	return fl->parm;
}

void fl_set_parm(fl_parm *fl, void* parm)
{
	assert(fl);
	fl->parm = parm;
}

void fl_set_verbose(fl_parm*fl, int verbose)
{
	assert(fl);
	fl->verbose = sig_verbose = verbose;
}

int fl_get_verbose(fl_parm*fl)
{
	assert(fl);
	return fl->verbose;
}

fl_callback fl_set_after_filter(fl_parm *fl, fl_callback after_filter)
{
	assert(fl);
	fl_callback old = fl->after_filter;
	fl->after_filter = after_filter;
	return old;
}


void fl_pass_message(fl_parm*fl, char const *resp)
/*
* see courier/cdfilters.C for meaning of responses:
* each line should start with three digits; if the first digit is
* '0', '4', or '5', execution of filters is stopped and the response
* is given to the remote client --replacing the first '0' in the first
* line with '2', or rejecting the message.
* 2xx responses are not parsed. However, we log them.
*/
{
	assert(fl);
	fl->resp = resp;
}

void fl_free_on_exit(fl_parm*fl, void *p)
// child exit, that is
{
	assert(fl);

	static const size_t n_max =
		sizeof fl->free_on_exit / sizeof fl->free_on_exit[0];
	if (p)
	{
		for (size_t n = 0; n < n_max; ++n)
			if (fl->free_on_exit[n] == NULL)
			{
				fl->free_on_exit[n] = p;
				return;
			}

		fl_report(LOG_ERR, "exceeded max of %zu items to free_on_exit", n_max);
	}
}

char const *fl_get_passed_message(fl_parm *fl)
{
	assert(fl);
	return fl->resp;
}

FILE* fl_get_file(fl_parm*fl)
{
	assert(fl);
	return fl->data_fp;
}

FILE *fl_get_write_file(fl_parm *fl)
{
	assert(fl);
	fl->write_file = 1;
	if (fl->write_fp == NULL)
	{
		if (fl->write_fname == NULL)
		{
			assert(fl->data_fname);
			
			char buf[PATH_MAX];
			int sz = snprintf(buf, sizeof buf, "%s" THE_FILTER "%d",
				fl->data_fname, my_getpid());
			if (sz < 0 || (unsigned)sz >= sizeof buf ||
				(fl->write_fname = strdup(buf)) == NULL)
			{
				fl_report(LOG_CRIT, "writename %s", strerror(errno));
				return NULL;
			}
		}

		if ((fl->write_fp = fopen(fl->write_fname, "w")) == NULL)
		{
			fl_report(LOG_CRIT, "cannot fopen %s: %s",
				fl->write_fname, strerror(errno));
			free(fl->write_fname);
			fl->write_fname = NULL;
		}
	}

	return fl->write_fp;
}

fl_test_mode fl_get_test_mode(fl_parm* fl)
{
	assert(fl);
	return fl->testing ? fl->batch_test ?
		fl_batch_test : fl_testing : fl_no_test;
}

void fl_report(int severity, char const* fmt, ...)
{
	char const *logmsg;
	switch (severity) // see liblog/logger.c
	{
		case LOG_EMERG:
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
		case LOG_INFO:
			logmsg = "INFO";
			break;

		case LOG_DEBUG:
			logmsg = "DEBUG";
			break;
	}

	fprintf(stderr, "%s:" THE_FILTER "[%d]:", logmsg, my_getpid());
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void print_alert(char const*fname, char const* msg, int ctl, int ctltot)
{
	fprintf(stderr, "ALERT:"
		THE_FILTER "[%d]: error %s ctl file %d/%d (%s): %s\n",
		my_getpid(), msg,
		ctl, ctltot, fname, strerror(errno));
}

/* read single record from ctlfile, via callback */
static int
read_ctlfile(fl_parm *fl, char const *chs, int (*cb)(char *, void*), void* arg)
{
	int ctl = 0, rtc = 0;
	ctl_fname_chain *cfc = fl->cfc;

	while (cfc && rtc == 0)
	{
		char const *irtc = NULL;
		FILE *fp = fopen(cfc->fname, "r");
		++ctl;
		if (fp)
		{
			char buf[4096];
			
			while (fgets(buf, sizeof buf - 1, fp))
			{
				char *ends = strchr(buf, '\n');
				if (ends)
					*ends = 0;
				else
				{
					int c;
					while ((c = fgetc(fp)) != EOF && c != '\n')
						continue;
					buf[sizeof buf -1] = 0;
				}

				if (buf[0] &&
					strchr(chs, buf[0]) != NULL &&
					(rtc = (*cb)(&buf[0], arg)) != 0)
						break;
			}
			if (ferror(fp))
				irtc = "reading";

			fclose(fp);
		}
		else
			irtc = "opening";

		if (irtc)
			print_alert(cfc->fname, irtc, ctl, fl->ctl_count);

		cfc = cfc->next;
	}

	return rtc;
}

/* get (auth) sender callback */
static int my_strdup(char *s, void*arg)
{
	char **rtc = (char**)arg;
	assert(rtc && *rtc == NULL);
	*rtc = strdup(s + 1);
	return 1;
}

/* get sender, rtc freed by caller */
char *fl_get_sender(fl_parm *fl)
{
	char *rtc = NULL;

	read_ctlfile(fl, "s", &my_strdup, &rtc);
	return rtc;
}

/* get sender, rtc freed by caller */
char *fl_get_authsender(fl_parm *fl)
{
	char *rtc = NULL;
	
	read_ctlfile(fl, "i", &my_strdup, &rtc);
	return rtc;
}

/* msg info callback */
static int msg_info_cb(char *s, void *arg)
{
	fl_msg_info *info = (fl_msg_info*)arg;
	switch (*s++)
	{
		case 'u':
			info->is_relayclient = strcmp(s, "authsmtp") == 0;
			break;

		case 'M':
			info->id = strdup(s);
			break;

		case 'O':
		{
			static char const relayclient[] = "RELAYCLIENT";
			char *eq = strchr(s, '=');
			if (eq && eq - s == sizeof relayclient - 1 &&
				strncmp(s, relayclient, sizeof relayclient - 1) == 0)
			{
				info->relayclient = strdup(s + sizeof relayclient);
				info->is_relayclient = 1;
			}
			else
				return 0; // don't count other environment variables
			break;
		}

		case 'i':
			info->authsender = strdup(s);
			break;

		case 'f':
			info->frommta = strdup(s);
			break;

		default:
			assert(0);
			return 0;
	}
	
	return ++info->count == 5;
}

int fl_get_msg_info(fl_parm *fl, fl_msg_info *info)
/*
* this should only be called once.  anyway, the first call
* gets the info structure registered to be cleaned after execution.
*/
{
	memset(info, 0, sizeof *info);
	read_ctlfile(fl, "uMOif", &msg_info_cb, info);
	if (fl->info_to_free == NULL)
		fl->info_to_free = info;
	return info->count != 5;
}

/* enumerate recipients */
struct fl_rcpt_enum
{
	fl_parm *fl;
	FILE *fp;
	ctl_fname_chain *cfc;
	int ctl;
	char buf[512];
};

void fl_rcpt_clear(fl_rcpt_enum *fre)
{
	if (fre)
	{
		if (fre->fp)
			fclose(fre->fp);
		free(fre);
	}
}

fl_rcpt_enum *fl_rcpt_start(fl_parm *fl)
{
	fl_rcpt_enum *fre = (fl_rcpt_enum*)malloc(sizeof(fl_rcpt_enum));
	if (fre)
	{
		memset(fre, 0, sizeof *fre);
		fre->cfc = fl->cfc;
		fre->fl = fl;
	}
	return fre;
}

char *fl_rcpt_next(fl_rcpt_enum* fre)
{
	if (fre)
	{
		while  (fre->cfc || fre->fp)
		{			
			while (fre->fp == NULL && fre->cfc)
			{
				++fre->ctl;
				if ((fre->fp = fopen(fre->cfc->fname, "r")) == NULL)
					print_alert(fre->cfc->fname, "opening", fre->ctl, fre->fl->ctl_count);
				fre->cfc = fre->cfc->next;
			}
			
			if (fre->fp)
			{
				while (fgets(fre->buf, sizeof(fre->buf), fre->fp))
				{
					char *ends = strchr(fre->buf, '\n');
					if (ends)
						*ends = 0;
					else
					{
						int c;
						while ((c = fgetc(fre->fp)) != EOF && c != '\n')
							continue;
					}

					if (fre->buf[0] == 'r')
						return &fre->buf[1];
				}
				
				if (ferror(fre->fp))
					print_alert("?", "reading", fre->ctl, fre->fl->ctl_count);

				fclose(fre->fp);
				fre->fp = NULL;
			}			
		}
	}
	return NULL;
}


/* ----- drop message ----- */
static int count_recipients(FILE *fp, char** msgid)
{
	int count = 0;
	char buf[2048];

	if (fseek(fp, 0, SEEK_SET) != 0)
		return -1;

	while (fgets(buf, sizeof(buf), fp))
	{
		char *ends = strchr(buf, '\n');
		if (ends)
			*ends = 0;
		else
		{
			int c;
			while ((c = fgetc(fp)) != EOF && c != '\n')
				continue;
		}

		if (buf[0] == 'r')
			++count;
		else if (buf[0] == 'M' && msgid && *msgid == NULL)
			*msgid = strdup(&buf[1]);
	}
	if (ferror(fp) || fseek(fp, 0, SEEK_END) != 0)
		return -1;

	return count;
}

int fl_drop_message(fl_parm*fl, char const *reason)
{
	int ctl = 0, rtc = 0;
	time_t tt;
	char *msgid = NULL;

	if (fl->verbose >= 7)
	{
		fprintf(stderr,
			THE_FILTER "[%d]: about to drop msg with %d ctl file(s)\n",
			my_getpid(), fl->ctl_count);
	}

	time(&tt);

	while (fl->cfc)
	{
		int irtc = 0, goterrno = 0;
		ctl_fname_chain *cfc = cfc_shift(&fl->cfc);
		FILE *fp;

		++ctl;
		errno = 0;
		fp = fopen(cfc->fname, "r+");
		if (fp)
		{
			int i;
			int const count = count_recipients(fp, &msgid);

			for (i = 0; i < count && !ferror(fp); ++i)
				fprintf(fp, "I%d R 250 Dropped.\nS%d %ld\n",
					i, i, (long)tt);
			fprintf(fp, "C%ld\n", (long)tt);

			if (count < 0 || ferror(fp))
			{
				irtc = 1;
				if (goterrno == 0)
					goterrno = errno;
			}
			fclose(fp);
			if (fl->verbose >= 7)
			{
				fprintf(stderr,
					THE_FILTER
					"[%d]: dropped %d/%d recipient(s) time=%ld on ctl file %s\n",
					my_getpid(), i, count, (long)tt, cfc->fname);
			}
		}
		else
		{
			irtc = 1;
			goterrno = errno;
		}

		if (irtc)
		{
			rtc = irtc;
			fprintf(stderr, "ALERT:"
				THE_FILTER "[%d]: error on ctl file %d/%d (%s): %s\n",
				my_getpid(), ctl, fl->ctl_count, cfc->fname, strerror(goterrno));
		}
		else if (fl->verbose >= 1)
		/*
		** main logging function
		** (given as error as the rest of refused messages)
		*/
		{
			fl_report(LOG_INFO,
				"drop msg,id=%s: %s", msgid? msgid: "", reason? reason: "dropped");
		}

		free(cfc);
	}

	free(msgid);
	return rtc;
}

/* ----- undo percent relay ----- */
int fl_undo_percent_relay(fl_parm*fl, char const *atdom)
{
	assert(fl);
	assert(atdom);

	ctl_fname_chain *fl_cfc = fl->cfc;
	off_t bufsize = 0;
	size_t const atdom_l = strlen(atdom);
	int rtc = 0;

	while (fl_cfc)
	{
		struct stat st;
		ctl_fname_chain *cfc = cfc_shift(&fl_cfc);
		if (stat(cfc->fname, &st) == 0 && bufsize < st.st_size)
			bufsize = st.st_size;
	}

	if (bufsize > 0 && atdom_l > 0)
	{
		char *buf = malloc(bufsize + 1);
		if (buf)
		{
			fl_cfc = fl->cfc;
			while (fl_cfc)
			{
				ctl_fname_chain *cfc = cfc_shift(&fl_cfc);
				FILE *fp = fopen(cfc->fname, "r");
				if (fp)
				{
					off_t fsize = fread(buf, 1, bufsize, fp);
					buf[fsize] = 0;

					char *in = buf, *out = buf;
					int ch, begin = 1;
					while ((ch = *(unsigned char *)in++) != 0)
					{
						if (begin && ch == 'r') // recipient
						{
							char *eol = strchr(in, '\n'), *at;
							if (eol && (size_t)(eol - in) >= atdom_l &&
								strncmp(at = eol - atdom_l, atdom, atdom_l) == 0)
							{
								if (fl->verbose >= 8)
									fl_report(LOG_DEBUG,
										"change recipient %.*s",
										(int)(eol - in), in);
								*out++ = 'r';
								char *perc = NULL;
								while (in < at &&
									(ch = *(unsigned char *)in++) != 0)
								{
									if (ch == '%')
										perc = out;
									*out++ = ch;
								}
								if (perc)
									*perc = '@';
								in = eol;
								continue;
							}
							else if (eol)
							{
								if (fl->verbose >= 1) // unexpected event
								{
									if (eol > in)
										fl_report(LOG_DEBUG,
											"let alone recipient %.*s",
											(int)(eol - in), in);
									else
										fl_report(LOG_DEBUG,
											"empty recipient");
								}
							}
							else
							{
								fl_report(LOG_CRIT,
									"unterminated line in ctlfile %s: %.10s...",
									cfc->fname, in);
								rtc = 1;
							}
						}
						*out++ = ch;
						begin = ch == '\n';
					}
					/*
					* freopen's mode is as in fopen, and "w" is as open's
					* flags O_WRONLY|O_CREAT|O_TRUNC, where O_CREAT has
					* no effect since the file exists --that is, the
					* inode number stays the same.
					*/
					if ((fp = freopen(NULL, "w", fp)) == NULL ||
						fwrite(buf, out - buf, 1, fp) != 1 ||
						fclose(fp))
					{
						fl_report(LOG_CRIT, "error on ctlfile %s: %s",
							cfc->fname, strerror(errno));
						rtc = 1;
					}
				}
			}
			free(buf);
		}
		else
			bufsize = 0;
	}

	if (bufsize == 0)
	{
		fl_report(LOG_CRIT, "memory or ctlfile error: %s", strerror(errno));
		rtc = 1;
	}

	return rtc;
}

#if defined TEST_UNDO_PERCENT
// gcc -W -Wall -O0 -g -DZDKIMFILTER_DEBUG -DTEST_UNDO_PERCENT -o tt filterlib.c

void set_check_inode(int argc, char *const argv[], ino_t *inode, int check)
{
	for (int i = 1; i < argc; ++i)
	{
		struct stat st;
		if (stat(argv[i], &st) != 0)
			st.st_ino = 0;
		if (check == 0)
			inode[i] = st.st_ino;
		else if (inode[i] != st.st_ino)
		{
			fl_report(LOG_CRIT, "Arg %d, %s, had inode %ld, now %ld\n",
				i, argv[i], (long) inode[i], (long) st.st_ino);
		}
	}
}

int main(int argc, char *argv[])
{
	ino_t inode[argc];
	set_check_inode(argc, argv, inode, 0);

	fl_parm fl;
	memset(&fl, 0, sizeof fl);
	fl.verbose = argc == 2? 8: 0;  // 2 or more ctl files -> no output
	sig_verbose = 0;

	fl.argv0 = THE_FILTER;
	fl.all_mode = 1;

	for (int i = 1; i < argc; ++i)
	{
		if (cfc_unshift(&fl.cfc, argv[i], strlen(argv[i])))
		{
			fl_report(LOG_ALERT, "MEMORY FAULT");
			return 1;
		}
	}

	fl_msg_info info;
	memset(&info, 0, sizeof info);
	fl_get_msg_info(&fl, &info); // leak memory

	char *atdom = info.relayclient? info.relayclient: "";
	int rtc = fl_undo_percent_relay(&fl, atdom);
	set_check_inode(argc, argv, inode, 1);

	if (fl.verbose)
		printf("%d from \"%s\"\n", rtc, atdom);
	return rtc;
}
#endif //defined TEST_UNDO_PERCENT


/* ----- core filter functions ----- */
typedef struct process_fname
{
	char buf[1024];
	unsigned count;
	int found, empty;
	char *data_fname;
} process_fname;

static void process_read_fname(process_fname *prof, fl_parm* fl)
{
	if (prof->buf[prof->count] != '\n')
		++prof->count;
	else if (prof->count == 0) /* empty line ends filenames */
		prof->empty = 1;
	else
	{
		prof->buf[prof->count] = 0;

#if !defined(NDEBUG)
		if (fl->verbose >= 8)
			fprintf(stderr, THE_FILTER
				"[%d]: piped fname[%d]: %s (len=%u)\n",
				my_getpid(), prof->found, prof->buf, prof->count);
#endif

		if (++prof->found == 1) /* first line */
			prof->data_fname = strdup(prof->buf);
		else if (prof->count > 1 ||
			prof->buf[0] != ' ') /* discard dummy placeholders */
		{
			if (cfc_unshift(&fl->cfc, prof->buf, prof->count))
				fprintf(stderr, "ALERT:"
					THE_FILTER "[%d]: malloc on filename #%d\n",
						my_getpid(), prof->found);
		}
		prof->count = 0;
	}
}

static int read_fname(fl_parm* fl)
/*
** This reads data and ctl file names. A file name must be either
** an absolute path or relative to the current directory (as usual.)
** When running as an installed filter, lf_init does chdir to
** COURIER_HOME, which is what was configured as @prefix@: so this
** is consistent whith courierfilter.html which states that path
** names may be relative to that directory. (However, it looks as
** if "LOCALSTATEDIR/tmp" is always used as a an absolute path.)
*/
{
	int const fd = fl->in;
	process_fname prof;
	prof.data_fname = NULL;
	prof.count = 0;
	prof.found = prof.empty = 0;
	int rtc = 0;

#if !defined(NDEBUG)
	if (fl->verbose >= 8)
		fprintf(stderr, THE_FILTER "[%d]: reading fd %d\n",
			my_getpid(), fd);
#endif

	fl_alarm(30);
	unsigned p = read(fd, prof.buf, sizeof prof.buf);
	if (p != (unsigned)(-1))
		for (prof.count = 0; prof.count < p;)
		{
			unsigned const len = prof.count + 1;
			process_read_fname(&prof, fl);
			if (prof.empty)
				break;

			if (prof.count == 0)
			{
				p -= len;
				memmove(&prof.buf[0], &prof.buf[len], p);
			}
		}

	if (fl->verbose >= 8 && prof.empty == 0)
		fl_report(LOG_DEBUG, "reading %d names not completed by first call",
			prof.found);

	// read any remaining info, one byte at a time to find the empty line
	while (prof.count < sizeof prof.buf && prof.empty == 0 && fl_keep_running())
	{
		p = read(fd, &prof.buf[prof.count], 1);
		if (p == (unsigned)(-1))
		{
			switch (errno)
			{
				case EAGAIN:
				case EINTR:
					continue;
				default:
					break;
			}
			fl_report(LOG_ALERT, "cannot read fname pipe: %s", strerror(errno));
			break;
		}
		else if (p != 1)
		{
			fl_report(LOG_ALERT, "Unexpected %s (%d) on fname pipe",
				p == 0 ? "EOF" : "rtc from read", p);
			break;
		}

		process_read_fname(&prof, fl);
	}

	alarm(0);
	fl->ctl_count = prof.found - 1;
	if (!fl_keep_running() || prof.found < 2 ||
		prof.empty == 0 || prof.count >= sizeof prof.buf ||
		prof.data_fname == NULL)
	{
		rtc = 1;
		if (!fl_keep_running())
			fl_report(LOG_ALERT, "reading fname pipe terminated prematurely");
		if (prof.found != 2 || prof.empty == 0 || prof.data_fname == NULL)
			fl_report(LOG_ALERT,
				"found%s %d file name(s)%s%s",
				prof.found < 2 ? " only" : "", prof.found,
				prof.empty ? "" : " no empty line",
				prof.data_fname == NULL ? " malloc failure" : "");
		if (prof.count >= sizeof prof.buf)
			fl_report(LOG_ALERT, "Buffer overflow reading fname pipe");
		free(prof.data_fname);
		prof.data_fname = NULL;
	}

	fl->data_fname = prof.data_fname;
	return rtc;
}

static void fl_reset_signal(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof act);

	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;

	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	act.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
}

static void fl_init_signal(fl_parm *fl)
{
	struct sigaction act;
	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);

	signal_timed_out = signal_break = signal_hangup = 0;

	act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	act.sa_handler = child_reaper;
	sigaction(SIGCHLD, &act, NULL);

	act.sa_flags = SA_RESTART;
	act.sa_handler = sig_catcher;

	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL); // sigign?
	sigaction(SIGUSR2, &act, NULL);

	sigemptyset(&fl->blockmask);
	sigaddset(&fl->blockmask, SIGALRM);
	sigaddset(&fl->blockmask, SIGPIPE);
	sigaddset(&fl->blockmask, SIGINT);
	sigaddset(&fl->blockmask, SIGTERM);
	sigaddset(&fl->blockmask, SIGHUP);
	sigaddset(&fl->blockmask, SIGUSR1);
	sigaddset(&fl->blockmask, SIGUSR2);
}

static void do_the_real_work(fl_parm* fl)
{
	char const *resp = NULL;

	if (fl->data_fp == NULL)
	{
		if ((fl->data_fp = fopen(fl->data_fname, "r")) == NULL)
			fl_report(LOG_ALERT, "cannot open %s: %s\n",
				fl->data_fname, strerror(errno));
	}

	if (fl->data_fp != NULL)
	{
		/* alarm will kill after resetting */
		fl_reset_signal();
		if (fl_get_test_mode(fl) != fl_testing)
			alarm(900); // 15 minutes (ways too much)

		fl->resp = NULL;
		if (fl->filter_fn)
			(*fl->filter_fn)(fl);
		
		alarm(0);

		/*
		* close input (if not stdin)
		*/
		if (fl->data_fp && fl->data_fname)
		{
			fclose(fl->data_fp);
			fl->data_fp = NULL;
		}
		
		/*
		* rename the temporary output file, fail on errors
		*/
		if (fl->write_fp && fl->write_fname)
		{
			int fail = ferror(fl->write_fp);
			if (fail)
				fprintf(stderr, "ALERT:"
					THE_FILTER ": error writing %s: %s\n",
					fl->write_fname, strerror(errno));
			
			if (fclose(fl->write_fp))
			{
				fprintf(stderr, "ALERT:"
					THE_FILTER ": error closing %s: %s\n",
					fl->write_fname, strerror(errno));
				fail = 1;
			}					
			fl->write_fp = NULL;

			if (fail == 0 && rename(fl->write_fname, fl->data_fname))
			{
				fprintf(stderr, "ALERT:"
					THE_FILTER ": error renaming %s %s: %s\n",
					fl->data_fname, fl->write_fname, strerror(errno));
				fail = 1;
			}
			
			if (fail)
				unlink(fl->write_fname);
			else
				resp = fl->resp;
		}
		else
			resp = fl->resp;

		if (fl->verbose && !fl_keep_running())
			fl_report(LOG_ERR, "interrupted");
	}

	// some cleanup here (should be in the calling function)
	while (fl->cfc)
		free(cfc_shift(&fl->cfc));
	free(fl->data_fname);
	fl->data_fname = NULL;
	free(fl->write_fname);
	fl->write_fname = NULL;
	
	/* 
	** give response --Courier (cdfilters.C) closes the connection when it
	** gets the last line of the response, and proceeds accordingly.
	*/
	if (resp == NULL)
	{
		resp = "432 Mail filter temporarily unavailable.\n";
		if (fl->resp == NULL)
		{
			fprintf(stderr, "ERR:"
				THE_FILTER "[%d]: response was NULL!!\n",
				my_getpid());
			fl->resp = resp;
		}
	}

	int const fd_out = fl->out;
	if (fd_out >= 0)
	{
		unsigned w = 0, l = strlen(resp);
		while (w < l && fl_keep_running())
		{
			unsigned p = write(fd_out, resp + w, l - w);
			if (p == (unsigned)(-1))
			{
				switch (errno)
				{
					case EAGAIN:
					case EINTR:
						continue;
					default:
						break;
				}
				fprintf(stderr, "ALERT:"
					THE_FILTER "[%d]: unable to write resp: %s\n",
					my_getpid(), strerror(errno));
				break;
			}
			w += p;
		}
	}
	
	if (fl->after_filter)
	{
		if (fd_out >= 0)
			close(fd_out);
		fl->in = fl->out = -1;
		(*fl->after_filter)(fl);
	}

	if (fl->info_to_free)
	{
		free(fl->info_to_free->id);
		free(fl->info_to_free->authsender);
		free(fl->info_to_free->frommta);
		free(fl->info_to_free->relayclient);
	}
}

static void free_on_exit(fl_parm* fl)
{
	static const size_t n_max =
		sizeof fl->free_on_exit / sizeof fl->free_on_exit[0];
	for (size_t n = 0; n < n_max; ++n)
	{
		if (fl->free_on_exit[n] == NULL)
			break;

		free(fl->free_on_exit[n]);
	}
}

#if !defined(NDEBUG)
static void fl_break(void)
{
	fputs("execution resumed\n", stderr);
}
#endif

static void fl_runchild(fl_parm* fl)
{
	pid_t pid;
	int retry = 2;
	
	while ((pid = fork()) < 0 && --retry >= 0)
		sleep(1);
	
	if (pid == 0) /* child */
	{
		fl->whence = fl_whence_in_child;
		if (fl->verbose >= 8)
			fprintf(stderr, THE_FILTER "[%d]: started child\n",
				my_getpid());

#if !defined(NDEBUG)
		if (fl_get_test_mode(fl) == fl_testing)
		{
			char *debug = getenv("DEBUG_FILTER");
			if (debug)
			{
				int nsec = atoi(debug);
				if (nsec <= 1) nsec = 30;
			
				/* hallo! */
				fprintf(stderr, "DEBUG_FILTER: %s\n"
					"now you have %d secs to\n"
					"%% gdb %s %d\n"
					"(gdb) break fl_break\n"
					"Breakpoint 1 at 0xxx: file %s, line %d.\n"
					"(gdb) cont\n",
						debug, nsec, fl->argv0, (int)getpid(),
						__FILE__, __LINE__ -35);
				nsec = sleep(nsec);
				fl_break();
			}
			else if (fl->verbose >= 2)
				fprintf(stderr,
					"set DEBUG_FILTER to debug the child in gdb\n");
		}
#endif

		int rtc = 0;
		if (read_fname(fl))
			rtc = 1;
		else
			do_the_real_work(fl);

		free_on_exit(fl);
		exit(rtc);
	}
	else if (pid > 0) /* parent */
	{
		fl->whence = fl_whence_after_fork;
		++live_children;
	}
	else
		perror("ALERT:" THE_FILTER ": fork");
}

static int my_lf_accept(int listensock, sigset_t *allowset)
/*
** copied from courier/filters/libfilter/libfilter.c
** changed: different return code for shutting down (0 instead of -1)
** changed: use pselect if available; assume signals are blocked on entry
*/
{
	struct sockaddr_un ssun;
	fd_set fd0;
	int fd;
	socklen_t sunlen;

	if (listensock <= 0)
		return 0;

	for (;;)
	{
		FD_ZERO(&fd0);
		FD_SET(0, &fd0);
		FD_SET(listensock, &fd0);

#if HAVE_PSELECT
		if (pselect(listensock+1, &fd0, 0, 0, 0, allowset) < 0)
#else
		sigset_t blockset;
		sigprocmask(SIG_SETMASK, allowset, &blockset);
		int rtc = select(listensock+1, &fd0, 0, 0, 0);
		sigprocmask(SIG_SETMASK, &blockset, NULL);
		if (rtc < 0)
#endif
		{
			if (errno == EAGAIN || errno == EINTR)
				return -1;

			fl_report(LOG_CRIT,
#if HAVE_PSELECT
				"p"
#endif
				"select() error: %s", strerror(errno));
			continue; // changed for 1.4, was return -1 in any case
		}

		if (FD_ISSET(0, &fd0))
		{
			char buf[16];

			if (read(0, buf, sizeof(buf)) <= 0)
				return 0; /* 0 is Shutting down (cannot be accepted socket) */
		}

		if (!FD_ISSET(listensock, &fd0))
			continue;

		sunlen = sizeof ssun;
		if ((fd = accept(listensock, (struct sockaddr*)&ssun, &sunlen)) < 0)
		{
			if (errno == EAGAIN || errno == EINTR)
				return -1; // changed for 1.3, was continue in any case;

			fl_report(LOG_CRIT, "accept() error: %s", strerror(errno));
			continue;
		}

		fcntl(fd, F_SETFL, 0);  /* Take out of NDELAY mode */
		break;
	}

	return fd;
}

/* ----- test, main functions ----- */

static int fl_runtest(fl_parm* fl, int ctlfiles, int argc, char *argv[])
{
	int rtc = 0;
	int mypipe[2], i, j;
	for (i = ctlfiles; i < argc && fl_keep_running(); ++i)
	{
		int irtc = 0;
		if (pipe(mypipe) == 0)
		{
			FILE *fp = fdopen(mypipe[1], "w");

			if (fp)
			{
				fl->in = mypipe[0];
				fl->out = 1; // stdout
				fl_runchild(fl);
#if !defined(NDEBUG)
				if (fl->verbose >= 8)
					fprintf(stderr, THE_FILTER "[%d]: Running %d child(ren)\n",
						my_getpid(), live_children);
#endif
				fprintf(fp, "%s\n", argv[i]);
				for (j = 0; j < ctlfiles; ++j)
					fprintf(fp, "%s\n", argv[j]);
				fputc('\n', fp);
				fclose(fp);
			}
			else
			{
				close(mypipe[1]);
				irtc = 2;
			}
			close(mypipe[0]);
		}
		else
			irtc = 1;
		
		if (irtc)
		{
			rtc = 1;
			fprintf(stderr, "ALERT:" THE_FILTER "[%d]: cannot %s: %s\n",
				my_getpid(), irtc == 1? "pipe": "fdopen", strerror(errno));
		}
	}
	return rtc;
}

static int fl_runstdio(fl_parm* fl, int ctlfiles, int argc, char *argv[])
{
	if (argc < ctlfiles)
		ctlfiles = argc;
	fl->ctl_count = ctlfiles;

	if (ctlfiles <= 0)
	{
		fl_report(LOG_ERR, "no ctlfile, no filter");
		return 1;
	}

	int i;
	for (i = 0; i < ctlfiles; ++i)
		if (cfc_unshift(&fl->cfc, argv[i], strlen(argv[i])))
			break;

	if (i < ctlfiles)
	{
		fl_report(LOG_ALERT, "MEMORY FAULT");
		while (fl->cfc)
			free(cfc_shift(&fl->cfc));
		return 1;
	}

	fl->data_fp = stdin;
	fl->write_fp = stdout;
	fl->out = fl->in = -1;

	do_the_real_work(fl);

	int bad = 0;
	if (fl->resp)
	{
		if (strchr("012", *fl->resp) != NULL &&
			fl->write_file == 0) // 250 not filtered
		{
			bad = fseek(stdin, 0, SEEK_SET) != 0 ||
				filecopy(stdin, stdout) != 0;
			if (bad)
				fl_report(LOG_CRIT, "cannot copy mailfile: %s", strerror(errno));
		}

		if (!bad)
			fprintf(stderr, "\nFILTER-RESPONSE:%s", fl->resp);
	}

	free_on_exit(fl);
	return bad;
}

static void
run_sig_function(fl_init_parm const*fn, fl_parm *fl, int sig)
{
	fl_callback handler;
	switch (sig)
	{
		case SIGHUP:
			handler = fn->on_sighup;
			break;

		case SIGUSR1:
			handler = fn->on_sigusr1;
			break;

		case SIGUSR2:
			handler = fn->on_sigusr2;
			break;

		default:
			handler = NULL;
			break;
	}

	if (handler)
		(*handler)(fl);
}

static int fl_run_batchtest(fl_init_parm const*fn, fl_parm *fl)
{
	int rtc = 0;
	int mypipe[2];
	int const interactive = isatty(fileno(stdout)) && isatty(fileno(stdin));

	if (pipe(mypipe) == 0)
	{
		FILE *fp = fdopen(mypipe[1], "w");
		int pending = 0, total = 0;
		unsigned sleep_arg = 0;
		
		fl->in = mypipe[0];
		fl->out = 1; // stdout
		if (interactive)
			fprintf(stdout,
				THE_FILTER ": batch test. Type `?' for help.\n");

		while (!feof(stdin) && fl_keep_running())
		{
			char cmdbuf[1024];
			char *s, *es = NULL;
			
			if (sleep_arg == 0)
			{
				if (interactive)
				{
					fprintf(stdout, "%d: ", total);
					fflush(stdout);
				}
				errno = 0;
				s = fgets(cmdbuf, sizeof cmdbuf, stdin);
				if (signal_hangup)
				{
					int const sig = signal_hangup;
					signal_hangup = 0;
					run_sig_function(fn, fl, sig);
				}
			}
			else
				s = NULL;
			if (s || sleep_arg)
			{
				int is_exit = 0;
				if (s)
				{
					es = s + strlen(s);
					while (--es >= s && isspace(*(unsigned char*)es))
						*es = 0;
					++es;
					if (strncmp(s, "exit", 4) == 0)
					{
						if (s[4] == '+' && s[5] == 0)
							is_exit = 2;
						else if (s[4] == 0)
							is_exit = 1;
					}
				}
				
				if (s == es || is_exit || sleep_arg)
				{
					if (is_exit > 1)
						fl->batch_test = 0;
					if (pending)
					{
						fputc('\n', fp);
						fflush(fp);
						fl_runchild(fl);
						pending = 0;
						++total;
					}
					if (is_exit)
						break;
					if (sleep_arg)
					{
						sleep(sleep_arg);
						sleep_arg = 0;
						if (signal_hangup)
						{
							int const sig = signal_hangup;
							signal_hangup = 0;
							run_sig_function(fn, fl, sig);
						}
					}
				}
				else if (strcmp(s, "sigusr1") == 0)
					run_sig_function(fn, fl, SIGUSR1);
				else if (strcmp(s, "sigusr2") == 0)
					run_sig_function(fn, fl, SIGUSR2);
				else if (strcmp(s, "sighup") == 0)
					run_sig_function(fn, fl, SIGHUP);
				else if (strncmp(s, "test", 4) == 0 && isdigit((unsigned char)s[4]))
				{
					fl_callback handler;
					switch (s[4])
					{
						case '1': handler = fn->test_fn1; break;
						case '2': handler = fn->test_fn2; break;
						case '3': handler = fn->test_fn3; break;
						case '4': handler = fn->test_fn4; break;
						default:
							handler = NULL;
							break;
					}
					if (handler)
						(*handler)(fl);
				}
				else if (strncmp(s, "sleep ", 6) == 0)
				{
					char *t = NULL;
					unsigned l = strtoul(s + 6, &t, 0);
					if (l == 0 || t == NULL || *t != 0)
						fputs("sleep requires a number\n", stderr);
					else
						sleep_arg = l;
				}
				else if (strcmp(s, "?") == 0) fputs(
				"filterlib batch test: recognized commands are:\n"
				" sigusr1, sigusr2, sighup   - simulate the corresponding signal\n"
				" test1, test2, test3, test4 - call app function, if defined\n"
				"                              (usually test1 prints configuration)\n"
				" sleep nn                   - sleep nn seconds or until signal\n"
				" exit                       - terminate batch testing\n"
				" exit+                      - terminate batch, enable plain testing\n"
				"unrecognized lines are interpreted as mail files and passed to the\n"
				"filter: mail file first, any number of ctl files until an empty line\n"
				"or one with a recognized command\n", stdout);
				
				else
				{
					if (fl->verbose >= 8)
						fprintf(stdout,
							"interpreted as %s file\n",
								pending == 0 ? "mail" : "ctl");
					fprintf(fp, "%s\n", s);
					++pending;
				}
			}
			else if (ferror(stdin))
			{
				int const handled = errno == EINTR || errno == EAGAIN;
				if (fl->verbose >= 8 || !handled)
					fprintf(stderr, "error reading stdin: %s\n",
						strerror(errno));
				if (!handled)
				{
					rtc = 1;
					break;
				}
				if (!feof(stdin))
					clearerr(stdin);
			}
		}
		fclose(fp);
		close(mypipe[0]);
		if (fl->verbose >= 8)
			fprintf(stderr, THE_FILTER ": batch run %d msg(s)\n", total);
	}
	else
	{
		rtc = 1;
		perror("cannot pipe");
	}
	return rtc;
}

static int fl_init_socket(fl_parm *fl)
{
	assert(fl);
	assert(fl->argv0);

	int listensock = -1;

	char const *name = strrchr(fl->argv0, '/');
	if (name) ++name;
	else name = fl->argv0;

	static const char dir[] = FILTERSOCKETDIR,
		alldir[] = ALLFILTERSOCKETDIR;
	size_t len = strlen(name) + 2 + sizeof alldir;
	typedef int compiletime_assert_alldir_is_longer
		[sizeof alldir >= sizeof dir? 1: -1]
#if __GNUC__
		__attribute__((unused))
#endif
	;

	char *sockname = malloc(len),
		*tmpsockname = malloc(len),
		*othername = malloc(len);
	if (sockname && tmpsockname && othername)
	{
		if (fl->all_mode)
		{
			strcat(strcat(strcpy(sockname, alldir), "/"), name);
			strcat(strcat(strcpy(tmpsockname, alldir), "/."), name);
			strcat(strcat(strcpy(othername, dir), "/"), name);
		}
		else
		{
			strcat(strcat(strcpy(sockname, dir), "/"), name);
			strcat(strcat(strcpy(tmpsockname, dir), "/."), name);
			strcat(strcat(strcpy(othername, alldir), "/"), name);
		}

		struct sockaddr_un ssun;
		ssun.sun_family=AF_UNIX;
		strcpy(ssun.sun_path, tmpsockname);
		unlink(ssun.sun_path);
		if ((listensock=socket(PF_UNIX, SOCK_STREAM, 0)) < 0 ||
			bind(listensock, (struct sockaddr *)&ssun, sizeof(ssun)) < 0 ||
			listen(listensock, SOMAXCONN) < 0 ||
			chmod(ssun.sun_path, 0660) ||
			rename (tmpsockname, sockname) ||
			fcntl(listensock, F_SETFL, O_NDELAY) < 0)
		{
			fl_report(LOG_ALERT, "fl_init_socket failed: %s", strerror(errno));
			if (listensock >= 0)
			{
				close(listensock);
				listensock = -1;
			}
			unlink(tmpsockname);
			unlink(sockname);
		}
		else if (unlink(othername) && errno != ENOENT)
			fl_report(LOG_ERR, "unlink(%s) failed: %s",
				othername, strerror(errno));

		if (listensock >= 0 && fl->verbose >= 6)
			fl_report(LOG_INFO, "listening on %s", sockname);
	}
	// else malloc failure on init...

	free(sockname);
	free(tmpsockname);
	free(othername);
	return listensock;
}

static void lf_init_completed(int sockfd)
{
	if (sockfd != 3)	close(3);
}

static int is_courierfilter(int verbose)
{
	int rtc = 1;
	struct stat stat;
	if (fstat(3, &stat) != 0)
	{
		if (errno == EBADF)
		{
			rtc = 0;
		}
		else if (verbose >= 1)
			fprintf(stderr, THE_FILTER ": cannot fstat 3: %s\n",
				strerror(errno));
	}
	else
	{
#if !defined(NDEBUG)
		fprintf(stderr, THE_FILTER ": fd 3 has mode=%lx size=%ld fstype=%.*s\n",
			(unsigned long)stat.st_mode,
			(unsigned long)stat.st_size,
#if HAVE_ST_FSTYPE_STRING
			(int)sizeof stat.st_fstype,
			stat.st_fstype);
#else
			6,
			"undef.");
#endif // HAVE_ST_FSTYPE_STRING
#endif // !defined(NDEBUG)

		if (stat.st_size > 1) // available to read
			rtc = 0;
	}

	if (rtc == 0)
		fprintf(stderr, THE_FILTER ": bad fd3: invalid call\n");
	return rtc;
}

int fl_main(fl_init_parm const*fn, void *parm,
	int argc, char *argv[], int all_mode, int verbose)
{
	int rtc = 0;
	fl_parm fl;

	memset(&fl, 0, sizeof fl);
	fl.parm = parm;
	fl.verbose = sig_verbose = verbose;
	fl.filter_fn = fn ? fn->filter_fn : NULL;
	fl.argv0 = argv[0]? argv[0]: THE_FILTER;
	fl.all_mode = all_mode != 0;

	for (int i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];

		if (strcmp(arg, "--no-fork") == 0)
		{
			fl.no_fork = 1;
			continue;
		}

		if (arg[0] == '-' && arg[1] == 't')
		{
			char *t = NULL;
			unsigned long l = strtoul(&arg[2], &t, 0);
			unsigned const int ctl_max = argc - i - (fl.no_fork? 1: 2);
			fl.testing = 1;
			if (*t) fl.batch_test = 1;
			if (l <= 0 || t == NULL || l > INT_MAX || l > ctl_max ||
				(*t != 0 && *t != ','))
			{
				fprintf(stderr,
					THE_FILTER ": bad parameter %s; t=%d, expected 1-%d ctlfiles\n",
						arg, *t, ctl_max);
				rtc = 1;
			}
			else
			{
				fl_init_signal(&fl);
				int (*const fl_fn)(fl_parm*, int, int, char*[]) =
					fl.no_fork? &fl_runstdio: &fl_runtest;

				if (fl.verbose >= 4)
					fprintf(stderr,
						THE_FILTER ": running for %s on %d ctl + %d mail files\n",
						*t == 0? "test": t + 1, (int)l, argc - i - 2);
				if (fn->on_fork)
					(*fn->on_fork)(&fl);
				rtc = (*fl_fn)(&fl, (int)l, argc - i - 1, argv + i + 1);
			}
			break;
		}

		if (strcmp(arg, "--batch-test") == 0)
		{
			fl.batch_test = fl.testing = 1;
			fl_init_signal(&fl);
			if (fn->init_complete)
				(*fn->init_complete)(&fl, 1);
			if (fn->on_fork)
				(*fn->on_fork)(&fl);
			rtc = fl_run_batchtest(fn, &fl);
			break;
		}

		if (strcmp(arg, "--help") == 0)
		{
			fputs(
			/*  12345678901234567890123456 */
				"  --no-fork               no children, implies stdI/O behavior\n"
				"  -tN[,x] file...         scan rest of args as N ctl and mail file(s)\n"
				"                          with \"x\" behave like batch test\n"
				"  --batch-test            enter batch test mode\n",
					stdout);
			return 1;
		}
	}

	fl.whence = fl_whence_init;

	if (fl.testing == 0 &&
		argc == 1 &&
		is_courierfilter(fl.verbose)) /* install filter */
	{
		int listensock = -1;

		setlinebuf(stderr);
		if (fl.verbose >= 3)
			fl_report(LOG_INFO, "running");
		setsid();

		fl_init_signal(&fl);
		listensock = fl_init_socket(&fl);

		if (listensock < 0)
		{
			close(3);
			return 1;
		}

		if (fn->init_complete)
			rtc = (*fn->init_complete)(&fl, 0);

		lf_init_completed(listensock);

		if (fn->on_fork)
			(*fn->on_fork)(&fl);

		/*
		* main loop
		*/
		sigprocmask(SIG_BLOCK, &fl.blockmask, &fl.allowset);
		while (rtc == 0)
		{
			int fd;
			int const sig = signal_hangup;

			fl.whence = fl_whence_main_loop;
			if (sig != 0)
			{
				signal_hangup = 0;
				sigprocmask(SIG_SETMASK, &fl.allowset, NULL);
				run_sig_function(fn, &fl, sig);
				sigprocmask(SIG_BLOCK, &fl.blockmask, NULL);
				if (signal_hangup)
					continue;
			}

			if ((fd = my_lf_accept(listensock, &fl.allowset)) <= 0)
			{
				if (fd < 0) /* select interrupted */
				{
					assert(errno == EAGAIN || errno == EINTR);
					if (fn->on_fork)
						(*fn->on_fork)(&fl);

					continue;
				}

				/* fd == 0 for clean shutdown */
				break;
			}
			signal_timed_out = signal_break = 0;
			sigprocmask(SIG_SETMASK, &fl.allowset, NULL);

			fl.in = fl.out = fd;
			fl.whence = fl_whence_before_fork;
			if (fn->on_fork)
				(*fn->on_fork)(&fl);
			fl_runchild(&fl);
			close(fd);

			sigprocmask(SIG_BLOCK, &fl.blockmask, NULL);
		} // end of loop
		sigprocmask(SIG_SETMASK, &fl.allowset, NULL);
	}

	if (((fl.testing == 0 && fl.verbose >= 3) || fl.verbose >= 8) &&
		live_children == 0)
			fl_report(LOG_INFO, "exiting");

	int wait_child = 5 + live_children;

	if (getenv("DEBUG_FILTER") && live_children == 1 &&
		fl_get_test_mode(&fl) == fl_testing)
	{
		fprintf(stderr, THE_FILTER
			": leaving the child running for dbg\n");
		return rtc;
	}

	while (live_children > 0 && wait_child >= 0 && signal_break == 0)
	{
		int nsec =  live_children*3;

		if (fl.batch_test == 0 && fl.verbose == 0)
			fprintf(stderr, THE_FILTER "[%d]: waiting for %d child(ren)\n",
				my_getpid(), live_children);

		// interrupted by child signal?
		if (sleep(nsec) != 0)
			continue;

		// kill all processes in the group, if group leader
#if defined ZDKIMFILTER_POSIX_GETPGRP
		if (getpgrp() == getpid())
#else
		if (fl.testing == 0) // since setsid()
#endif
			kill(0, SIGTERM);

		if (--wait_child < 0)
		{
			fprintf(stderr, "WARN:"
				THE_FILTER
				"[%d]: leaving %d naughty child(ren) running\n",
				my_getpid(), live_children);
		}
	}
	
	return rtc;
}
