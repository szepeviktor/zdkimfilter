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
	signal_hangup = 0;
static int live_children = 0;

typedef struct ctl_fname_chain
{
	 struct ctl_fname_chain *next;
	 char fname[1]; // actually large as needed
} ctl_fname_chain;

struct filter_lib_struct
{
	void *parm;

	char const *resp;
	int in, out;
	char *data_fname, *write_fname;
	FILE *data_fp, *write_fp;
	ctl_fname_chain *cfc;
	char *argv0;

	fl_callback filter_fn;

	int ctl_count;
	unsigned int verbose:4;
	unsigned int testing:4;
	unsigned int batch_test:4;
};

/* ----- sig handlers ----- */

static int sig_verbose = 0;
static void child_reaper(int sig)
{
	int status;
	pid_t child;

	(void)sig;
	
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
}

int is_batch_test;
static inline int my_getpid(void)
{
	return is_batch_test? 0: (int)getpid();
}

static void sig_catcher(int sig)
{
#if !defined(NDEBUG)
	if (sig_verbose > 0)
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
			signal_break = 1;
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

void *fl_get_parm(fl_parm*fl)
{
	return fl->parm;
}

void fl_set_parm(fl_parm *fl, void* parm)
{
	fl->parm = parm;
}

void fl_set_verbose(fl_parm*fl, int verbose)
{
	fl->verbose = sig_verbose = verbose;
}

int fl_get_verbose(fl_parm*fl)
{
	return fl->verbose;
}

int fl_keep_running(void)
{
	return signal_timed_out == 0 && signal_break == 0;
}

void fl_pass_message(fl_parm*fl, char const *resp)
/*
* see courier/cdfilters.C for meaning of responses:
* each line should start with three digits; if the first digit is
* '0', '4', or '5', execution of filters is stopped and the response
* is given to the remote client --replacing the first '0' with '2',
* or rejecting the message.
* 2xx responses are not parsed. However, we log them.
*/
{
	fl->resp = resp;
}

char const *fl_get_passed_message(fl_parm *fl)
{
	return fl->resp;
}

FILE* fl_get_file(fl_parm*fl)
{
	return fl->data_fp;
}

FILE *fl_get_write_file(fl_parm *fl)
{
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
				fputs("ALERT:" THE_FILTER ": writename\n", stderr);
				return NULL;
			}
		}
		
		if ((fl->write_fp = fopen(fl->write_fname, "w")) == NULL)
			perror("ALERT:" THE_FILTER ": openwritename");
	}
	
	return fl->write_fp;
}

fl_test_mode fl_get_test_mode(fl_parm* fl)
{
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

				if (strchr(chs, buf[0]) != NULL &&
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

		case 'i':
			info->authsender = strdup(s);
			break;

		default:
			assert(0);
			break;
	}
	
	return ++info->count == 3;
}

int fl_get_msg_info(fl_parm *fl, fl_msg_info *info)
{
	memset(info, 0, sizeof *info);
	read_ctlfile(fl, "uMi", &msg_info_cb, info);
	return info->count != 3;
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
#if defined FILTERLIB_DROP_MESSAGE_SUPPORT
static int count_recipients(FILE *fp, char **from_mta)
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
		else if (buf[0] == 'f' && from_mta && *from_mta == NULL)
			*from_mta = strdup(&buf[1]);
		
	}
	if (ferror(fp) || fseek(fp, 0, SEEK_END) != 0)
		return -1;

	return count;
}

int fl_drop_message(fl_parm*fl, char const *reason)
{
	int ctl = 0, rtc = 0;
	time_t tt;
	char *from_mta = NULL;
	
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
			int const count = count_recipients(fp, &from_mta);
#if COURIERSUBMIT_WANTS_UGLY_HACK
			/*
			** the ugly hack: since submit writes various records
			** ("8", "U", "V", "w", "E", "p" "W" and "A") _after_
			** running global filters, we have to estimate enough
			** space so that it won't overwrite our faked delivery
			**
			** we put 254, about 32 bytes per record is enough and
			** we still allowing any unlikely old-fashioned fgets
			** with 256 bytes of buffer
			*/
			fprintf(fp, "%254s\n", "");
#endif
			
			for (i = 0; i < count && !ferror(fp); ++i)
				fprintf(fp, "I%d R 200 Dropped.\nS%d %ld\n",
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
		else if (fl->verbose)
		/*
		** main logging function
		** (given as error as the rest of refused messages)
		*/
		{
			fprintf(stderr,
				"ERR:dropped,From-MTA=<%s>: "
				THE_FILTER "[%d]: %s",
				from_mta ? from_mta : "",
				my_getpid(),
				reason ? reason : "w/o apparent reason\n");
		}
		
		free(cfc);
	}
	
	free(from_mta);
	return rtc;
}
#endif /* defined FILTERLIB_DROP_MESSAGE_SUPPORT */
/* ----- core filter functions ----- */

static int read_fname(fl_parm* fl)
/*
** This reads data and ctl file names. A file name must be either
** an absolute path or relative to the current directory (as usual.)
** When runnining as an installed filter, lf_init does chdir to
** COURIER_HOME, which is what was configured as @prefix@: so this
** is consistent whith courierfilter.html which states that path
** names may be relative to that directory. (However, it looks as
** if "LOCALSTATEDIR/tmp" is always used as a an absolute path.)
*/
{
	char buf[1024];
	unsigned count = 0;
	int found = 0, empty = 0, rtc = 0;
	int const fd = fl->in;
	fl->data_fname = NULL;

#if !defined(NDEBUG)
	if (fl->verbose >= 8)
		fprintf(stderr, THE_FILTER "[%d]: reading fd %d\n",
			my_getpid(), fd);
#endif
	
	fl_alarm(30);
	while (count < sizeof buf && empty == 0 && fl_keep_running())
	{
		unsigned const p = read(fd, &buf[count], 1);
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
				THE_FILTER "[%d]: cannot read fname pipe: %s\n",
				my_getpid(), strerror(errno));
			break;
		}
		else if (p != 1)
		{
			fprintf(stderr, "ALERT:"
				THE_FILTER "[%d]: Unexpected %s (%d) on fname pipe\n",
				my_getpid(), p == 0 ? "EOF" : "rtc from read", p);
			break;
		}

		if (buf[count] != '\n')
			++count;
		else if (count == 0) /* empty line ends filenames */
			empty = 1;
		else
		{
			buf[count] = 0;

#if !defined(NDEBUG)
			if (fl->verbose >= 8)
				fprintf(stderr, THE_FILTER 
					"[%d]: piped fname[%d]: %s (len=%u)\n",
					my_getpid(), found, buf, count);
#endif

			if (++found == 1) /* first line */
				fl->data_fname = strdup(buf);
			else if (count > 1 || buf[0] != ' ') /* discard dummy placeholders */
			{
				if (cfc_unshift(&fl->cfc, buf, count))
					fprintf(stderr, "ALERT:"
						THE_FILTER "[%d]: malloc on filename #%d\n",
							my_getpid(), found);
			}
			count = 0;
		}
	}
	
	alarm(0);
	fl->ctl_count = found - 1;
	if (!fl_keep_running() || found < 2 ||
		empty == 0 || count >= sizeof buf || fl->data_fname == NULL)
	{
		rtc = 1;
		if (!fl_keep_running())
			fprintf(stderr, "ALERT:"
				THE_FILTER
				"[%d]: reading fname pipe terminated prematurely\n",
					my_getpid());
		if (found != 2 || empty == 0 || fl->data_fname == NULL)
			fprintf(stderr, "ALERT:"
				THE_FILTER "[%d]: found%s %d file name(s)%s%s\n",
				my_getpid(),
				found < 2 ? " only" : "", found,
				empty ? "" : " no empty line",
				fl->data_fname == NULL ? " malloc failure" : "");
		if (count >= sizeof buf)
			fprintf(stderr, "ALERT:"
				THE_FILTER "[%d]: Buffer overflow reading fname pipe\n",
					my_getpid());
		free(fl->data_fname);
		fl->data_fname = NULL;
	}

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
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
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
	int const fd_out = fl->out;
	
	while ((pid = fork()) < 0 && --retry >= 0)
		sleep(1);
	
	if (pid == 0) /* child */
	{
		char const *resp = NULL;
		unsigned w = 0, l;
		int rtc = 0;
		
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
				if (nsec <= 0) nsec = 30;
				
				/* hallo! */
				fprintf(stderr, "DEBUG_FILTER: %s\n"
					"now you have %d secs to\n"
					"%% gdb %s %d\n"
					"(gdb) break fl_break\n"
					"Breakpoint 1 at 0xxx: file %s, line %d.\n"
					"(gdb) cont\n",
						debug, nsec, fl->argv0, (int)getpid(),
						__FILE__, __LINE__ -40);
				nsec = sleep(nsec);
				fl_break();
			}
			else if (fl->verbose >= 2)
				fprintf(stderr,
					"set DEBUG_FILTER to debug the child in gdb\n");
		}
#endif

		if (read_fname(fl))
			rtc = 1;
		else
		{
			if ((fl->data_fp = fopen(fl->data_fname, "r")) != NULL)
			{
				/* kill me after 15 minutes, no matter what */
				fl_reset_signal();
				if (fl_get_test_mode(fl) != fl_testing)
					alarm(900);

				fl->resp = NULL;
				if (fl->filter_fn)
					(*fl->filter_fn)(fl);
				
				alarm(0);

				fclose(fl->data_fp);
				fl->data_fp = NULL;
				
				if (fl->write_fp)
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
				
				while (fl->cfc)
					free(cfc_shift(&fl->cfc));
				if (fl->verbose && !fl_keep_running())
					fl_report(LOG_ERR, "interrupted");
			}
			else
			{
				fprintf(stderr, "ALERT:"
					THE_FILTER ": cannot open %s: %s\n",
					fl->data_fname, strerror(errno));
			}
			free(fl->data_fname);
			fl->data_fname = NULL;
			free(fl->write_fname);
			fl->write_fname = NULL;
		}
		
		/* 
		** give response
		*/
		if (rtc == 0 && resp == NULL)
		{
			resp = "432 Mail filter temporarily unavailable.\n";
			if (fl->resp == NULL)
				fprintf(stderr, "ERR:"
					THE_FILTER "[%d]: response was NULL!!\n",
					my_getpid());
		}
		l = rtc ? 0 : strlen(resp);
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
		exit(rtc);
	}
	else if (pid > 0) /* parent */
		++live_children;
	else
		perror("ALERT:" THE_FILTER ": fork");
}

static int my_lf_accept(int listensock)
/*
** copied from courier/filters/libfilter/libfilter.c
** changed: different return code for shutting down (0 instead of -1)
*/
{
	struct sockaddr_un ssun;
	fd_set fd0;
	int fd;
	int sunlen;

	if (listensock <= 0)
		return 0;
	
	for (;;)
	{
		FD_ZERO(&fd0);
		FD_SET(0, &fd0);
		FD_SET(listensock, &fd0);
 
		if (select(listensock+1, &fd0, 0, 0, 0) < 0)
		{
			return -1;
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
			continue;

		fcntl(fd, F_SETFL, 0);  /* Take out of NDELAY mode */
		break;
	}
	
	return fd;
}

/* ----- init, test, main functions ----- */

static void fl_init(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
		
	act.sa_flags = SA_NOCLDSTOP;
	act.sa_handler = child_reaper;
	sigaction(SIGCHLD, &act, NULL);
		
	act.sa_flags = 0;
	act.sa_handler = sig_catcher;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
}

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
	if (pipe(mypipe) == 0)
	{
		FILE *fp = fdopen(mypipe[1], "w");
		int pending = 0, total = 0;
		unsigned sleep_arg = 0;
		
		fl->in = mypipe[0];
		fl->out = 1; // stdout

		while (!feof(stdin) && fl_keep_running())
		{
			char cmdbuf[1024];
			unsigned char *s, *es = NULL;
			
			if (sleep_arg == 0)
			{
				if (isatty(fileno(stdout)))
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
					while (--es >= s && isspace(*es))
						*es = 0;
					++es;
					is_exit = strcmp(s, "exit") == 0;
				}
				
				if (s == es || is_exit || sleep_arg)
				{
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
				else if (strncmp(s, "test", 4) == 0 && isdigit(s[4]))
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

static int fl_init_socket(int all_mode)
{
	int listensock;
	const char *sockname, *tmpsockname;
	struct sockaddr_un ssun;
		
	if (all_mode)
	{
		sockname = ALLFILTERSOCKETDIR "/" THE_FILTER;
		tmpsockname = ALLFILTERSOCKETDIR "/." THE_FILTER;
		unlink(FILTERSOCKETDIR "/" THE_FILTER);
	}
	else
	{
		sockname = FILTERSOCKETDIR "/" THE_FILTER;
		tmpsockname = FILTERSOCKETDIR "/." THE_FILTER;
		unlink(ALLFILTERSOCKETDIR "/" THE_FILTER);
	}
	
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
		perror("ALERT:" THE_FILTER ": fl_init_socket failed");
		if (listensock >= 0)
			close(listensock);
		return (-1);
	}
	
	return listensock;
}

static void lf_init_completed(int sockfd)
{
	if (sockfd != 3)	close(3);
}

static int is_courierfilter(int verbose)
{
	int rtc = 1;
#if defined(COURIERFILTER_SETS_FD3)
	struct stat stat;
	if (fstat(3, &stat) != 0)
	{
		if (errno == EBADF)
		{
			rtc = 0;
		}
		else if (verbose)
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
#else
	(void)verbose;
#endif // COURIERFILTER_SETS_FD3
	return rtc;
}

int fl_main(fl_init_parm const*fn, void *parm,
	int argc, char *argv[], int all_mode, int verbose)
{
	int rtc = 0, wait_child = 5, i;
	fl_parm fl;

	memset(&fl, 0, sizeof fl);
	fl.parm = parm;
	fl.verbose = sig_verbose = verbose;
	fl.filter_fn = fn ? fn->filter_fn : NULL;
	fl.argv0 = argv[0];
	
	for (i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		if (arg[0] == '-' && arg[1] == 't')
		{
			char *t = NULL;
			unsigned long l = strtoul(&arg[2], &t, 0);
			fl.testing = 1;
			if (l <= 0 || t == NULL || *t != 0 || l > INT_MAX ||
				(int)l >= argc - i - 1)
			{
				fprintf(stderr,
					THE_FILTER ": bad parameter %s; expected 1-%d ctlfiles\n",
						arg, argc - i - 2);
				rtc = 1;
			}
			else
			{
				fl_init();
				if (fl.verbose >= 2)
					fprintf(stderr,
						THE_FILTER ": running test on 1 ctl +%d mail files\n",
						argc - i - 2);
				rtc = fl_runtest(&fl, (int)l, argc - i - 1, argv + i + 1);
			}
			break;
		}

		if (strcmp(arg, "--batch-test") == 0)
		{
			fl.batch_test = fl.testing = 1;
			fl_init();
			if (isatty(fileno(stdout)))
				fprintf(stdout,
					THE_FILTER ": batch test. Type `?' for help.\n");
			rtc = fl_run_batchtest(fn, &fl);
			break;
		}
		
		if (strcmp(arg, "--help") == 0)
		{
			fputs(
			/*  12345678901234567890123456 */
				"  -tN file...             scan rest of args as N ctl and mail file(s)\n"
				"  --batch-test            enter batch test mode\n",
					stdout);
			return 1;
		}
	}

	if (fl.testing == 0 &&
		argc == 1 &&
		is_courierfilter(fl.verbose)) /* install filter */
	{
		int listensock = -1;
		
		if (fl.verbose >= 3)
			fl_report(LOG_INFO, "running");
		setsid();
		/*
		int rtc = setpgrp();
	
		if (rtc)
			fprintf(stderr, THE_FILTER ": cannot set process group\n");
		*/

		fl_init();
		listensock = fl_init_socket(all_mode);

		if (listensock < 0)
			return 1;
		
		if (fn->init_complete)
			(*fn->init_complete)(&fl);

		lf_init_completed(listensock);

		for (;;)
		{
			int fd;
			int const sig = signal_hangup;

			if (sig != 0)
			{
				signal_hangup = 0;
				run_sig_function(fn, &fl, sig);
			}
			
			if ((fd = my_lf_accept(listensock)) <= 0)
			{
				if (fd < 0) /* select interrupted */
				{
					switch (errno)
					{
						case EAGAIN:
						case EINTR:
							continue;
						default:
							break;
					}
					perror("select");
					rtc = 1;
				}
				/* fd == 0 for clean shutdown */
				break;
			}
			signal_timed_out = signal_break = 0;
			fl.in = fl.out = fd;
			fl_runchild(&fl);
			close(fd);
		}		
	}

	if ((fl.testing == 0 && fl.verbose >= 3 || fl.verbose >= 8) &&
		live_children == 0)
			fl_report(LOG_INFO, "exiting");

	wait_child += live_children;

#if !defined(NDEBUG)
	i = getenv("DEBUG_FILTER") ? 1 : 0;
	if (i == 1 && live_children == 1 &&
		fl_get_test_mode(&fl) == fl_testing)
	{
		fprintf(stderr, THE_FILTER
			": leaving the child running for dbg\n");
		return rtc;
	}
#else
	i = 0;
#endif

	while (live_children > 0)
	{
		int nsec =  live_children*3;

		if (fl.batch_test == 0 && i == 0)
			fprintf(stderr, THE_FILTER "[%d]: waiting for %d child(ren)\n",
				my_getpid(), live_children);

		if (sleep(nsec) != 0)
			continue;

		if (fl.testing == 0)
		{
			kill(0, SIGTERM);
			if (--wait_child < 0)
			{
				fprintf(stderr, "WARN:"
					THE_FILTER
					"[%d]: leaving %d naughty child(ren) running\n",
					my_getpid(), live_children);
			}
		}
	}
	
	return rtc;
}
