/*
* dkimsign - written by ale in milano on Fri Jun 24 18:48:11 CEST 2011 
* Sign a mail message on a file

Copyright (C) 2011-2012 Alessandro Vesely

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

#include "filedefs.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

static volatile int
	signal_child = 0,
	signal_timed_out = 0,
	signal_break = 0;

static void sig_catcher(int sig)
{
#if !defined(NDEBUG)
	char buf[80];
	unsigned s = snprintf(buf, sizeof buf,
		"dkimsign[%d]: received signal %s\n",
		(int)getpid(), strsignal(sig));
	if (s >= sizeof buf)
	{
		buf[sizeof buf - 1] = '\n';
		s = sizeof buf;
	}
	write(2, buf, s);
#endif
	switch(sig)
	{
		case SIGALRM:
			signal_timed_out = 1;
			break;

		case SIGHUP:
		case SIGPIPE:
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			signal_break = 1;
			break;

		case SIGCHLD:
			signal_child = 1;
			break;

		default:
			break;
	}
}

static void set_signal(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
		
	act.sa_handler = sig_catcher;
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
}

static int run_zdkimfilter(char *argv[])
{
	int rtc = 0;
	int worst_level = LOG_DEBUG;
	int pipe_err[2];
	if (pipe(pipe_err) < 0)
		syslog(LOG_CRIT, "Cannot open pipe: %s\n", strerror(errno));
	else
	{
		pid_t const pid = fork();
		if (pid < 0)
			syslog(LOG_CRIT, "Cannot fork: %s\n", strerror(errno));
		else if (pid)
		{
			char buf[2048], *next = &buf[0];
			char *const first = &buf[0], *const last = &buf[sizeof buf - 2];
			
			close(pipe_err[1]);
			alarm(30);
			last[1] = 0; // terminator on forced newline
			while (signal_timed_out == 0 &&
				signal_break == 0 &&
				signal_child == 0)
			{

				int rd = read(pipe_err[0], next, last - next);
#if !defined NDEBUG
	printf("rd=%2d, next=%2ld\n", rd, next - first);
#endif
				if (rd > 0)
				{
					char *p = first, *br;
					next += rd;
				
					*next = next == last? '\n': 0; // force newline if full

					while ((br = strchr(p, '\n')) != NULL)
					{
						int level = LOG_INFO;
						*br = 0;

						if (strncmp(p, "ERR:", 4) == 0)
						{
							level = LOG_ERR;
							p += 4;
						}
						else if (strncmp(p, "WARN:", 5) == 0)
						{
							level = LOG_WARNING;
							p += 5;
						}
						else if (strncmp(p, "ALERT:", 6) == 0)
						{
							level = LOG_ALERT;
							p += 6;
						}
						else if (strncmp(p, "CRIT:", 5) == 0)
						{
							level = LOG_CRIT;
							p += 5;
						}
						else if (strncmp(p, "DEBUG:", 6) == 0)
						{
							level = LOG_DEBUG;
							p += 6;
						}
						else if (strncmp(p, "INFO:", 5) == 0)
							p += 5;

						if (level < worst_level)
							worst_level = level;

						while (*p == ' ')
							++p;
					
						if (*p) syslog(level, "%s\n", p);
						p = br + (br < last);     // +1 if not forced newline
						assert(first <= p && p <= next);
					}
				
					memmove(first, p, next - p);
					next -= p - first;
					assert(first <= next && next < last);
				}
				else if (rd == 0 || errno != EINTR && errno != EAGAIN)
				{
					if (rd)
						syslog(LOG_CRIT, "Pipe broken: %s\n", strerror(errno));
					break;
				}
			}
			alarm(0);
			if (signal_timed_out || signal_break)
			{
				kill(pid, SIGTERM);
			}
			close(pipe_err[0]);
			
			for (;;)
			{
				int status;
				pid_t wpid = wait(&status);
				if (wpid < 0 && errno != EAGAIN && errno != EINTR)
				{
					syslog(LOG_CRIT,
						"Cannot wait %s[%u]: %s\n",
						argv[0], (unsigned)wpid, strerror(errno));
					break;
				}
				else if (wpid == pid)
				{
					if (WIFEXITED(status))
					{
						int level, s_rtc = WEXITSTATUS(status);
						switch (s_rtc)
						{
							case 0: level = worst_level; break;
							default: level = LOG_CRIT; break;
						}
						
						/*
						* we never give 99 for examining content: just 0 or 1
						*/
						rtc = s_rtc? s_rtc: (level <= LOG_ERR);
						syslog(level,
							"zdkimfilter exited %d, rtc=%d\n", s_rtc, rtc);
					}
					else if (WIFSIGNALED(status))
					{
						rtc = 2;
						syslog(LOG_CRIT,
							"zdkimfilter terminated with signal %d, rtc=%d\n",
							WTERMSIG(status), rtc);
					}
					else continue; // stopped?
					
					break;
				}
			}
		}
		else // child process
		{
			close(0);
			open("/dev/null", O_RDONLY);
			close(1);
			open("/dev/null", O_WRONLY);
			close(2);
			dup(pipe_err[1]);
			close(pipe_err[0]);
			close(pipe_err[1]);
			closelog();
			execv(argv[0], argv);
			syslog(LOG_MAIL|LOG_CRIT, "dkimsign: cannot execv: %s\n",
				strerror(errno));
			exit(0);
		}
	}
	return rtc;
}

static char *create_ctlfile(char const *domain)
{
	char fname[] = "/tmp/dkimsign_ctlfileXXXXXX";
	int const fd = mkstemp(fname);
	if (fd < 0)
	{
		syslog(LOG_CRIT, "mkstemp failure: %s\n", strerror(errno));
		return NULL;
	}
	
	if (geteuid() == 0 && fchown(fd, MAILUID, MAILGID))
	{
		syslog(LOG_CRIT, "fchown failure: %s\n", strerror(errno));
		close(fd);
		unlink(fname);
		return NULL;
	}
	
	FILE *fp = fdopen(fd, "w+");
	fprintf(fp, "uauthsmtp\nipostmaster@%s\nMdkimsign\n", domain);
	int rtc = ferror(fp) | fclose(fp);
	char *const fnamedup = rtc? NULL: strdup(fname);
	if (fnamedup == NULL)
	{
		syslog(LOG_CRIT, "cannot write ctlfile %s: %s\n",
			fname, strerror(errno));
		unlink(fname);
	}

	return fnamedup;
}

int main(int argc, char *argv[])
{
	int rtc = 0;
	char *xargv[32];
	size_t xargc = 0;
	
//	xargv[xargc++] = ZDKIMFILTER_EXECUTABLE;
	xargv[xargc++] = "/home/ale/sw/zdkimfilter/src/zdkimfilter";
	
	/*
	* TODO: what options are to be passed to zdkimfilter?  Perhaps -f conf-file?
	* and shouldn't I read the default domain from such file?
	*/
	xargv[xargc] = NULL;
	if (argc < 3)
	{
		fprintf(stderr, "usage: %s <domain> <message-file>\n", argv[0]);
		return 1;
	}

	openlog("dkimsign", LOG_PID, LOG_MAIL);
	char *domain = argv[1];
	char *fname = argv[2];
	char *ctlfile = create_ctlfile(domain);
	
	if (ctlfile == NULL)
		return 1;	

	xargv[xargc++] = "-t1,dkimsign";
	xargv[xargc++] = ctlfile;
	xargv[xargc++] = fname; // can add more fnames here...
	xargv[xargc] = NULL;

/* What if the file is not readable by MAILUID?

	struct stat buf;

	if (geteuid() == 0)
	{
		setgid(MAILGID);
		setuid(MAILUID);
	}
*/
	set_signal();

	rtc = run_zdkimfilter(xargv);
	closelog();
	unlink(ctlfile);
	free(ctlfile);
	return rtc;
}
