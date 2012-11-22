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
#include <limits.h>
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

#include "parm.h"

static volatile int
	signal_child = 0,
	signal_timed_out = 0,
	signal_break = 0;

static int no_needless_logging = 0;
static void sig_catcher(int sig)
{
#if !defined(NDEBUG)
	if (!no_needless_logging)
	{
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
	}
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

static logfun_t do_report = &stderrlog;

static const int do_config = 1;
static const int do_version = 2;
static const int do_syslog = 4;
static const int do_mail = 8;
static const int do_filter = 16;

static int run_zdkimfilter(char *argv[], int do_what)
{
	int rtc = 0;
	int worst_level = LOG_DEBUG;

	// for config parent writes to child on stdin;
	// for version there is no communication
	// otherwise (mail)
	//    child writes to parent on stderr
	//    for filter
	//       child inherits stdin (mail file) and stdout (processed mail file)
	//       and the filter output is echoed to the real stderr

	int io_pipe[2];
	if (do_what & (do_config | do_mail))
	{
		if (pipe(io_pipe) < 0)
		{
			(*do_report)(LOG_CRIT, "Cannot open pipe: %s\n", strerror(errno));
			return 1;
		}
	}

	if (do_what & do_version)
		printf("running %s\n", argv[0]);

	pid_t const pid = fork();
	if (pid < 0)
		(*do_report)(LOG_CRIT, "Cannot fork: %s\n", strerror(errno));
	else if (pid)
	{
		alarm(30);
		if (do_what & do_config)
		{
			static char const test1[] = "test1\nexit\n", *out = test1;
			size_t len = sizeof test1 - 1;
			close(io_pipe[0]);
			while (len > 0 &&
				signal_timed_out == 0 &&
				signal_break == 0 &&
				signal_child == 0)
			{
				int wn = write(io_pipe[1], out, len);
				if (wn > 0 && (size_t)wn <= len)
				{
					out += wn;
					len -= wn;
				}
				else if (wn == 0 || errno != EINTR && errno != EAGAIN)
				{
					if (wn)
						(*do_report)(LOG_CRIT, "Pipe broken: %s\n", strerror(errno));
					break;
				}
			}

		}
		else if (do_what & do_mail)
		{
			char buf[2048], *next = &buf[0];
			char *const first = &buf[0], *const last = &buf[sizeof buf - 2];

			close(io_pipe[1]);
			last[1] = 0; // terminator on forced newline
			while (signal_timed_out == 0 &&
				signal_break == 0 &&
				signal_child == 0)
			{

				int rd = read(io_pipe[0], next, last - next);
#if !defined NDEBUG
	if (!no_needless_logging)
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
							p += 5;        // 1234567890123456
						else if (strncmp(p, "FILTER-RESPONSE:", 16) == 0)
						{
							p += 16;
							while (isspace(*(unsigned char*)p))
								++p;
							if (isdigit(*(unsigned char*)&p[0]) &&
								isdigit(*(unsigned char*)&p[1]) &&
								isdigit(*(unsigned char*)&p[2]) &&
								isspace(*(unsigned char*)&p[3]) &&
								p[0] >= '3')
							{
								fprintf(stderr, "%s\n", p + 4); // for parent process
								level = LOG_ERR;                // this will set rtc
							}
						}

						if (level < worst_level)
							worst_level = level;

						while (*p == ' ')
							++p;

						if (*p) (*do_report)(level, p);
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
						(*do_report)(LOG_CRIT, "Pipe broken: %s\n", strerror(errno));
					break;
				}
			}
		}

		alarm(0);
		if (signal_timed_out || signal_break)
		{
			kill(pid, SIGTERM);
		}
		if (do_what & do_config)
			close(io_pipe[1]);
		else if (do_what & do_mail)
			close(io_pipe[0]);

		for (;;)
		{
			int status;
			pid_t wpid = wait(&status);
			if (wpid < 0 && errno != EAGAIN && errno != EINTR)
			{
				(*do_report)(LOG_CRIT,
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

					// rtc = 0 if all clear
					rtc = s_rtc? s_rtc: (level <= LOG_ERR);
					if (rtc)
						(*do_report)(level,
							"zdkimfilter exited %d, rtc=%d\n", s_rtc, rtc);
				}
				else if (WIFSIGNALED(status))
				{
					rtc = 2;
					(*do_report)(LOG_CRIT,
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
		if ((do_what & do_filter) == 0)
		{
			close(0);
			if (do_what & do_config)
				dup(io_pipe[0]);
			else
				open("/dev/null", O_RDONLY);
		}

		if (do_what & do_mail)
		{
			if ((do_what & do_filter) == 0)
			{
				close(1);
				open("/dev/null", O_WRONLY);
			}
			close(2);
			dup(io_pipe[1]);
		}
		if (do_what & (do_config | do_mail))
		{
			close(io_pipe[0]);
			close(io_pipe[1]);
		}
		if (do_what & do_syslog)
			closelog();
		execv(argv[0], argv);
		(*do_report)(LOG_MAIL|LOG_CRIT, "dkimsign: cannot execv: %s\n",
			strerror(errno));
		exit(0);
	}

	return rtc;
}

static int my_mkstemp(int is_msg, char *tmp, char **fname)
{
	static char const fname_templ1[] = "dkimsign_";
	static char const fname_templ2[] = "fileXXXXXX";
	int dlen = tmp? strlen(tmp): 4;

	char *f = *fname =
		malloc(dlen + sizeof fname_templ1 + 3 + sizeof fname_templ2);
	if (f == NULL)
	{
		(*do_report)(LOG_ALERT, "MEMORY FAULT");
		return -1;
	}

	strcpy(f, tmp? tmp: "/tmp");
	if (f[dlen - 1] != '/')
		strcat(f, "/");
	strcat(strcat(strcat(f, fname_templ1), is_msg? "msg": "ctl"), fname_templ2);
	
	int const fd = mkstemp(f);
	if (fd < 0)
		(*do_report)(LOG_CRIT, "mkstemp failure: %s\n", strerror(errno));

	return fd;
}

static int create_tmpfiles(char const *config_file, char const *domain,
	char **ctlfile, char **msgfile)
{
	/*
	* Read the tmp directory and, if not given, the default domain
	*/
	static char const *names[] = {"tmp", "default_domain"};
	char *out[2] = { NULL, NULL};
	char *buf = NULL;
	int rtc = read_single_values(config_file, domain? 1: 2, names, out);
	if (rtc < 0)
	{
		(*do_report)(LOG_CRIT, "error reading %s: %s\n",
			config_file? config_file: "default config file",
			strerror(errno));
		return 1;
	}

	rtc = 1; // unless cleared before error_exit;

	int fd = my_mkstemp(0, out[0], ctlfile);
	if (fd < 0)
		goto error_exit;

#if 0	
	// What if the message-files are not readable by MAILUID?
	if (geteuid() == 0 && fchown(fd, MAILUID, MAILGID))
	{
		(*do_report)(LOG_CRIT, "fchown failure: %s\n", strerror(errno));
		close(fd);
		unlink(fname);
		return NULL;
	}
#endif

	FILE *fp = fdopen(fd, "w+");
	if (fp)
	{
		fputs("uauthsmtp\nipostmaster", fp);
		if (domain == NULL)
			domain = out[1];
		if (domain)
		{
			char const* const at = strchr(domain, '@');
			fprintf(fp, "@%s", at? at + 1: domain);
		}
		fputs("\nMdkimsign\n", fp);
		fclose(fp);
	}
	else goto error_exit;

	if (msgfile)
	{
		struct stat st;
		if (fstat(0, &st))
		{
			(*do_report)(LOG_CRIT, "fstat fd 0 fails: %s\n", strerror(errno));
			goto error_exit;
		}

		if (!S_ISREG(st.st_mode))
		{
#if defined NDEBUG
			size_t const sizeofbuf = 8192;
#else
			size_t const sizeofbuf = 64;
#endif
			if ((buf = malloc(sizeofbuf)) == NULL)
				goto error_exit;

			if ((fd = my_mkstemp(1, out[0], msgfile)) < 0)
				goto error_exit;

			for (;;)
			{
				ssize_t nr = read(0, buf, sizeofbuf);
				if (nr == 0)
					break;

				if (nr < 0 && errno != EAGAIN && errno != EINTR)
				{
					(*do_report)(LOG_CRIT, "copying fd0, read stdin: %s",
						strerror(errno));
					close(fd);
					goto error_exit;
				}

				char *bw = buf;
				while (nr > 0)
				{
					ssize_t nw = write(fd, bw, nr);
					if (nw > 0)
					{
						nr -= nw;
						bw += nw;
					}
					else if (errno != EAGAIN && errno != EINTR)
					{
						(*do_report)(LOG_CRIT, "copying fd0, write %s: %s",
							*msgfile, strerror(errno));
						close(fd);
						goto error_exit;
					}
				}
			}
			close(0);
			dup(fd);
			close(fd);
		}
	}

	rtc = 0;

	error_exit:
		free(out[0]);
		free(out[1]);
		free(buf);
	return rtc;
}

static const char zdkimfilter_executable[] = ZDKIMFILTER_EXECUTABLE;

static char* get_executable(char *argv0)
{
	static const char zdkimfilter[] = "zdkimfilter";
	struct stat a, e, me;

	char *alt = NULL;
	char *slash = strrchr(argv0, '/');
	if (slash == NULL)
	// assume this happens because we were found in PATH.
	{
		char *path = getenv("PATH");
		if (path)
		{
			size_t len = strlen(argv0);
			if (len < sizeof zdkimfilter)
				len = sizeof zdkimfilter;
			len += 2 + strlen(path);

			char buf[len];
			for (;;)
			{
				char *const next = strchr(path, ':');
				len = next? (size_t)(next - path): strlen(path);
				memcpy(buf, path, len);
				buf[len++] = '/';
				strcpy(&buf[len], argv0);
				if (stat(buf, &me) == 0)
				{
					strcpy(&buf[len], zdkimfilter);
					if (stat(buf, &a) == 0)
					{
						alt = strdup(buf);
						break;  // found
					}
				}
				else if (next == NULL)
					break; // not found

				path = next + 1;
			}			
		}
	}
	else if (stat(argv0, &me) == 0)
	{
		size_t len = slash - argv0 + 1;
		char buf[len + 1 + sizeof zdkimfilter];
		memcpy(buf, argv0, len);
		strcpy(&buf[len], zdkimfilter);
		if (stat(buf, &a) == 0)
			alt = strdup(buf);
	}

	if (stat(zdkimfilter_executable, &e))
		return alt; // possibly NULL

	if (alt)
	/*
	* If there is a freshly installed executable, return that,
	* unless we're a much older thing, of about the same time
	* as the alternative.
	*/
	{
		if (!(e.st_mtime > a.st_mtime &&
			labs(me.st_mtime - a.st_mtime) < labs(e.st_mtime - a.st_mtime)/16L))
				return alt;

		free(alt);
	}

	return (char*)zdkimfilter_executable;
}

int main(int argc, char *argv[])
{
	int rtc = 0, file_arg = 0, do_what = 0;
	char *config_file = NULL;
	char *domain = NULL;

	set_parm_logfun(&stderrlog);

	for (int i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		
		if (strcmp(arg, "-f") == 0)
		{
			config_file = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "--syslog") == 0)
		{
			do_what |= do_syslog;
		}
		else if (strcmp(arg, "--domain") == 0)
		{
			domain = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "--config") == 0)
		{
			do_what |= do_config;
		}
		else if (strcmp(arg, "--version") == 0)
		{
			do_what |= do_version;
		}
		else if (strcmp(arg, "--filter") == 0)
		{
			do_what |= do_filter;
			do_what |= do_syslog;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			printf("This is a wrapper around the zdkimfilter executable.\n"
				"Usage:\n"
				"           dkimsign [opts] message-file...\n"
				"with opts:\n"
				"  -f config-filename  override %s\n"
				"  --syslog            use syslog (MAIL) rather than stderr\n"
				"  --filter            use stdin and ignore any message-file\n"
				"  --domain domain     domain used for signing\n"
				"  --config            have the exec check and print config\n"
				"  --help              print this stuff and exit\n"
				"  --version           have the exec print version and exit\n",
					default_config_file);
			return 0;
		}
		else // message files
		{
			file_arg = i;
			break;
		}
	}

	if (file_arg == 0 && (do_what & ~do_syslog) == 0)
		return 1;

	// hack to ease auto tests
	if (strcmp(argv[argc-1], "--batch-test") == 0)
	{
		do_what &= ~do_syslog;
		no_needless_logging = 1;
	}

	if (do_what & do_syslog)
	{
		openlog("dkimsign", LOG_PID, LOG_MAIL);
		set_parm_logfun(do_report = &syslog);
	}

	char *xargv[argc - file_arg + 10];
	size_t xargc = 0;

	char *ctlfile = NULL;
	char *msgfile = NULL;
	char *execfile = get_executable(argv[0]);
	if (execfile == NULL)
	{
		(*do_report)(LOG_CRIT, "Cannot find the zdkimfilter executable");
		rtc = 1;
	}
	else
		xargv[xargc++] = execfile;

	if (config_file)
	{
		xargv[xargc++] = "-f";
		xargv[xargc++] = config_file;
	}

	if (do_what & do_version)
	{
		do_what &= ~do_config;
		xargv[xargc++] = "--version";
	}
	else if (do_what & do_config)
	{
		xargv[xargc++] = "--batch-test";
	}
	else if ((file_arg || (do_what & do_filter)) && rtc == 0)
	{
		do_what |= do_mail;
		rtc = create_tmpfiles(config_file, domain, &ctlfile,
			(do_what & do_filter)? &msgfile: NULL);

		if (rtc == 0)
		{
			xargv[xargc++] = "--no-db";
			if ((do_what & do_filter) != 0)
				xargv[xargc++] = "--no-fork";
			xargv[xargc++] = "-t1,dkimsign";
			xargv[xargc++] = ctlfile;
			if (file_arg)
				for (int i = file_arg; i < argc; ++i)
					xargv[xargc++] = argv[i];
		}
	}

	if (rtc == 0)
	{
		xargv[xargc] = NULL;
		set_signal();

		rtc = run_zdkimfilter(xargv, do_what);
	}

	if (do_what & do_syslog)
		closelog();

	if (ctlfile)
	{
		unlink(ctlfile);
		free(ctlfile);
	}

	if (msgfile)
	{
		unlink(msgfile);
		free(msgfile);
	}

	if (execfile && execfile != zdkimfilter_executable)
		free(execfile);

	return rtc;
}
