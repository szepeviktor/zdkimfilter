/*
** zdkimstats-wait.c - written in milano by vesely on 7sep2010
** wait for a lock available on file, for use in postrotate clause
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

#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>

#include "filedefs.h"

static char *progname;
static const char pid_file[] = ZDKIMFILTER_PID_FILE;

#if !defined PID_MAX
#define PID_MAX ((~((pid_t) 0)) / 2)
#endif

static pid_t read_pid(void)
{
	pid_t rtc = 0;
	FILE *fp = fopen(pid_file, "r");
	if (fp)
	{
		char buf[256];
		size_t len = fread(buf, 1, sizeof buf, fp);
		if (len < sizeof buf)
		{
			buf[len] = 0;
			char *t = NULL;
			unsigned long l = strtoul(buf, &t, 0);
			if (t && (*t == '\n' || *t == 0) && t > &buf[0] && l <= PID_MAX)
				rtc = (pid_t)l;
		}
		fclose(fp);
	}
	else if (errno != ENOENT)
		fprintf(stderr,
			"%s: cannot open %s: %s\n",
			progname, pid_file, strerror(errno));
	return rtc;
}

int main(int argc, char* argv[])
{
	int timeout = 0, errs = 0, i;
	char *waitfile = NULL;

	if ((progname = strrchr(argv[0], '/')) != NULL)
		++progname;
	else
		progname = argv[0];

	for (i = 1; i < argc; ++i)
	{
		char *const arg = argv[i];
		
		if (strcmp(arg, "-f") == 0)
		{
			waitfile = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "-t") == 0)
		{
			if (++i < argc)
			{
				char *t = NULL;
				unsigned long l = strtoul(argv[i], &t, 0);
				if (l < INT_MAX && t && *t == 0)
					timeout = (int)l;
			}
			else
				++errs;
		}
		else if (strcmp(arg, "--version") == 0)
		{
			puts(PACKAGE_NAME ", version " PACKAGE_VERSION "\n");
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			/*  zdkimstats-wait */
			printf(         "%s signals (USR1) zdkimfilter to reopen stats\n"
				"files and then waits until it can acquire a write lock on\n"
				"the renamed file; for use in postrotate clauses.\n"
				"Command line args:\n"
			/*  12345678901234567890123456 */
				" [-f] filename            renamed file to wait for\n"
				"  -t seconds              timeout (default: wait forever)\n"
				"  --help                  print this stuff and exit\n"
				"  --version               print version string and exit\n",
				progname);
			return 0;
		}
		else if (waitfile)
		{
			fprintf(stderr, "%s: invalid argument %s, try --help\n",
				progname, arg);
			return 1;
		}
		else
			waitfile = arg;
	}
	
	if (errs)
		return 1;

	/*
	* Signal zdkimfilter. It should ignore USR1, unless it is running
	* after filter.  This signal interrupts waiting for a lock, so the
	* stats writer closes the file, reopens it, and tries to lock it again.
	* Thus, we get rid of most (see BUG) concurrent attempts to acquire
	* the lock, and waiting for an existing lock, if any, to be released
	* will suffice.  (fcntl locking doesn't seem to be FIFO.)
	*
	* BUG: offline verifiers are not considered, as a workaround, stats
	* should not be enabled in their conf file.
	*/
	pid_t filterpid = read_pid();
	if (filterpid > 1 &&
		kill(-filterpid, SIGUSR1))
			fprintf(stderr,
				"%s: cannot signal to group %d: %s\n",
				progname, filterpid, strerror(errno));

	int rtc = 1;
	if (waitfile)
	{
		int fd = open(waitfile, O_WRONLY | O_APPEND);

		if (fd >= 0)
		{
			struct flock lock;		
			memset(&lock, 0, sizeof lock);
			lock.l_type = F_WRLCK;
			lock.l_whence = SEEK_SET;
			lock.l_len = 1;

			if (timeout)
				alarm(timeout);

			if (fcntl(fd, F_SETLKW, &lock) == 0)
				rtc = 0;
			else
				fprintf(stderr,
					"%s: cannot lock %s: %s\n",
					progname, waitfile, strerror(errno));

			alarm(0);
			close(fd);
		}
		else
			fprintf(stderr,
				"%s: cannot open %s: %s\n",
				progname, waitfile, strerror(errno));
	}
	
	return rtc;
}

