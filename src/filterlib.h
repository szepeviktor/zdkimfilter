/*
** filterlib.h - written in milano by vesely on 27sep2003
** utilities for forking global filters for courier-mta
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

Copyright (C) 2010-2011 Alessandro Vesely

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

#if !defined(FILTERLIB_H_INCLUDED)
// set pid==0 in messages and temp filenames
extern int fl_log_no_pid;

struct filter_lib_struct;
typedef struct filter_lib_struct fl_parm;

struct fl_rcpt_enum;
typedef struct fl_rcpt_enum fl_rcpt_enum;

typedef void (*fl_callback)(fl_parm*);
typedef struct fl_init_parm
{
	fl_callback
		filter_fn, // filter function
		init_complete, // called once before main loop
		on_fork, // called on the parent, before main loop and before forking
		on_sighup, on_sigusr1, on_sigusr2, // possibly null sig handlers
		test_fn1, test_fn2, test_fn3, test_fn4; // test functions
} fl_init_parm;

typedef enum fl_whence_value
{
	fl_whence_other,
	fl_whence_init,
	fl_whence_main_loop,
	fl_whence_before_fork,
	fl_whence_after_fork,
	fl_whence_in_child,
	FL_WHENCE_VALUE_MAX
} fl_whence_value;

typedef struct fl_msg_info
{
	char *id, *authsender, *frommta; //freed by caller
	int is_relayclient;
	int count;
} fl_msg_info;

int fl_main(fl_init_parm const*, void *parm,
	int argc, char*argv[], int allmode, int verbose);

/* utilities for callback function */
fl_whence_value fl_whence(fl_parm *fl);
char const* fl_whence_string(fl_parm *fl);
void *fl_get_parm(fl_parm*);
void fl_set_parm(fl_parm *, void* parm);
void fl_set_verbose(fl_parm*, int);
int fl_get_verbose(fl_parm*);
typedef enum fl_test_mode { fl_no_test,
	fl_testing, fl_batch_test } fl_test_mode;
fl_test_mode fl_get_test_mode(fl_parm*);

/* utilities only for filter function */
FILE* fl_get_file(fl_parm*);
FILE *fl_get_write_file(fl_parm*);
int fl_drop_message(fl_parm*, char const* reason);
void fl_pass_message(fl_parm*, char const *);
void fl_free_on_exit(fl_parm*fl, void *p);
char const *fl_get_passed_message(fl_parm*);
void fl_alarm(unsigned seconds);
int fl_keep_running(void);
char *fl_get_sender(fl_parm *);
char *fl_get_authsender(fl_parm *);
void fl_rcpt_clear(fl_rcpt_enum*);
fl_rcpt_enum *fl_rcpt_start(fl_parm*);
char *fl_rcpt_next(fl_rcpt_enum*);
int fl_get_msg_info(fl_parm *, fl_msg_info *);
#if defined __GNUC__
__attribute__ ((format(printf, 2, 3)))
#endif
void fl_report(int, char const*, ...);
fl_callback fl_set_after_filter(fl_parm *, fl_callback);
typedef enum init_signal_arg
	{init_signal_all, init_signal_lock} init_signal_arg;
void fl_init_signal(init_signal_arg);
void fl_reset_signal(void);

#define FILTERLIB_H_INCLUDED 1
#endif
