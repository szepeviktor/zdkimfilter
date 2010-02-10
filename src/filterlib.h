/*
** filterlib.h - written in milano by vesely on 27sep2003
** utilities for forking global filters for courier-mta
*/
/*
** Copyright (c) 1999, 2000, 2001, 2002, 2003 Alessandro Vesely
** All rights reserved. see COPYING
*/

#if !defined(FILTERLIB_H_INCLUDED)

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
		on_sighup, on_sigusr1, on_sigusr2, // possibly null sig handlers
		test_fn1, test_fn2, test_fn3, test_fn4; // test functions
} fl_init_parm;

int fl_main(fl_init_parm const*, void *parm,
	int argc, char*argv[], int allmode, int verbose);

/* utilities for callback function */
void *fl_get_parm(fl_parm*);
void fl_set_parm(fl_parm *, void* parm);
void fl_set_verbose(fl_parm*, int);
int fl_get_verbose(fl_parm*);
typedef enum fl_test_mode { fl_no_test,
	fl_testing, fl_batch_test } fl_test_mode;
fl_test_mode fl_get_test_mode(fl_parm*);

/* utilities only for filter function */
FILE* fl_get_file(fl_parm*);
int fl_drop_message(fl_parm*, char const* reason);
void fl_pass_message(fl_parm*, char const *);
void fl_alarm(unsigned seconds);
int fl_keep_running(void);
char *fl_get_sender(fl_parm *);
void fl_rcpt_clear(fl_rcpt_enum*);
fl_rcpt_enum *fl_rcpt_start(fl_parm*);
char *fl_rcpt_next(fl_rcpt_enum*);
char *fl_get_sender(fl_parm *fl);

// int fl_rewrite_message(fl_parm*);
// int fl_is_pass_signed(fl_parm*, char const *header, size_t header_length);

#define FILTERLIB_H_INCLUDED 1
#endif
