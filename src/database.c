/*
** database.c - written in milano by vesely on 25sep2012
** read/write via odbx
*/
/*
* zdkimfilter - Sign outgoing, verify incoming mail messages

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
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#if defined HAVE_OPENDBX
#include <opendbx/api.h>
#endif // HAVE_OPENDBX
#include "database.h"
#include <assert.h>

static logfun_t do_report = &syslog;
#if defined TEST_MAIN
static int verbose = 0;
static int dry_run = 0;
#endif

#if defined HAVE_OPENDBX
/*
* Statements also need to be defined in db_parm_t
*/

#define DATABASE_STATEMENT(x) x,
typedef enum stmt_id
{
	#include "database_statements.h"

	total_statements
} stmt_id;
#undef DATABASE_STATEMENT

#define STRING2(P) #P
#define STRING(P) STRING2(P)

#define DATABASE_STATEMENT(x) STRING(x),
static const char*stmt_name[] =
{
	#include "database_statements.h"
};
#undef DATABASE_STATEMENT

/*
* Each query/statement has a number of allowed variables that may or may not
* be used.  They are passed as parameters to the relevant function
*/

#define DATABASE_VARIABLE(x) x##_variable,
typedef enum variable_id
{
	not_used_variable, // last stmt part, sentinel, ...
	#include "database_variables.h"
	DB_SQL_VAR_SIZE,
	FLAG_VAR_SIZE = (DB_SQL_VAR_SIZE + 7) & -8 // round up
} variable_id;
#undef DATABASE_VARIABLE

#define DATABASE_VARIABLE(x) STRING(x),
static const char * const variable_name[] =
{
	"", // not used variable
	#include "database_variables.h"
	NULL
};	
#undef DATABASE_VARIABLE

// high bit: allowed in statement
// rest: number of uses in a statement (max 127 times)
typedef struct flags_var
{
	stmt_id sid;
	unsigned char var[FLAG_VAR_SIZE];
} flags_var;

static inline stmt_id var_stmt_id(flags_var const *flags) { return flags->sid; }
static inline int var_is_allowed(flags_var const *flags, variable_id id)
{ return (flags->var[id] & 0x80U) != 0; }
static inline int var_is_used(flags_var const *flags, variable_id id)
{ return flags->var[id] & 0x7fU; }
static inline void set_var_used(flags_var *flags, variable_id id)
{ flags->var[id] =
	flags->var[id] & 0x80U | 0x7fU & (var_is_used(flags, id) + 1); }
	
// make sure a 32-bit flag holds all the variables we use;
typedef int
compile_time_check_that_FLAG_VAR_SIZE_le_32[FLAG_VAR_SIZE <= 32? 1: -1];
typedef uint32_t var_flag_t;

static void set_var_allowed(flags_var *flags, var_flag_t bitflag, stmt_id sid)
{
	memset(flags, 0, sizeof *flags);
	flags->sid = sid;
	variable_id id = 0;
	var_flag_t mask = 1;
	for (; bitflag; bitflag &= ~mask, mask <<= 1, ++id)
		if (bitflag & mask)
			flags->var[id] |= 0x80U;
}

typedef struct stmt_part
{
	char *snippet;
	size_t length;
	variable_id id;
} stmt_part;

typedef struct stmt_compose
{
	flags_var flags;
	uint32_t length;
	uint32_t count;
	stmt_part part[]; 
} stmt_compose;

static int
search_var(char *p, flags_var *flags, char **q, size_t *sz, stmt_part *part)
{
	char *s = strchr(p, '$');
	if (s && s[1] == '(')
	{
		char *name = &s[2], *e = name;
		int ch;
		while (isalnum(ch = *(unsigned char*)e) || ch == '_')
			++e;

		variable_id id = DB_SQL_VAR_SIZE;
		size_t length = e - name;

		if (length && ch == ')')
			for (id = 1; id < DB_SQL_VAR_SIZE; ++id)
				if (strncmp(variable_name[id], name, length) == 0)
					break;

		if (id >= DB_SQL_VAR_SIZE || !var_is_allowed(flags, id))
		{
			if (id >= DB_SQL_VAR_SIZE)
				(*do_report)(LOG_ERR,
					"Malformed or unknown variable near: %.*s",
						(int)(e - p), p);
			else
				(*do_report)(LOG_ERR,
					"Variable %s cannot be used in %s",
						variable_name[id], stmt_name[var_stmt_id(flags)]);
			return -1;
		}

		length += 3;  // for '$', '(', and ')': length of text to be removed
		set_var_used(flags, id);
		*sz += length;
		*q = e;
		if (part)
		{
			part->length = length; // to be changed by caller
			part->id = id;
		}
	}
	else
	{
		*q = NULL;
	}

	return 0;
}

static int count_vars(flags_var *flags, char *src, size_t *sz, stmt_part *part)
{
	int count = 0;
	char *p = src, *dest;

	if (part)
		dest = part->snippet;

	for (;;)
	{
		char *q;
		if (search_var(p, flags, &q, sz, part))
			return -1;

		if (part && *p)
		{
			part->snippet = dest;
			if (q)
				// turn length of tail into length of head
				part->length = q - p + 1 - part->length;
			else
				part->length = strlen(p);

			memcpy(dest, p, part->length);
			dest[part->length] = 0;

			dest += part->length + 1;
			part += 1;
		}

		if (q)
		{
			++count;
			p = q + 1;
		}
		else
			return count + (*p != 0); // one more for the last snippet
	}
}

static stmt_compose *stmt_alloc(flags_var *flags, char *src)
{
	size_t sz = 0;
	int count = count_vars(flags, src, &sz, NULL);

	if (count <= 0)
		return NULL;

	/*
	* allocate room for count snippets, which means
	* the last part may be without variable;
	*/
	size_t const length = strlen(src) - sz; // sum of snippets, excluding term 0
	size_t const array = count * sizeof(stmt_part);
	size_t const alloc = sizeof (stmt_compose) + array + length + count;
	stmt_compose *stmt = malloc(alloc);
	if (stmt == NULL)
	{
		(*do_report)(LOG_ALERT, "MEMORY FAULT");
		return NULL;
	}

	memset(&stmt->part[0], 0, array);
	stmt->flags = *flags;
	stmt->length = length;
	stmt->count = count;
	stmt->part[0].snippet = (char*)&stmt->part[count];
	count_vars(flags, src, &sz, &stmt->part[0]);

	assert(stmt->part[count-1].snippet + strlen(stmt->part[count-1].snippet) ==
		(char*)stmt + alloc - 1);

	return stmt;
}

//////////////////////////////////////////////////////////////
// typedef'd in .h
struct db_work_area
{
	odbx_t *handle;
	odbx_result_t *result;
	stmt_compose *stmt[total_statements];
	char *var[DB_SQL_VAR_SIZE];
	char *user_domain;

	db_parm_t z;

	time_t pending_result;
	char pending_result_msg;

	char is_test;
};

db_parm_t* db_parm_addr(db_work_area *dwa) { return dwa? &dwa->z: NULL; }

void db_clear(db_work_area* dwa)
{
	if (dwa)
	{
		if (dwa->handle)
		{
			int err = odbx_unbind(dwa->handle);
			if (err)
				(*do_report)(LOG_ERR, "Error unbinding odbx handle: %s",
					odbx_error(dwa->handle, err));
			err = odbx_finish(dwa->handle);

			if (err)
				(*do_report)(LOG_ERR, "Error closing odbx handle: %s",
					odbx_error(dwa->handle, err));
		}
		for (int i = 0; i < DB_SQL_VAR_SIZE; ++i)
			free(dwa->var[i]);
		for (int i = 0; i < total_statements; ++i)
			free(dwa->stmt[i]);
		free(dwa->user_domain);
		free(dwa);
	}
}

db_work_area *db_init(void)
/*
* this must be the first function called.  Do config_default as well.
*/
{
	do_report = set_parm_logfun(NULL);  // use that logging function

	db_work_area *dwa = calloc(1, sizeof(db_work_area));
	if (dwa == NULL)
	{
		(*do_report)(LOG_ALERT, "MEMORY FAULT");
		return NULL;
	}

	// options not set will be left alone
	dwa->z.db_opt_compress = dwa->z.db_opt_multi_statements = -1;
	dwa->z.db_opt_paged_results = -1;
	return dwa;
}

int db_config_wrapup(db_work_area *dwa, int *in, int *out)
/*
* Parse SQL statements.
* Set the counters to the total number of db_sql_* statements configured
* for incoming (verified) and outgoing (signed) messages.
* return 0 if ok, -1 for fatal error;
*/
{
	int fatal = -1;
	if (dwa)
	{
		int count = 0;
		fatal = 0;

#define STMT_ALLOC(STMT, BITFLAG) \
		if (dwa->z.STMT) { ++count; \
			flags_var flags; \
			set_var_allowed(&flags, BITFLAG, STMT); \
			if (dwa->z.STMT != NULL && *dwa->z.STMT != 0 && \
				(dwa->stmt[STMT] = stmt_alloc(&flags, dwa->z.STMT)) == NULL) \
					fatal = -1; \
		} else (void)0

		STMT_ALLOC(db_sql_whitelisted,
			1 << domain_variable | 1 << ip_variable);

		const var_flag_t common_variables =
			1 << ino_variable | 1 << mtime_variable | 1 << pid_variable |
			1 << date_variable | 1 << message_id_variable | 1 << subject_variable |
			1 << content_type_variable | 1 << content_encoding_variable |
			1 << from_variable | 1 << mailing_list_variable |
			1 << envelope_sender_variable | 1 << ip_variable;


		const var_flag_t message_variables = common_variables |
			1 << received_count_variable | 1 << signatures_count_variable |
			1 << message_status_variable | 1 << adsp_flags_variable;

		STMT_ALLOC(db_sql_insert_message, message_variables);

		const var_flag_t domain_variables = message_variables |
			1 << domain_variable | 1 << auth_type_variable |
			1 << vbr_mv_variable | 1 << vbr_response_variable |
			1 << reputation_variable;

		STMT_ALLOC(db_sql_select_domain, domain_variables);

		STMT_ALLOC(db_sql_insert_domain, domain_variables);

		STMT_ALLOC(db_sql_update_domain, domain_variables |
			1 << domain_ref_variable);

		STMT_ALLOC(db_sql_insert_msg_ref, domain_variables |
			1 << domain_ref_variable | 1 << message_ref_variable);

		if (in)
			*in = count;
		count = 0;

		const var_flag_t outgoing_variables =
			common_variables | 1 << domain_variable | 1 << rcpt_count_variable;

		// $(domain) is the local domain when selecting/checking the user
		const var_flag_t outgoing_user_variables =
			outgoing_variables | 1 << local_part_variable;

		STMT_ALLOC(db_sql_select_user, outgoing_user_variables);
		STMT_ALLOC(db_sql_check_user, outgoing_user_variables |
			1 << user_ref_variable);

		// $(domain) is the target domain when selecting the target domain
		// so disallow the local_part here
		const var_flag_t target_variables = outgoing_variables |
			1 << message_ref_variable;

		STMT_ALLOC(db_sql_select_target, target_variables);
		STMT_ALLOC(db_sql_insert_target, target_variables);

		const var_flag_t target_dom_variables = target_variables |
			1 << domain_ref_variable;

		STMT_ALLOC(db_sql_update_target, target_dom_variables);

		STMT_ALLOC(db_sql_insert_target_ref, target_dom_variables);

		if (out)
			*out = count;
#undef STMT_ALLOC

		if (dwa->z.db_timeout <= 0)
			dwa->z.db_timeout = 2;
	}
	return fatal;
}

static int clear_pending_result(db_work_area* dwa)
/*
* Some DB backends seem to be unable to fetch results promptly.  The doc says:
*
*   If a timeout or error occurs, the result pointer is set to NULL. In case
*   of a timeout, odbx_result() should be called again because the query
*   isn't canceled. This function must be called multiple times until it
*   returns zero, even if the query contains only one statement. Otherwise,
*   memory will be leaked and odbx_query() will return an error.
*/
{
	assert(dwa);

	if (dwa->pending_result)
	{
		odbx_result_t *result;
		struct timeval timeout;
		timeout.tv_sec = dwa->z.db_timeout;
		timeout.tv_usec = 0;

		int err = odbx_result(dwa->handle, &result, &timeout, 0 /* chunk */);
		if (result)
		{
			int err2 = odbx_result_finish(result);
			time_t now = time(NULL);
			(*do_report)(LOG_NOTICE,
				"DB server result discarded after %ld seconds (err=%d, %d)",
				(long)(now - dwa->pending_result), err, err2);
			dwa->pending_result = 0;
		}
		else if (dwa->pending_result_msg == 0)
		{
			time_t now = time(NULL);
			(*do_report)(LOG_CRIT,
				"DB server stuck after %ld seconds: %s (err=%d)",
					(long)(now - dwa->pending_result),
					odbx_error(dwa->handle, err), err);
			dwa->pending_result_msg = 1;  // limit logs to 1 per message
		}
	}

	return dwa->pending_result? -1: 0;
}

#define OTHER_ERROR (-100 - (ODBX_MAX_ERRNO))

#if !defined TEST_MAIN
static const char database_dump[] = "database_dump";
#endif

static int dump_vars(db_work_area* dwa, stmt_id sid, var_flag_t bitflag)
{
	assert(dwa);
	assert(sid < total_statements);

	stmt_compose const *const stmt = dwa->stmt[sid];
	if (stmt == NULL) // db_is_whitelisted and db_check_user don't check this
		return 0;

#if defined TEST_MAIN
	FILE *fp = stdout;
#else
	FILE *fp = fopen(database_dump, "a");
#endif
	if (fp)
	{
		assert(sid < total_statements);
		fprintf(fp, "Variables allowed for statement %s:\n", stmt_name[sid]);

		variable_id id = 0;
		var_flag_t mask = 1, bit;
		for (bit = bitflag; bit; bit &= ~mask, mask <<= 1, ++id)
		{
			if (var_is_allowed(&stmt->flags, id))
			{
				char const *const var = (bitflag & mask)? dwa->var[id]: NULL;
				fprintf(fp, "%s: %s\n",
					variable_name[id], var? var: "-- not given --");
			}
		}
		fputc('\n', fp);
#if !defined TEST_MAIN
		fclose(fp);
#endif
	}
	return 0;
}

static int stmt_run_n(db_work_area* dwa, stmt_id sid, var_flag_t bitflag,
	int count, ...)
/*
* Build a statement assembling snippets and arguments, then run it.
* count is the number of pairs of arguments that follow.
*
* If count is negative, then the remaining arguments are -count pointers to int.
* Otherwise, they are count pointers to char*.  Currently only whitelist uses
* integer return types.  Whitelist queries should return just a single numeric
* result within [-1000, 1000] (count = -1).
*
* After inserting a message, or after querying or inserting domain, a reference
* variable can be returned.  Those queries must be conceived so as to return a
* single value that will become the message_ref or domain_ref variable.  This
* can be done by explicitely SELECT LAST_INSERT_ID() after the insertion, using
* multi-statement.  Otherwise those variables will be undefined, and replaced
* with an empty string when used.
*
* Return n (1 <= n <= count) for the results found and returned in wantchar,
* 0 if no result was found or if the statement is not defined.
* If an error is found (and logged) return OTHER_ERROR.
*/
{
	assert(dwa);
	assert(sid < total_statements);

	int wantint = 0;
	if (count < 0)
	{
		wantint = 1;
		count = -count;
	}

	stmt_compose const *const stmt = dwa->stmt[sid];
	if (stmt == NULL)
		return 0;

	if (dwa->is_test)
		return dump_vars(dwa, sid, bitflag);

	odbx_t *const handle = dwa->handle;
	if (handle == NULL || clear_pending_result(dwa))
	{
		if (handle == NULL)
			(*do_report)(LOG_CRIT, "Internal error: not connected");
		return OTHER_ERROR;
	}

	size_t arglen[DB_SQL_VAR_SIZE];
	memset(arglen, 0, sizeof arglen);

	size_t length = 0;
	variable_id id = 0;
	var_flag_t mask = 1, bit;
	for (bit = bitflag; bit; bit &= ~mask, mask <<= 1, ++id)
	{
		if (dwa->var[id] == NULL)
			bitflag &= ~mask;

		// arglen[id] remains 0 for variables that are not actually given,
		// albeit allowed and used.  They are replaced with an empty string.
		else if (bitflag & mask)
		{
			int const use = var_is_used(&stmt->flags, id);
			if (use)
				length += 2 * use * (arglen[id] = strlen(dwa->var[id]));
		}
	}

	size_t alloc = stmt->length + length + 1;
	char *sql = malloc(alloc), *p = sql, *ep = sql + alloc;

	if (sql == NULL)
	{
		(*do_report)(LOG_ALERT, "MEMORY FAULT");
		return OTHER_ERROR;
	}

	variable_id last_id = 0;
	uint32_t i;
	for (i = 0; i < stmt->count; ++i)
	{
		stmt_part const * const part = &stmt->part[i];

		if (part->length)
		{
			char *next = p + part->length;
			if (next >= ep)
			{
				(*do_report)(last_id? LOG_WARNING: LOG_CRIT,
					"Escape space exhausted at step %d, after $(%s)",
						i, last_id? variable_name[last_id]: "<internal error>");
				break;
			}

			memcpy(p, part->snippet, part->length);
			p = next;
		}

		variable_id const id = part->id;
		if (id && arglen[id]) // not_used_variable or empty strings don't play
		{
			size_t l = ep - p;
			int err = odbx_escape(handle, dwa->var[id], arglen[id], p, &l);
			char *next = p + l;
			if (err || next >= ep)
			{
				(*do_report)(LOG_WARNING,
					"Bad %s name %.63s (length=%zu) cannot be queried: %s",
						variable_name[id], dwa->var[id], arglen[id],
							err? odbx_error(handle, err): "escape space exhausted");
				break;
			}

			last_id = id;
			p = next;
		}
	}

	if (i < stmt->count) // error during the loop
	{
		free(sql);
		return OTHER_ERROR;
	}

	*p = 0;

#if defined TEST_MAIN
	(*do_report)(LOG_DEBUG, "query: %s", sql);
	if (dry_run)
	{
		free(sql);
		return 0;
	}
#endif

	int err = odbx_query(handle, sql, p - sql);
	if (err != ODBX_ERR_SUCCESS)
	{
		(*do_report)(LOG_ERR, "DB error: %s (query: %s)",
			odbx_error(handle, err), sql);
		free(sql);
		return OTHER_ERROR;
	}

	/*
	* All queries return at most a single row.  So we match the (numeric)
	* columns with the variable arguments.
	*/

	int got_result = 0;
	for (int r_set = 1;; ++r_set)
	{
		odbx_result_t *result = NULL;
		struct timeval timeout;
		timeout.tv_sec = dwa->z.db_timeout;
		timeout.tv_usec = 0;

		int err = odbx_result(handle, &result, &timeout, 0 /* chunk */);
#if defined TEST_MAIN
		if (verbose > 2)
			(*do_report)(LOG_DEBUG, "part #%d: rc=%d, result=%sNULL",
				r_set, err, result == NULL? "": "non-");
#endif

		if (err == ODBX_RES_DONE)
			break;

		if (err == ODBX_RES_NOROWS)
		{
			uint64_t rows = odbx_rows_affected(result);
#if defined TEST_MAIN
			if (verbose > 2)
				(*do_report)(rows > 1? LOG_WARNING: LOG_DEBUG,
					"part #%d of the query affected %ld rows",
						r_set, rows);
#else
			if (rows > 1)
				(*do_report)(LOG_WARNING,
					"part #%d of the query affected %ld rows (query: %s)",
						r_set, rows, sql);
#endif
			odbx_result_finish(result);
		}

		else if (err == ODBX_RES_ROWS)
		{
			unsigned long seen = 0;
			for (;;)
			{
				int fetch_more = odbx_row_fetch(result);
				if (fetch_more <= 0)
					break;

				++seen;
				int const column_count = odbx_column_count(result);
				if (got_result == 0 && column_count > 0)
				{
					got_result = 1;
					va_list ap;
					va_start(ap, count);
					for (int column = 0; column < column_count; ++column)
					{
						char const *field = odbx_field_value(result, column);
						if (column < count)
						{
							if (wantint)
							{
								int *want = va_arg(ap, int*);
								if (field != NULL)
								{
									char *t = NULL;
									long l = strtol(field, &t, 0);
									if (t && *t == 0 && l < INT_MAX && l > INT_MIN)
										*want = (int)l;
									else
									{
										*want = *field != 0;
#if !defined TEST_MAIN
										(*do_report)(LOG_WARNING,
											"query %s, part #%d, row 1, col %d "
											"is not a number: %s converted to %d",
												stmt_name[sid], r_set, column + 1,
												field, *want);
#endif
									}
								}
							}
							else
							{
								char **want = va_arg(ap, char**);
								if (field != NULL && (*want = strdup(field)) == NULL)
									(*do_report)(LOG_ALERT, "MEMORY FAULT");
							}
						}
						else
						{
							(*do_report)(LOG_WARNING,
								"query %s, part #%d, row 1, col %d "
								"is ignored: expected %d column(s) only",
									stmt_name[sid], r_set, column + 1, count);
						}
#if defined TEST_MAIN
						if (verbose)
							(*do_report)(LOG_DEBUG, "row#%ld, col %d: %s",
								seen, column + 1, field? field: "NULL");
#endif
					}
					va_end(ap);
				}
			}
			if (seen > 1)
			{
				(*do_report)(LOG_WARNING,
					"part #%d of query %s had %ld rows",
						r_set, stmt_name[sid], seen);
			}
			odbx_result_finish(result);
		}

		else if (err < 0)
		{
			(*do_report)(LOG_ERR, "DB error: %s (err: %d, %s, part #%d, query: %s)",
				odbx_error(handle, err), err, stmt_name[sid], r_set, sql);
			if (result)
				odbx_result_finish(result);
			break;
		}

		else if (err == ODBX_RES_TIMEOUT)
		{
			(*do_report)(LOG_ERR,
				"DB timeout: %d secs is too low? (part #%d, query: %s)",
				dwa->z.db_timeout, r_set, stmt_name[sid]);
			dwa->pending_result = time(0);
			dwa->pending_result_msg = 0;
			err =  OTHER_ERROR;
			if (result)
				odbx_result_finish(result);
			break;
		}

		else
		{
			(*do_report)(LOG_CRIT,
				"Internal error: unexpected rc=%d in part #%d of query %s",
				err, r_set, stmt_name[sid]);
			if (result)
				odbx_result_finish(result);
			break;
		}
	}

	free(sql);
	return got_result;
}

static inline int stmt_run(db_work_area* dwa, stmt_id sid, var_flag_t bitflag,
	char **wantchar, int* wantint)
/*
* Return 1 if a result is found and returned in any of wantchar and wantint,
* 0 if no result was found or if the statement is not defined.
* If an error is found (and logged) return OTHER_ERROR.
*
* TODO: rewrite stmt_run calls so as to avoid this hack.
*/
{
	assert(wantchar == NULL || wantint == NULL);
	void *passed = wantint != NULL? (void*)wantint: (void*)wantchar;
	int const count = wantint != NULL? -1: wantchar != NULL? 1: 0;

	return stmt_run_n(dwa, sid, bitflag, count, passed);
}

static inline int do_set_option(odbx_t *handle,
	int code, int value, char const *opt, char const *opt_name)
/*
* either value or opt are passed to odbx.
* assume thet integer values can neve be -1.
*/
{
	int err = odbx_set_option(handle, code,
		value == -1? (void*)opt: (void*)&value);
	if (err)
	{
		int errtype = odbx_error_type(handle, err);
		if (opt)
			(*do_report)(errtype? LOG_CRIT: LOG_WARNING,
				"%s error setting %s to \"%s\": %s",
				errtype? "Fatal": "Transient",
				opt_name, opt, odbx_error(handle, err));
		else
			(*do_report)(errtype? LOG_CRIT: LOG_WARNING,
				"%s error setting %s to %d: %s",
				errtype? "Fatal": "Transient",
				opt_name, value, odbx_error(handle, err));
		if (errtype)
		{
			odbx_finish(handle);
			return -1;
		}
	}
	return 0;
}

static int set_enable_disable_option(odbx_t *handle,
	int code, int opt, char const *opt_name)
{
	int value;
	switch (opt)
	{
		case 0:
			value = ODBX_DISABLE;
			break;
		case 1:
			value = ODBX_ENABLE;
			break;
		default:
			return 0;
	}
	return do_set_option(handle, code, value, NULL, opt_name);
}

int db_connect(db_work_area *dwa)
/*
* if inited (dwa != NULL) connect to server
* return 0, or -1 on unexpected error
*/
{
	if (dwa == NULL)
		return 0;

	odbx_t *handle;
	if (dwa->z.db_backend == NULL)
	{
		(*do_report)(LOG_CRIT, "Missing db_backend: cannot connect");
		return -1;
	}
	else if (strcmp(dwa->z.db_backend, "test") == 0)
	{
		dwa->is_test = 1;
		return 0;
	}

	int err = odbx_init(&handle, dwa->z.db_backend,
		dwa->z.db_host, dwa->z.db_port);
	if (err)
	{
		(*do_report)(LOG_CRIT,
			"Unable to initialize ODBX with backend=%s, host=%s, port=%s: %s",
			dwa->z.db_backend,
			dwa->z.db_host? dwa->z.db_host: "NULL",
			dwa->z.db_port? dwa->z.db_port: "NULL",
			odbx_error(NULL, err));
		return -1;
	}

	// option TLS (enum)
	if (dwa->z.db_opt_tls)
	{
		int value;
		switch (*dwa->z.db_opt_tls)
		{
			case 'A':
			case 'a':
				value = ODBX_TLS_ALWAYS;
				break;
			case 'N':
			case 'n':
				value = ODBX_TLS_NEVER;
				break;
			case 'T':
			case 't':
				value = ODBX_TLS_TRY;
				break;
			default:
				(*do_report)(LOG_WARNING,
					"Invalid value \"%s\" for db_opt_tls: "
					"use \"ALWAYS\", \"TRY\", or \"NEVER\"",
						dwa->z.db_opt_tls);
				value = -1;
				break;
		}
		if (value != -1 &&
			do_set_option(handle, ODBX_OPT_TLS, value,
			dwa->z.db_opt_tls, "db_opt_tls") == -1)
				return -1;
	}

	// option MULTI_STATEMENTS
	if (dwa->z.db_opt_multi_statements &&
		set_enable_disable_option(handle, ODBX_OPT_MULTI_STATEMENTS,
			dwa->z.db_opt_multi_statements, "db_opt_multi_statements") == -1)
				return -1;

	// option PAGED_RESULTS (int != -1)
	if (dwa->z.db_opt_paged_results != -1 &&
		do_set_option(handle, ODBX_OPT_PAGED_RESULTS,
		dwa->z.db_opt_paged_results, NULL, "db_opt_paged_results") == -1)
			return -1;

	// option COMPRESS
	if (dwa->z.db_opt_compress &&
		set_enable_disable_option(handle, ODBX_OPT_COMPRESS,
			dwa->z.db_opt_compress, "db_opt_compress") == -1)
				return -1;

	// option MODE (string)
	if (dwa->z.db_opt_mode &&
		do_set_option(handle, ODBX_OPT_MODE,
			-1, dwa->z.db_opt_mode, "db_opt_mode") == -1)
				return -1;

	// bind
	err = odbx_bind(handle, dwa->z.db_database,
		dwa->z.db_user, dwa->z.db_password, ODBX_BIND_SIMPLE);
	if (err)
	{
		(*do_report)(LOG_CRIT,
			"Cannot bind to %s (user: %s, %s): %s",
			dwa->z.db_database? dwa->z.db_database: "NULL",
			dwa->z.db_user? dwa->z.db_user: "NULL",
			dwa->z.db_password?
				*dwa->z.db_password? "using password: yes":
					"using empty password": "using password: no",
			odbx_error(handle, err));
		odbx_finish(handle);
		return -1;
	}

	dwa->handle = handle;
	return 0;
}

static int test_whitelisted(db_work_area* dwa, char const* domain)
{
	char *const h = dwa->z.db_sql_whitelisted;
	if (h)
	{
		char *x = strstr(h, domain);
		if (x)
		{
			x += strlen(domain);
			if (*x == ':')
				++x;
			return atoi(x);
		}
	}
	return 0;
}

int db_is_whitelisted(db_work_area* dwa, char *domain)
/*
* Run db_sql_whitelisted query for domain.  If the query is a statement,
* return 0 if it affected no rows, 1 otherwise (log a warning if > 1 rows).
* If the query is a SELECT, and the result contains a row with a non-null
* value in the first column, if that field is a positive int return that
* value, otherwise return 1 if there was such a row, otherwise 0 (log a
* warning if more than one row or column are found).
*
* The numeric result should be >= 1 if the domain is found, where > 1
* implies some trust.  0 or negative values may cause signatures to be
* ignored.
*/
{
	assert(dwa == NULL || dwa->handle || dwa->is_test);
	assert(domain);

	if (dwa == NULL)
		return 0;

	const var_flag_t bitflag = 1 << domain_variable | 1 << ip_variable;
	int rtc = 0;

	assert(dwa->var[domain_variable] == NULL);
	dwa->var[domain_variable] = domain;

	if (dwa->is_test) // need our own rtc for testsuite
	{
		dump_vars(dwa, db_sql_whitelisted, bitflag);
		rtc = test_whitelisted(dwa, domain);
	}
	else
		stmt_run(dwa, db_sql_whitelisted, bitflag, NULL, &rtc);

	dwa->var[domain_variable] = NULL;
	return rtc;
}

static char* test_check_user(db_work_area* dwa)
{
	char *r = NULL;
	char *const h = dwa->z.db_sql_check_user;
	if (h)
	{
		char *const u = dwa->var[local_part_variable];
		char *x = strstr(h, u);
		if (x)
		{
			x += strlen(u);
			if (*x++ == ':')
			{
				int ch;
				while ((ch = *(unsigned char*)x) != 0 && isspace(ch))
					++x;
				if (ch)
				{
					char *start = x++;
					while ((ch = *(unsigned char*)x) != 0 && !isspace(ch))
						++x;
					*x = 0;
					r = strdup(start);
					*x = ch;
				}
			}
		}
	}
	return r;
}

char *db_check_user(db_work_area* dwa)
/*
* Run db_sql_check_user query.  Return any result, or NULL.
* Returned values are to be freed by caller.
*/
{
	assert(dwa == NULL || dwa->handle || dwa->is_test);

	if (dwa == NULL || dwa->var[local_part_variable] == NULL)
		return NULL;

	var_flag_t bitflag = 1 << local_part_variable;
	if (dwa->user_domain)
	{
		// there may be multiple domain_variable, so they are not kept here
		assert(dwa->var[domain_variable] == NULL);

		dwa->var[domain_variable] = dwa->user_domain;
		bitflag |= 1 << domain_variable;
	}

	if (dwa->var[user_ref_variable])
		bitflag |= 1 << user_ref_variable;
	
	char *r = NULL;

	if (dwa->is_test) // need our own rtc for testsuite
	{
		dump_vars(dwa, db_sql_check_user, bitflag);
		r = test_check_user(dwa);
	}
	else
		stmt_run(dwa, db_sql_check_user, bitflag, &r, NULL);

	dwa->var[domain_variable] = NULL;
	return r;
}

void db_set_authenticated_user(db_work_area *dwa,
	char const *local_part, char const *domain)
{
	assert(dwa);
	assert(local_part);

	if (dwa->var[local_part_variable])
		free(dwa->var[local_part_variable]);
	dwa->var[local_part_variable] = strdup(local_part);

	if (dwa->user_domain)
		free(dwa->user_domain);
	if (domain)
		dwa->user_domain = strdup(domain);
	else
		dwa->user_domain = NULL;
}

extern char *ip_to_hex(char const *ip); // ip_to_hex.c
void db_set_client_ip(db_work_area *dwa, char const *ip)
{
	assert(dwa);
	assert(ip);

	if (dwa->var[ip_variable])
		free(dwa->var[ip_variable]);
	dwa->var[ip_variable] = ip_to_hex(ip);
}


#if 0
static inline int makeint2(int const ch, char const **p)
{
	assert(isdigit(ch));
	assert(**(unsigned char const **)p == ch);

	int ch2, r = ch - '0';
	if (isdigit(ch2 = *(unsigned char const*)++*p) && ch2 != 0)
	{
		r *= 10;
		r += ch2 - '0';
		*p += 1;
	}
	return r;
}

static char*date_convert(char const *date)
{
	if (date == NULL) return NULL;

	struct tm tm;
	memset(&tm, 0, sizeof tm);

	char const *p = date;
	int ch;
	while (!isdigit(ch = *(unsigned char const*)p) && ch != 0)
		++p;
	if (ch == 0) return NULL;

	tm.tm_mday = makeint2(ch, &p);
	while (isspace(ch = *(unsigned char const*)p) && ch != 0)
		++p;
	if (!isalpha(ch)) return NULL;

	static const char *month[12] = {"Jan", "Feb", "Mar", "Apr",
		"May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	int i;
	for (i = 0; i < 12; ++i)
		if (strncasecmp(p, month[i], 3) == 0)
			break;
	if (i >= 12) return NULL;

	tm.tm_mon = i;
	p += 3;
	while (!isdigit(ch = *(unsigned char const*)p) && ch != 0)
		++p;
	if (ch == 0) return NULL;

	char *t = NULL;
	long l = strtoul(p, &t, 10);
	if (l < 1900 || l > INT_MAX) return NULL;

	tm.tm_year = l - 1900;
	p = t;
	while (!isdigit(ch = *(unsigned char const*)p) && ch != 0)
		++p;
	if (ch == 0) return NULL;

	tm.tm_hour = makeint2(ch, &p);
	if	(*p != ':') return NULL;
	if (!isdigit(ch = *(unsigned char const*)++p)) return NULL;

	tm.tm_min = makeint2(ch, &p);
	if	(*p != ':') return NULL;
	if (!isdigit(ch = *(unsigned char const*)++p)) return NULL;

	tm.tm_sec = makeint2(ch, &p);
	while (isspace(ch = *(unsigned char const*)p) && ch != 0)
		++p;

	if (ch)
	{
		time_t t;
		int tz = 0;
		char *save_tz = getenv("TZ");
		char const *new_tz;
		tm.tm_isdst = -1;

		if (ch && strchr("+-", ch))
		{
			int sign = ch == '+'? 1: -1;
			if (!isdigit(ch = *(unsigned char const*)++p)) return NULL;

			tz = 60 * makeint2(ch, &p);
			if (!isdigit(ch = *(unsigned char const*)p)) return NULL;

			tz += makeint2(ch, &p);
			tz *= 60*sign;
			new_tz = ""; // GMT
		}
		else
			new_tz = p; // doesn't work

		setenv("TZ", p, 1);
		tzset();
		t = mktime(&tm);
		if (save_tz)
			setenv("TZ", save_tz, 1);
		else
			unsetenv("TZ");
		tzset();
		if (t == (time_t)-1) return NULL;

		t -= tz;
		if (localtime_r(&t, &tm) == NULL) return NULL;
	}

	char buf[80];
	sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
		tm.tm_year + 1900, tm.tm_mday, tm.tm_mon + 1,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	return strdup(buf);
}
#endif

static void comma_copy(char *buf, char const *value, int *comma)
{
	if (*comma)
		strcat(buf, ",");
	strcat(buf, value);
	*comma = 1;
}

static var_flag_t
in_stmt_run(db_work_area* dwa, var_flag_t bitflag, stats_info *info)
{
	assert(dwa);
	assert(info);

	var_flag_t zeroflag = 0;

	char *var = NULL;
	int rc = stmt_run(dwa, db_sql_insert_message, bitflag, &var, NULL);

	if ((dwa->var[message_ref_variable] = var) != NULL)
		bitflag |= 1 << message_ref_variable;

	/*
	* For each domain:
	* Query it.  If not found, insert it, and possibly query it again so as to
	* have a reference.  If found, update it.
	* With the retrieved reference, insert a msg_ref.
	*/
	if (rc >= 0 && info->domain_head != NULL)
	{
		// author,spf,spf_helo,dkim,vbr,rep,rep_s,dnswl
		// 12345678901234567890123456789012345678901234
		char authbuf[48];
		dwa->var[auth_type_variable] = authbuf;
		var_flag_t bit2 = 1 << auth_type_variable | 1 << domain_variable;
		bitflag |= bit2;
		zeroflag |= bit2;

		var_flag_t vbr_bit = 1 << vbr_mv_variable;
		if (info->vbr_result_resp)
		{
			vbr_bit |= 1 << vbr_response_variable;
			dwa->var[vbr_response_variable] = info->vbr_result_resp;
		}
		zeroflag |= vbr_bit;

		// reputation (usually 0) available for domain and message_ref
		bit2 = 1 << reputation_variable;
		bitflag |= bit2;
		zeroflag |= bit2;
		
		// constant bit for the loop
		bit2 = 1 << domain_ref_variable;

		for (domain_prescreen *dps = info->domain_head;
			dps != NULL; dps = dps->next)
		{
			int comma = 0;
			authbuf[0] = 0;
			if (dps->u.f.is_from)
				comma_copy(authbuf, "author", &comma);
			if (dps->u.f.is_helo)
				comma_copy(authbuf, "spf_helo", &comma);
			if (dps->u.f.is_mfrom)
				comma_copy(authbuf, "spf", &comma);
			if (dps->u.f.sig_is_ok)
				comma_copy(authbuf, "dkim", &comma);
			if (dps->u.f.vbr_is_ok)
			{
				comma_copy(authbuf, "vbr", &comma);
				dwa->var[vbr_mv_variable] = dps->vbr_mv;
				bitflag |= vbr_bit;
			}
			else
				bitflag &= ~vbr_bit;
			if (dps->u.f.is_reputed)
				comma_copy(authbuf, "rep", &comma);
			if (dps->u.f.is_reputed_signer)
				comma_copy(authbuf, "rep_s", &comma);
			if (dps->u.f.is_dnswl)
				comma_copy(authbuf, "dnswl", &comma);

			char rep_buf[8*sizeof(int)/3 + 3];
			sprintf(rep_buf, "%d", dps->reputation);
			dwa->var[reputation_variable] = rep_buf;

			dwa->var[domain_variable] = dps->name;
			bitflag &= ~bit2;

			int selected = 1;
			char *domain_ref = NULL;
			rc = stmt_run(dwa, db_sql_select_domain, bitflag, &domain_ref, NULL);
			if (rc < 0)
				continue;

			if (domain_ref == NULL)
			{
				selected = 0;
				rc = stmt_run(dwa, db_sql_insert_domain, bitflag, &domain_ref, NULL);
				if (rc < 0)
					continue;

				if (domain_ref == NULL)
					stmt_run(dwa, db_sql_select_domain, bitflag, &domain_ref, NULL);
			}

			if (domain_ref)
			{
				free(dwa->var[domain_ref_variable]);
				dwa->var[domain_ref_variable] = domain_ref;
				bitflag |= bit2;
			}

			if (selected)
				stmt_run(dwa, db_sql_update_domain, bitflag, NULL, NULL);

			stmt_run(dwa, db_sql_insert_msg_ref, bitflag, NULL, NULL);
		}
	}
	return zeroflag;
}

static var_flag_t
out_stmt_run(db_work_area* dwa, var_flag_t bitflag, stats_info *info)
{
	assert(dwa);
	assert(info);

	var_flag_t zeroflag = 1 << domain_variable;

	bitflag |= 1 << local_part_variable | 1 << domain_variable;
	dwa->var[domain_variable] = dwa->user_domain;
	char *user_ref = NULL, *message_ref = NULL;
	stmt_run_n(dwa, db_sql_select_user, bitflag, 2, &user_ref, &message_ref);

	if ((dwa->var[user_ref_variable] = user_ref) != NULL)
		bitflag |= 1 << user_ref_variable;
	if ((dwa->var[message_ref_variable] = message_ref) != NULL)
		bitflag |= 1 << message_ref_variable;

	/*
	* For each target domain:
	* Query it.  If not found, insert it, and possibly query it again so as to
	* have a reference.  If found, update it.
	* With the retrieved reference, insert a target_ref.
	*/
	if (info->domain_head != NULL)
	{
		// constant bits for the loop
		var_flag_t bit2 = 1 << domain_ref_variable;
		
		for (domain_prescreen *dps = info->domain_head;
			dps != NULL; dps = dps->next)
		{
			dwa->var[domain_variable] = dps->name;
			bitflag &= ~bit2;

			int selected = 1;
			char *domain_ref = NULL;
			int rc =
				stmt_run(dwa, db_sql_select_target, bitflag, &domain_ref, NULL);
			if (rc < 0)
				continue;

			if (domain_ref == NULL)
			{
				selected = 0;
				rc = stmt_run(dwa, db_sql_insert_target, bitflag, &domain_ref, NULL);
				if (rc < 0)
					continue;

				if (domain_ref == NULL)
					stmt_run(dwa, db_sql_select_target, bitflag, &domain_ref, NULL);
			}

			if (domain_ref)
			{
				free(dwa->var[domain_ref_variable]);
				dwa->var[domain_ref_variable] = domain_ref;
				bitflag |= bit2;
			}

			if (selected)
				stmt_run(dwa, db_sql_update_target, bitflag, NULL, NULL);

			stmt_run(dwa, db_sql_insert_target_ref, bitflag, NULL, NULL);
		}
	}

	return zeroflag;
}

void db_set_stats_info(db_work_area* dwa, stats_info *info)
{
	assert(dwa);
	assert(info);
#if !defined NDEBUG
	for (int i = 0; i < DB_SQL_VAR_SIZE; ++i)
		assert(dwa->var[i] == NULL ||
			i == ip_variable || i == local_part_variable);
#endif

	if (info == NULL || info->domain_head == NULL)
	{
		(*do_report)(LOG_CRIT,
			"Internal error, invalid stats for id: %s",
			info && info->ino_mtime_pid? info->ino_mtime_pid: "unknown");
		return;
	}

	var_flag_t bitflag = 0, zeroflag = 0;
	if (info->ino_mtime_pid != NULL)
	{
		char const *mtime = strchr(info->ino_mtime_pid, '.');
		if (mtime && mtime[1])
		{
			char const *pid = strchr(mtime + 1, '.');
			if (pid && pid[1])
			{
				if ((dwa->var[pid_variable] = strdup(&pid[1])) != NULL)
					bitflag |= 1 << pid_variable;
				size_t l = pid - mtime;
				char *p = malloc(l);
				if ((dwa->var[mtime_variable] = p) != NULL)
				{
					memcpy(p, &mtime[1], l);
					p[l-1] = 0;
					bitflag |= 1 << mtime_variable;
				}
				l = mtime - info->ino_mtime_pid + 1;
				p = malloc(l);
				if ((dwa->var[ino_variable] = p) != NULL)
				{
					memcpy(p, info->ino_mtime_pid, l);
					p[l-1] = 0;
					bitflag |= 1 << ino_variable;
				}
			}
		}
	}

	if (!dwa->is_test &&
		bitflag != (1 << ino_variable | 1 << mtime_variable | 1 << pid_variable))
	{
		(*do_report)(LOG_CRIT,
			"Internal error at " __FILE__ ":%d: missing %s", __LINE__,
			info->ino_mtime_pid == NULL? "ino_mtime_pid":
			(bitflag & 1 << pid_variable) == 0? "pid_variable":
			(bitflag & 1 << mtime_variable) == 0? "mtime_variable":
			(bitflag & 1 << ino_variable) == 0? "ino_variable": "something");
		return;
	}

	if (dwa->var[ip_variable] != NULL) // this may have been set in its own call
		bitflag |= 1 << ip_variable;

#define PICK_STRING(N) \
	if ((dwa->var[N##_variable] = info->N) != NULL) { \
		info->N = NULL; \
		bitflag |= 1 << N##_variable; \
	} else (void)0
	PICK_STRING(date);
	PICK_STRING(message_id);
	PICK_STRING(from);
	PICK_STRING(subject);
	PICK_STRING(envelope_sender);
	PICK_STRING(content_type);
	PICK_STRING(content_encoding);
#undef PICK_STRING

	// these must be zeroed from dwa->var before they are freed:
	// that's what zeroflag is for.
	// we assume no number takes more than 10 chars to print.
	// safe_stop accounts for "discardable,fail,whitelisted"
	char buf[80], *p = buf, *safe_stop = &buf[sizeof buf - 30];
#define SET_NUMBER(N) \
	if (p < safe_stop) { \
		p += 1 + sprintf(dwa->var[N##_variable] = p, "%u", info->N); \
		var_flag_t bit = 1 << N##_variable; \
		bitflag |= bit; zeroflag |= bit; } else (void)0
	if (info->outgoing == 0)
	{
		SET_NUMBER(received_count);
		SET_NUMBER(signatures_count);
		if (p < safe_stop)
		{
			char *msg_st = info->reject? "reject": info->drop? "drop": "accept";
			size_t len = strlen(msg_st) + 1;
			strcpy(dwa->var[message_status_variable] = p, msg_st);
			p += len;
			var_flag_t bit = 1 << message_status_variable;
			bitflag |= bit;
			zeroflag |= bit;
		}
		if (p < safe_stop)
		{
			char *adsp_st = info->adsp_all? "all":
				info->adsp_discardable? "discardable": "unknown";
			strcpy(dwa->var[adsp_flags_variable] = p, adsp_st);
			if (info->adsp_unknown && info->adsp_found)
				strcat(p, ",found");
			if (info->adsp_fail) strcat(p, ",fail");
			if (info->adsp_whitelisted) strcat(p, ",whitelisted");
			p += strlen(p) + 1;
			var_flag_t bit = 1 << adsp_flags_variable;
			bitflag |= bit;
			zeroflag |= bit;
		}
	}
	else
		SET_NUMBER(rcpt_count);
	SET_NUMBER(mailing_list);
#undef SET_NUMBER

	/*
	* With the variables in place, run in/out series of statements
	*/
	if (info->outgoing == 0)
		zeroflag |= in_stmt_run(dwa, bitflag, info);
	else
		zeroflag |= out_stmt_run(dwa, bitflag, info);

	variable_id id = 0;
	var_flag_t mask = 1;
	for (; zeroflag; zeroflag &= ~mask, mask <<= 1, ++id)
		if (zeroflag & mask)
			dwa->var[id] = NULL;
}

#if defined TEST_MAIN

// the probability that rand() > RAND_MAX/2 is 50%, etcetera.
#define PERC_50 (RAND_MAX/2)
#define PERC_90 (RAND_MAX/10)
#define PERC_10 (RAND_MAX - RAND_MAX/10)
#define PERC_20 (RAND_MAX - RAND_MAX/5)

#include <sys/types.h>
#include <unistd.h>

static int autoargip(db_work_area *dwa)
{
	char buf[32];
	sprintf(buf, "192.0.2.%d", (int)(rand() & 255));
	db_set_client_ip(dwa, buf);
	return 1;
}

static int autoarg(db_work_area *dwa, stats_info *stats, int i)
{
	int set_client_ip = 0;
	char buf[100];
	switch(i)
	{
		case 1:
		{
			if (stats->outgoing)
			{
				db_set_authenticated_user(dwa, "user",
					rand() > PERC_50? "user.example" : NULL);
			}

			set_client_ip = autoargip(dwa);
			break;
		}
		case 2:
		{
			stats->envelope_sender = strdup("bounce.address@example.com");
			break;
		}
		case 3:
		{
			stats->from = strdup("sender@example.com");
			break;
		}
		case 4:
		{
			struct tm tm;
			time_t snd = time(NULL) - drand48()*1800;
			localtime_r(&snd, &tm);
			strftime(buf, sizeof buf, "%a, %d %b %Y %T %z", &tm);
			stats->date = strdup(buf);
			break;
		}
		case 5:
		{
			sprintf(buf, "<%x@example.com>", rand());
			stats->message_id = strdup(buf);
			break;
		}
		case 6:
		{
			stats->subject = strdup("Subject of the msg");
			break;
		}
		case 7:
		{
			char *ct = rand() > PERC_50? "text/plain": "multipart/mixed";
			stats->content_type = strdup(ct);
			break;
		}
		case 8:
		{
			if (stats->content_type != NULL &&
				strstr(stats->content_type, "ultipa") == 0)
					stats->content_encoding = strdup(rand() > PERC_50? "7bit": "8bit");
			break;
		}
		case 9:
		{
			unsigned *const target = stats->outgoing?
				&stats->rcpt_count: &stats->received_count;
			*target = 2 + (int)(4.0 * drand48());
			break;
		}
		case 10:
		{
			stats->signatures_count = 3;
			break;
		}
		case 11:
		{
			stats->mailing_list = rand() > PERC_50? 1: 0;
			break;
		}
		case 12:
		{
			sprintf(buf, "%x.%lx.%x", rand(), time(NULL), getpid());
			stats->ino_mtime_pid = strdup(buf);
			break;
		}
	}

	return set_client_ip;
}

static char *token_argument(char *arg, size_t len, int *re)
{
	assert(arg);
	assert(len <= strlen(arg));

	int ch;
	if (len == 0)
	{
		++arg;
		while ((ch = *(unsigned char*)arg) != 0 && ch != ':')
			++arg;
	}
	else
	{
		arg += len;
		ch = *(unsigned char*)arg;
	}

	if (len > 0 || ch == ':')
		*arg++ = 0;

	if (ch != ':')
		return NULL;

	if (re)
		*re = atoi(arg);
	return arg;
}

int main(int argc, char*argv[])
{
	size_t maxarglen = strlen(argv[0]);
	int rtc = 0, errs = 0, config = 0, force_test = 0,
		query_whitelisted = argc,
		set_stats = argc,
		set_stats_domain = argc;
	char const *config_file = NULL;

	for (int i = 1; i < argc; ++i)
	{
		char const *const arg = argv[i];
		size_t arglen = strlen(arg);

		if (arglen > maxarglen)
			maxarglen = arglen;

		if (arg[0] != '-')
			continue;

		if (arg[1] != '-')
		{
			for (char const *o = &arg[1]; *o != 0; ++o)
			{
				if (*o == 'f')
				{
					config_file = ++i < argc ? argv[i] : NULL;
				}
				else if (*o == 'v')
				{
					++verbose;
				}
				else
				{
					printf("Invalid short option %c in %s\n", *o, arg);
					++errs;
					break;
				}
			}	
		}
		else if (strcmp(arg, "--config") == 0)
		{
			config = 1;
		}
		else if (strcmp(arg, "--version") == 0)
		{
			fputs(PACKAGE_NAME ", version " PACKAGE_VERSION "\n"
				"Compiled with"
#if defined NDEBUG
				"out"
#endif
				" debugging support\n", stdout);
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			printf("zfilter_db is for testing / querying the db configuration.\n"
			"\n"
			"Command line args:\n"
			"\n"
			"  -v                                   increase verbosity\n"
			"  -f config-filename                   override %s\n"
			"  --config                             report configuration\n"
			"  --help                               print this and exit\n"
			"  --version                            print version string and exit\n"
			"  --dry-run                            don't actually run queries\n"
			"  --test                               force the \"test\" backend\n"
			"  --db-sql-whitelisted domain ...      query domains\n"
			"  --set-stats <d> [msg-data]           insert new data (see below)\n"
			" [--set-stats-domain] domain[,tok] ... domains related to the message\n"
			"\n"
			"For set-stats, the <d> (direction) must be either I (incoming) or\n"
			"O (outgoing).  The following arguments are one or more msg-data, if\n"
			"the --set-stats-domain option is given, otherwise are domains.\n"
			"In the former case, some of the following ten arguments are expected:\n"
			"\n"
			"  either ip or user@domain, envelope sender, from, date, message_id,\n"
			"  subject, content_type, content_encoding, received or rcpt _count,\n"
			"  signatures_count, mailing_list, and ino.mtime.pid.\n"
			"\n"
			"The set-stats-domain option marks the end of message data and the\n"
			"beginning of the domain list.  It is only necessary if msg-data is\n"
			"given.  Domains must be one per argument, using commas to separate\n"
			"the tokens, which are the domain name, followed by any of the words:\n"
			"author, spf_helo, spf, dkim, vbr.  If using @, tokens are generated at\n"
			"random, provided no comma appear at the end of the domain name.\n",
				default_config_file);
			return 0;
		}
		else if (strcmp(arg, "--dry-run") == 0)
		{
			dry_run = 1;
		}
		else if (strcmp(arg, "--test") == 0)
		{
			force_test = 1;
		}
		else if (strcmp(arg, "--db-sql-whitelisted") == 0)
		{
			query_whitelisted = i + 1;
		}
		else if (strcmp(arg, "--set-stats") == 0)
		{
			set_stats = i + 1;
		}
		else if (strcmp(arg, "--set-stats-domain") == 0)
		{
			set_stats_domain = i + 1;
		}
		else
		{
			printf("Invalid option %s\n", arg);
			++errs;
		}
	}
	if (errs)
		return 1;

	set_parm_logfun(&stderrlog);
	db_work_area *dwa = db_init();
	if (dwa == NULL)
		return 1;

	if (config_file == NULL)
		config_file = default_config_file;

	void *parm_target[PARM_TARGET_SIZE];
	parm_target[parm_t_id] = NULL;
	parm_target[db_parm_t_id] = db_parm_addr(dwa);

	if (*config_file &&
		read_all_values(parm_target, config_file))
	{
		db_clear(dwa);
		return 1;
	}

	if (force_test)
	{
		free(dwa->z.db_backend);
		dwa->z.db_backend = strdup("test");
	}

	db_config_wrapup(dwa, NULL, NULL);

	if (config)
		print_parm(parm_target);

	if (db_connect(dwa) == 0)
	{
		int set_client_ip = 0;
		stats_info stats;
		memset(&stats, 0, sizeof stats);

		if (set_stats < argc)
		{
			unsigned ndomains = 0, nwhitelisted = 0;
			unsigned char const dir = toupper((unsigned char)argv[set_stats][0]);
			int atauto = 0;
			
			if (argv[set_stats][1] != 0 || strchr("IO", dir) == NULL)
			{
				printf("invalid set-stats argument: %s\n", argv[set_stats]);
			}
			else
			{
				int auto_from = 99; // to be determined
				stats.outgoing = dir == 'O';

				if (set_stats_domain >= argc)
				{
					set_stats_domain = set_stats + 1;
					auto_from = 0;
				}

				srand((unsigned int)time(NULL));

				if (auto_from > 12)
				{
					for (int i = set_stats + 1; i < argc; ++i)
					{
						auto_from = i - set_stats;

						char *arg = argv[i];
						if (arg[0] == '-')
							break;

						if (arg[0] == 0)
							continue;

						if (arg[0] == '@' && arg[1] == 0)
						{
							autoarg(dwa, &stats, auto_from);
							continue;
						}

						switch(auto_from)
						{
							case 1:
							{
								if (stats.outgoing)
								{
									char *at = strchr(arg + 1, '@');
									char *u_dom = at? at + 1: NULL;
									if (at) *at = 0;
									db_set_authenticated_user(dwa, arg, u_dom);
									if (at) *at = '@';
								}
								else
								{
									set_client_ip = 1;
									db_set_client_ip(dwa, arg);
								}

								break;
							}
							case 2: stats.envelope_sender = strdup(arg); break;
							case 3: stats.from = strdup(arg); break;
							case 4: stats.date = strdup(arg); break;
							case 5: stats.message_id = strdup(arg); break;
							case 6: stats.subject = strdup(arg); break;
							case 7: stats.content_type = strdup(arg); break;
							case 8: stats.content_encoding = strdup(arg); break;
							case 9:
							{
								unsigned *const target = stats.outgoing?
									&stats.rcpt_count: &stats.received_count;
								*target = atoi(arg);
								break;
							}
							case 10: stats.signatures_count = atoi(arg); break;
							case 11: stats.mailing_list = atoi(arg); break;
							case 12: stats.ino_mtime_pid = strdup(arg); break;
							default:
								printf("extra set-stats argument \"%s\" ignored\n", arg);
								break;
						}
					}
				}

				for (int i = auto_from + 1; i <= 12; ++i)
					set_client_ip |= autoarg(dwa, &stats, i);

				if (set_client_ip == 0)
					set_client_ip = autoargip(dwa);
			}

			domain_prescreen **pdps = &stats.domain_head;
			size_t prelength = sizeof(domain_prescreen) + maxarglen + 1;
			for (int i = set_stats_domain; i < argc; ++i)
			{
				char *arg = argv[i];
				if (arg[0] == '-')
					break;

				if (arg[0] == '@' && arg[1] == 0)
				{
					atauto = 1;
					continue;
				}

				domain_prescreen *dps = *pdps = calloc(1, prelength);
				if (dps == NULL)
					break;

				pdps = &dps->next;
				strcpy(dps->name, strtok(arg, ","));
				ndomains += 1;
				if (stats.outgoing == 0 &&
					db_is_whitelisted(dwa, dps->name))
						nwhitelisted += 1;

				int m = 0;
				while ((arg = strtok(NULL, ",")) != NULL)
				{
					++m;
					if (strcmp(arg, "author") == 0)
						dps->u.f.is_from = 1;
					else if (strcmp(arg, "spf") == 0)
						dps->u.f.is_mfrom = 1;
					else if (strcmp(arg, "spf_helo") == 0)
						dps->u.f.is_helo = 1;
					else if (strcmp(arg, "dkim") == 0)
						dps->u.f.sig_is_ok = 1;
					else if (strncmp(arg, "vbr", 3) == 0)
					{
						dps->u.f.has_vbr = 1;
						dps->u.f.vbr_is_trusted = 1;
						dps->u.f.vbr_is_ok = 1;
						if ((dps->vbr_mv = token_argument(arg, 3, NULL)) != NULL)
							stats.vbr_result_resp =
								token_argument(dps->vbr_mv, 0, NULL);
					}
					else if (strncmp(arg, "rep", 3) == 0)
					{
						dps->u.f.is_reputed = 1;
						token_argument(arg, 3, &dps->reputation);
					}
					else if (strncmp(arg, "rep_s", 5) == 0)
					{
						dps->u.f.is_reputed_signer = 1;
						token_argument(arg, 5, &dps->reputation);
					}
					else if (strncmp(arg, "dnswl", 5) == 0)
						dps->u.f.is_dnswl = 1;
					else if (*arg)
						printf("invalid domain token \"%s\" for %s\n", arg, dps->name);
				}

				if (atauto && m == 0 && stats.outgoing == 0)
				{
					dps->u.f.is_from = rand() >
						(i == set_stats_domain? PERC_90: PERC_10);
					dps->u.f.is_mfrom = rand() > PERC_20;
					dps->u.f.is_helo = dps->u.f.is_mfrom && rand() > PERC_20;
					dps->u.f.sig_is_ok = rand() > PERC_20;
					dps->u.f.is_reputed  = rand() > PERC_10;
					if (dps->u.f.is_reputed)
					{
						dps->reputation = (rand() - RAND_MAX/2) / (RAND_MAX/1000);
						dps->u.f.is_reputed_signer  = rand() > PERC_90;
					}
					dps->u.f.is_dnswl = rand() > PERC_50;
					dps->u.f.vbr_is_ok = rand() > PERC_20;
					if (dps->u.f.vbr_is_ok)
					{
						dps->u.f.has_vbr = 1;
						dps->u.f.vbr_is_trusted = 1;
						dps->vbr_mv = rand() > PERC_90?
							"dwl.spamhaus.org": "who_else";
						stats.vbr_result_resp = "all";
					}
				}
			}

			db_set_stats_info(dwa, &stats);
			if (stats.outgoing)
			{
				char *s = db_check_user(dwa);
				printf("user check: %s\n", s? s: "negative");
				free(s);
			}
			else
				printf("%d/%d domain(s) whitelisted\n", nwhitelisted, ndomains);

			free(stats.ino_mtime_pid);
			for (domain_prescreen *dps = stats.domain_head; dps;)
			{
				domain_prescreen *next = dps->next;
				free(dps);
				dps = next;
			}
		}


		for (int i = query_whitelisted; i < argc; ++i)
		{
			if (argv[i][0] == '-')
				break;

			if (stats.outgoing)
			{
				puts("NOTE: db_sql_whitelisted is not for outgoing messages");
				stats.outgoing = 0;
			}

			if (set_client_ip == 0)
				set_client_ip = autoargip(dwa);

			printf("%s: %d\n", argv[i], db_is_whitelisted(dwa, argv[i]));
		}
	}

	clear_parm(parm_target);
	db_clear(dwa);

	return rtc;
}
#endif // TEST_MAIN
#else // HAVE_OPENDBX
// dummy functions.  Warnings that they don't use arguments are appreciated...
db_work_area *db_init(void) {return NULL;}
void db_clear(db_work_area* dwa) {}
db_parm_t* db_parm_addr(db_work_area *dwa) {return NULL;}
int db_config_wrapup(db_work_area* dwa, int *in, int *out)
{
	if (in) *in = 0;
	if (out) *out = 0;
	return 0;
}
int db_connect(db_work_area *dwa) { return 0; }
int db_is_whitelisted(db_work_area* dwa, char *domain) {return 0;}
char *db_check_user(db_work_area* dwa) {return NULL;}

void db_set_authenticated_user(db_work_area *dwa,
	char const *local_part, char const *domain) {}
void db_set_client_ip(db_work_area *dwa, char const *ip) {}
void db_set_stats_info(db_work_area* dwa, stats_info *info) {}
#if defined TEST_MAIN
int main()
{
	puts("This program does nothing!\nPlease install OpenDBX then reconfigure");
	return 0;
}
#endif // TEST_MAIN
#endif // HAVE_OPENDBX
