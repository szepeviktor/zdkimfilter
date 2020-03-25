/*
**  Copyright (c) 2005, 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#include <config.h>
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif

/* system inludes */
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* libopendkim includes */
#include "dkim-mailparse.h"

#include <assert.h>

/* types */
typedef unsigned long cmap_elem_type;

/* symbolic names */
#define MY_MAILPARSE_OK                0   /* success */
#define MY_MAILPARSE_ERR_PUNBALANCED   1   /* unbalanced parentheses */
#define MY_MAILPARSE_ERR_QUNBALANCED   2   /* unbalanced quotes */
#define MY_MAILPARSE_ERR_SUNBALANCED   3   /* unbalanced sq. brackets */
#define MY_MAILPARSE_ERR_ESCAPE_EOS    4   /* cannot escape end-of-string */
#define MY_MAILPARSE_ERR_ANGLE_BRA     5   /* found closed bracket only */
#define MY_MAILPARSE_ERR_BAD_LITERAL   6   /* unexpected special between [] */
#define MY_MAILPARSE_ERR_MANY_AT       7   /* multiple @'s, not source-route */
#define MY_MAILPARSE_ERR_NO_DOMAIN     8   /* domain cannot be empty */
#define MY_MAILPARSE_ERR_SEMICOL       9   /* ';' without group syntax */

/* a bitmap for the "specials" character class */
#define	CMAP_NBITS	 	(sizeof(cmap_elem_type) * CHAR_BIT)
#define	CMAP_NELEMS	  	((1 + UCHAR_MAX) / CMAP_NBITS)
#define	CMAP_INDEX(i)		((unsigned char)(i) / CMAP_NBITS)
#define	CMAP_BIT(i)  		(1L << (unsigned char)(i) % CMAP_NBITS)
#define	CMAP_TST(ar, c)    	((ar)[CMAP_INDEX(c)] &  CMAP_BIT(c))
#define	CMAP_SET(ar, c)    	((ar)[CMAP_INDEX(c)] |= CMAP_BIT(c))

static unsigned char const SPECIALS[] = "()<>@,;:\\\"/[]";

static cmap_elem_type /* almost const */ is_special[CMAP_NELEMS] = { 0 };
static int /* almost const */ inited = 0;

/*
**  DKIM_MAIL_PARSE_INIT -- initialize dkim-mailparse
**
**  It is the caller's responsibility to initialize dkim-mailparse before
**  starting multiple threads.
*/

void
my_mail_parse_init __P((void))
{
	/* set up special finder */
	size_t		i;
	for (i = 0; SPECIALS[i] != '\0'; i++)
		CMAP_SET(is_special, SPECIALS[i]);
	inited = 1;
}


#ifdef TEST_MAIN
/*
**  DKIM_MAIL_UNESCAPE -- remove escape characters from a string
**
**  Parameters:
**  	s -- the string to be unescaped
**
**  Return value:
**  	s.
*/

static char *
my_mail_unescape(char *s)
{
	char *w, *r, *p, *e;

	if (s == NULL)
		return NULL;

	r = w = s;
	e = s + strlen(s);

	while ((p = memchr(r, '\\', e - s)) != NULL)
	{
		if (p > s)
		{
			if (r != w)
				memmove(w, r, p - r);
			w += p - r;
		}

		if (p[1] == '\0')
		{
			r = p + 1;
		}
		else
		{
			*w++ = p[1];
			r = p + 2;
		}
	}

	if (r > w)
	{
		if (e > r)
		{
			memmove(w, r, e - r);
			w += e - r;
		}
		*w = '\0';
	}

	return s;
}
#endif /* TEST_MAIN */

/*
**  DKIM_MAIL_MATCHING_PAREN -- return the location past matching opposite
**                              parentheses
**
**  Parameters:
**  	s -- start of string to be processed
**  	e -- end of string to be processed
**  	open_paren -- open parenthesis character
**  	close_paren -- close parenthesis character
**
**  Return value:
**  	Location of the final close parenthesis character in the string.
**  	For example, given "xxx((yyyy)zz)aaaa", would return the location
**  	of the second ")".  There may be more beyond that, but at that point
**  	everything is balanced.
*/

static char *
my_mail_matching_paren(char *s, char *e, int open_paren, int close_paren)
{
	int 		paren = 1;

	for (; s < e; s++)
	{
		if (*s == close_paren)
		{
			if (--paren == 0)
				break;
		}
		else if (*s == open_paren)
		{
			paren++;
		}
		else if (*s == '\\')
		{
			if (s[1] != '\0')
				s++;
		}
	}

	return s;
}


/*
**  DKIM_MAIL_TOKEN -- find the next token
**
**  Parameters:
**  	s -- start of input string
**  	e -- end of input string
**  	type_out -- type of token (returned)
**  	start_out -- start of token (returned)
**  	end_out -- end of token (returned)
**  	uncommented_whitespace -- set to TRUE if uncommented whitespace is
**  	                          discovered (returned)
**
**  Return value:
**  	0 on success, or an MY_MAILPARSE_ERR_* on failure.
*/

static int
my_mail_token(char *s, char *e, int *type_out, char **start_out,
                char **end_out, int *uncommented_whitespace)
{
	char *p;
	int err = 0;
	int token_type;
	char *token_start, *token_end;

	*start_out = NULL;
	*end_out   = NULL;
	*type_out  = 0;

	err = 0;

	assert(inited);
	p = s;

	/* skip white space between tokens */
	while (p < e && (*p == '(' ||
	                 (isascii(*(unsigned char *)p) &&
	                  isspace(*(unsigned char *)p))))
	{
		if (*p != '(')
		{
			*uncommented_whitespace = 1;
			p++;
		}
		else
		{
			p = my_mail_matching_paren(p + 1, e, '(', ')');
			if (*p == '\0')
				return MY_MAILPARSE_ERR_PUNBALANCED;
			else
				p++;
		}
	}

	if (p >= e || *p == '\0')
		return 0;

	/* our new token starts here */
	token_start = p;

	/* fill in the token contents and type */
	if (*p == '"')
	{
		token_end = my_mail_matching_paren(p + 1, e, '\0', '"');
		token_type = '"';
		if (*token_end != '\0')
			token_end++;
		else
			err = MY_MAILPARSE_ERR_QUNBALANCED;
	}
	else if (*p == '[')
	{
		token_end = p = my_mail_matching_paren(p + 1, e, '\0', ']');
		token_type = '[';
		if (*token_end != '\0')
			token_end++;
		else
			err = MY_MAILPARSE_ERR_SUNBALANCED;
	}
	else if (CMAP_TST(is_special, *(unsigned char*)p))
	{
		token_end  = p + 1;
		token_type = *p;
	}
	else
	{
		int ch;
		while ((ch = *(unsigned char*)p) != '\0' &&
				!CMAP_TST(is_special, ch) &&
				(!isascii(ch) || !isspace(ch)) &&
				*p != '(')
			++p;

		token_end = p;
		token_type = 'x';
	}

	*start_out = token_start;
	*end_out   = token_end;
	*type_out  = token_type;

	return err;
}

static int end_token(char **cont, char *in)
{
	bool escaped = false, quoted = false;
	int parens = 0, rtc = 0;

	for (char *p = in; ; ++p)
	{
		if (escaped)
		{
			escaped = false;
			continue;
		}

		switch (*p)
		{
		  case '\\':
			escaped = true;
			continue;

		  case '"':
			quoted = !quoted;
			continue;

		  case '(':
			++parens;
			continue;

		  case ')':
			if (--parens < 0)
				rtc = MY_MAILPARSE_ERR_PUNBALANCED;

			continue;

		  case ',':
			if (parens > 0 || quoted)
				continue;

			*cont = ++p;
			return rtc;

		  case '\0':
			if (parens || quoted)
				rtc = parens? MY_MAILPARSE_ERR_PUNBALANCED:
					MY_MAILPARSE_ERR_QUNBALANCED;
			*cont = p;
			return rtc;
		}
	}
}

/*
**  DKIM_MAIL_PARSE_C -- extract the local-part and hostname from a mail
**                       header field, e.g. "From:"
**
**  Parameters:
**  	line -- input line
**  	user_out -- pointer to "local-part" (returned)
**  	domain_out -- pointer to hostname (returned)
**    cont -- continuation point for a further call (returned)
**
**  Return value:
**  	0 on success, or an MY_MAILPARSE_ERR_* on failure.
**
**  Notes:
**  	Input string is modified.
*/

int
my_mail_parse_c(char *entry_line, char **user_out,
                char **domain_out, char **cont)
{
	assert(entry_line);
	assert(user_out);
	assert(domain_out);
	assert(cont);


	*user_out = NULL;
	*domain_out = NULL;

	int type;
	int ws = 0;
	int err = 0;
	char *tok_s, *tok_e;
	char *line = entry_line;
	char *w = line;
	char *e = line + strlen(line);
	bool angle_bracket = false, seen_at = false, ignore_input = false,
		seen_group = false;

	/* non-multithreaded clients don't have to initialize */
	if (inited == 0)
		my_mail_parse_init();

	for (;;)
	{
		err = my_mail_token(line, e, &type, &tok_s, &tok_e, &ws);
		if (err != 0  || type == '\0')
		{
			*w = 0;
			end_token(cont, line);
			if (err == 0)
			{
				if (*domain_out == NULL || **domain_out == 0)
					err = MY_MAILPARSE_ERR_NO_DOMAIN;
				else if (angle_bracket)
					err = MY_MAILPARSE_ERR_ANGLE_BRA;
			}
			return err;
		}

		if (type == '<')
		{
			*user_out = NULL;
			*domain_out = NULL;
			w = entry_line;
			line = tok_s + 1;
			angle_bracket = true;
		}
		else if (type == '>')
		{
			if (angle_bracket)
			{
				*w = '\0';
				err = end_token(cont, tok_e);
				if (err == 0 &&
					(*domain_out == NULL || **domain_out == 0))
						err = MY_MAILPARSE_ERR_NO_DOMAIN;
				return err;
			}
			*user_out = NULL;
			*domain_out = NULL;
			end_token(cont, tok_e);
			return MY_MAILPARSE_ERR_ANGLE_BRA;
		}
		else if (type == ')' || type == ']')
		{
			*user_out = NULL;
			*domain_out = NULL;
			end_token(cont, tok_e);
			return type == ')'? MY_MAILPARSE_ERR_PUNBALANCED:
				MY_MAILPARSE_ERR_SUNBALANCED;
		}
		else if (type == '@')
		{
			if (w > entry_line && !ignore_input) // have user
			{
				if (seen_at)
				{
					*domain_out = NULL;
					end_token(cont, tok_e);
					return MY_MAILPARSE_ERR_MANY_AT;
				}
				*w++ = '\0';
				*domain_out = w;
				seen_at = true;
			}
			else
			/*
			* @example.com must be a source route.
			*/
				ignore_input = true;
		}
		else if (type == ':' || type == ';')
		{
			/* group or source-routing */
			*user_out = NULL;
			*domain_out = NULL;
			w = entry_line;
			ignore_input = false;

			if (!ignore_input) // group
			{
				if (type == ':')
					seen_group = true;
				else if (seen_group)
					seen_group = false;
				else // lone ';'
				{
					end_token(cont, tok_e);
					return MY_MAILPARSE_ERR_SEMICOL;
				}
			}
		}
		else if (type == '\\')
		{
			if (!ignore_input)
			{
				if (*user_out == NULL)
					*user_out = w;
				int ch = *(unsigned char*)tok_e++;
				do
				{
					*w++ = ch;
					ch = *(unsigned char*)tok_e++;
				} while ((ch & 0xc0) == 0x80);
				--tok_e;
			}
		}
		else if (type == ',')
		{
			*w = 0;
			*cont = tok_e;
			return 	(*domain_out == NULL || **domain_out == 0)?
				MY_MAILPARSE_ERR_NO_DOMAIN: 0;
		}
		else if (type == '[')
		{
			if (*domain_out == w && !ignore_input)
			{
				int i_type, nu;
				char *i_tok_s, *i_tok_e;

				++tok_s;
				*w++ = '[';
				for (;;)
				{
					err = my_mail_token(tok_s, tok_e, &i_type, &i_tok_s, &i_tok_e, &nu);
					if (err == 0 && (i_type == 'x' || i_type == ':' || i_type == ']'))
					{
						if (i_type == 'x')
						{
							memmove(w, i_tok_s, i_tok_e - i_tok_s);
							w += i_tok_e - i_tok_s;
						}
						else if (i_type == ':')
							*w++ = ':';
						else
						{
							assert(i_type == ']');
							break;
						}
						tok_s = i_tok_e;
					}
					else
					{
						*domain_out = NULL;
						end_token(cont, line);
						return MY_MAILPARSE_ERR_BAD_LITERAL;
					}
				}
				*w++ = ']';
			}
			else
			{
				*user_out = NULL;
				*domain_out = NULL;
				end_token(cont, line);
				return MY_MAILPARSE_ERR_BAD_LITERAL;
			}
		}
		else if (!ignore_input)
		{
			bool local_part = false;
			if (type == '"') // remove quotes
			{
				++tok_s;
				--tok_e;
			}
			if (*user_out == NULL)
			{
				*user_out = w;
				local_part = true;
			}
			memmove(w, tok_s, tok_e - tok_s);
			w += tok_e - tok_s;
			if (type == '"') // restore token
			{
				++tok_e;
				if (local_part)
					*w++ = 0; // in case local part is empty
			}
		}
		line = tok_e;
	}
}

/*
**  DKIM_MAIL_PARSE -- compatibility function, see my_mail_parse_c
**
**  Parameters:
**  	line -- input line
**  	user_out -- pointer to "local-part" (returned)
**  	domain_out -- pointer to hostname (returned)
**
**  Return value:
**  	0 on success, or an MY_MAILPARSE_ERR_* on failure.
**
**  Notes:
**    Don't use this function, use the new one instead.
**  	Input string is modified.
*/

int
my_mail_parse(char *line, char **user_out, char **domain_out)
{
	assert(line);
	assert(user_out);
	assert(domain_out);

	char *nu;
	return my_mail_parse_c(line, user_out, domain_out, &nu);
}


#ifdef TEST_MAIN

#define MAX_CONT_ARRAY 3 // cannot be flexible?
static const struct addr_test
{
	char const *src; // the string to test
	int nres;        // number of results expected
	struct addr_test_result
	{
		char const *user;
		char const *domain;
		int rtc;
	} res[MAX_CONT_ARRAY];
} addr_test[] =
{
	/*
	* NOTES:
	* When an error is returned, user and domain are what they are.
	* Address literals are not checked to be valid IPv4 or IPv6.
	* Domain names are not checked for validity.
	* Local-part starting with '.' or with consecutive 's's are allowed.
	* Escaping backslashes are allowed also outside of quoted strings.
	*/
	{"user@example.com", 1, {{"user", "example.com", MY_MAILPARSE_OK}}},
	{".user@example.com", 1, {{".user", "example.com", MY_MAILPARSE_OK}}}, // bad
	{".us..er@example.com", 1, {{".us..er", "example.com", MY_MAILPARSE_OK}}}, // bad
	{";user@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"us;er@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"user;@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"user@;example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"user@example;com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"user@example.com;", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <;user@example.com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <us;er@example.com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <user;@example.com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <user@;example.com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <user@example;com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <user@example.com;", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SEMICOL}}},
	{"U. Ser <user@example.com", 1, {{"user", "example.com", MY_MAILPARSE_ERR_ANGLE_BRA}}},
	{"[user]@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"us[er]@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"U.S. <us[er]@example.com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"user]@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SUNBALANCED}}},
	{"U.S. <user]@example.com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_SUNBALANCED}}},
	{"user@[]example.com", 1, {{"user", "[]example.com", MY_MAILPARSE_OK}}},  // bad
	{"U.S. <user@[]example.com>", 1, {{"user", "[]example.com", MY_MAILPARSE_OK}}},  //bad
	{"user@example.[]com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"U.S. <user@example.[]com>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"user@example.com[]", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"U.S. <user@example.com[]>", 1, {{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"U.S. <user@example.com> []", 1, {{"user", "example.com", MY_MAILPARSE_OK}}}, // ?
	{"\"user@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_QUNBALANCED}}},
	{"\"user\\\"@example.com", 1, {{NULL, NULL, MY_MAILPARSE_ERR_QUNBALANCED}}},
	{"\"\"\"@example.com", 1, {{"", NULL, MY_MAILPARSE_ERR_QUNBALANCED}}},
	{"\"\"@example.com", 1, {{"", "example.com", MY_MAILPARSE_OK}}},
	{"Empty local part <\"\"@example.com>", 1, {{"", "example.com", MY_MAILPARSE_OK}}},
	{"\"\"@ , \"\" , @", 3, {{"", "", MY_MAILPARSE_ERR_NO_DOMAIN},
		{"", NULL, MY_MAILPARSE_ERR_NO_DOMAIN}, {NULL, NULL, MY_MAILPARSE_ERR_NO_DOMAIN}}},
	{"user@example@example.com, user (without @), The <user (without @)>", 3, {{"user", NULL, MY_MAILPARSE_ERR_MANY_AT},
		{"user", NULL, MY_MAILPARSE_ERR_NO_DOMAIN}, {"user", NULL, MY_MAILPARSE_ERR_NO_DOMAIN}}},
	{"user@@example.com, user (with trailing @)@, The <user (without @)>@", 3, {{"user", NULL, MY_MAILPARSE_ERR_MANY_AT},
		{"user", "", MY_MAILPARSE_ERR_NO_DOMAIN}, {"user", NULL, MY_MAILPARSE_ERR_NO_DOMAIN}}},
	{"@1.example @2.example: user@example.com", 1, {{"user", "example.com", MY_MAILPARSE_OK}}},
	{"a@b.c,d@e.f,g@h.i", 3, {{"a", "b.c", MY_MAILPARSE_OK}, {"d", "e.f", MY_MAILPARSE_OK},
		{"g", "h.i", MY_MAILPARSE_OK}}},
	{"\"I have spaces\"@example.com", 1, {{"I have spaces", "example.com", MY_MAILPARSE_OK}}},
	{"\"I have  two  spaces\"@example.com", 1, {{"I have  two  spaces", "example.com", MY_MAILPARSE_OK}}},
	{"To: user@example.com", 1, {{"user", "example.com", MY_MAILPARSE_OK}}},
	{"To: U. Ser <user@example.com>", 1, {{"user", "example.com", MY_MAILPARSE_OK}}},
	{"To: U. Ser <user@example.com> not continued", 1, {{"user", "example.com", MY_MAILPARSE_OK}}}, // ?
	{"To: U\" Ser <user@example.com> not continued", 1, {{"U", NULL, MY_MAILPARSE_ERR_QUNBALANCED}}},
	{"To: \"someone@example.org\" <user@example.com>", 1, {{"user", "example.com", MY_MAILPARSE_OK}}},
	{"To: someone\\@example.org <user@example.com>", 1, {{"user", "example.com", MY_MAILPARSE_OK}}},
	{"Bcc: User with a comma <user\\,@example.com>", 1, {{"user,", "example.com", MY_MAILPARSE_OK}}},
	{"Bcc: User with a comma <\"user,\"@example.com>", 1, {{"user,", "example.com", MY_MAILPARSE_OK}}},
	{"Bcc: User with inner comma <us\\,er@example.com>", 1, {{"us,er", "example.com", MY_MAILPARSE_OK}}},
	{"Bcc: User with inner comma <\"us,er\"@example.com>", 1, {{"us,er", "example.com", MY_MAILPARSE_OK}}},
	{"Bcc: User with leading comma <\\,user@example.com>", 1, {{",user", "example.com", MY_MAILPARSE_OK}}},
	{"Bcc: User with leading comma <\",user\"@example.com>", 1, {{",user", "example.com", MY_MAILPARSE_OK}}},
	{"user\\,@example.com", 1, {{"user,", "example.com", MY_MAILPARSE_OK}}},
	{"From: final.comma@example.org ,", 1, {{"final.comma", "example.org", MY_MAILPARSE_OK},
		{NULL, NULL, MY_MAILPARSE_OK}}},
	{"From: final.comma@example.org , ", 2, {{"final.comma", "example.org", MY_MAILPARSE_OK},
		{NULL, NULL, MY_MAILPARSE_ERR_NO_DOMAIN}}},
	{"From: first@example.org , second@example.com", 2, {{"first", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: \"first,last\"@example.org , second(is it?\n)@example.com", 2, {{"first,last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: \"first.last\"@example.org , second@example.com", 2, {{"first.last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: first.last@example.org , second@example.com", 2, {{"first.last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: first\\,last@example.org , second@example.com", 2, {{"first,last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: first\\@last@example.org , second@example.com", 2, {{"first@last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: \"first@last\"@example.org , second@example.com", 2, {{"first@last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"first\\@last@example.org,second@example.com", 2, {{"first@last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"first\\\\last@example.org,second@example.com", 2, {{"first\\last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"\"first\\last\"@example.org,second@example.com", 2, {{"first\\last", "example.org", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"first\\@last@>example.org,second@example.com", 2, {{NULL, NULL, MY_MAILPARSE_ERR_ANGLE_BRA},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: \"(me)\"@example.net, second@example.com", 2, {{"(me)", "example.net", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: \\(m(the em)e\\)@example.net, second@example.com", 2, {{"(me)", "example.net", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"From: \"<me>\"@example.net, [second]s@example.com", 2, {{"<me>", "example.net", MY_MAILPARSE_OK},
		{NULL, NULL, MY_MAILPARSE_ERR_BAD_LITERAL}}},
	{"\\用(useless to escape)戶@example.net, second@example.com", 2, {{"用戶", "example.net", MY_MAILPARSE_OK},
		{"second", "example.com", MY_MAILPARSE_OK}}},
	{"\\用(never closed戶@example.net, second@example.com", 1, {{"用", NULL, MY_MAILPARSE_ERR_PUNBALANCED}}},
	{"\\用never opened)戶@example.net, second@[(the ip address) 192.0.2.30]", 2, {{NULL, NULL, MY_MAILPARSE_ERR_PUNBALANCED},
		{"second", "[192.0.2.30]", MY_MAILPARSE_OK}}},
	{"mimì@foà.example, second@[2001:db8::1]", 2, {{"mimì", "foà.example", MY_MAILPARSE_OK},
		{"second", "[2001:db8::1]", MY_MAILPARSE_OK}}},
	{"first@[2001:db8::1], second@[IPv6:2001:db8::1], third@[in fact: anything would do]", 3, {{"first", "[2001:db8::1]", MY_MAILPARSE_OK},
		{"second", "[IPv6:2001:db8::1]", MY_MAILPARSE_OK}, {"third", "[infact:anythingwoulddo]", MY_MAILPARSE_OK}}}, // bad

	// rfc5322 appendix-A.1.2, A.1.3
	{"From: \"Joe Q. Public\" <john.q.public@example.com>", 1, {{"john.q.public", "example.com", MY_MAILPARSE_OK}}},
	{"To: Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>", 3, {{ "mary", "x.test", MY_MAILPARSE_OK},
		{"jdoe", "example.org", MY_MAILPARSE_OK}, {"one", "y.test", MY_MAILPARSE_OK}}},
	{"Cc: <boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>", 2, {{"boss", "nil.test", MY_MAILPARSE_OK},
		{"sysservices", "example.net", MY_MAILPARSE_OK}}},
	{"To: A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;", 3, {{"c", "a.test", MY_MAILPARSE_OK},
		{"joe", "where.test", MY_MAILPARSE_OK}, {"jdoe", "one.test", MY_MAILPARSE_OK}}},
	{"Cc: Undisclosed recipients:;", 1, {{ NULL, NULL, MY_MAILPARSE_ERR_NO_DOMAIN}}},

	// rfc3696 section 3, discarding errata
	{"Abc\\@def@example.com", 1, {{"Abc@def", "example.com", MY_MAILPARSE_OK}}},
	{"Fred\\ Bloggs@example.com", 1, {{"Fred Bloggs", "example.com", MY_MAILPARSE_OK}}},
	{"Joe.\\\\Blow@example.com", 1, {{"Joe.\\Blow", "example.com", MY_MAILPARSE_OK}}},
	{"\"Abc@def\"@example.com", 1, {{"Abc@def", "example.com", MY_MAILPARSE_OK}}},
	{"\"Fred Bloggs\"@example.com", 1, {{"Fred Bloggs", "example.com", MY_MAILPARSE_OK}}},
	{"user+mailbox@example.com", 1, {{"user+mailbox", "example.com", MY_MAILPARSE_OK}}},
	{"customer/department=shipping@example.com", 1, {{"customer/department=shipping", "example.com", MY_MAILPARSE_OK}}},
	{"$A12345@example.com", 1, {{"$A12345", "example.com", MY_MAILPARSE_OK}}},
	{"!def!xyz%abc@example.com", 1, {{"!def!xyz%abc", "example.com", MY_MAILPARSE_OK}}},
	{"_somename@example.com", 1, {{"_somename", "example.com", MY_MAILPARSE_OK}}},
	{NULL, 0, {{NULL, NULL, 0}}}
};

static int strnullcmp(char const *a, char const *b)
{
	if (a && b) return strcmp(a, b);
	return a != b;
}

static const char* chknull(char const *p)
{
	return p? p: "NULL";
}

static void do_testsuite(void)
{
	int nr = 0;
	for (struct addr_test const *t = &addr_test[0]; t->src; ++t)
	{
		assert(t->nres <= MAX_CONT_ARRAY);

		char *in = strdup(t->src);
		if (in)
		{
			int r = 0;
			char *line = in, *domain, *user, *cont = NULL;
			while (line && *line)
			{
				int rtc = my_mail_parse_c(line, &user, &domain, &cont);
				if (r >= t->nres)
					fprintf(stderr, "test %d/%d fail: extra result %d/%d\n",
						nr + 1, r + 1, r, t->nres);
				else if (rtc != t->res[r].rtc ||
					strnullcmp(user, t->res[r].user) ||
					strnullcmp(domain, t->res[r].domain))
						fprintf(stderr,
							"test %d/%d fail: have %d %s %s, not %d %s %s\n",
							nr + 1, r + 1, rtc, chknull(user), chknull(domain),
							t->res[r].rtc, chknull(t->res[r].user),
								chknull(t->res[r].domain));
				++r;
				line = cont;
			}
			if (r != t->nres)
				fprintf(stderr, "test %d/%d fail: have %d result(s) not %d in %s\n",
					nr + 1, r + 1, r, t->nres, t->src);
			free(in);
		}
		else
			fprintf(stderr, "test %d fail: MEMORY FAULT\n", nr + 1);
		++nr;
	}
}

int main(int argc, char **argv)
{
	int err;
	char *domain, *user, *cont;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s mailheader\n", argv[0]);
		exit(64);
	}
	if (strcmp(argv[1], "testsuite") == 0)
	{
		do_testsuite();
		return 0;
	}

	cont = argv[1];
	while (cont && *cont)
	{
		err = my_mail_parse_c(cont, &user, &domain, &cont);

		if (err)
		{
			printf("error %d\n", err);
			break;
		}
		else
		{
			printf("user: '%s'\ndomain: '%s'\n", 
				user ? my_mail_unescape(user) : "null",
				domain ? my_mail_unescape(domain) : "null");
		}
	}

	return 0;
}
#endif /* TEST_MAIN */
