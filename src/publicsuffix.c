/*
* publicsuffix.c - written by ale in milan on 9 feb 2015
* based on test.c written on 27 jan 2015
* structures and functions for using Mozilla Public Suffix List

Copyright (C) 2015 Alessandro Vesely

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
#include <stdint.h>
#include <search.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// LIBIDN2
#include <iconv.h>
#include <idn2.h>
#include <unicase.h>
#include <unistring/version.h>

#include "parm.h" // for do_report
#include "publicsuffix.h"
#include <assert.h>

static logfun_t do_report = &syslog;

// write a file "debug_tables.h" with a printout of the rules:
// #define DEBUG_PUBLICSUFFIX 1


/*
* This code reuses Bryan McQuade's design of domain-registry-provider, see
* https://code.google.com/p/domain-registry-provider/wiki/DesignDoc
*
* A suffix trie is used to store rules, where each node represents a label
* in a domain name.  Labels are stored in a string table.  Each node holds
* the offset in the string table of the label it represents.  The final nodes
* are stored in two arrays, where the short one is for full nodes.  A full
* node, in addition to the label, holds the array index of its first child,
* the total number of children, and an is_terminal flag.  An element of the
* short array, a trie_node, holds just those extra members.  All the children
* of a given node are stored consecutively (one after another, without gaps)
* after the first child.  Elements of the long array, string_node's, hold
* just the string offset.  Equal indexes of both array semantically refer to
* the same trie node.
*
* Initialization consists of about twice as much lines of code as the runtime
* functions, and it uses more than twelve times as much memory.  Memory used
* at runtime is allocated in one big chunk, while initialization uses small
* amounts allocated as needed and linked into lists.  The corresponding
* structures are defined right before the code which uses them, so that it is
* clear that functions defined earlier don't use them.
*/

static char **
reverse_labels(char *domain, size_t len, char const *extra)
{
	assert(domain);
	assert(strlen(domain) == len);

	// trim trailing and leading dots
	while (len > 0 && domain[len-1] == '.')
		domain[--len] = 0;

	while (len > 0 && *domain == '.')
	{
		++domain;
		--len;
	}

	/*
	Various objects and parameters in the DNS have size limits.  They are
	listed below.  Some could be easily changed, others are more
	fundamental. --RFC 1035

	labels          63 octets or less
	names           255 octets or less
	*/
	if (len == 0 || len > 255)
		return NULL;

	char *labels[128];
	size_t count = 0;
	
	// backward, starting off-string
	char *prev = &domain[len], *s = &domain[len];
	while	(len-- > 0)
	{
		int ch = *(unsigned char*)--s;
		if (isupper(ch))
			*s = tolower(ch);
		else if (!isalnum(ch) && strchr("-_.", ch) == NULL &&
			(extra == NULL || strchr(extra, ch) == NULL))
				return NULL;

		if (ch == '.' || len == 0)
		{
			char *label = s;
			if (ch == '.')
			{
				*s = 0;
				++label;
			}

			size_t l_len = prev - label;
			if (l_len == 0 || l_len > 63)
				return NULL;

			// silly hack, saves about 700 bytes of string table
			if (l_len > 4 && strncmp(label, "xn--", 4) == 0)
			{
				labels[count] = label + 3;
				*labels[count] = '#';
			}
			else
				labels[count] = label;
			++count;
			prev = s;
		}
	}

	char **rtc = malloc(sizeof(char*)*(count + 1));
	if (rtc)
	{
		memcpy(rtc, labels, sizeof(char*) * count);
		rtc[count] = NULL;
	}

	return rtc;
}

// trie nodes, only for the first names
typedef struct trie_node // 4 bytes
{
	unsigned int first_child: 13;
#define MAX_NUM_TRIE_NODES 0x1fffU

	unsigned int num_children: 11;
#define MAX_NUM_CHILDREN 0x7ffU

	unsigned int is_terminal: 1;
	//unsigned int nu: 7;
} trie_node;

// string table entry, for each name
typedef struct string_node
{
	uint16_t n;
} string_node;

/*
* Data structures used to perform the search. Should be
* populated once at startup by a call to publicsuffix_init.
*/
struct publicsuffix_trie
{
	trie_node *node_table; // allocated
	string_node *str;
	char* string_table;

	size_t num_root_nodes, num_trie_nodes;
	size_t num_strings; // total number of string nodes
	time_t old_time;
	off_t old_size;
	char old_fname[];
};

typedef struct bsearch_key
{
	publicsuffix_trie const *pst;
	char const *component;
} bsearch_key;

static int bsearch_cmp(void const *k, void const *el)
{
	bsearch_key const *const key = k;
	register char const *a = key->component;
	string_node const *const str = el;
	register char const *b = key->pst->string_table + str->n;

	register int c, d, r;
	do c = *a++, d = *b++;
	while (c && d && (r = c - d) == 0);

	return c - d;
}

static string_node *find_node(publicsuffix_trie const *pst,
	char *component, string_node *parent)
{
	assert(pst);
	assert(component);
	assert(parent == NULL ||
		(parent >= pst->str && parent - pst->str < (int)pst->num_strings));

	bsearch_key key;
	key.pst = pst;
	key.component = component;

	string_node *base;
	size_t size;
	if (parent == NULL)
	{
		base = pst->str;
		size = pst->num_root_nodes;
	}
	else if ((size = parent - pst->str) < pst->num_trie_nodes)
	{
		trie_node const *const node = &pst->node_table[size];
		base = &pst->str[node->first_child];
		size = node->num_children;
	}
	else
		return NULL;

	string_node *current =
		bsearch(&key, base, size, sizeof(string_node), bsearch_cmp);
	if (current)
		return current;

	/*
	* We didn't find an exact match, so see if there's a wildcard
	* match.  From https://publicsuffix.org/list/: "The wildcard
	* character * (asterisk) matches any valid sequence of characters
	* in a hostname part. (Note: the list uses Unicode, not Punycode
	* forms, and is encoded using UTF-8.) Wildcards may only be used to
	* wildcard an entire level. That is, they must be surrounded by
	* dots (or implicit dots, at the beginning of a line)."
	*/
	key.component = "*";
	current = bsearch(&key, base, size, sizeof(string_node), bsearch_cmp);
	if (current)
	/*
	* If there was a wildcard match, see if there is a wildcard
	* exception match, and prefer it if so.  From
	* https://publicsuffix.org/list/: "An exclamation mark (!) at
	* the start of a rule marks an exception to a previous wildcard
	* rule. An exception rule takes priority over any other matching
	* rule."
	*/
	{
		char exception_component[68];
		exception_component[0] = '!';
		strcpy(&exception_component[1], component);
		key.component = exception_component;
		string_node *exception =
			bsearch(&key, base, size, sizeof(string_node), bsearch_cmp);
		if (exception)
			current = exception;
	}

	return current;
}

char *org_domain(publicsuffix_trie const *pst, char const *c_domain)
/*
* c_domain must be ascii
*/
{
	char *domain = c_domain? strdup(c_domain): NULL;
	if (domain == NULL)
		return NULL;

	char *org = NULL;
	size_t len = strlen(domain);
	char **labels = reverse_labels(domain, len, NULL);

	if (labels)
	{
		char **last_valid = NULL;
		string_node *current = NULL;
		for (char **l = labels; *l; ++l)
		{
			current = find_node(pst, *l, current);
			if (current == NULL)
				break;

			unsigned int const ndx = current - pst->str;
			if (ndx >= pst->num_trie_nodes || pst->node_table[ndx].is_terminal)
			{
				last_valid = l;
				if (ndx >= pst->num_trie_nodes)
					break;
			}
			else
				last_valid = NULL;
		}

		if (last_valid == NULL)
		{
			free(domain);
			free(labels);
			return NULL; // not listed
		}

		int const exception = current && pst->string_table[current->n] == '!';

		if (!exception)
		{
			if (last_valid[1])
				++last_valid;
			else if (current)
			{
				free(domain);
				free(labels);
				return NULL; // listed, but missing an org domain
			}
		}

		len = 0;
		for (char **l = labels; ; ++l)
		{
			len += strlen(*l) + 1;
			if (**l == '#')
				len += 3;
			if (l == last_valid)
				break;
		}
		org = malloc(len);
		if (org)
		{
			*org = 0;
			for (char **l = last_valid; ; --l)
			{
				if (**l == '#')
				{
					strcat(org, "xn--");
					*l += 1;
				}
				strcat(org,  *l);
				if (l == labels)
					break;

				strcat(org, ".");
			}
		}
		free(labels);
	}
	free(domain);
	return org;
}

// ----- read rules -----

typedef struct loose_label
{
	struct loose_label *next;
	uint16_t n; // offset in the string table
	char label[];
} loose_label;

typedef struct loose_trie
{
	struct loose_trie *next, *child, *parent;
	size_t num_children;
	uint16_t n; // offset of corresponding trie_node/ string_node
	unsigned int is_terminal: 1;
	unsigned int is_string: 1;
	unsigned int is_first_child: 1;
	unsigned int nu: 4;
	unsigned int u_is_ll: 1;
	union
	{
		loose_label *ll;
		char label[sizeof(loose_label*)];
	} u;
} loose_trie;

typedef struct loose_init
{
	FILE *fp; // debug output
	publicsuffix_trie *pst;
	loose_label *string_loose;
	loose_trie *boundary;
	void *reserve;
	size_t string_size, max_num_children;
	size_t num_strings; // number of string_loose
	uint16_t next_str, next_node;
} loose_init;

static loose_trie *add_trie_node(loose_trie **prev, char const *label)
{
	assert(prev);
	assert(label);

	loose_trie *p;
	int cmp;

	while ((p = *prev) != NULL && (cmp = strcmp(p->u.label, label)) < 0)
		prev = &p->next;

	if (p && cmp == 0)
		return p;

	size_t len = strlen(label) + 1;
	len -= len >= sizeof p->u.label? sizeof p->u.label: len;
	loose_trie *pn = calloc(1, sizeof *p + len);
	if (pn)
	{
		pn->next = p;
		*prev = pn;
		strcpy(pn->u.label, label);
	}

	return pn;
}

typedef int (*w_traverse_cb)(loose_trie*, void *, int);
typedef enum {w_traverse_head, w_traverse_tail} w_traverse_mode;

static int
w_traverse(loose_trie *parent, w_traverse_mode mode,
	w_traverse_cb cb, void *cb_arg, int depth)
{
	assert(cb);

	loose_trie *t = parent;
	int rtc = 0;

	while (t)
	{
		if (mode == w_traverse_head &&
			(rtc = (*cb)(t, cb_arg, depth)) < 0)
				return rtc;
		t = t->next;
	}

	t = parent;
	while (t)
	{
		if (t->child &&
			(rtc = w_traverse(t->child, mode, cb, cb_arg, depth + 1)) < 0)
				return rtc;

		loose_trie *next = t->next;
		if (mode != w_traverse_head &&
			(rtc = (*cb)(t, cb_arg, depth)) < 0)
				return rtc;

		t = next;
	}

	return rtc;
}

static int read_rules(FILE *fp, char const *fname, loose_trie **root)
/*
* populate the root node with all rules.
* return number of bad lines, or -1 if out of memory
*/
{
	char buf[512];
	char *s;
	int lineno = 0, bad = 0;

	while ((s = fgets(buf, sizeof buf, fp)) != NULL)
	{
		++lineno;
		if (s[0] == '/' && s[1] == '/')
			continue;

		int is_ascii = 1;
		int ch;
		while ((ch = *(unsigned char *)s++) != 0)
		{
			if (ch & 0x80) // utf-8, check it is a valid sequence
			{
				int m = 0x40;
				is_ascii = (ch & m) != 0? 0: -1;
				while ((ch & m) != 0 && is_ascii == 0)
				{
					is_ascii = (*(unsigned char*)s++ & 0xc0) == 0x80? 0: -1;
					m >>= 1;
				}
				continue;
			}

			if (isspace(ch)) // end of rule
			{
				*--s = 0;
				break;
			}
		}

		if (ch == 0)
		{
			(*do_report)(LOG_CRIT, "Line too long at %s:%d: \"%.10s...\"",
				fname, lineno, buf);
			++bad;
			while ((ch = fgetc(fp)) != '\n' && ch != EOF)
				;
			continue;
		}

		assert(*s == 0);

		size_t len = s - &buf[0];
		if (len == 0) // empty line
			continue;

		if (!is_ascii)
		{
			if (is_ascii < 0)
			{
				(*do_report)(LOG_CRIT, "Bad UTF-8 sequence at %s:%d: \"%s\"",
					fname, lineno, buf);
				++bad;
				continue;
			}

			uint8_t norm[128];
			size_t ulen = sizeof norm - 1;
			uint8_t* n = u8_tolower((uint8_t*)buf, len, NULL, UNINORM_NFC, norm, &ulen);
			if (n != &norm[0])
			{
				(*do_report)(LOG_CRIT, "Failed u8_tolower at %s:%d: %s, len = %zu for \"%s\"",
					fname, lineno, strerror(errno), ulen, buf);
				free(n);
				++bad;
				continue;
			}

			n[ulen] = 0;

			uint8_t *xn = NULL;
			int rtc = idn2_lookup_u8(n, &xn, 0);
			if (rtc != IDN2_OK || xn == NULL || (len = strlen((char*)xn)) >= sizeof buf)
			{
				(*do_report)(LOG_CRIT, "IDNA failed at %s:%d: %s for \"%s\"",
					fname, lineno, idn2_strerror_name(rtc), buf);
				++bad;
				continue;
			}

			memcpy(buf, xn, len);
			idn2_free(xn);
			buf[len] = 0;
		}

		char **labels = reverse_labels(buf, len, "!*");
		if (labels == NULL)
		{
			(*do_report)(LOG_CRIT, "Invalid domain at %s:%d for \"%s\"",
				fname, lineno, buf);
			++bad;
			continue;
		}

		loose_trie *node = add_trie_node(root, *labels);
		for (size_t i = 1; labels[i] && node; ++i)
			node = add_trie_node(&node->child, labels[i]);

		free(labels);
		if (node == NULL) // out of memory
			return -1;

		node->is_terminal = 1;
	}

	return bad;
}

static int wt_free(loose_trie* t, void *v, int depth)
{
	assert(t);

	free(t);
	return 0;

	(void)v; (void)depth;
}

static int wt_step1(loose_trie* t, void *v, int depth)
{
	assert(t);
	assert(v);
	assert(t->u_is_ll == 0);

	loose_init *ini = v;
	publicsuffix_trie *pst = ini->pst;

	// there is string node (a.k.a. leaf node) for each element,
	// num_trie_nodes is also increased, but later decreased.
	pst->num_strings += 1;
	pst->num_trie_nodes += 1;
	pst->num_root_nodes += depth == 0;

	if (t->child)
	{
		t->child->is_first_child = 1;

		size_t num_children = 0, leaf_children = 0;
		for (loose_trie *p = t->child; p; p = p->next)
		{
			++num_children;
			p->parent = t;
			if (p->child == NULL)
				++leaf_children;
		}
		if (num_children > ini->max_num_children)
			ini->max_num_children = num_children;

		t->num_children = num_children;

		// when all children are leaves, they don't have to be full nodes:
		// decrease num_trie_nodes accordingly
		if (num_children == leaf_children)
		{
			pst->num_trie_nodes -= num_children;
			for (loose_trie *p = t->child; p; p = p->next)
				p->is_string = 1;
		}
	}

	// insert a loose_label element and move the label string there.
	char const* const label = t->u.label;
	size_t len = strlen(label);

	loose_label **ll = &ini->string_loose, *l;
	int cmp;
	while ((l = *ll) != NULL && (cmp = strcmp(l->label, label)) < 0)
		ll = &l->next;

	if (l == NULL || cmp > 0)
	{
		loose_label *ln = malloc(len + 1 + sizeof(loose_label));
		if (ln == NULL)
			return -1;

		++ini->num_strings;
		ini->string_size += len + 1;
		strcpy(ln->label, label);
		ln->next = l;
		*ll = l = ln;
	}

	t->u_is_ll = 1;
	t->u.ll = l;
	return 0;
}

#if DEBUG_PUBLICSUFFIX
static int wt_print(loose_trie* t, void *v, int depth)
{
	assert(t);
	loose_init *ini = v;
	assert(ini && ini->fp);

	fprintf(ini->fp, "%2d  %-7s ",
		depth, t->is_string? "string": "full");

	int len = 0;
	for (loose_trie *p = t; p; p = p->parent)
		len += fprintf(ini->fp, "%s%s", len? ".": "",
			p->u_is_ll? p->u.ll->label: p->u.label);

	if (t->child)
		fprintf(ini->fp, "%*zu -> %s%s",
			len < 40? 40 - len: 4, t->num_children,
			t->child->u_is_ll? t->child->u.ll->label: t->child->u.label,
			t->num_children > 1? ", ...": "");
	fputc('\n', ini->fp);

	return 0;
}
#endif //DEBUG_PUBLICSUFFIX

static int wt_step2(loose_trie* t, void *v, int depth)
// write full nodes except first_child
{
	assert(t);
	assert(v);
	assert(t->u_is_ll == 1);
	assert(depth == 0 || t->parent != NULL);  // non-root nodes have a parent
	assert(t->is_string == 0 || depth > 0);  // leaf nodes are non-root

	loose_init *ini = v;
	publicsuffix_trie *pst = ini->pst;

	if (t->is_string == 0) // full node
	{
		uint16_t n = ini->next_node++;

		// trie part
		trie_node *node = &pst->node_table[n];
		memset(node, 0, sizeof *node);
		node->num_children = t->num_children;
		node->is_terminal = t->is_terminal;

		// string part
		pst->str[n].n = t->u.ll->n;
		t->n = n;
	}

	return 0;
}

static int wt_step3(loose_trie* t, void *v, int depth)
// write leaf nodes and first_child
{
	assert(t);
	assert(v);
	assert(t->u_is_ll == 1);
	assert(depth == 0 || t->parent != NULL);
	assert(t->is_first_child == 0 || depth > 0);

	loose_init *ini = v;
	publicsuffix_trie *pst = ini->pst;

	if (t->is_string == 1) // leaf node
	{
		uint16_t n = ini->next_node++;
		pst->str[n].n = t->u.ll->n;
		t->n = n;
	}

	if (t->is_first_child)
	{
		trie_node *parent = &pst->node_table[t->parent->n];
		parent->first_child = t->n;
	}

	return 0;
}

void publicsuffix_done(publicsuffix_trie *pst)
{
	if (pst)
	{
		free(pst->node_table);
		free(pst);
	}
}

publicsuffix_trie *publicsuffix_init(char const *fname, publicsuffix_trie *old)
/*
* If old is given, check if it needs an update and return immediately if not.
* If an update is needed, do the initialization and free the old structure
* before allocating the final chunk of memory --at that point initialization
* cannot fail but for malloc.
* If old is not given, use the file size as an estimate of the final chunk size
* and allocate it before starting initialization.  That way, the final heap
* should be shrinkable.
*/
{
	assert(fname);

	do_report = set_parm_logfun(NULL);  // use that logging function

	if (_LIBUNISTRING_VERSION != _libunistring_version) // (major<<8) + minor
		(*do_report)(LOG_WARNING,
			"unistring version mismatch, expecting %d, have %d",
			_LIBUNISTRING_VERSION, _libunistring_version);
	if (!idn2_check_version(IDN2_VERSION))
	{
		(*do_report)(LOG_WARNING,
			"IDN2 version mismatch, expecting %s", IDN2_VERSION);
	}

	struct stat stat_dat;
	int rtc = stat(fname, &stat_dat);
	if (rtc)
		(*do_report)(LOG_CRIT, "cannot stat %s: %s", fname, strerror(errno));
	else if (old && old->old_time == stat_dat.st_mtime &&
		old->old_size == stat_dat.st_size && strcmp(fname, old->old_fname) == 0)
	{
		(*do_report)(LOG_INFO, "%s not changed", fname);
		rtc = 1;
	}

	if (rtc)
		return old;

	publicsuffix_trie *pst = NULL;
	FILE *fp = fopen(fname, "r");
	if (fp)
	{
		pst = calloc(1, sizeof *pst + strlen(fname) + 1);
		if (pst)
		{
			pst->old_time = stat_dat.st_mtime;
			pst->old_size = stat_dat.st_size;
			strcpy(pst->old_fname, fname);

			loose_init ini;
			memset(&ini, 0, sizeof ini);
			ini.pst = pst;
			if (old == NULL)
				ini.reserve = malloc(stat_dat.st_size);

			loose_trie *root = NULL;
			rtc = read_rules(fp, fname, &root) < 0;
			if (rtc == 0)
			{

				rtc = w_traverse(root, w_traverse_head, wt_step1, &ini, 0);
				if (rtc == 0 &&
					(pst->num_trie_nodes > MAX_NUM_TRIE_NODES ||
					ini.max_num_children > MAX_NUM_CHILDREN ||
					pst->num_strings > UINT16_MAX))
				{
					if (pst->num_trie_nodes > MAX_NUM_TRIE_NODES)
						(*do_report)(LOG_CRIT, "Too many trie nodes %zu, max %u",
							pst->num_trie_nodes, MAX_NUM_TRIE_NODES);
					if (ini.max_num_children > MAX_NUM_CHILDREN)
						(*do_report)(LOG_CRIT, "Too many child nodes %zu, max %u",
							ini.max_num_children, MAX_NUM_CHILDREN);
					if (pst->num_strings > UINT16_MAX)
						(*do_report)(LOG_CRIT, "Too many string nodes %zu, max %u",
							pst->num_strings, UINT16_MAX);
					rtc = -1;
				}
			}

			if (rtc == 0)
			{
				size_t const tot_alloc =
					pst->num_trie_nodes * sizeof(trie_node) +
					pst->num_strings * sizeof(string_node) +
					ini.string_size;

#if DEBUG_PUBLICSUFFIX
				ini.fp = fopen("debug_tables.h", "w");
				if (ini.fp)
				{
					fprintf(ini.fp,
						"/* Size of kStringTable %zu */\n"
						"/* Size of kNodeTable %zu of size %zu */\n"
						"/* Size of kLeafNodeTable %zu of size %zu */\n"
						"/* Total size %zu bytes */\n\n",
							ini.string_size,
							pst->num_trie_nodes, sizeof(trie_node),
							pst->num_strings - pst->num_trie_nodes,
							sizeof(string_node),
							tot_alloc);
					fprintf(ini.fp,
						"%zu root nodes\n"
						"%zu trie nodes (max=%u)\n"
						"%zu total string nodes (max=%u)\n"
						"%zu max children (max=%u)\n",
						pst->num_root_nodes,
						pst->num_trie_nodes, MAX_NUM_TRIE_NODES,
						pst->num_strings, UINT16_MAX,
						ini.max_num_children, MAX_NUM_CHILDREN);
					fprintf(ini.fp, "%zu num strings in string table\n\n",
						ini.num_strings);

					fputs("Strings:\n", ini.fp);
					for (loose_label *ll = ini.string_loose; ll; ll= ll->next)
					{
						size_t len = strlen(ll->label);
						fprintf(ini.fp, " \"%s\\0\" %*s/*%3zu */\n",
							ll->label, (int)(len < 40? 40 - len: 0), "", len + 1);
					}

					fputs("\nNodes:\n", ini.fp);
					w_traverse(root, w_traverse_head, wt_print, &ini, 0);
					fclose(ini.fp);
					ini.fp = NULL;
				}
#endif // DEBUG_PUBLICSUFFIX

				free(ini.reserve);
				ini.reserve = NULL;
				publicsuffix_done(old);
				old = NULL;
				pst->node_table = malloc(tot_alloc);
				if (pst->node_table)
				{
					pst->str = (string_node*)
						(pst->node_table + pst->num_trie_nodes);
					pst->string_table = (char*) (pst->str + pst->num_strings);

					// copy all labels in the string table;
					uint16_t n = 0;
					char *const st = pst->string_table;
					for (loose_label *ll = ini.string_loose; ll; ll= ll->next)
					{
						size_t const len = strlen(ll->label) + 1;
						memcpy(&st[n], ll->label, len);
						ll->n = n;
						n += len;
					}

					// step2 and step 3 cannot fail
					w_traverse(root, w_traverse_head, wt_step2, &ini, 0);
					w_traverse(root, w_traverse_head, wt_step3, &ini, 0);
				}
				else rtc = -1;
			}

			for (loose_label *ll = ini.string_loose; ll;)
			{
				loose_label *tmp = ll->next;
				free(ll);
				ll = tmp;
			}
			w_traverse(root, w_traverse_tail, wt_free, NULL, 0);
			free(ini.reserve);
			if (rtc)
			{
				free(pst->node_table);
				free(pst);
				pst = old;
				(*do_report)(LOG_CRIT, "Cannot init publicsuffix%s",
					pst? " (old data retained)": "");
			}
		}
		fclose(fp);
	}
	else // fopen failure
	{
		pst = old;
		(*do_report)(LOG_CRIT, "cannot read %s: %s%s",
			fname, strerror(errno), pst? " (old data retained)": "");
	}

	return pst;
}

#if defined TEST_MAIN
#include <stdarg.h>

static void stdalone_reporting(int nu, char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	(void)nu;
}

logfun_t set_parm_logfun(logfun_t nu)
{
	return stdalone_reporting;
	(void)nu;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
	{
		publicsuffix_trie *pst = publicsuffix_init(argv[1], NULL);
		if (pst)
		{
			for (int i = 2; i < argc; ++i)
			{
				char *od = org_domain(pst, argv[i]);
				printf("%s -> %s\n", argv[i], od? od: "null");
				free(od);
			}
			publicsuffix_done(pst);
		}
	}
	else fprintf(stderr, "usage: %s rule-file domain...\n", argv[0]);

	return 0;
}
#endif // TEST_MAIN
