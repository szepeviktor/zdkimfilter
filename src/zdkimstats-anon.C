/*
** zdkimstats-anon.C - written in milano by vesely on 10sep2010
** filter stats from stdin to stdout

This file can be compiled standalone, e.g. as

   g++ -I. -o foo -DCONVERT_TO_LOWERCASE -DPACKAGE_VERSION="\"$(date)\"" \
   	zdkimstats-anon.C -lssl

if OpenDKIMstats.h is in the same directory.

See http://www.tana.it/sw/zdkimfilter/ for more info.
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
with software developed by The OpenDKIM Project and its contributors,
containing parts covered by the applicable licence, the licensor or
zdkimfilter grants you additional permission to convey the resulting work.
*/
#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#if !ZDKIMFILTER_DEBUG
#define NDEBUG
#endif
#if !defined PACKAGE_NAME
#define PACKAGE_NAME "standalone"
#endif
#if !defined PACKAGE_VERSION
#define PACKAGE_VERSION "unknown"
#endif

#include <cstring>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <set>
#include <map>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <openssl/md5.h>
#include <ctime>
#include <OpenDKIMstats.h>

#include <cassert>

using namespace std;
static char *progname;

static string do_digest(char const* prefix, string s)
{
	assert(prefix);

	static const char conv[] = "0123456789abcdef";

	MD5_CTX md5;
	unsigned char dig[MD5_DIGEST_LENGTH];
	char hex[2*MD5_DIGEST_LENGTH + 1], *p;
	
	MD5_Init(&md5);
	MD5_Update(&md5, prefix, strlen(prefix));
	MD5_Update(&md5, s.c_str(), s.size());
	MD5_Final(dig, &md5);
	p = &hex[0];
	for (size_t i = 0; i < sizeof dig; ++i)
	{
		unsigned ch = dig[i];
		*p++ = conv[ch >> 4];
		*p++ = conv[ch & 0xf];
	}
	*p = 0;
	
	return string(hex);
}

static string date_string(time_t date)
{
	char buf[256];
	tm d = *localtime(&date);
	sprintf(buf, "%04d-%02d-%02d",
		d.tm_year + 1900, d.tm_mon + 1, d.tm_mday);
	return string(buf);
}

class count_t
{
public:
	time_t last;
	size_t msgs, sigs, oksigs, bad_bh,
		disca_tot, disca_fail, all_tot, all_fail;
	~count_t() {}
	count_t(): last(0), msgs(0), sigs(0), oksigs(0), bad_bh(0),
		disca_tot(0), disca_fail(0), all_tot(0), all_fail(0) {}
	void add(count_t const& c)
		{ if (c.last > last) last = c.last;
		msgs += c.msgs, sigs += c.sigs, oksigs += c.oksigs, bad_bh += c.bad_bh,
		disca_tot += c.disca_tot, disca_fail += c.disca_fail,
		all_tot += c.all_tot, all_fail += c.all_fail; }
};

static ostream& operator<<(ostream& out, count_t const& count)
{
	if (out.tellp() == 0)
	{
		out << "# one line per log, tab-separated fields are\n"
			"# last date seen in log, followed by the total number of\n"
			"# messages,\n"
			"# signatures,\n"
			"# good signatures,\n"
			"# signatures failed because of body changes,\n"
			"# ADSP \"discardable\" messages,\n"
			"# ADSP \"discardable\" failures,\n"
			"# ADSP \"all\" messages, and\n"
			"# ADSP \"all\" failures.\n"
			"#\n";
	}
	out << date_string(count.last) << '\t' <<
		count.msgs << '\t' <<
		count.sigs << '\t' <<
		count.oksigs << '\t' <<
		count.bad_bh << '\t' <<
		count.disca_tot << '\t' <<
		count.disca_fail << '\t' <<
		count.all_tot << '\t' <<
		count.all_fail << endl;
	return out;
}		

struct a_count { size_t no_sig, fail, good;
	~a_count() {}
	a_count(): no_sig(0), fail(0), good(0) {}
	bool empty() const {return no_sig == 0 && fail == 0 && good == 0;}
	void add(a_count const &c)
		{no_sig += c.no_sig, fail += c.fail, good += c.good;}
};
struct adsp_count { a_count all, disca; };
class adsp_map: public map<string, adsp_count>
{
public:
	time_t last;
	void add(string const& domain, bool discardable, a_count const& c)
	{
		a_count o;
		iterator p = find(domain);
		if (p == end())
		{
			adsp_count a;
			if (discardable) a.all = o, a.disca = c;
			else a.all = c, a.disca = o;
			insert(value_type(domain, a));
		}
		else if (discardable)
			(*p).second.disca.add(c);
		else
			(*p).second.all.add(c);
	}
};

static ostream& operator<<(ostream& out, adsp_map const& adsp)
{
	if (out.tellp() == 0)
	{
		out << "# tab-separated fields are\n"
			"# last date seen in log (YYYY-MM-DD),\n"
			"# type of ADSP: \"all\" or \"dis\" (for \"discardable\")\n"
			"# number of messages with no author domain signature\n"
			"# number of messages with failed author domain signature\n"
			"# number of messages with good author domain signature\n"
			"# \"From:\" domain name,\n"
			"#\n";
	}
	string last = date_string(adsp.last);
	for (adsp_map::const_iterator i = adsp.begin(); i != adsp.end(); ++i)
	{
		string const& domain = (*i).first;
		adsp_count const& ac = (*i).second;
		if (!ac.all.empty())
		{
			out << last << "\tall\t" <<
				ac.all.no_sig << '\t' <<
				ac.all.fail << '\t' <<
				ac.all.good << '\t' <<
				domain << endl;
		}
		if (!ac.disca.empty())
		{
			out << last << "\tdis\t" <<
				ac.disca.no_sig << '\t' <<
				ac.disca.fail << '\t' <<
				ac.disca.good << '\t' <<
				domain << endl;
		}
	}
	return out;
}		

// line of input
//
class stats_line: public vector<string>
{
	bool is_good;
public:	
	~stats_line() {}
	stats_line(): is_good(true) {}
	void clear() { is_good = true; this->vector<string>::clear(); }
	bool good() const {return is_good;}
	bool set_bad() {return is_good = false;}
	bool bool_at(size_type n)
	{
		if (n < size() && at(n).size() == 1)
		{
			int const ch = *at(n).c_str();
			if (ch == '0') return false;
			if (ch == '1') return true;
		}
		return set_bad();
	}
	char const *char_ptr_at(size_type n) const
		{return n < size()? at(n).c_str(): 0;}
};

static ostream& operator<<(ostream& out, stats_line const& sl)
{
	if (!sl.empty())
	{
		stats_line::size_type n = sl.size() - 1, i;
		for (i = 0; i < n; ++i)
			out << sl.at(i) << '\t';
		out << sl.at(i);
	}
	return out;
}		

// set of excluded domains
//
class compare_charp
{
public:
	bool operator()(char const* const& a, char const* const& b) const
		{return strcasecmp(a, b) < 0;}
};

typedef set<char const*, compare_charp> xdomains;

class domain_set // check excluded domain
{
	domain_set();
public:
	xdomains const &xd;
	int ndx;
	domain_set(xdomains const &x, int n): xd(x), ndx(n) {}
	bool operator()(stats_line const& l) const
	{
		char const* const domain = l.char_ptr_at(ndx);
		if (domain == 0) return false;
		xdomains::const_iterator p = xd.find(domain);
		return p != xd.end();
	}
};

// helper class and functions for searching signatures
//
class domain_string // find author signatures
{
	domain_string();
public:
	string const &domain;
	domain_string(string const &d): domain(d) {}
	bool operator()(stats_line const& s) const
		{return s.size() > ODsS_domain && s[ODsS_domain] == domain;}
};

static bool stats_good(stats_line const& s) {return s.good();}
static bool s_pass(stats_line& s) {return s.bool_at(ODsS_pass);}
static bool s_fail_body(stats_line& s) {return s.bool_at(ODsS_fail_body);}

// signatures
//
class stats_signatures: public vector<stats_line>
{
public:
	iterator find_domain(string& d)
		{return find_if(begin(), end(), domain_string(d));}
	bool check()
		{return find_if(begin(), end(), domain_string("-")) == end();}
	bool good() const
		{unsigned const g = count_if(begin(), end(), stats_good);
		return g == size();}
	ptrdiff_t pass() {return count_if(begin(), end(), s_pass);}
	ptrdiff_t fail_body() {return count_if(begin(), end(), s_fail_body);}
	bool signed_by(domain_set const &ds) const
		{return find_if(begin(), end(), ds) != end();}
};

// log entry and related fnctions
//
class stats_t
{
public:
	stats_line m;
	stats_signatures s;
	~stats_t() {};
	stats_t() {};
	bool empty() const {return m.empty();}
	bool good() const {return !empty() && m.good();}
	bool set_bad() {return m.set_bad();}
	void clear() {m.clear(); s.clear();}
	unsigned lines() const {return (empty()? 0: 1) + s.size();}
	bool verify(count_t &count, adsp_map &adsp, bool do_adsp)
	{
		if (good())
		{
			a_count a;
			count_t c;
			c.msgs = 1;
			c.sigs = s.size();
			c.oksigs = s.pass();
			c.bad_bh = s.fail_body();

			bool const adsp_found = m.bool_at(ODsM_adsp_found);
			bool const adsp_unknown = m.bool_at(ODsM_adsp_unknown);
			bool const adsp_all = m.bool_at(ODsM_adsp_all);
			bool const adsp_discardable = m.bool_at(ODsM_adsp_discardable);
			bool const adsp_fail = m.bool_at(ODsM_adsp_fail);

			if (adsp_all)
				c.all_tot = 1;
			else if (adsp_discardable)
				c.disca_tot = 1;

			if (!s.check()) set_bad();

			string fromdomain = m.at(ODsM_fromdomain);
			stats_signatures::iterator f = s.find_domain(fromdomain);
			if (adsp_fail)
			{
				// if there is a signature it must have failed
				if (!adsp_found || !(adsp_all || adsp_discardable) ||
					(adsp_all && adsp_discardable) ||
					(f != s.end() && (*f).bool_at(ODsS_pass)))
						set_bad();
				else if (adsp_all)
					c.all_fail = 1;
				else
					c.disca_fail = 1;
				
				if (f == s.end()) a.no_sig = 1; else a.fail = 1;
			}
			// there must be a signature if it passed
			else if (adsp_all || adsp_discardable)
			{
				if (adsp_unknown || !adsp_found ||
					(adsp_all && adsp_discardable) || 
					f == s.end() || !(*f).bool_at(ODsS_pass) || !(*f).good())
						set_bad();
				a.good = 1;
			}
			/*
			* cannot do
			*
			*   else if (!adsp_unknown) set_bad();
			*
			* because policy might not have been determined due to missing
			* "From" header field.
			*/

			if (!s.good()) set_bad();
			
			char const *d = m.at(ODsM_msgtime).c_str();
			char *t = NULL;
			unsigned long l = strtoul(d, &t, 10);
			if (t && *t == 0)
				c.last = l;
			else
				set_bad();

			if (good())
			{
				count.add(c);
				if (do_adsp)
					adsp.add(fromdomain, adsp_discardable, a);
			}
		}
		return good();
	}
	bool is_anon() const {return *m[ODsM_anon].c_str() == '1';}
	bool has_domain(xdomains &xd) const
	{
		domain_set ds(xd, ODsM_fromdomain);
		if (ds(m))
			return true;
		ds.ndx = ODsS_domain;
		return s.signed_by(ds);
	}
	void anon(char const *prefix)
	{
		assert(prefix);
		m[ODsM_fromdomain] = do_digest(prefix, m[ODsM_fromdomain]);
		if (isdigit(*(unsigned char const*)m[ODsM_ipaddr].c_str())) // !"unnown"
			m[ODsM_ipaddr] = do_digest(prefix, m[ODsM_ipaddr]);
		m[ODsM_anon] = string("1");
		for (stats_signatures::iterator i = s.begin(); i != s.end(); ++i)
			if ((*i).size() > ODsS_domain)
				(*i)[ODsS_domain] = do_digest(prefix, (*i)[ODsS_domain]);
	}
};

static ostream& operator<<(ostream& out, stats_t const& stats)
{
	out << 'M' << stats.m << '\n';
	for (stats_signatures::const_iterator i = stats.s.begin();
		i != stats.s.end(); ++i)
			out << 'S' << *i << '\n';
	return out;
}

static const unsigned int STATS_LINE_MAX = 4096;

static bool strtok_max(stats_line& sl, char const*cl, int count)
{
	static const char tab[] = "\t";
	char buf[STATS_LINE_MAX], *p;
	int ch;
	for (p = buf;
		p < &buf[STATS_LINE_MAX] && (ch = *(unsigned const char*)cl++) != 0;
			++p)
	{
#if defined CONVERT_TO_LOWERCASE
	// converting domain names would suffice...
		*p = (isupper(ch) && isascii(ch))? tolower(ch): ch;
#else
	// zdkimfilter logs are lower case already
		*p = ch;
#endif
	}
	if (p < &buf[STATS_LINE_MAX])
	{
		*p = 0;
		for (p = strtok(buf, tab); p; p = strtok(0, tab))
			if (--count >= 0)
				sl.push_back(string(p));
	}

	return count == 0;
}

static istream& operator>>(istream& in, stats_t& stats)
{
	string buf;
	stats.clear();
	if (in.good())
		getline(in, buf);
	if (!buf.empty())
	{
		char const *line = buf.c_str();
		if (*line != 'M' ||
			buf.size() >= STATS_LINE_MAX ||
			!strtok_max(stats.m, line + 1, ODsM_MAX_FIELDS))
				stats.set_bad();
		else
		{
			unsigned const nsigs = atoi(stats.m[ODsM_nsigs].c_str());
			for (unsigned i = 0; i < nsigs && stats.good() && !in.eof(); ++i)
			{
				getline(in, buf);
				if (!buf.empty())
				{
					line = buf.c_str();
					if (*line == 'S' && buf.size() < STATS_LINE_MAX)
					{
						stats_line ns;
						if (strtok_max(ns, line + 1, ODsS_MAX_FIELDS))
							stats.s.push_back(ns);
						else
							stats.set_bad();
					}
					else
						stats.set_bad();
				}
			}
			if (stats.s.size() != nsigs)
				stats.set_bad();
		}
	}
	
	return in;
}

// main function
//
int main(int argc, char* argv[])
{
	int errs = 0, i;
	char *prefix = NULL, *adsp_fname = NULL, *count_fname = NULL;

	xdomains xd;
	count_t count;
	adsp_map adsp;
	
	if ((progname = strrchr(argv[0], '/')) != NULL)
		++progname;
	else
		progname = argv[0];

	for (i = 1; i < argc; ++i)
	{
		char *const arg = argv[i];
		
		if (strcmp(arg, "-p") == 0)
		{
			prefix = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "-a") == 0)
		{
			adsp_fname = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "-c") == 0)
		{
			count_fname = ++i < argc ? argv[i] : NULL;
		}
		else if (strcmp(arg, "-x") == 0)
		{
			while (i + 1 < argc && argv[i+1][0] != '-')
				xd.insert(argv[++i]);
		}
		else if (strcmp(arg, "--version") == 0)
		{
			printf("%s, " PACKAGE_NAME ", version " PACKAGE_VERSION "\n",
				progname);
			return 0;
		}
		else if (strcmp(arg, "--help") == 0)
		{
			/*   zdkimstats-anon */
			printf(          "%s reads stdin assuming that it is in the\n"
				"OpenDKIM stats format, checks it, optionally appends counts\n"
				"and/or ADSP failures to the respective files, and rewrites\n"
				"data to stdout, possibly anonymized; for use before mailing\n"
				"data to OpenDKIM (see http://www.opendkim.org/.)\n"
				"Command line args:\n"
			/*  12345678901234567890123456 */
				" [-p] prefix              secret string for MD5 digests\n"
				"  -x domain ...           don't anonymize data about messages\n"
				"                          signed by these domains\n"
				"  -a adsp-track           append a line for each adsp domain\n"
				"  -c count-file           append there one line with totals\n"
				"  --help                  print this stuff and exit\n"
				"  --version               print version string and exit\n",
				progname);
			return 0;
		}
		else if (prefix)
		{
			fprintf(stderr, "%s: invalid argument %s, try --help\n",
				progname, arg);
			return 1;
		}
		else
			prefix = arg;
	}
	
	if (errs)
		return 1;

	stats_t stats;
	int lineno = 1;
	while (!cin.eof())
	{
		cin >> stats;
		if (stats.good() && stats.verify(count, adsp, adsp_fname))
		{
			if (prefix && !stats.is_anon() && !stats.has_domain(xd))
				stats.anon(prefix);
			cout << stats;
		}
		else if (!cin.eof())
		{
			fprintf(stderr, "%s: garbled input around line %d (%d line(s))\n",
				progname, lineno, stats.lines());
			++errs;
		}
		if (cin.good())
			lineno += stats.lines();
	}
	cout << flush;

	if (count_fname)
	{
		ofstream cf(count_fname, ios::app);
		if (cf.is_open())
		{
			cf << count;
			cf.close();
		}
	}

	if (adsp_fname && !adsp.empty())
	{
		ofstream af(adsp_fname, ios::app);
		if (af.is_open())
		{
			adsp.last = count.last;
			af << adsp;
			af.close();
		}
	}

	return errs != 0;
}

