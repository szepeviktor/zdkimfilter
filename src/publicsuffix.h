/*
* publicsuffix.h - written by ale in milan on 10 feb 2015
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

#if !defined PUBLICSUFFIX_H_INCLUDED

struct publicsuffix_trie;
typedef struct publicsuffix_trie publicsuffix_trie;

char *org_domain(publicsuffix_trie const *pst, char const *domain);
void publicsuffix_done(publicsuffix_trie *pst);
publicsuffix_trie *publicsuffix_init(char const *fname, publicsuffix_trie *old);

#define PUBLICSUFFIX_H_INCLUDED
#endif
