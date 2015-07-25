/*
* spf_result_string.h - written by ale in milano on 14mar2015
* convert string to spf_result

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

#if !defined SPF_RESULT_STRING_H_INCLUDED

#include <string.h>
#include "database.h"
#include "util.h"
#include <assert.h>

static inline spf_result spf_result_string(char const *s)
{
	assert(s && *s);
	switch (*(unsigned char const*)s)
	{
		case 'e': if (strincmp(s, "error", 5) == 0) return spf_temperror;
			break;
		case 'f': if (strincmp(s, "fail", 4) == 0) return spf_fail;
			break;
		case 'n': if (strincmp(s, "none", 4) == 0) return spf_none;
			if (strincmp(s, "neutral", 7) == 0) return spf_neutral;
			break;
		case 'p': if (strincmp(s, "pass", 4) == 0) return spf_pass;
			break;
		case 's': if (strincmp(s, "softfail", 8) == 0) return spf_softfail;
			break;
		case 'u': if (strincmp(s, "unknown", 7) == 0) return spf_permerror;
			break;
		default: break;
	}
	return spf_none;
}
#define SPF_RESULT_STRING_H_INCLUDED
#endif

