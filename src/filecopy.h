/*
* filecopy.h - written by ale in milano on 21nov2012
* function for copying two files

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

#if !defined FILECOPY_H_INCLUDED

#include <stdio.h>
static int filecopy(FILE *in, FILE *out)
{
	char buf[8192];
	size_t sz;
	while ((sz = fread(buf, 1, sizeof buf, in)) > 0)
		if (fwrite(buf, sz, 1, out) != 1)
			return -1;
	return ferror(in)? -1: 0;
}

#define FILECOPY_H_INCLUDED
#endif

