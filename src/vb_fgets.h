/*
* vb_fgets.h - written by ale in milano on 21sep2012
* variable buffer fgets

Copyright (C) 2010-2012 Alessandro Vesely

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

#if !defined VB_FGETS_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef struct var_buf
{
	char *buf;
	size_t alloc;
} var_buf;

#define VB_LINE_MAX 5000
#if defined NDEBUG
#define VB_INIT_ALLOC 8192
#else
#define VB_INIT_ALLOC (VB_LINE_MAX/2)
#endif

static inline int vb_init(var_buf *vb)
// 0 on success
{
	assert(vb);
	return (vb->buf = (char*)malloc(vb->alloc = VB_INIT_ALLOC)) == NULL;
}

static inline void vb_clean(var_buf *vb)
// 0 on success
{
	assert(vb);
	if (vb->buf)
	{
		free(vb->buf);
		vb->buf = NULL;
	}
}

static inline char const *vb_what(var_buf const* vb, FILE *fp)
{
	assert(vb && fp);
	if (feof(fp)) return "EOF reached";
	return vb->buf? vb->buf: "malloc failed";
}

#if !defined SSIZE_MAX
#define SSIZE_MAX ((~((size_t) 0)) / 2)
#endif

static inline char* vb_fgets(var_buf *vb, size_t keep, FILE *fp)
/*
* Variable buffer fgets:  read until a physical line,
* making sure that it can take VB_LINE_MAX, and keep any
* amount of data that is already in the logical line already.
*
* return the newly read data (buf + keep) if OK, NULL on error
*/
{
	assert(vb && vb->buf && vb->alloc);
	assert(keep < vb->alloc);
	assert(fp);

	size_t avail = vb->alloc - keep;

	if (avail < VB_LINE_MAX)
	{
		char *new_buf;
		if (vb->alloc > SSIZE_MAX ||
			(new_buf = realloc(vb->buf, vb->alloc *= 2)) == NULL)
		{
			free(vb->buf);
			return vb->buf = NULL;
		}

		vb->buf = new_buf;
		avail = vb->alloc - keep;
	}
	
	return fgets(vb->buf + keep, avail - 1, fp);
}

#define VB_FGETS_H_INCLUDED
#endif
