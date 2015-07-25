/*
** cstring.h - written by vesely in milano on 18 feb 2002
** simple string that grows
*/

#if !defined(CSTRING_H_INCLUDED)
#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct simple_string_type_in_c
{
	size_t alloc;          /* allocated size of data */
	size_t length;         /* currently used size */
	char data[1];          /* start of storage */
} cstring;

cstring* cstr_init(size_t initial_data_size);
cstring* cstr_from_string(char const *initial_data);
cstring* cstr_reserve(cstring*, size_t required_total_size);
cstring* cstr_grow(cstring*, size_t required_additional_length);
cstring* cstr_addch(cstring*, int character);
cstring* cstr_addstr(cstring*, char const*additional_data);
cstring* cstr_addblob(cstring*, char const*add_data, size_t add_data_len);
cstring* cstr_add(cstring*, cstring const *);
void cstr_trunc(cstring*, size_t set_length);
cstring* cstr_final(cstring*);
cstring* cstr_dup(cstring const*);
cstring* cstr_setblob(cstring*, char const*data, size_t data_len);
cstring* cstr_setstr(cstring*, char const*data);
cstring* cstr_set(cstring*dest, cstring const*data);
static inline char const *cstr_get(cstring const* s) {return s? s->data: NULL;}
static inline size_t cstr_length(cstring const *s) {return s? s->length: 0;}
#if defined __GNUC__
__attribute__ ((format(printf, 2, 3)))
#endif
cstring *cstr_printf(cstring*, char const*, ...);

#ifdef	__cplusplus
}
#endif

#define CSTRING_H_INCLUDED
#endif
