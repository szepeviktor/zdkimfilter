/*
** myvbr.h - written in milano by vesely on 1oct2010
** IPv4 address query for vbr certification
*/

#if !defined MYVBR_H_INCLUDED

typedef struct vbr_info
{
	struct vbr_info *next;
	char *md;  // domain: ascending order
	char *mc;
	char *mv[];
	// the buffer is here, at mv[no of elements]
} vbr_info;

int vbr_info_add(vbr_info **first, char const *s);
vbr_info* vbr_info_get(vbr_info *first, char const *domain);
void vbr_info_clear(vbr_info *first);
char *vbr_info_vouchers(vbr_info const *v);

typedef int (*vbr_cb)(char const**, char const*);
typedef struct vbr_check_result
{
	vbr_info *vbr;   // the list element (vbr->md == domain) of last call
	char *mv;        // its vbr->mv array element of first good/nxdomain query
	char *resp;      // malloc'd response of last good query
	size_t queries;  // accumulated count of total queries
	size_t tempfail; // accumulated count of temporary failures
	char const **tv; // 1st arg of callback function (context)
} vbr_check_result;
int vbr_check(vbr_info *first, char const*domain, vbr_cb, vbr_check_result*);
int flip_vbr_query_was_faked(void);

#define MYVBR_H_INCLUDED
#endif
