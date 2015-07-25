/*
** myreputation.h - written in milano by vesely on 20dec2014
** query for dkim-reputation.org
*/

#if !defined MYREPUTATION_H_INCLUDED

#define DKIM_REPUTATION_ROOT "al.dkim-reputation.org"

int my_get_reputation(DKIM* dkim, DKIM_SIGINFO* sig, char *root, int *rep);
int flip_reputation_query_was_faked(void);

#define MYREPUTATION_H_INCLUDED
#endif
