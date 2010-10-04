/*
** myvbr.h - written in milano by vesely on 1oct2010
** IPv4 address query for vbr certification
*/

#if !defined MYVBR_H_INCLUDED

int spamhaus_vbr_query(char const *signer, char **resp);
#define MYVBR_H_INCLUDED
#endif
