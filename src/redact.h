/*
** redact.h - written in milano by vesely on 20sep2010
** string redaction (encription)
*/
#if !defined REDACT_H_INCLUDED

char *redacted(char const *password, char const*value);
int redact_is_fully_featured(void);

#define REDACT_H_INCLUDED
#endif
