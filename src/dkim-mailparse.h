/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _MY_MAILPARSE_H_
#define _MY_MAILPARSE_H_


/* prototypes */
extern int my_mail_parse(char *line, char **user_out, char **domain_out);
extern int my_mail_parse_c(char *line, char **user_out, char **domain_out, char **cont);
extern void my_mail_parse_init __P((void));
#endif /* ! _MY_MAILPARSE_H_ */
