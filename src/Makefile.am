## Automake

@SET_MAKE@

AM_CFLAGS = -I$(top_srcdir)
AM_CPPFLAGS = -fno-strict-aliasing
noinst_HEADERS = filterlib.h filedefs.h filecopy.h dkim-mailparse.h util.h\
 myadsp.h myvbr.h myreputation.h md5.h redact.h vb_fgets.h parm.h \
 database.h database_variables.h database_statements.h publicsuffix.h \
 spf_result_string.h cstring.h rfc822.h

filterexecdir = @COURIER_FILTER_INSTALL@
filterexec_PROGRAMS = zdkimfilter
filterexecPROGRAMS_INSTALL = $(INSTALL_PROGRAM)@PROGRAM_OWNER@

INSTALL_PROGRAM = /bin/sh $(top_builddir)/myinstall.sh

zdkimfilter_SOURCES = zdkimfilter.c filterlib.c parm.c myvbr.c redact.c \
 database.c publicsuffix.c ip_to_hex.c util.c myreputation.c md5.c myadsp.c \
 rfc822.c rfc822_getaddr.c rfc822_getaddrs.c dkim-mailparse.c
zdkimfilter_LDADD = @SOCKET_LIB@ @OPENDKIM_LIB@ @RESOLVER_LIB@ @NETTLE_LIB@ @OPENDBX_LIB@ @IDN2_LIB@ @LIBUNISTRING@
zdkimfilter_CPPFLAGS = -DFILTER_NAME=zdkimfilter @OPENDKIM_CFLAGS@ @OPENDBX_CFLAGS@
# nozdkimfilter_CCLD = libtool --mode=link $(CCLD)

bin_PROGRAMS = dkimsign redact zfilter_db zaggregate urlencode urldecode 2idn
dkimsign_SOURCES = dkimsign.c dkim-mailparse.c parm.c
redact_SOURCES = redact.c parm.c
redact_CPPFLAGS = -DMAIN
redact_LDADD = @NETTLE_LIB@
zfilter_db_SOURCES = database.c ip_to_hex.c parm.c myadsp.c
zfilter_db_CPPFLAGS = @OPENDBX_CFLAGS@ -DTEST_MAIN -DNO_DNS_QUERY
zfilter_db_LDADD = @OPENDBX_LIB@
zaggregate_SOURCES = zaggregate.c database.c ip_to_hex.c parm.c myadsp.c cstring.c urlencode.c
zaggregate_CPPFLAGS = @ZLIB_CFLAGS@ -DTEST_ZAG
zaggregate_LDADD = @OPENDBX_LIB@ @RESOLVER_LIB@ @ZLIB_LIB@ @UUID_LIB@ @IDN2_LIB@
urlencode_SOURCES = urlencode.c cstring.c
urlencode_CPPFLAGS = -DTEST_URLENCODE
urldecode_SOURCES = urldecode.c cstring.c
2idn.SOURCES = 2idn.c
2idn_LDADD = @IDN2_LIB@

check_PROGRAMS = TESTmyvbr TESTutil TESTmyrep TESTmyadsp TESTpublicsuffix TESTundo_percent_relay TESTcstring TESTmailparse
TESTmyvbr_SOURCES = myvbr.c
TESTmyvbr_CPPFLAGS = -DTEST_MAIN
TESTmyvbr_LDADD = @RESOLVER_LIB@
TESTutil_SOURCES = util.c
TESTutil_CPPFLAGS = -DTEST_MAIN
TESTmyrep_SOURCES = myreputation.c md5.c
TESTmyrep_CPPFLAGS = -DTEST_MAIN
TESTmyrep_LDADD = @RESOLVER_LIB@
TESTmyadsp_SOURCES = myadsp.c
TESTmyadsp_CPPFLAGS = -DTEST_MAIN
TESTmyadsp_LDADD = @RESOLVER_LIB@ @IDN2_LIB@
TESTpublicsuffix_SOURCES = publicsuffix.c
TESTpublicsuffix_CPPFLAGS = -DTEST_MAIN
TESTpublicsuffix_LDADD = @IDN2_LIB@ @LIBUNISTRING@
TESTundo_percent_relay_SOURCES = filterlib.c
TESTundo_percent_relay_CPPFLAGS = -DTEST_UNDO_PERCENT
TESTcstring_SOURCES = cstring.c
TESTcstring_CPPFLAGS = -DTEST_MAIN
TESTmailparse_SOURCES = dkim-mailparse.c
TESTmailparse_CPPFLAGS = -DTEST_MAIN


