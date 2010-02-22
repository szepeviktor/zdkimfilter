## Automake

AM_CFLAGS = -I$(top_srcdir) -fno-strict-aliasing
noinst_HEADERS = filterlib.h filedefs.h

filterexecdir = @COURIER_FILTER_INSTALL@
filterexec_PROGRAMS = zdkimfilter
filterexecPROGRAMS_INSTALL = $(INSTALL_PROGRAM)@PROGRAM_OWNER@

# noinst_PROGRAMS = tdkimfilter

zdkimfilter_SOURCES = zdkimfilter.c filterlib.c
zdkimfilter_LDADD = @OPENDKIM_LIB@
zdkimfilter_LDFLAGS = @OPENDKIM_LIB_PATH@
zdkimfilter_CFLAGS = -DFILTER_NAME=zdkimfilter $(AM_CFLAGS)@OPENDKIM_CFLAGS@

