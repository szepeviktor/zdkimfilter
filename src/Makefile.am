## Automake

@SET_MAKE@

AM_CFLAGS = -I$(top_srcdir) -fno-strict-aliasing
noinst_HEADERS = filterlib.h filedefs.h OpenDKIMstats.h

filterexecdir = @COURIER_FILTER_INSTALL@
filterexec_PROGRAMS = zdkimfilter
filterexecPROGRAMS_INSTALL = $(INSTALL_PROGRAM)@PROGRAM_OWNER@

zdkimfilter_SOURCES = zdkimfilter.c filterlib.c
zdkimfilter_LDADD = @OPENDKIM_LIB@
zdkimfilter_LDFLAGS = @OPENDKIM_LIB_PATH@
zdkimfilter_CFLAGS = -DFILTER_NAME=zdkimfilter $(AM_CFLAGS)@OPENDKIM_CFLAGS@

bin_PROGRAMS = zdkimstats-wait zdkimstats-anon
zdkimstats_wait_SOURCES = zdkimstats-wait.c
zdkimstats_anon_SOURCES = zdkimstats-anon.C
zdkimstats_anon_CXXFLAGS = @LIBSSL_CFLAGS@ $(AM_CXXFLAGS)
zdkimstats_anon_LDADD = @LIBSSL_LDADD@
