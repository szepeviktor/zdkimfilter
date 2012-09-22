## Automake

@SET_MAKE@

AM_CFLAGS = -I$(top_srcdir) -fno-strict-aliasing
noinst_HEADERS = filterlib.h filedefs.h OpenDKIMstats.h myvbr.h redact.h vb_fgets.h parm.h

filterexecdir = @COURIER_FILTER_INSTALL@
filterexec_PROGRAMS = zdkimfilter
filterexecPROGRAMS_INSTALL = $(INSTALL_PROGRAM)@PROGRAM_OWNER@

zdkimfilter_SOURCES = zdkimfilter.c filterlib.c myvbr.c redact.c
zdkimfilter_LDADD = @OPENDKIM_LIB@ @RESOLVER_LIB@ @NETTLE_LIB@
zdkimfilter_LDFLAGS = @OPENDKIM_LIB_PATH@
zdkimfilter_CFLAGS = -DFILTER_NAME=zdkimfilter $(AM_CFLAGS)@OPENDKIM_CFLAGS@

bin_PROGRAMS = zdkimstats-wait zdkimstats-anon dkimsign redact
zdkimstats_wait_SOURCES = zdkimstats-wait.c
zdkimstats_anon_SOURCES = zdkimstats-anon.C
zdkimstats_anon_CXXFLAGS = @LIBSSL_CFLAGS@ $(AM_CXXFLAGS)
zdkimstats_anon_LDADD = @LIBSSL_LDADD@
dkimsign_SOURCES = dkimsign.c
redact_SOURCES = redact.c
redact_LDADD = @NETTLE_LIB@
redact_CFLAGS = -DMAIN $(AM_CFLAGS)

check_PROGRAMS = TESTmyvbr
TESTmyvbr_SOURCES = myvbr.c myvbr.h
TESTmyvbr_CPPFLAGS = -DTEST_MAIN
TESTmyvbr_LDADD = @RESOLVER_LIB@

