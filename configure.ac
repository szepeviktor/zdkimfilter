#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([zdkimfilter for courier],[2.0],[vesely@tana.it],[zdkimfilter])

AC_CONFIG_SRCDIR([src/zdkimfilter.c])
AC_CONFIG_MACRO_DIR([m4])
AC_LANG([C])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE

# Silent rules should need V=0
AM_SILENT_RULES
# dnl AC_PROG_MAKE_SET
AC_CONFIG_HEADERS([config.h])

# Checks for programs, this may alter CFLAGS
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O()

AC_PROG_AWK
AC_PROG_EGREP
PKG_PROG_PKG_CONFIG

# Need libtool to properly link static/dynamic inter-library dependencies,
# as accessible through .la files.  We build no library, though.
LT_INIT
LT_OUTPUT

# Need perl to build documentation
AC_CHECK_PROG([PERL], [perl], [perl])
AC_CHECK_PROG([POD2MAN], [pod2man], [pod2man])
AM_CONDITIONAL([BUILD_DOC], [test "$PERL" = perl -a "$POD2MAN" = pod2man])
AC_SUBST([POD2MAN_OPTIONS], ['--release="$(PACKAGE) $(VERSION)" --center=zdkimfilter'])

# check debugging
ZDKIMFILTER_DEBUG="0"
AC_ARG_ENABLE([debug],
	[[  --enable-debug          enable debugging code and macros
  --disable-debug         use release mode (this is the default)]],
	[
	if test "$enableval" = "yes" -o "$enableval" = "on" -o "$enableval" = "1"; then
		ZDKIMFILTER_DEBUG="1"
	fi
	])
AC_DEFINE_UNQUOTED([ZDKIMFILTER_DEBUG], [$ZDKIMFILTER_DEBUG], [enable debug / NDEBUG])

# check the filter mode
zdkimfilter_mode="Y"
AC_ARG_ENABLE([allfilter],
	[[  --enable-allfilter      filter all mail (this is the default)
  --disable-allfilter     optional use with maildrop filtering API]],
	[
	if test "$enableval" = "yes" -o "$enableval" = "on" -o "$enableval" = "all"; then
		:
	else
		zdkimfilter_mode="N"
	fi
	])
AC_SUBST([zdkimfilter_mode])


# setuid dkimsign
DKIMSIGN_MODE=""
AC_ARG_ENABLE([dkimsign-setuid],
	[[  --enable-dkimsign-setuid      dkimsign run as Courier user
  --disable-dkimsign-setuid     normal install (this is the default)]],
	[
	if test "$enableval" = "yes" -o "$enableval" = "on" -o "$enableval" = "all"; then
		DKIMSIGN_MODE="-m 4755"
	fi
	])
AC_SUBST([DKIMSIGN_MODE])

# XCOMPILE: accept courier-config output file
# or find courier-config and get its output
COURIER_CONFIG_OUT=""
m4_pattern_allow([AS_HELP_STRING])
m4_pattern_allow([AC_MSG_ERROR])
AC_ARG_WITH([courier-config-output],
	[AS_HELP_STRING([--with-courier-config-output=file],
		[supply a file with the output of running courier-config on the
		target system; if not given, assume this is the target system
		and run courier-config to learn installation directories.])],
	[
	if test -r "$withval" -a -s "$withval"; then
		COURIER_CONFIG_OUT=$(<$withval)
	else
		AC_MSG_ERROR([bad file with-courier-config-output $withval])
	fi
	],
	[
	AC_PATH_PROG([COURIER_CONFIG], [courier-config], [no], [${PATH}])
	if test "$COURIER_CONFIG" = "no"; then
		:
	else
		COURIER_CONFIG_OUT=$($COURIER_CONFIG)
	fi
	])

courier_bindir=""
courier_sbindir=""
courier_libexecdir=""
courier_sysconfdir=""
courier_localstatedir=""
courier_mailuser=""
courier_mailgroup=""
courier_mailuid=""
courier_mailgid=""

if test -z "$COURIER_CONFIG_OUT"; then
	AC_MSG_ERROR([cannot find courier-config, use --with-courier-config-output])
else
	vars=""
	eval $(echo "$COURIER_CONFIG_OUT" |\
		$EGREP '^(bindir|sbindir|libexecdir|sysconfdir|localstatedir|mailuser|mailgroup|mailgid|mailuid)=' |\
		sed 's/^/courier_/')
fi

all_ok="ok"
test "x$courier_bindir" = "x" && all_ok="bi"
test "x$courier_sbindir" = "x" && all_ok="sb"
test "x$courier_libexecdir" = "x" && all_ok="li"
test "x$courier_sysconfdir" = "x" && all_ok="sy"
test "x$courier_localstatedir" = "x" && all_ok="lo"
test "x$courier_mailuser" = "x" && all_ok="us"
test "x$courier_mailgroup" = "x" && all_ok="gr"
test "x$courier_mailgid" = "x" && all_ok="gi"
test "x$courier_mailuid" = "x" && all_ok="ui"

if test "$all_ok" = "ok"; then
	:
else
	AC_MSG_ERROR([["bad courier-config data (miss $all_ok)"]])
fi

# get courier version
how_do_i_know=""
courier_version=""
AC_MSG_CHECKING([what Courier version])
AC_ARG_WITH([courier-version],
	[[  --with-courier-version  specify middle courier version
	                  (default: 60 if cannot invoke imapd --version)]],
	[[
		courier_version="$withval"
		how_do_i_know=" (given parameter)"
	]],
	[[
		if test -x "${courier_bindir}/imapd"; then
			courier_version=`${courier_bindir}/imapd --version | sed -n 's/^[^0-9]*.[0-9]*.\([0-9]*\).*/\1/p'`
			if test -z "$courier_version"; then
				courier_version="0.40.0"
				how_do_i_know=" (imapd ante 2003)"
			fi
		else
			courier_version="0.60.0"
			how_do_i_know=" (assumed)"
		fi
	]])
AC_MSG_RESULT([${courier_version}${how_do_i_know}])

# this was COURIERSUBMIT_WANTS_UGLY_HACK (until zdkimfilter 1.4)
# Courier version 57.1 fixes that, I check 58
AX_COMPARE_VERSION($courier_version, [lt], [0.58.0],
	[AC_MSG_ERROR([too old courier version])])

# set installation path
AC_MSG_CHECKING([filter installation directory])
COURIER_FILTER_INSTALL=${courier_libexecdir}/filters
AC_MSG_RESULT([$COURIER_FILTER_INSTALL])
AC_SUBST([COURIER_FILTER_INSTALL])

# check courier/etc directory (zdkimfilter.conf goes in its "filters" subdir
AC_MSG_CHECKING([courier configuration directory])
COURIER_SYSCONF_INSTALL=${courier_sysconfdir}
AC_MSG_RESULT([$COURIER_SYSCONF_INSTALL])
AC_SUBST([COURIER_SYSCONF_INSTALL])

# XCOMPILE: nothing for add option for library containing accept
# Checks for libraries.
SOCKET_LIB=""
SAVE_LIBS="$LIBS"
AC_SEARCH_LIBS([accept], [socket],
	[test "$LIBS" = "$SAVE_LIBS" || SOCKET_LIB=" -lsocket"],
	[SOCKET_LIB="no"])
if test "$SOCKET_LIB" = "no"; then
	AC_SEARCH_LIBS([accept], [socket],
		[test "$LIBS" = "$SAVE_LIBS" || SOCKET_LIB=" -lsocket -lnsl"],
		[SOCKET_LIB="no"],
		[-lnsl])
fi
if test "$SOCKET_LIB" = "no"; then
	AC_MSG_ERROR([missing accept function])
fi
LIBS="$SAVE_LIBS"
AC_SUBST([SOCKET_LIB])

# XCOMPILE: nothing for OpenDKIM.  It must be installed the same version
AC_CACHE_CHECK([if opendkim.pc exists], [av_cv_opendkim_version],
	[av_cv_opendkim_version=`$PKG_CONFIG --modversion opendkim 2>/dev/null || echo false`
	])

AC_CACHE_CHECK([if opendkim is at least 1.2.2], [av_cv_opendkim_version_ok],
	[av_cv_opendkim_version_ok=false
	if test "$av_cv_opendkim_version" != "false" ; then
		$PKG_CONFIG --atleast-version=1.2.2 opendkim && av_cv_opendkim_version_ok="true"
	else
		SAVE_LIBS="$LIBS"
		LIBS="$SAVE_LIBS -lopendkim"
		save_ac_link="$ac_link"
		ac_link="./libtool --mode=link --tag=CC $ac_link"
		AC_RUN_IFELSE([AC_LANG_SOURCE([
			#include <opendkim/dkim.h>
			int main(){unsigned long v = dkim_libversion();
			return v < 0x01020200U;}
			])],
			[av_cv_opendkim_version_ok="true"], [])
		ac_link="$save_ac_link"
		LIBS="$SAVE_LIBS"
	fi
	])
if test "$av_cv_opendkim_version_ok" = "false"; then
	AC_MSG_ERROR([unsupported or unrecognized opendkim library])
fi

AC_CACHE_CHECK([opendkim 2.2.0 or better], [av_cv_opendkim_version_220],
	[av_cv_opendkim_version_220=0
	if test "$av_cv_opendkim_version" != "false" ; then
		$PKG_CONFIG --atleast-version=2.2.0 opendkim && av_cv_opendkim_version_220=1
	else
		SAVE_LIBS="$LIBS"
		LIBS="$SAVE_LIBS -lopendkim"
		save_ac_link="$ac_link"
		ac_link="./libtool --mode=link --tag=CC $ac_link"
		AC_RUN_IFELSE([AC_LANG_SOURCE([
			#include <opendkim/dkim.h>
			int main(){unsigned long v = dkim_libversion();
			return v < 0x02020000U;}
			])],
			[av_cv_opendkim_version_220=1], [])
		ac_link="$save_ac_link"
		LIBS="$SAVE_LIBS"
	fi
	])

AC_CACHE_CHECK([opendkim 2.10.1 or better], [av_cv_opendkim_version_2A1],
	[av_cv_opendkim_version_2A1=0
	if test "$av_cv_opendkim_version" != "false" ; then
		$PKG_CONFIG --atleast-version=2.10.1 opendkim && av_cv_opendkim_version_2A1=1
	else
		SAVE_LIBS="$LIBS"
		LIBS="$SAVE_LIBS -lopendkim"
		save_ac_link="$ac_link"
		ac_link="./libtool --mode=link --tag=CC $ac_link"
		AC_RUN_IFELSE([AC_LANG_SOURCE([
			#include <opendkim/dkim.h>
			int main(){unsigned long v = dkim_libversion();
			return v < 0x020a0000U;}
			])],
			[av_cv_opendkim_version_2A1=1], [])
		ac_link="$save_ac_link"
		LIBS="$SAVE_LIBS"
	fi
	])

# XCOMPILE: nothing for OpenDKIM.  It must be installed the same way;
# that is, linked to either OpenSSL or GNUTLS, static or dynamic.
AC_CACHE_CHECK([cflags for opendkim],
	av_cv_cflags_opendkim,
	[
	SAVE_CFLAGS="$CFLAGS"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([
		#include <opendkim/dkim.h>
		])],
		[av_cv_cflags_opendkim="none"],
		[av_cv_cflags_opendkim="fail"]
		)
	if test "$av_cv_cflags_opendkim" = "fail"; then
		av_cv_cflags_opendkim="`$PKG_CONFIG --cflags-only-I opendkim`"
		CFLAGS="$av_cv_cflags_opendkim $CFLAGS"
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([
			#include <opendkim/dkim.h>
			])],
			[],
			[av_cv_cflags_opendkim="fail"]
			)
	fi
	CFLAGS="$SAVE_CFLAGS"
	])

if test "$av_cv_cflags_opendkim" = "fail"; then
	AC_MSG_ERROR([unable to use dkim.h])
fi
if test "$av_cv_cflags_opendkim" = "none"; then
	OPENDKIM_CFLAGS=""
else
	OPENDKIM_CFLAGS=" $av_cv_cflags_opendkim"
fi
AC_SUBST([OPENDKIM_CFLAGS])

OPENDKIM_LIB="`$PKG_CONFIG --libs-only-L opendkim` -lopendkim $OPENDKIM_LIB"
AC_MSG_CHECKING([flags for opendkim library])
	av_cv_flags_library_opendkim="none"
	SAVE_LIBS="$LIBS"
	LIBS="$SAVE_LIBS $OPENDKIM_LIB"
	save_ac_link="$ac_link"
	ac_link="./libtool --mode=link --tag=CC $ac_link"
	AC_LINK_IFELSE([AC_LANG_CALL([], [dkim_init])],
		[av_cv_flags_library_opendkim="ok"])
	ac_link="$save_ac_link"
	LIBS="$SAVE_LIBS"

if test "$av_cv_flags_library_opendkim" = "none"; then
	AC_MSG_ERROR([unable to use opendkim library])
fi
AC_MSG_RESULT([$OPENDKIM_LIB])
AC_SUBST([OPENDKIM_LIB])


SAVE_CFLAGS="$CFLAGS"
CFLAGS="$OPENDKIM_CFLAGS $CFLAGS"
SAVE_LIBS="$LIBS"
LIBS="$SAVE_LIBS $OPENDKIM_LIB"
save_ac_link="$ac_link"
ac_link="./libtool --mode=link --tag=CC $ac_link"
AC_CHECK_FUNCS([dkim_get_sigsubstring dkim_getuser dkim_libversion])
CFLAGS="$SAVE_CFLAGS"
ac_link="$save_ac_link"
LIBS="$SAVE_LIBS"

# XCOMPILE: option for HAVE_OPENDBX, OPENDBX_CFLAGS, OPENDBX_LIB
AC_CACHE_CHECK([opendbx version],
	av_cv_opendbx_version,
	[
	av_cv_opendbx_version="`$PKG_CONFIG --modversion opendbx`"
	])
OPENDBX_CFLAGS=""
OPENDBX_LIB=""
HAVE_OPENDBX="false"
if $PKG_CONFIG --atleast-version=1.4.5 opendbx; then
	AC_CACHE_CHECK([cflags for opendbx],
		av_cv_cflags_opendbx,
		[
		SAVE_CFLAGS="$CFLAGS"
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([
			#include <opendbx/api.h>
			])],
			[av_cv_cflags_opendbx="none"],
			[av_cv_cflags_opendbx="fail"]
			)
		if test "$av_cv_cflags_opendbx" = "fail"; then
			av_cv_cflags_opendbx="`$PKG_CONFIG --cflags-only-I opendbx`"
			CFLAGS="$av_cv_cflags_opendbx $CFLAGS"
			AC_COMPILE_IFELSE([AC_LANG_SOURCE([
				#include <opendbx/api.h>
				])],
				[],
				[av_cv_cflags_opendbx="fail"]
				)
		fi
		CFLAGS="$SAVE_CFLAGS"
		])

	if test "$av_cv_cflags_opendbx" = "fail"; then
		AC_MSG_ERROR([unable to use opendbx/api.h])
	fi
	if test "$av_cv_cflags_opendbx" = "none"; then
		:
	else
		OPENDBX_CFLAGS=" $av_cv_cflags_opendbx"
	fi

	# Check opendbx library
	AC_MSG_CHECKING([whether opendbx is usable])
	OPENDBX_LIB=" `$PKG_CONFIG --libs-only-L opendbx` -lopendbx"
	SAVE_LIBS="$LIBS"
	LIBS="$SAVE_LIBS $OPENDBX_LIB"
	save_ac_link="$ac_link"
	ac_link="./libtool --mode=link --tag=CC $ac_link"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <opendbx/api.h>
	], [odbx_t *h;
	odbx_init(&h, "", "", "");
	])], [HAVE_OPENDBX="true"])
	ac_link="$save_ac_link"
	LIBS="$SAVE_LIBS"
	AC_MSG_RESULT([$HAVE_OPENDBX])
	AC_SUBST([HAVE_OPENDBX])
	if test "$HAVE_OPENDBX" = "true"; then
		AC_DEFINE(HAVE_OPENDBX, 1, [Define if using opendbx])
	else
		OPENDBX_LIB=""
	fi
fi
AC_SUBST([OPENDBX_CFLAGS])
AC_SUBST([OPENDBX_LIB])
AC_SUBST([HAVE_OPENDBX])

AC_HEADER_RESOLV
RESOLVER_LIB=
av_cv_flags_library_resolver="none"
# res_query has been seen in libc, libbind and libresolv (jabber's AC)
if test "x-$ac_cv_header_resolv_h" = "x-yes" ; then
	AC_MSG_CHECKING([flags for resolver library])
	SAVE_LIBS="$LIBS"
	LIBS="$SAVE_LIBS $RESOLVER_LIB"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <resolv.h>]], [[res_query(0,0,0,0,0)]])],
		[av_cv_flags_library_resolver="none needed"])
	if test "$av_cv_flags_library_resolver" = "none"; then
		RESOLVER_LIB="-lresolv"
		LIBS="$SAVE_LIBS $RESOLVER_LIB"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <resolv.h>]], [[res_query(0,0,0,0,0)]])],
			[av_cv_flags_library_resolver="$RESOLVER_LIB"])
	fi
	if test "$av_cv_flags_library_resolver" = "none"; then
		RESOLVER_LIB="-lbind"
		LIBS="$SAVE_LIBS $RESOLVER_LIB"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <resolv.h>]], [[res_query(0,0,0,0,0)]])],
			[av_cv_flags_library_resolver="$RESOLVER_LIB"])
	fi
	if test "$av_cv_flags_library_resolver" = "none"; then
		RESOLVER_LIB="-lresolv -lsocket -lnsl"
		LIBS="$SAVE_LIBS $RESOLVER_LIB"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <resolv.h>]], [[res_query(0,0,0,0,0)]])],
			[av_cv_flags_library_resolver="$RESOLVER_LIB"])
	fi
	LIBS="$SAVE_LIBS"
fi
if test "$av_cv_flags_library_resolver" = "none"; then
	AC_MSG_ERROR([unable to use resolver library])
fi
AC_MSG_RESULT([$RESOLVER_LIB])
AC_SUBST([RESOLVER_LIB])


ZLIB_CFLAGS=""
AX_CHECK_ZLIB([ZLIB_LIB="-lz"
if test "$ZLIB_HOME" != "/usr" -a "$ZLIB_HOME" != "/usr/local"; then
	ZLIB_LIB="-L${ZLIB_HOME}/lib $ZLIB_LIB"
	ZLIB_CFLAGS="-I${ZLIB_HOME}/include"
fi])
AC_SUBST([ZLIB_LIB])
AC_SUBST([ZLIB_CFLAGS])

UUID_LIB=
AC_CHECK_LIB([uuid], [uuid_generate], [av_cv_libuuid=yes], [av_cv_libuuid=no])
AC_CHECK_HEADER([uuid/uuid.h], [av_cv_uuid_h=yes], [av_cv_uuid_h=no])
if test "$av_cv_libuuid" = "yes" && test "$av_cv_uuid_h" = "yes"; then
	AC_DEFINE([HAVE_UUID], [1], [Define to 1 if you have uuid library (-luuid)])
	UUID_LIB="-luuid"
fi
AC_SUBST([UUID_LIB])


# Checks for other header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h stdlib.h string.h unistd.h fcntl.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm memmove memset pselect random])
AX_VAR_TIMEZONE_EXTERNALS
AX_FUNC_SNPRINTF


# Check if nettle exists (for redact.c)
NETTLE_LIB=" -lnettle"
AC_MSG_CHECKING([whether nettle is avalable])
SAVE_LIBS="$LIBS"
LIBS="$SAVE_LIBS $NETTLE_LIB"
HAVE_NETTLE=""
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <nettle/arcfour.h>
#include <nettle/base64.h>
], [struct arcfour_ctx c0;
struct base64_encode_ctx c1;
struct base64_decode_ctx c2;
arcfour_set_key(&c0, 0, "");
base64_decode_init(&c1);
base64_decode_init(&c2);
])], [HAVE_NETTLE="1"])
LIBS="$SAVE_LIBS"
AC_SUBST([HAVE_NETTLE])
if test "$HAVE_NETTLE" = "1"; then
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_NETTLE, 1, [Define if using nettle])
else
	AC_MSG_RESULT([nope])
	NETTLE_LIB=""
fi
AC_SUBST([NETTLE_LIB])

# Check if nettle version is after April 2013
HAVE_NETTLE_V3=""
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <stdint.h>
#include <nettle/base64.h>
], [struct base64_decode_ctx ctx;
size_t dst_length;
uint8_t dst;
size_t src_length;
char src;
return base64_decode_update(&ctx, &l, dest, len, src);
])], [HAVE_NETTLE_V3="1"])
AC_SUBST([HAVE_NETTLE_V3])
if test "$HAVE_NETTLE" = "1"; then
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_NETTLE_V3, 1, [Define if using nettle v3])
else
	AC_MSG_RESULT([nope])
fi

# check libunistring and libidn2
gl_LIBUNISTRING()
if test "$HAVE_LIBUNISTRING" != "yes"; then
	AC_MSG_ERROR([missing libunistring])
fi
IDN2_LIB=""
SAVE_LIBS="$LIBS"
AC_SEARCH_LIBS([idn2_lookup_u8], [idn2],
	[IDN2_LIB=" -lidn2"],
	[IDN2_LIB="no"])
if test "$IDN2_LIB" = "no"; then
	AC_MSG_ERROR([missing libidn2])
fi
LIBS="$SAVE_LIBS"
AC_SUBST([IDN2_LIB])

# effective_tld_names.dat might use off_t
AC_TYPE_OFF_T

# get mailuser/mailgroup for the executable stuff
AC_CACHE_CHECK([user:group for courier executables],
	av_cv_permission_user_group,
	[[
	av_cv_permission_user_group="failed"
	ZDKIMFILTER_USER=${courier_mailuser}
	if test -n "$ZDKIMFILTER_USER" ; then
		ZDKIMFILTER_GROUP=${courier_mailgroup}
		if test -n "$ZDKIMFILTER_GROUP" ; then
			av_cv_permission_user_group="${ZDKIMFILTER_USER}:$ZDKIMFILTER_GROUP"
		fi
	fi
	]])
if test "$av_cv_permission_user_group" = "failed"; then
	ZDKIMFILTER_USER=bin
	ZDKIMFILTER_GROUP=bin
	av_cv_permission_user_group="bin:bin"
	AC_MSG_WARN([cannot get mailuser:mailgroup, using $av_cv_permission_user_group])
fi
AC_SUBST([PROGRAM_OWNER], [" -o $ZDKIMFILTER_USER -g $ZDKIMFILTER_GROUP"])

AC_SUBST([MAILUID], ["$courier_mailuid"])
AC_SUBST([MAILGID], ["$courier_mailgid"])
AC_SUBST([MAILUSER], ["$courier_mailuser"])
AC_SUBST([FILTERSOCKETDIR], ["${courier_localstatedir}/filters"])
AC_SUBST([ALLFILTERSOCKETDIR], ["${courier_localstatedir}/allfilters"])
AC_SUBST([ZDKIMFILTER_PID_DIR], ["${courier_localstatedir}/tmp"])

# easier than throwing in inet_aton --0x7f0000ff as int
AC_C_BIGENDIAN(
	[AC_SUBST([DNSWL_ORG_INVALID_IP_ENDIAN], [2130706687])],
	[AC_SUBST([DNSWL_ORG_INVALID_IP_ENDIAN], [-16777089])])

# limit test suite entries
AC_SUBST([HAVE_LIBOPENDKIM_220], ["${av_cv_opendkim_version_220}"])

# precompiler conditionals
AC_DEFINE_UNQUOTED([HAVE_LIBOPENDKIM_220], [$av_cv_opendkim_version_220], [OpenDKIM 2.2.0 or better])
AC_DEFINE_UNQUOTED([HAVE_LIBOPENDKIM_2A1], [$av_cv_opendkim_version_2A1], [OpenDKIM 2.10.1 or better])

# LN_S used in tests/aclocal.in
AC_PROG_LN_S

# base64 used in tests (mailfile)
AC_CHECK_PROG([BASE64], [base64], [base64])
AC_SUBST([BASE64])

# make tests/atconfig
AC_CONFIG_TESTDIR([tests], [src])

AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_CONFIG_FILES([Makefile
                 zdkimfilter.spec
                 myinstall.sh
                 src/Makefile
                 src/filedefs.h
                 etc/Makefile
                 etc/zdkimfilter.conf.dist
                 etc/zdkimfilter.pod
                 etc/zdkimfilter.conf.pod
                 etc/dkimsign.pod
                 etc/redact.pod
                 etc/zfilter_db.pod
                 etc/zaggregate.pod
                 etc/odbx_example.pod
                 etc/2idn.pod
                 tests/atlocal
                 tests/Makefile
                 debian/Makefile
                ])
AC_OUTPUT
