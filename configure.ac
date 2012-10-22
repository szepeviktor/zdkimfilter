#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([zdkimfilter for courier],[1.0b],[vesely@tana.it],[zdkimfilter])

AC_CONFIG_SRCDIR([src/zdkimfilter.c])
AC_CONFIG_MACRO_DIR([m4])
AC_LANG([C])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE
# dnl AC_PROG_MAKE_SET
AC_CONFIG_HEADER([config.h])

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


# find courier-config and get variables
AC_PATH_PROG([COURIER_CONFIG], [courier-config], [no],
	[${PATH}])

courier_bindir=""
courier_sbindir=""
courier_libexecdir=""
courier_sysconfdir=""
courier_localstatedir=""
courier_mailuser=""
courier_mailgroup=""
courier_mailuid=""
courier_mailgid=""


if test "$COURIER_CONFIG" = "no"; then
	:
else
	vars=""
	eval "`$COURIER_CONFIG |\
		$EGREP '^(bindir|sbindir|libexecdir|sysconfdir|localstatedir|mailuser|mailgroup|mailgid|mailuid)=' |\
		sed 's/^/courier_/'`"
fi

if test "$COURIER_CONFIG" = "no"; then
	AC_MSG_ERROR([cannot find courier-config])
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
	AC_MSG_ERROR([["cannot get courier config data ($all_ok)"]])
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
				courier_version="40"
				how_do_i_know=" (imapd ante 2003)"
			fi
		else
			courier_version="60"
			how_do_i_know=" (assumed)"
		fi
	]])
AC_MSG_RESULT([${courier_version}${how_do_i_know}])

# set COURIERSUBMIT_WANTS_UGLY_HACK based on Courier version
# version 57.1 fixes that, but the hack won't hurt anyway so I check 58
# this change also allows to change the message
AC_MSG_CHECKING([if courier version is less than 58])
	COURIERSUBMIT_WANTS_UGLY_HACK='yes'
	test $courier_version -ge 58 && COURIERSUBMIT_WANTS_UGLY_HACK='no'
AC_MSG_RESULT([$COURIERSUBMIT_WANTS_UGLY_HACK])
if test "$COURIERSUBMIT_WANTS_UGLY_HACK" = "yes"; then
	AC_DEFINE(COURIERSUBMIT_WANTS_UGLY_HACK, 1,
		[Define if courier allows writing messages])
	AC_MSG_ERROR([too old courier version])
fi

# set installation path
AC_MSG_CHECKING([filter installation directory])
COURIER_FILTER_INSTALL=${courier_libexecdir}/filters
AC_MSG_RESULT([$COURIER_FILTER_INSTALL])
if test -d "$COURIER_FILTER_INSTALL"; then
	:
else
	AC_MSG_ERROR([cannot find the filter directory])
fi
AC_SUBST([COURIER_FILTER_INSTALL])

# check courier/etc directory (zdkimfilter.conf goes in its "filters" subdir
# and below check the content of maildrop)
AC_MSG_CHECKING([courier configuration directory])
COURIER_SYSCONF_INSTALL=${courier_sysconfdir}
AC_MSG_RESULT([$COURIER_SYSCONF_INSTALL])
if test -d "$COURIER_SYSCONF_INSTALL"; then
	:
else
	AC_MSG_ERROR([cannot find courier configuration directory])
fi
AC_SUBST([COURIER_SYSCONF_INSTALL])

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

AC_CACHE_CHECK([opendkim version],
	av_cv_opendkim_version,
	[
	av_cv_opendkim_version="`$PKG_CONFIG --modversion opendkim`"
	])
AC_CACHE_CHECK([if that was at least 1.2.2],
	av_cv_opendkim_version_ok,
	[
	av_cv_opendkim_version_ok="no"
	$PKG_CONFIG --atleast-version=1.2.2 opendkim && av_cv_opendkim_version_ok="yes"
	])
if test "$av_cv_opendkim_version_ok" = "no"; then
	AC_MSG_ERROR([unsupported old opendkim library])
fi

AC_CACHE_CHECK([if that was 2.2.0 or better],
	av_cv_opendkim_version_220,
	[
	av_cv_opendkim_version_220="false"
	$PKG_CONFIG --atleast-version=2.2.0 opendkim && av_cv_opendkim_version_220="true"
	])

AC_CACHE_CHECK([cflags for opendkim],
	av_cv_cflags_opendkim,
	[
	SAVE_CFLAGS="$CFLAGS"
	AC_COMPILE_IFELSE([
		#include <opendkim/dkim.h>
		],
		[av_cv_cflags_opendkim="none"],
		[av_cv_cflags_opendkim="fail"]
		)
	if test "$av_cv_cflags_opendkim" = "fail"; then
		av_cv_cflags_opendkim="`$PKG_CONFIG --cflags-only-I opendkim`"
		CFLAGS="$av_cv_cflags_opendkim $CFLAGS"
		AC_COMPILE_IFELSE([
			#include <opendkim/dkim.h>
			],
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

AC_CACHE_CHECK([arguments for dkim_policy],
	av_cv_opendkim_dkim_policy_args,
	[
	SAVE_CFLAGS="$CFLAGS"
	CFLAGS="$OPENDKIM_CFLAGS $CFLAGS"
	AC_COMPILE_IFELSE([
		#include <opendkim/dkim.h>
		int main(){return dkim_policy((DKIM*)0,(dkim_policy_t*)0,(DKIM_PSTATE*)0)
		== DKIM_STAT_OK? 1: 0;}
		],
		[av_cv_opendkim_dkim_policy_args="three"],
		[av_cv_opendkim_dkim_policy_args="fail"]
		)
	if test "$av_cv_opendkim_dkim_policy_args" = "fail"; then
		AC_COMPILE_IFELSE([
			#include <opendkim/dkim.h>
			int main(){return
			dkim_policy((DKIM*)0,(dkim_policy_t*)0,(unsigned int*)0,(DKIM_PSTATE*)0)
			== DKIM_STAT_OK? 1: 0;}
			],
			[av_cv_opendkim_dkim_policy_args="four"],
			[av_cv_opendkim_dkim_policy_args="fail"]
			)
	fi
	CFLAGS="$SAVE_CFLAGS"
	])

if test "$av_cv_opendkim_dkim_policy_args" = "fail"; then
	AC_MSG_ERROR([unable to use libopendkim])
fi
if test "$av_cv_opendkim_dkim_policy_args" = "four"; then
	OPENDKIM_DKIM_POLICY_ARGS="4"
else
	OPENDKIM_DKIM_POLICY_ARGS="3"
fi
AC_DEFINE_UNQUOTED([OPENDKIM_DKIM_POLICY_ARGS], [$OPENDKIM_DKIM_POLICY_ARGS], [3 OR 4])

AC_CHECK_HEADERS([dkim-rep/dkim-rep.h])
if $PKG_CONFIG --exists dkim-rep; then
	OPENDKIM_LIB="-ldkimrep"
fi

OPENDKIM_LIB="`$PKG_CONFIG --libs-only-L opendkim` -lopendkim $OPENDKIM_LIB"
AC_MSG_CHECKING([flags for opendkim library])
	av_cv_flags_library_opendkim="none"
	SAVE_LIBS="$LIBS"
	LIBS="$SAVE_LIBS $OPENDKIM_LIB"
	save_ac_link="$ac_link"
	ac_link="libtool --mode=link $ac_link"
	AC_LINK_IFELSE([AC_LANG_CALL([], [dkim_init])],
		[av_cv_flags_library_opendkim="ok"])
	ac_link="$save_ac_link"
	LIBS="$SAVE_LIBS"
	LDFLAGS="$SAVE_LDFLAGS"

if test "$av_cv_flags_library_opendkim" = "none"; then
	AC_MSG_ERROR([unable to use opendkim library])
fi
AC_MSG_RESULT([$OPENDKIM_LIB])
AC_SUBST([OPENDKIM_LIB])


#
AC_CACHE_CHECK([opendbx version],
	av_cv_opendbx_version,
	[
	av_cv_opendbx_version="`$PKG_CONFIG --modversion opendbx`"
	])
OPENDBX_CFLAGS=""
OPENDBX_LIB=""
if $PKG_CONFIG --atleast-version=1.4.5 opendbx; then
	AC_CACHE_CHECK([cflags for opendbx],
		av_cv_cflags_opendbx,
		[
		SAVE_CFLAGS="$CFLAGS"
		AC_COMPILE_IFELSE([
			#include <opendbx/api.h>
			],
			[av_cv_cflags_opendbx="none"],
			[av_cv_cflags_opendbx="fail"]
			)
		if test "$av_cv_cflags_opendbx" = "fail"; then
			av_cv_cflags_opendbx="`$PKG_CONFIG --cflags-only-I opendbx`"
			CFLAGS="$av_cv_cflags_opendbx $CFLAGS"
			AC_COMPILE_IFELSE([
				#include <opendbx/api.h>
				],
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
	HAVE_OPENDBX="no"
	OPENDBX_LIB=" `$PKG_CONFIG --libs-only-L opendbx` -lopendbx"
	SAVE_LIBS="$LIBS"
	LIBS="$SAVE_LIBS $OPENDBX_LIB"
	save_ac_link="$ac_link"
	ac_link="libtool --mode=link $ac_link"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <opendbx/api.h>
	], [odbx_t *h;
	odbx_init(&h, "", "", "");
	])], [HAVE_OPENDBX="yes"])
	ac_link="$save_ac_link"
	LIBS="$SAVE_LIBS"
	AC_MSG_RESULT([$HAVE_OPENDBX])
	if test "$HAVE_OPENDBX" = "yes"; then
		AC_DEFINE(HAVE_OPENDBX, 1, [Define if using opendbx])
	else
		OPENDBX_LIB=""
	fi
fi
AC_SUBST([OPENDBX_CFLAGS])
AC_SUBST([OPENDBX_LIB])

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


# ssl
AC_MSG_CHECKING([flags for ssl library])
LIBSSL_CFLAGS="`$PKG_CONFIG --cflags libssl`"
LIBSSL_LDADD="`$PKG_CONFIG --libs libssl`"
AC_MSG_RESULT([$LIBSSL_CFLAGS $LIBSSL_LDADD])
AC_SUBST([LIBSSL_CFLAGS])
AC_SUBST([LIBSSL_LDADD])

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
AC_CHECK_FUNCS([alarm memmove memset select strchr strdup strerror strtol strtoul])

# Check if nettle exists (for redact.c)
NETTLE_LIB=" -lnettle"
AC_MSG_CHECKING([whether nettle is avalable])
SAVE_LIBS="$LIBS"
LIBS="$SAVE_LIBS $NETTLE_LIB"
HAVE_NETTLE="no"
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <nettle/arcfour.h>
#include <nettle/base64.h>
], [struct arcfour_ctx c0;
struct base64_encode_ctx c1;
struct base64_decode_ctx c2;
arcfour_set_key(&c0, 0, "");
base64_decode_init(&c1);
base64_decode_init(&c2);
])], [HAVE_NETTLE="yes"])
LIBS="$SAVE_LIBS"
AC_MSG_RESULT([$HAVE_NETTLE])
if test "$HAVE_NETTLE" = "yes"; then
	AC_DEFINE(HAVE_NETTLE, 1, [Define if using nettle])
else
	NETTLE_LIB=""
fi
AC_SUBST([NETTLE_LIB])


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

# limit test suite entries
AC_SUBST([HAVE_LIBOPENDKIM_220], ["${av_cv_opendkim_version_220}"])

# LN_S used in tests/aclocal.in
AC_PROG_LN_S

# make tests/atconfig
AC_CONFIG_TESTDIR([tests], [src])

AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/filedefs.h
                 etc/Makefile
                 etc/zdkimfilter.conf.dist
                 etc/zdkimfilter.pod
                 tests/atlocal
                 tests/Makefile
                ])
AC_OUTPUT
