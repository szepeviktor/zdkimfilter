## Automake

@SET_MAKE@

MAILFILE = $(srcdir)/funnymail.noparen.eml.b64
TESTFILE = $(srcdir)/undo_percent_relay.ctlfile.txt

TESTSUITE = $(srcdir)/testsuite

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{					\
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])' && \
	  echo 'm4_define([AT_PACKAGE_URL],       [@PACKAGE_URL@])'; \
	} >$(srcdir)/package.m4

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE) atlocal.in  \
 $(MAILFILE) $(TESTFILE)

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

CONFIG_CLEAN_FILES = atconfig atlocal

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' --clean

#AUTOM4TE = $(SHELL) $(srcdir)/build-aux/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4 $(MAILFILE) $(TESTFILE)
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

