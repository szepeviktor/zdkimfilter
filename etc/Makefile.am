## Automake

@SET_MAKE@

man_MANS = zdkimfilter.conf.5

CLEANFILES = zdkimfilter.conf.5

if BUILD_DOC
zdkimfilter.conf.5: zdkimfilter.conf.dist $(srcdir)/conf2man.pl
	perl $(srcdir)/conf2man.pl zdkimfilter.conf.dist

endif

sysfilterconfDATA_INSTALL = $(INSTALL) -m 640@PROGRAM_OWNER@

sysfilterconfdir = @COURIER_SYSCONF_INSTALL@/filters
sysfilterconf_DATA = zdkimfilter.conf.dist

install-data-hook:
	@if test -f $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf.dist; then \
		if test -f $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf; then \
			echo --------------------------------------------------------------; \
			echo installed  $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf.dist;  \
			echo existing $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf preserved; \
			echo --------------------------------------------------------------; \
		else \
			cp -p $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf.dist \
				$(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf; \
		fi; \
	fi

