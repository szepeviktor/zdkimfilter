## Automake

@SET_MAKE@

EXTRA_DIST = logrotate.example opendkim-genstats.patch

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

