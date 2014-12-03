## Automake

@SET_MAKE@

man_MANS = zdkimfilter.conf.5 zdkimfilter.8 zfilter_db.1 dkimsign.1 redact.1

CLEANFILES = zdkimfilter.conf.pod zdkimfilter.conf.5 zdkimfilter.8 \
 zfilter_db.1 dkimsign.1 redact.1

if BUILD_DOC

.pod.1:
	$(POD2MAN) @POD2MAN_OPTIONS@ --section=1 --name=$* $< $@

.pod.5:
	$(POD2MAN) @POD2MAN_OPTIONS@ --section=5 --name=$* $< $@

.pod.8:
	$(POD2MAN) @POD2MAN_OPTIONS@ --section=8 --name=$* $< $@


# zdkimfilter.conf.5: zdkimfilter.conf.pod
#	pod2man --release="$(PACKAGE) $(VERSION)" --center=zdkimfilter --section=5 \
#    --name=zdkimfilter.conf zdkimfilter.conf.pod zdkimfilter.conf.5

endif

INSTALL = /bin/sh $(top_builddir)/myinstall.sh

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
			echo --------------------------------------------------------------; \
			echo installed  $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf.dist;  \
			echo copy it to $(DESTDIR)$(sysfilterconfdir)/zdkimfilter.conf and edit; \
			echo --------------------------------------------------------------; \
		fi; \
	fi

