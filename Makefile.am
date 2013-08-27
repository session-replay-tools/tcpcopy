SUBDIRS = src
EXTRA_DIST = README.md\
             COPYING\
             AUTHORS\
             ChangeLog\
             INSTALL\
             NEWS\
             configure.ac

.PHONY: release snapshot

release:
	rm -rf .deps */.deps
	$(MAKE) distcheck

snapshot:
	$(MAKE) dist distdir=$(PACKAGE)-`date +%Y-%m-%d`
