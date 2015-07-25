#! /bin/sh
#
# custom install to set per-file ownership (except in staged install)
#

case $1 in
	zdkimfilter)
		install_options=' -o courier -g courier'
		if [ -n "$DESTDIR" -a ! -w / ]; then
			stars="***************************************************************"
			printf '%s\n**  WARNING:\n**  %s\n**  %s\n%s\n' \
				"$stars" \
				'Permissions and ownership of installed files not being set!' \
				'You must be root in order to install this package properly.' \
				"$stars"
		fi
		;;
	dkimsign)
		install_options='  -o courier -g courier';;
	zdkimfilter.conf.dist)
		install_options='-m 640  -o courier -g courier';;
	*)
		install_options=;;
esac
if [ -n "$DESTDIR" -a ! -w / ]; then
		install_options=
fi

/usr/bin/install -c $install_options $@

