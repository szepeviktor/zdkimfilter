#bin/bash

dbcom="mysql --batch --skip-column-names -u test_zfilter test_zfilter"

doms=$($dbcom <<< "select domain from domain where domain rlike 'xn--'")
for d in $doms; do
	u="$(2idn $d)"
	echo "$d -> $u"
	printf "update domain set domain='%s' where domain='%s'" "$u" "$d" |\
		$dbcom
done
