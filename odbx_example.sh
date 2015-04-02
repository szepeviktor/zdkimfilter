#! /bin/sh
#
# calls to zfilter_db to simulate incoming messages

ZFILTER_DB=src/zfilter_db

if [ "$1" = "-t" ]; then
	TEST='--test'
elif [ "$1" = "-g" ]; then
	GGG='gdb --args'
elif [ "$1" = "-v" ]; then
	GGG='valgrind --leak-check=full --track-origins=yes --show-reachable=yes'
else
	TEST=
	GGG=
fi

# message from s.example.org
$GGG $ZFILTER_DB $TEST -f odbx_example.conf \
	--set-stats I @ bounces@s.example.org ugo@s.example.org @ @ @  @ @ @  @ @ @ pass fail \
	--set-stats-domain \
		example.org/org/aligned/dmarc:'v=DMARC1; aspf=s; p=reject sp=quarantine pct=50; ri=300   ;   rua=mailto:dmarc@some.example!40,mailto:suchaverylongnamethatwontfininthedatabase@some-other.example!50' \
		s.example.org/author/aligned/spf:softfail/dkim:pass \
		other.example/dkim \
		mailer.s.example.org/spf_helo:permerror

# message from example.com
$ZFILTER_DB $TEST -f odbx_example.conf \
	--set-stats I @ bounces@example.com foo@example.com @ @ @  @ @ @  @ @ @ fail fail \
	--set-stats-domain \
		example.com/author/org/aligned/dmarc:'v=DMARC1; p=reject; ri=600; rua=mailto:dmarc@example.com; fo=1:2:3:4:s:d:a:S:D:' \
		another.example/dkim \
		signed.example/dkim \
		yet.another.example/dkim \
		mailer.example.com/spf_helo

# message from non-dkim.example
$ZFILTER_DB $TEST -f odbx_example.conf \
	--set-stats I @ bounces@non-dmarc.example ugo@non-dmarc.example @ @ @  @ @ @  @ @ @  none none none none\
	--set-stats-domain \
		non-dmarc.example/author/org/aligned/spf:pass/dkim:pass \
		mailer.non-dmarc.example/spf_helo:pass

