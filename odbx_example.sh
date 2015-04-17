#! /bin/sh
#
# faked calls to zfilter_db to simulate incoming messages
#
# After running odbx_example.sql to create a test database, run this script
# to populate it.  After a few minutes, run a command like the following to
# see aggregate reports:
#
# ORG_EMAIL=foo@example.edu src/zaggregate -vf odbx_example.conf

ZFILTER_DB=src/zfilter_db

# message from s.example.org
$ZFILTER_DB $TEST -f odbx_example.conf \
	--set-stats I @ bounces@s.example.org ugo@s.example.org @ @ @  @ @ @  @ @ @ pass fail \
	--set-stats-domain \
		example.org/org/aligned/dmarc:'v=DMARC1; aspf=s; p=reject sp=quarantine pct=50; ri=300;   rua=mailto:dmarc@example.org!40,mailto:f@example.org' \
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

