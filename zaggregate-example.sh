#! /bin/sh
#
# A script like this can be invoked by cron to produce and send reports.
# The child shell executes a pipeline consisting of a subshell with a multiline
# printf, cat -, and another printf, all piped through dkimsign and sendmail.
#
# Reusing MESSAGE_ID for the MIME boundary just for fun.  An underscore
# character (_) is enough to guarantee that no base64 encoded line contains it.
#
# Bcc: sends a copy, possibly to the same address that receives aggregate
# reports from external organizations.
#
ORG_DOMAIN=example.com \
ORG_EMAIL=postmaster@$ORG_DOMAIN \
ORG_NAME="This is an example" \
zaggregate -zul --pipe /bin/sh -c '(printf "\
From: $ORG_EMAIL
$TO_HEADER
Bcc: postmaster-dmarc@$ORG_DOMAIN
Date: $(date --rfc-2822)
Subject: Report domain: $DOMAIN Submitter: $ORG_DOMAIN
MIME-Version: 1.0
Message-Id: ${MESSAGE_ID}@$ORG_DOMAIN
Content-Type: multipart/mixed; boundary=BB__${MESSAGE_ID}
Content-Transfer-Encoding: 7bit

\n--BB__${MESSAGE_ID}
Content-Type: text/plain; charset=us-ascii

\n--BB__${MESSAGE_ID}
Content-Type: $CONTENT_TYPE
Content-Transfer-Encoding: $CONTENT_TRANSFER_ENCODING
Content-Disposition: attachment;
	filename=\"$FILENAME\"\n\n"
cat -
printf "\n--BB__${MESSAGE_ID}--\n") |\
dkimsign --filter --domain $ORG_DOMAIN |\
sendmail -f dmarc-bounce@$ORG_DOMAIN'

