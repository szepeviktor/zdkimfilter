#! /bin/sh
#
ORG_DOMAIN=example.com
ORG_EMAIL=postmaster@$ORG_DOMAIN \
ORG_NAME="This is an example" \
sw/zdkimfilter/src/zaggregate -zul --pipe /bin/sh -c '(printf "\
From: $ORG_EMAIL\n\
$TO_HEADER\n\
Bcc: postmaster-dmarc@$ORG_DOMAIN\n\
Date: $(date --rfc-2822)\n\
Subject: Report domain: $DOMAIN Submitter: $ORG_DOMAIN\n\
MIME-Version: 1.0\n\
Message-Id: ${MESSAGE_ID}@$ORG_DOMAIN\n\
Content-Type: multipart/mixed; boundary=BB__${MESSAGE_ID}\n\
Content-Transfer-Encoding: 7bit\n\
\n\
\n--BB__${MESSAGE_ID}\n\
Content-Type: text/plain; charset=us-ascii\n\
\n\
\n--BB__${MESSAGE_ID}\n\
Content-Type: $CONTENT_TYPE\n\
Content-Transfer-Encoding: $CONTENT_TRANSFER_ENCODING\n\
Content-Disposition: attachment;\n\
	filename=\"$FILENAME\"\n\n"; cat -; printf "\
\n--BB__${MESSAGE_ID}--\n") |\
/usr/local/bin/sendmail'

