#! /bin/sh
#
# DMARC aggregate reports still undelivered late in the morning
#
# The MAIL FROM is being set in the last line of zaggregate-example.sh:
#
#    sendmail -f dmarc-bounce@$ORG_DOMAIN'
#
# ORG_DOMAIN must match the value there and the user in mailq is assumed
# to be "courier" (hey, this is an example, eh?)

ORG_DOMAIN=example.com

reason="DMARC aggregate report still (partially) undelivered in the morning"
for id in $(mailq -batch |\
	sed -rn "s/[^;]*;([^;]*);[^;]*;courier;dmarc-bounce@$ORG_DOMAIN;.*/\1/p")
	do cancelmsg "$id" "$reason" > /dev/null 2>&1
done
