export TZ=UTC

../parentI3 ../lib-parentI1/ikev2.record westnet--eastnet-ikev2 parentR2.pcap 2>&1 | sed -f sanity.sed


