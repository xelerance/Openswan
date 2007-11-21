(../parentR2 ../lib-parentR1/ikev2.record westnet--eastnet-ikev2 parentI2.pcap
    echo TCPDUMP output
    tcpdump -v -v -s 1600 -n -r parentR2.pcap) 2>&1 | sed -f sanity.sed





