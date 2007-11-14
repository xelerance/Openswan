(../parentI2 ../lib-parentI1/ikev2.record westnet--eastnet-ikev2 parentR1.pcap
    echo TCPDUMP output
    tcpdump -v -v -s 1600 -n -r parentI2.pcap) 2>&1 | sed -f sanity.sed





