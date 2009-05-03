(../parentR1dcookie ikev2.record westnet--eastnet-ikev2 ../lib-parentI1psk//parentI1psk.pcap parentR1dcookie.pcap
    echo TCPDUMP output
    tcpdump -v -v -s 1600 -n -r parentR1dcookie.pcap) 2>&1 | sed -f ../lib-parentR1/sanity.sed
