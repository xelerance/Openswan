(../parentI1psk ikev2.record westnet--eastnet-ikev2
    echo TCPDUMP output
    tcpdump -t -v -v -s 1600 -n -r parentI1psk.pcap ) 2>&1 | sed -f ../lib-parentI1/sanity.sed




