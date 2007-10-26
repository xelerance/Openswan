(../parentI1 ikev2.record westnet--eastnet-ikev2
    echo TCPDUMP output
    tcpdump -v -v -s 1600 -n -r parentI1.pcap ) 2>&1 | sed -f sanity.sed




