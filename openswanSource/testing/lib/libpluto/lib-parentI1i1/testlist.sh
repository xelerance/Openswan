(../parentI1i1 ikev2.record westnet--eastnet-ikev2 ../lib-parentR1dcookie/parentR1dcookie.pcap parentI1i1.pcap
    echo TCPDUMP output
    tcpdump -t -v -v -s 1600 -n -r parentI1i1.pcap ) 2>&1 | sed -f sanity.sed




