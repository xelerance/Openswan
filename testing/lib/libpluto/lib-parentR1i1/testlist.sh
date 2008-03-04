(../parentR1i1 ikev2.record westnet--eastnet-ikev2 ../lib-parentR1dcookie/parentR1dcookie.pcap parentR1i1.pcap
    echo TCPDUMP output
    tcpdump -t -v -v -s 1600 -n -r parentR1I1dcookie.pcap ) 2>&1 | sed -f sanity.sed




