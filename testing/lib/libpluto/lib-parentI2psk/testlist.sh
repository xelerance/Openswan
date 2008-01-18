(../parentI2psk ../lib-parentI1psk/ikev2.record westnet--eastnet-ikev2 ../lib-parentR1psk/parentR1.pcap 2>&1 | tee secrets.raw
    grep '^| ikev2 [IR]' secrets.raw | cut -c3- >ike-secrets.txt
    echo TCPDUMP output
    tcpdump -t -v -v -s 1600 -n -E 'file ike-secrets.txt' -r parentI2psk.pcap ) 2>&1 | sed -f sanity.sed






