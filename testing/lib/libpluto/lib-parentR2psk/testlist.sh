(../parentR2psk ../lib-parentR1psk/ikev2.record westnet--eastnet-ikev2 ../lib-parentI2psk/parentI2psk.pcap 2>&1 | tee secrets.raw
    grep '^| ikev2 [IR]' secrets.raw | cut -c3- >ike-secrets.txt
    echo TCPDUMP output
    tcpdump -v -v -s 1600 -n -E 'file ike-secrets.txt' -r parentR2psk.pcap) 2>&1 | sed -f sanity.sed





