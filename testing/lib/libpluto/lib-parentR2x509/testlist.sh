(../parentR2x509 ikev2.record ikev2-westnet-eastnet-x509-cr ../lib-parentI2x509/parentI2x509.pcap 2>&1 | tee secrets.raw
    grep '^| ikev2 [IR]' secrets.raw | cut -c3- >ike-secrets.txt
    echo TCPDUMP output
    tcpdump -v -v -s 1600 -n -E 'file ike-secrets.txt' -r parentR2x509.pcap) 2>&1 | sed -f sanity.sed
