: ==== start ====
TESTNAME=ikev2-x509-01
source /testing/pluto/bin/eastlocal.sh

rm /tmp/$TESTNAME/ipsec.d/certs/west*
rm /tmp/$TESTNAME/ipsec.d/crls/nic.crl

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec setup start
ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add ikev2-westnet-eastnet-x509-cr

/testing/pluto/basic-pluto-01/eroutewait.sh trap
