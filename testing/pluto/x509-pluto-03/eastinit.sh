: ==== start ====
TESTNAME=x509-pluto-03
source /testing/pluto/bin/eastlocal.sh

rm /tmp/$TESTNAME/ipsec.d/certs/west*
rm /tmp/$TESTNAME/ipsec.d/crls/nic.crl

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec setup start
ipsec auto --add westnet-eastnet-x509-cr

/testing/pluto/basic-pluto-01/eroutewait.sh trap
