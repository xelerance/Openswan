: ==== start ====
TESTNAME=dpd-05
source /testing/pluto/bin/westlocal.sh

iptables -F INPUT 
iptables -F OUTPUT

ipsec setup start
sleep 5
ipsec auto --add west-east

