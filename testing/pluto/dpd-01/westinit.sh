TESTNAME=dpd-01

source /testing/pluto/bin/westlocal.sh

ipsec setup start
sleep 5
ipsec auto --add west-east

