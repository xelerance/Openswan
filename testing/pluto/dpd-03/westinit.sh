TESTNAME=dpd-03
source /testing/pluto/bin/westlocal.sh

ipsec setup start

/testing/pluto/bin/wait-until-policy-loaded

ipsec auto --add west-east


