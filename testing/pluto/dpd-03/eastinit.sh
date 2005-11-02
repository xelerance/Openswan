TESTNAME=dpd-03
source /testing/pluto/bin/eastlocal.sh

ipsec setup start

/testing/pluto/bin/wait-until-policy-loaded

ipsec auto --add west-east

/testing/pluto/basic-pluto-01/eroutewait.sh trap


