TESTNAME=dpd-01

source /testing/pluto/bin/eastlocal.sh

ipsec setup start

ipsec auto --add west-east

/testing/pluto/basic-pluto-01/eroutewait.sh trap

