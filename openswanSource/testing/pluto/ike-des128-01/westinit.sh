: ==== start ====
TESTNAME=ike-des128-01
source /testing/pluto/bin/westlocal.sh

ipsec setup restart
ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt
/testing/pluto/bin/wait-until-pluto-started

echo done

