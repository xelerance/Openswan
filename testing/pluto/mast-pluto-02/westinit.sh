: ==== start ====
TESTNAME=mast-pluto-02
source /testing/pluto/bin/westlocal.sh

ipsec setup start
ipsec auto --add west-east
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt
/testing/pluto/bin/wait-until-pluto-started

echo done

