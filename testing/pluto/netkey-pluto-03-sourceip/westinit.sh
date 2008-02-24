: ==== start ====
TESTNAME=netkey-pluto-03-sourceip
source /testing/pluto/bin/westlocal.sh

ipsec setup start
ipsec auto --add westnet-east-sourceip
/testing/pluto/bin/wait-until-pluto-started

echo done

