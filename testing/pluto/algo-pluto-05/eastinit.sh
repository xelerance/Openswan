: ==== start ====
TESTNAME=algo-pluto-05
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-both
/testing/pluto/bin/wait-until-pluto-started
echo done
