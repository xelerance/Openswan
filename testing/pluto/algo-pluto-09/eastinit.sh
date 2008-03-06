: ==== start ====
TESTNAME=algo-pluto-09
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-esp-3des-alg
/testing/pluto/basic-pluto-01/eroutewait.sh trap
