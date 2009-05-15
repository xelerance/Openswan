: ==== start ====
TESTNAME=netkey-pluto-05
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet
/testing/pluto/bin/wait-until-pluto-started
