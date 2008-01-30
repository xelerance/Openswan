: ==== start ====
TESTNAME=multinet-03
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-subnets
/testing/pluto/bin/wait-until-pluto-started

