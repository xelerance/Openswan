: ==== start ====
TESTNAME=multinet-04
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnets-eastnet
/testing/pluto/bin/wait-until-pluto-started

