: ==== start ====
TESTNAME=basic-pluto-07
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-twofish
/testing/pluto/basic-pluto-01/eroutewait.sh trap
