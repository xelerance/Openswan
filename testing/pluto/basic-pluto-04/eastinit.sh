TESTNAME=basic-pluto-04
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-aes
/testing/pluto/basic-pluto-01/eroutewait.sh trap
