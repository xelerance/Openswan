TESTNAME=dh1-pluto-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-weak
/testing/pluto/basic-pluto-01/eroutewait.sh trap
