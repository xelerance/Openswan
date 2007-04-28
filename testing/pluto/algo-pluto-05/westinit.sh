: ==== start ====
TESTNAME=algo-pluto-05 
source /testing/pluto/bin/westlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-aes256
/testing/pluto/bin/wait-until-pluto-started 

echo done

