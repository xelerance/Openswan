: ==== start ====
TESTNAME=protoport-02
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet-protoport-any
/testing/pluto/bin/wait-until-pluto-started

