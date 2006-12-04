: ==== start ====
TESTNAME=alias-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add franklin
/testing/pluto/bin/wait-until-pluto-started
