: ==== start ====
TESTNAME=whackrecord-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec whack --whackrecord /tmp/east.record
ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-crypt
/testing/pluto/bin/wait-until-pluto-started

