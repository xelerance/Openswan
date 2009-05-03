: ==== start ====
TESTNAME=phase1-expire-01-reconnect-klips
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-crypt
/testing/pluto/bin/wait-until-pluto-started
