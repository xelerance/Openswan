: ==== start ====
TESTNAME=ikev2-05
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
# no conns are loaded
# ipsec auto --add  westnet--eastnet-ikev2
ipsec whack --debug-control --debug-controlmore --debug-crypt
/testing/pluto/bin/wait-until-pluto-started
