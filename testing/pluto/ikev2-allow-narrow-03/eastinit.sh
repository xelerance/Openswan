: ==== start ====
TESTNAME=ikev2-allow-narrow-03
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add  westnet--eastnet-ikev2
ipsec whack --debug-control --debug-controlmore --debug-crypt
