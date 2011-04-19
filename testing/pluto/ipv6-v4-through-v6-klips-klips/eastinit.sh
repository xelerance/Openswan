: ==== start ====
TESTNAME=ipv6-v4-through-v6-klips-klips
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-4in6
ipsec whack --debug-control --debug-controlmore --debug-crypt
