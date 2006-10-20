TESTNAME=iv-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec auto --add westnet-eastnet
ipsec whack --name westnet-eastnet --impair-sa-fail --debug-control --debug-controlmore --debug-crypt
/testing/pluto/bin/wait-until-pluto-started

