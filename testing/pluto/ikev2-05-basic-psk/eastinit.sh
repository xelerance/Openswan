: ==== start ====
TESTNAME=ikev2-05-basic-psk
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add  westnet--eastnet-ikev2
/testing/pluto/bin/wait-until-pluto-started
