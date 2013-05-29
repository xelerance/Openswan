: ==== start ====
TESTNAME=ikev2-allow-narrow-03
source /testing/pluto/bin/westlocal.sh
export PLUTO_EVENT_RETRANSMIT_DELAY=3
export PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=4

# confirm that the network is alive
ping -n -c 1 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping to east-in
ping -n -c 1 192.0.2.254

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add westnet--eastnet-ikev2
ipsec auto --status
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo done

