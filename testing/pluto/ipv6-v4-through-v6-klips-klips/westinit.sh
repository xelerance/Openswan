: ==== start ====
TESTNAME=ipv6-v4-through-v6-klips-klips
source /testing/pluto/bin/westlocal.sh

# confirm that the network is alive
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -p icmp -j DROP
# confirm with a ping to east-in
ping -n -c 4 -I 192.0.1.254 192.0.2.254

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east-4in6
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo done

