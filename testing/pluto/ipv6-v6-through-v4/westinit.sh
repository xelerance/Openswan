: ==== start ====
TESTNAME=ipv6-basic-pluto-01
source /testing/pluto/bin/westlocal.sh

# confirm that the network is alive
ping6 -n -c 4 -I 2001:db8:0:1::45 2001:db8:0:2::23
# make sure that clear text does not get through
ip6tables -A INPUT -i eth1 -s 2001:db8:1:2::/48 -j DROP
# confirm with a ping to east-in
ping6 -n -c 4 -I 2001:db8:0:1::45 2001:db8:0:2::23

ipsec setup start
ipsec auto --add westnet-eastnet-ipv6-in-ipv4
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt
/testing/pluto/bin/wait-until-pluto-started

echo done

