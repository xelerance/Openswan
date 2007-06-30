: ==== start ====

# make sure that packets don't sneak in
iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509
