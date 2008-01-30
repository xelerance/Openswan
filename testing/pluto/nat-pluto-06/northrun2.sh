ipsec setup stop
ifconfig eth1 inet 192.1.3.34
route add -net default gw 192.1.3.254

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet--eastnet-nat
ipsec whack --debug-control --debug-controlmore --debug-parsing

ipsec auto --up northnet--eastnet-nat

echo two


