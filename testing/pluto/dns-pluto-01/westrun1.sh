ipsec setup stop
named
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --replace  dns--westnet-eastnet
ipsec whack --status

ipsec auto --up dns--westnet-eastnet

echo done
