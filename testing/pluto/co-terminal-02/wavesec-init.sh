#!/bin/sh

: ==== start ====

ipsec setup stop

# move gateway to the 3 network so that we can get OE to work.
route delete default
ifconfig eth1 inet 192.1.3.45 netmask 255.255.255.0 broadcast 192.1.3.255
route add -net default gw 192.1.3.254

rndc stop
named

sleep 1

dig 2.2.0.192.in-addr.arpa. txt

# nuke special route that may be there.
route delete -net 192.0.2.0 netmask 255.255.255.0 gw 192.1.2.23

ipsec setup --config /testing/pluto/co-terminal-02/wavesec.conf start
ipsec auto --config /testing/pluto/co-terminal-02/wavesec.conf --add japan--wavesec

ipsec eroute


