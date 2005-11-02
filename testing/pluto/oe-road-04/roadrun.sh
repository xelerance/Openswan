#!/bin/sh

: turn on debugging
ipsec whack --debug-control --debug-oppo --debug-dns

: check out config
ipsec eroute

ping -c 4 -n 192.0.2.2

: transfer some data
nc -w 5 192.0.2.2 2 | wc -l

if ! ipsec eroute | grep -q tun ; then echo 'MISSING TUNNEL!' ; ipsec eroute ; ipsec auto --status ; else echo 'found expected tunnel' ; fi

# output required!
grep '^found KEY RR but not TXT RR ' /tmp/pluto.log || echo "DIAGNOSTIC MISSING"
