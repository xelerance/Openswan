#!/bin/sh

: ==== start ====

hostname road.uml.freeswan.org

ifconfig eth0 inet 192.1.3.194
route delete -net default 
route add -net default gw 192.1.3.254

netstat -rn

TESTNAME=xauth-pluto-xauthusername-01
source /testing/pluto/bin/roadlocal.sh

ipsec setup start

ipsec auto --replace xauth-road--eastnet
ipsec whack --status

echo done


