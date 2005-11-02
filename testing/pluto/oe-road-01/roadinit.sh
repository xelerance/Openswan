#!/bin/sh

named
sleep 2

/testing/pluto/bin/look-for-key road.uml.freeswan.org AQNxbOBmD

netstat -rne

route add -net default gw 192.1.3.254
ipsec setup start

/testing/pluto/oe-road-01/policy-wait.sh

echo done


