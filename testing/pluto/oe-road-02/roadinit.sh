#!/bin/sh

ifconfig eth0 inet 192.1.3.210
route delete -net default 
route add -net default gw 192.1.3.254

netstat -rne

named
sleep 2

/testing/pluto/bin/look-for-txt roadtxt.uml.freeswan.org AQNxbOBmD


mkdir -p /tmp/oe-road-02
cp /testing/pluto/oe-road-02/road.conf  /tmp/oe-road-02/ipsec.conf
cp /etc/ipsec.secrets                   /tmp/oe-road-02
(cd /tmp/oe-road-02 && ln -s /etc/ipsec.d ipsec.d )

IPSEC_CONFS=/tmp/oe-road-02 export IPSEC_CONFS

ipsec setup start

/testing/pluto/oe-road-01/policy-wait.sh

echo done


