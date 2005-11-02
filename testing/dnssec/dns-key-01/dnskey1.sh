#!/bin/sh

sh /etc/init.d/bind9 stop

named -c /etc/bind/named.conf-dnssec

ping -n -c 1 192.1.2.254
ping -n -c 1 192.1.2.129
ping -n -c 1 192.1.2.130

: let things settle a bit
sleep 10

dig . key @localhost
dig freeswan.org. key @localhost
dig uml.freeswan.org. key @localhost

echo "key 1234 east.uml.freeswan.org." | ipsec lwdnsq --regress --ignoreeof
echo hi there


