#!/bin/sh

iptables -t nat -F
iptables -F

# change internal interface to same as for north
ifconfig eth0 inet 192.1.3.254 netmask 255.255.255.0 up

# NAT west IP to ours
iptables -t nat -A POSTROUTING --source 192.1.3.0/24 --destination 0.0.0.0/0 -j SNAT --to-source 192.1.2.45

# make sure that we never acidentially let ESP through.
iptables -I FORWARD 1 --proto 50 -j DROP
iptables -I FORWARD 2 --destination 192.0.2.0/24 -j DROP
iptables -I FORWARD 3 --source 192.0.2.0/24 -j DROP

# route
iptables -I INPUT 1 --destination 192.0.2.0/24 -j DROP

# Display the table, so we know it's correct.
iptables -t nat -L -n
iptables -L -n

echo done.
