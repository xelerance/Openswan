#!/bin/sh
# NOTE: this is shared by a number of tests

: turn on debugging
ipsec whack --debug-control --debug-oppo --debug-dns

: check out config
ipsec eroute

ping -c 4 -n 192.0.2.2

: transfer some data
nc -w 5 192.0.2.2 2 | wc -l

ipsec eroute | grep -l tun

