#!/bin/sh

iptables -t nat -A POSTROUTING -s 192.0.1.0/24 -d 0.0.0.0/0 -j SNAT --to-source 192.1.2.45
