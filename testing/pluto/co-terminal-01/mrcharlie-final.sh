#!/bin/sh

ipsec auto --status

: ==== cut ====
cat /tmp/pluto.log
ipsec look
: ==== tuc ====
: ==== end ====
