#!/bin/sh
TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

#ipsec klipsdebug --set pfkey
ROOT= export ROOT

sh $ROOT/testing/klips/saref-alloc-01/alloc_dealloc.sh

#ipsec look


