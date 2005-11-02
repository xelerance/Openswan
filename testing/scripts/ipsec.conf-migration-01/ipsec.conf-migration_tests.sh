#!/bin/sh

set +o emacs

ICP=/testing/scripts/ipsec.conf.pairs

export PATH="$ICP/bin:$PATH"

cd $ICP

ipsec setup start

cat /var/run/ipsec.info

( cd empty ; drill ; differ+ ; cd .. ; )
