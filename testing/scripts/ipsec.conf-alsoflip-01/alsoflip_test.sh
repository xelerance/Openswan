#!/bin/sh

set +o emacs

: ==== start ====

D=/testing/scripts/ipsec.conf-alsoflip-01

export IPSEC_CONFS="$D/etc-alsoflip"

ipsec setup start ; i=0 ; while i=`expr $i + 1`; [ $i -lt 20 ] && ! { ipsec auto --status | grep 'prospective erouted' >/dev/null ; } ; do sleep 1 ; done
ipsec auto --add flip-base-net
ipsec auto --add flip-flip-net-base
ipsec auto --add noflip-base-base
ipsec auto --status
ipsec setup stop

: ==== end ====
