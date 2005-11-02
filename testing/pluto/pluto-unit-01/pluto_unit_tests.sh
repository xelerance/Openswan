#!/bin/sh

PATH=/testing/pluto/bin:$PATH export PATH

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"
/testing/pluto/bin/ifconfigs up

cd /tmp
mkdir log
ln -s /testing/pluto/log.ref       .
ln -s /testing/pluto/ipsec.secrets .
ln -s /testing/pluto/ipsec.d .

. doauto --diff isakmp-psk isakmp-rsa isakmp-rsa-case isakmp-rsa-dot ipsec-psk ipsec-rsa ipsec-rsa-time-neg ipsec-rsa-time-trunc ipsec-rsa-time-neg-dontrekey ipsec-rsa-delete ipsec-rsa-c ipsec-rsa-co ipsec-psk-rw ipsec-psk-id-rw ipsec-rsa-rw
