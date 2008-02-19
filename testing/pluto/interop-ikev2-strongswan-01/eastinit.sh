: ==== start ====
TESTNAME=interop-ikev2-strongswan-01

mkdir -p /tmp/strongswan/etc/ipsec.d/certs
cp /testing/pluto/$TESTNAME/east.conf /tmp/strongswan/etc/ipsec.conf
cp /testing/pluto/$TESTNAME/east.secrets /tmp/strongswan/etc/ipsec.secrets
chmod 600 /tmp/strongswan/etc/ipsec.secrets
touch /tmp/strongswan/etc/ipsec.secrets
#strongswan way of starting
/usr/local/strongswan/sbin/ipsec start
# no conns are loaded
#
# note: ikev2 is done by charon, but ikev1 by pluto, so hopefully
# the below script is still good to use 
/testing/pluto/bin/wait-until-pluto-started

echo done
