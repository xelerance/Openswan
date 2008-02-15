: ==== start ====
TESTNAME=interop-ikev2-strongswan-01

#strongswan way of starting
/usr/local/strongswan/sbin/ipsec start
# no conns are loaded
#
# note: ikev2 is done by charon, but ikev1 by pluto, so hopefully
# the below script is still good to use 
/testing/pluto/bin/wait-until-pluto-started
