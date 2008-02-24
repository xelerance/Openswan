: ==== start ====
TESTNAME=netkey-pluto-03-sourceip
source /testing/pluto/bin/westlocal.sh

# we break the second interface route to our remote subnet, because
# we are testing the functionality of leftsourceip=
ip route delete 192.0.2.0/24

ipsec setup start
ipsec auto --add westnet-eastnet-sourceip
/testing/pluto/bin/wait-until-pluto-started

echo done

