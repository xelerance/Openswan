: ==== start ====
ipsec setup start
ipsec auto --add westnet-eastnet-ipcomp
/testing/pluto/basic-pluto-01/eroutewait.sh trap
ipsec setup stop
halt -p -f
