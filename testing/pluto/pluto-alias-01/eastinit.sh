: ==== start ====
TESTNAME=pluto-alias-01
source /testing/pluto/bin/eastlocal.sh
ifconfig eth0:0 192.168.99.1
ifconfig eth0:1 172.16.0.1
ifconfig
ipsec setup start
netstat -ln
