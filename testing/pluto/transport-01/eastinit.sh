TESTNAME=transport-01
source /testing/pluto/bin/eastlocal.sh

sh /etc/init.d/inetd restart

ipsec setup start
ipsec auto --add west--east-port3
ipsec auto --add west--east-pass
ipsec auto --route west--east-pass
ipsec whack --debug-control --debug-controlmore --debug-crypt
/testing/pluto/basic-pluto-01/eroutewait.sh trap
