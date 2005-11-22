TESTNAME=l2tp-01
source /testing/pluto/bin/eastlocal.sh

sh /etc/init.d/inetd restart

ipsec setup start
ipsec auto --add west--east-l2tp
ipsec auto --add west--east-pass
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --route west--east-pass
ipsec whack --debug-control --debug-controlmore --debug-crypt
