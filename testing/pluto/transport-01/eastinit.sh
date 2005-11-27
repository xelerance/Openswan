: ==== start ====
TESTNAME=transport-01
source /testing/pluto/bin/eastlocal.sh

sh /etc/init.d/inetd stop
sh /etc/init.d/inetd start

telnet localhost 3 | wc -l

ipsec setup start
ipsec auto --add west--east-port3
ipsec auto --add west--east-pass
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --route west--east-pass
ipsec whack --debug-control --debug-controlmore --debug-crypt
