TESTNAME=l2tp-01
source /testing/pluto/bin/eastlocal.sh

sh /etc/init.d/inetd restart

if [ -f /var/run/l2tpd.pid ]; then kill `cat /var/run/l2tpd.pid`; fi
ipsec setup restart
ipsec auto --add west--east-l2tp
ipsec auto --add west--east-pass
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --route west--east-pass
ipsec whack --debug-control --debug-controlmore --debug-crypt

# make sure that clear text does not get through
iptables -A INPUT  -i eth1 -d 192.1.2.23 -p udp --dport 1701 -j REJECT
iptables -A OUTPUT -o eth1 -s 192.1.2.23 -p udp --sport 1701 -j REJECT

mount --bind /testing/pluto/l2tp-01 /etc/ppp
l2tpd -c east.l2tpd.conf 

