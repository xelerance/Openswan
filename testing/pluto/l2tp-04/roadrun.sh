ipsec auto --up road--east-l2tp
echo "c server" >/var/run/l2tp-control

ipsec look
sleep 5
telnet 192.0.2.254 2 | wc -l
ifconfig ppp0 | grep 'inet addr'
echo done
