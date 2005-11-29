ipsec auto --up north--east-l2tp
echo "c server" >/var/run/l2tp-control

ipsec look
sleep 5
ifconfig ppp0
telnet 192.0.2.254 2 | wc -l
echo done
