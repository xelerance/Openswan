ipsec auto --up north--east-l2tp
echo "c server" >/var/run/l2tp-control
sleep 4

ipsec look
ifconfig ppp0
echo done
