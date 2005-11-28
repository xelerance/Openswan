# confirm network with a ping to east-in
ping -n -c 4 192.0.2.254

ipsec auto --up north--east-l2tp
echo "c server" >/var/run/l2tp-control
sleep 4

ipsec look
ifconfig ppp0
echo done
