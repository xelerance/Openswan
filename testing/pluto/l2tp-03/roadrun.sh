ipsec auto --up road--east-l2tp
echo "c server" >/var/run/l2tp-control

ipsec look
sleep 5
ifconfig ppp0
echo done
