# we can transmit in the clear
ping -q -c 8 -n 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
ping -c 8 -n 192.1.2.23
echo done

echo end westrun.sh
