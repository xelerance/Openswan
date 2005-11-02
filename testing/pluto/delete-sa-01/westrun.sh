# we can transmit in the clear
ping -q -c 8 -n 192.1.2.23
# bring up the tunnel
ipsec auto --up west-east
# use the tunnel
ping -q -c 8 -n 192.1.2.23
# show the tunnel!
ipsec eroute
# "Time to shut down my computer!"...
ipsec setup stop
# ...but unless the delete SA is acknowledged, this ping will fail, 
# as our peer still us routed
sleep 5
ping -q -c 8 -n 192.1.2.23
echo done

