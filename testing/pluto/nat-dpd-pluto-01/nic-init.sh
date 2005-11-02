iptables -A FORWARD -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP
iptables -t nat -A POSTROUTING -s 192.1.3.0/24 -d 0.0.0.0/0 -j SNAT --to-source 192.1.2.254
